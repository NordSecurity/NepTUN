use std::{
    io::{self, Write},
    mem::MaybeUninit,
    net::{IpAddr, SocketAddr},
    ops::ControlFlow,
    os::fd::AsFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use nix::poll::{PollFd, PollFlags};
use socket2::Socket;

use crate::{
    device::{
        dev_lock::Lock,
        peer::Peer,
        waker::{poll_retry, Resume, Waker},
        Device, DeviceHandle, Error, MAX_PKT_SIZE,
    },
    noise::{self, rate_limiter::RateLimiter, Packet, PacketData, Received, Tunn, TunnResult},
};

pub(super) struct Inbound {
    device: Arc<Lock<Device>>,
    stop: Arc<AtomicBool>,
    waker: Arc<Waker>,
}

impl Inbound {
    pub fn new(device: Arc<Lock<Device>>, stop: Arc<AtomicBool>, waker: Arc<Waker>) -> Self {
        Self {
            device,
            stop,
            waker,
        }
    }

    pub fn run(&self) {
        if let Err(e) = self.run_thread_main_loop() {
            tracing::error!(message = "Critical inbound thread failure, closing device", error = ?e);
            let mut d = self.device.read();
            DeviceHandle::close_device(&mut d);
        }
    }

    fn run_thread_main_loop(&self) -> Result<(), Error> {
        let mut rcvbuf = [0u8; MAX_PKT_SIZE];
        let mut dstbuf = [0u8; MAX_PKT_SIZE];

        while !self.stop.load(Ordering::Relaxed) {
            if let Resume::OnWake = self.run_inner_loop(&mut rcvbuf, &mut dstbuf)? {
                self.waker.wait()?;
            }
        }

        Ok(())
    }

    fn run_inner_loop(
        &self,
        rcvbuf: &mut [u8; MAX_PKT_SIZE],
        dstbuf: &mut [u8; MAX_PKT_SIZE],
    ) -> Result<Resume, Error> {
        let device = self.device.read();

        let view = match InboundView::new(&device, &self.waker) {
            Ok(v) => v,
            Err(e) => {
                match e {
                    ViewFailed::NotConnected => {
                        tracing::debug!(message = "Not connected, parked until sockets are opened.")
                    }
                    ViewFailed::EmptyKeyPair => tracing::trace!(message = "Empty key pair"),
                }
                return Ok(Resume::OnWake);
            }
        };

        let mut poll_set = PollSet::new(&view);

        // Sockets readiness loop
        loop {
            poll_retry(poll_set.as_mut_slice())?;

            if poll_set.woken() {
                self.waker.ack();
                return Ok(Resume::Now);
            }

            let mut invalidated = false;

            for (slot, revents) in poll_set.ready() {
                if revents.contains(PollFlags::POLLNVAL) {
                    return Err(Error::InternalError(format!(
                        "Polled an invalid fd on {}",
                        slot.kind()
                    )));
                }

                if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP) {
                    match slot {
                        Slot::Conn(conn) => {
                            tracing::debug!(message = "Connected socket failed", revents = ?revents);
                            let _ = conn.peer.shutdown_endpoint();
                            invalidated = true;
                        }
                        Slot::Anon(_) => {
                            tracing::warn!(message = "UDP socket invalidated", revents = ?revents);
                            invalidated = true;
                        }
                    }
                    continue;
                }

                if revents.contains(PollFlags::POLLIN) {
                    let result = match slot {
                        Slot::Anon(sock) => view.drain_anon(sock, rcvbuf, dstbuf)?,
                        Slot::Conn(conn) => view.drain_conn(conn, rcvbuf, dstbuf)?,
                    };

                    if result.is_break() {
                        invalidated = true;
                        break;
                    }
                }
            }

            if invalidated {
                return Ok(Resume::Now);
            }
        }
    }
}

fn verify_incoming<'a, 'c>(
    rate_limiter: Option<&RateLimiter>,
    src_addr: Option<IpAddr>,
    datagram: &'a [u8],
    cookie_buf: &'c mut [u8],
) -> Result<Packet<'a>, Option<&'c mut [u8]>> {
    match rate_limiter {
        Some(rate_limiter) => match rate_limiter.verify_packet(src_addr, datagram, cookie_buf) {
            Ok(packet) => Ok(packet),
            Err(TunnResult::WriteToNetwork(cookie)) => Err(Some(cookie)),
            Err(_) => Err(None),
        },
        None => Tunn::parse_incoming_packet(datagram).map_err(|_| None),
    }
}

struct InboundView<'a> {
    device: &'a Device,
    waker: &'a Waker,
    udp4: &'a Socket,
    udp6: &'a Socket,
    // this is owned, as the `try_clone`d fds must outlive the poll
    conns: Vec<Conn>,
}

enum ViewFailed {
    NotConnected,
    EmptyKeyPair,
}

impl<'a> InboundView<'a> {
    fn new(device: &'a Device, waker: &'a Waker) -> Result<Self, ViewFailed> {
        let (Some(udp4), Some(udp6)) = (device.udp4.as_deref(), device.udp6.as_deref()) else {
            return Err(ViewFailed::NotConnected);
        };

        if device.key_pair.is_none() {
            return Err(ViewFailed::EmptyKeyPair);
        }

        let conns = device
            .peers
            .values()
            .filter_map(|peer| {
                let endpoint = peer.endpoint();
                let sock = endpoint.conn.as_ref()?.try_clone().ok()?;
                Some(Conn {
                    peer: Arc::clone(peer),
                    sock,
                    peer_addr: endpoint.addr?,
                })
            })
            .collect();

        Ok(Self {
            device,
            waker,
            udp4,
            udp6,
            conns,
        })
    }

    fn drain_anon(
        &self,
        sock: &Socket,
        rcvbuf: &mut [u8; MAX_PKT_SIZE],
        dstbuf: &mut [u8; MAX_PKT_SIZE],
    ) -> Result<ControlFlow<()>, Error> {
        let mut resnapshot = false;

        loop {
            if self.waker.is_pending() {
                self.waker.ack();
                return Ok(ControlFlow::Break(()));
            }

            // Safety: the `recv_from` implementation promises not to write uninitialised
            // bytes to the buffer, so this casting is safe.
            let src_buf = unsafe { &mut *(&mut rcvbuf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };

            let Ok((packet_len, addr)) = sock.recv_from(src_buf) else {
                break;
            };

            let packet = match rcvbuf.get(..packet_len) {
                Some(p) => p,
                None => {
                    tracing::error!("Buffer size different from packet length");
                    continue;
                }
            };

            let sock_addr = match addr.as_socket() {
                Some(s) => s,
                None => {
                    tracing::warn!("Invalid socket address family");
                    continue;
                }
            };

            let parsed_packet = match verify_incoming(
                self.device.rate_limiter.as_deref(),
                Some(sock_addr.ip()),
                packet,
                dstbuf,
            ) {
                Ok(packet) => packet,
                Err(Some(cookie)) => {
                    if let Err(err) = sock.send_to(cookie, &addr) {
                        tracing::warn!(message = "Failed to send cookie", error = ?err, dst = ?addr);
                    }
                    continue;
                }
                Err(None) => continue,
            };

            let data = match parsed_packet {
                Packet::PacketData(data) => data,
                // handshake messages are handled by the control plane
                _ => {
                    self.device.queue_handshake(packet, sock_addr);
                    continue;
                }
            };

            let Some(peer) = self.device.peers_by_idx.get(&(data.receiver_idx >> 8)) else {
                continue;
            };

            if !self.deliver_data(peer, data, &mut dstbuf[..]) {
                continue;
            }

            if peer.set_endpoint(sock_addr) {
                resnapshot = true;
            }

            // This packet was OK, that means we want to create a connected socket for this peer
            #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
            {
                if self.device.config.use_connected_socket {
                    if let Err(e) = peer.connect_endpoint(
                        self.device.listen_port,
                        self.device.config.skt_buffer_size,
                    ) {
                        tracing::error!(
                            message = "Failed to create connected socket for a peer",
                            public_key = peer.public_key.1,
                            error = ?e
                        );
                    } else {
                        resnapshot = true;
                    }
                }
            }

            if resnapshot {
                return Ok(ControlFlow::Break(()));
            }
        }

        Ok(ControlFlow::Continue(()))
    }

    fn drain_conn(
        &self,
        conn: &Conn,
        rcvbuf: &mut [u8; MAX_PKT_SIZE],
        dstbuf: &mut [u8; MAX_PKT_SIZE],
    ) -> Result<ControlFlow<()>, Error> {
        loop {
            if self.waker.is_pending() {
                self.waker.ack();
                return Ok(ControlFlow::Break(()));
            }

            // Safety: socket2 promises not to write uninitialised bytes into the buffer.
            let recv_buf =
                unsafe { &mut *(&mut rcvbuf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };

            let read_bytes = match conn.sock.recv(recv_buf) {
                Ok(n) => n,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => break,
                    io::ErrorKind::Interrupted => continue,
                    _ => {
                        tracing::warn!(message = "Connected socket recv failed", error = ?e);
                        let _ = conn.peer.shutdown_endpoint();
                        return Ok(ControlFlow::Break(()));
                    }
                },
            };

            if read_bytes > 0 {
                #[allow(clippy::indexing_slicing)]
                let datagram = &rcvbuf[..read_bytes];

                let parsed_packet = match verify_incoming(
                    self.device.rate_limiter.as_deref(),
                    Some(conn.peer_addr.ip()),
                    datagram,
                    dstbuf,
                ) {
                    Ok(packet) => packet,
                    Err(Some(cookie)) => {
                        if let Err(err) = conn.sock.send(cookie) {
                            tracing::warn!(message = "Failed to send cookie", error = ?err);
                        }
                        continue;
                    }
                    Err(None) => continue,
                };

                let data = match parsed_packet {
                    Packet::PacketData(data) => data,
                    // handshake messages are handled by the control plane
                    _ => {
                        self.device.queue_handshake(datagram, conn.peer_addr);
                        continue;
                    }
                };

                self.deliver_data(&conn.peer, data, &mut dstbuf[..]);
            } else {
                // Avoid spin in case of the EOF on a shutdown socket
                return Ok(ControlFlow::Break(()));
            }
        }

        Ok(ControlFlow::Continue(()))
    }

    /// Decrypts a data packet and writes it to the tunnel
    ///
    /// Returns `true` if the packet should update peer's endpoint
    fn deliver_data(&self, peer: &Peer, data: PacketData<'_>, dstbuf: &mut [u8]) -> bool {
        let Received {
            result,
            queue_ready,
        } = noise::decapsulate_data_off_lock(&peer.tunnel, data, dstbuf);

        if queue_ready && peer.request_handshake() {
            self.device.notify_control();
        }

        match result {
            TunnResult::Done => true,
            TunnResult::WriteToTunnel(packet, src_addr) => {
                if let Some(callback) = &self.device.config.firewall_process_inbound_callback {
                    if !callback(&peer.public_key.0, packet) {
                        return false;
                    }
                }

                if peer.is_allowed_ip(src_addr) {
                    _ = self.device.iface.as_ref().write(packet);
                    tracing::trace!(
                        message = "Writing packet to tunnel",
                        interface = ?self.device.iface.name(),
                        packet_length = packet.len(),
                        src_addr = ?src_addr,
                        public_key = peer.public_key.1,
                    );
                } else {
                    tracing::debug!(
                        message = "Dropping packet from outside of allowed IPs",
                        src_addr = ?src_addr,
                    );
                }
                true
            }
            TunnResult::Err(e) => {
                tracing::warn!(message = "Failed to handle packet", error = ?e);
                false
            }
            TunnResult::WriteToNetwork(_) => {
                tracing::error!("Unexpected result from decapsulate");
                false
            }
        }
    }
}

struct Conn {
    peer: Arc<Peer>,
    sock: Socket,
    peer_addr: SocketAddr,
}

enum Slot<'a> {
    Anon(&'a Socket),
    Conn(&'a Conn),
}

impl Slot<'_> {
    fn kind(&self) -> &'static str {
        match self {
            Slot::Anon(_) => "anonymous UDP socket",
            Slot::Conn(..) => "connected peer socket",
        }
    }
}

// TODO: consider PollSet restructuring to clearly distinguish always present waker
struct PollSet<'a> {
    // pfds[0] is always the waker
    pfds: Vec<PollFd<'a>>,
    slots: Vec<Slot<'a>>,
}

impl<'a> PollSet<'a> {
    fn new(view: &'a InboundView) -> Self {
        // TODO: ony pass the relevant part of the snap
        // 3 pfds are always present: a waker and two anonymous UDP sockets
        let capacity = 3 + view.conns.len();
        let mut pfds = Vec::with_capacity(capacity);
        let mut slots = Vec::with_capacity(capacity);

        // Push Waker's PollFd first, it has no corresponding slot
        pfds.push(PollFd::new(view.waker.wait_fd(), PollFlags::POLLIN));

        // Push anonymous UDP sockets' PollFds and their corresponding anon slots
        for sock in [&view.udp4, &view.udp6] {
            pfds.push(PollFd::new(sock.as_fd(), PollFlags::POLLIN));
            slots.push(Slot::Anon(sock));
        }

        // Push connected UDP sockets' PollFds and their corresponding conn slots
        for conn in &view.conns {
            pfds.push(PollFd::new(conn.sock.as_fd(), PollFlags::POLLIN));
            slots.push(Slot::Conn(conn));
        }

        Self { pfds, slots }
    }

    fn as_mut_slice(&mut self) -> &mut [PollFd<'a>] {
        &mut self.pfds
    }

    // TODO: looks more like a property of a poll rather than a set of pfds (struct Poll { poll_set: PollSet })?
    fn woken(&self) -> bool {
        self.pfds
            .first() // pfds[0] is Waker's PollFd
            .and_then(|pfd| pfd.revents())
            .is_some_and(|revents| !revents.is_empty())
    }

    // TODO: looks more like a property of a poll rather than a set of pfds (struct Poll { poll_set: PollSet })?
    fn ready(&self) -> impl Iterator<Item = (&Slot<'a>, PollFlags)> + '_ {
        self.pfds
            .iter()
            .skip(1) // skip waker's PollFd
            .zip(&self.slots)
            .filter_map(|(pfd, slot)| {
                let revents = pfd.revents().unwrap_or(PollFlags::empty());
                (!revents.is_empty()).then_some((slot, revents))
            })
    }
}
