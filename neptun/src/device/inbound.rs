use std::{
    io::{self},
    mem::MaybeUninit,
    net::IpAddr,
    ops::ControlFlow,
    os::fd::AsFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use nix::poll::{PollFd, PollFlags};
use parking_lot::MutexGuard;
use socket2::Socket;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    device::{
        dev_lock::Lock,
        outbound,
        peer::Peer,
        routing::RoutableIp,
        waker::{poll_retry, Resume, Waker},
        Device, DeviceHandle, Error, MAX_PKT_SIZE,
    },
    noise::{
        errors::WireGuardError,
        handshake::parse_handshake_anon,
        packet::{self, Decapsulated},
        rate_limiter::RateLimiter,
        session::Session,
        Packet, PacketData, RxCommit, Tunn, TunnResult,
    },
    x25519,
};

/// Inbound path state
enum RxPath<'p, 'd> {
    Data {
        session: Arc<Session>,
        packet: PacketData<'d>,
        commit: RxCommit,
    },
    NoSession,
    Control(ControlRx<'p, 'd>),
}

struct ControlRx<'p, 'd> {
    guard: MutexGuard<'p, Tunn>,
    packet: Packet<'d>,
}

impl<'p, 'd> ControlRx<'p, 'd> {
    #[inline]
    fn handle<'a>(self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let ControlRx { mut guard, packet } = self;
        guard.handle_verified_packet(packet, dst)
    }
}

pub(crate) fn handle_verified_packet<'a, 'd>(
    peer: &Peer,
    packet: Packet<'d>,
    dst: &'a mut [u8],
) -> TunnResult<'a> {
    let (session, packet, commit) = match begin_rx(peer, packet) {
        RxPath::Data {
            session,
            packet,
            commit,
        } => (session, packet, commit),
        RxPath::NoSession => {
            tracing::trace!("No current session available");
            return TunnResult::Err(WireGuardError::NoCurrentSession);
        }
        RxPath::Control(control) => return control.handle(dst),
    };

    // Tunnel lock is released at this point
    let decapsulated = match session
        .receive_packet_data(packet, dst)
        .and_then(|p| packet::parse_inbound_ip(p))
    {
        Ok(d) => d,
        Err(e) => {
            commit.discard();
            return TunnResult::Err(e);
        }
    };

    // Reacquiring tunnel lock
    peer.tunnel.lock().commit_rx(commit, &decapsulated);

    match decapsulated {
        Decapsulated::Keepalive => TunnResult::Done,
        Decapsulated::Ip(packet) => TunnResult::WriteToTunnel(packet),
    }
}

fn begin_rx<'p, 'd>(peer: &'p Peer, packet: Packet<'d>) -> RxPath<'p, 'd> {
    let guard = peer.tunnel.lock();
    match packet {
        Packet::PacketData(p) => match guard.begin_rx_data(&p) {
            Some((session, commit)) => {
                drop(guard);
                RxPath::Data {
                    session,
                    packet: p,
                    commit,
                }
            }
            None => {
                drop(guard);
                RxPath::NoSession
            }
        },
        control => RxPath::Control(ControlRx {
            guard,
            packet: control,
        }),
    }
}

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
    key_pair: &'a (StaticSecret, PublicKey),
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
    // TODO: move logging out of new
    fn new(device: &'a Device, waker: &'a Waker) -> Result<Self, ViewFailed> {
        let (Some(udp4), Some(udp6)) = (device.udp4.as_deref(), device.udp6.as_deref()) else {
            return Err(ViewFailed::NotConnected);
        };

        let Some(key_pair) = device.key_pair.as_ref() else {
            return Err(ViewFailed::EmptyKeyPair);
        };

        let conns = device
            .peers
            .values()
            .filter_map(|peer| {
                let endpoint = peer.endpoint();
                let sock = endpoint.conn.as_ref()?.try_clone().ok()?;
                Some(Conn {
                    peer: Arc::clone(peer),
                    sock,
                    peer_ip: endpoint.addr.map(|a| a.ip()),
                })
            })
            .collect();

        Ok(Self {
            device,
            waker,
            key_pair,
            udp4,
            udp6,
            conns,
        })
    }

    // TODO: refactor into dedicated methods like for outbound
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

            // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
            let parsed_packet = match self.device.rate_limiter.as_ref() {
                Some(rate_limiter) => {
                    match rate_limiter.verify_packet(Some(sock_addr.ip()), packet, dstbuf) {
                        Ok(packet) => packet,
                        Err(TunnResult::WriteToNetwork(cookie)) => {
                            if let Err(err) = sock.send_to(cookie, &addr) {
                                tracing::warn!(message = "Failed to send cookie", error = ?err, dst = ?addr);
                            }
                            continue;
                        }
                        Err(_) => continue,
                    }
                }
                None => match Tunn::parse_incoming_packet(packet) {
                    Ok(packet) => packet,
                    Err(_) => continue,
                },
            };

            let peer = match &parsed_packet {
                Packet::HandshakeInit(p) => {
                    let (private_key, public_key) = self.key_pair;
                    parse_handshake_anon(private_key, public_key, p)
                        .ok()
                        .and_then(|hh| {
                            self.device
                                .peers
                                .get(&x25519::PublicKey::from(hh.peer_static_public))
                        })
                }
                // TODO: three branches handled in the same way
                Packet::HandshakeResponse(p) => {
                    self.device.peers_by_idx.get(&(p.receiver_idx >> 8))
                }
                Packet::PacketCookieReply(p) => {
                    self.device.peers_by_idx.get(&(p.receiver_idx >> 8))
                }
                Packet::PacketData(p) => self.device.peers_by_idx.get(&(p.receiver_idx >> 8)),
            };

            let peer = match peer {
                None => continue,
                Some(peer) => peer,
            };

            let mut flush = false; // Are there packets to send from the queue?

            let res = handle_verified_packet(peer, parsed_packet, &mut dstbuf[..]);

            match res {
                TunnResult::Done => {}
                TunnResult::Err(err) => {
                    tracing::warn!(message = "Failed to handle packet", error = ?err);
                    continue;
                }
                TunnResult::WriteToNetwork(packet) => {
                    flush = true;
                    if let Err(err) = sock.send_to(packet, &addr) {
                        tracing::warn!(message = "Failed to send packet", error = ?err, dst = ?addr);
                    }
                }
                TunnResult::WriteToTunnel(mut packet) => {
                    if let Some(callback) = self
                        .device
                        .config
                        .firewall_process_inbound_callback
                        .as_ref()
                    {
                        if !callback(&peer.public_key.0, packet.payload_mut()) {
                            continue;
                        }
                    }

                    match RoutableIp::check(packet, peer) {
                        Ok(packet) => {
                            _ = packet.write_to(self.device.iface.as_ref());
                            tracing::trace!(
                                message = "Writing packet to tunnel",
                                interface = ?self.device.iface.name(),
                                packet_length = packet.len(),
                                src_addr = ?packet.src_addr(),
                                public_key = peer.public_key.1,
                            );
                        }
                        Err(packet) => {
                            tracing::debug!(
                                message = "Dropping packet from outside of allowed IPs",
                                src_addr = ?packet.src_addr(),
                            );
                        }
                    }
                }
            };

            if flush {
                // Flush pending queue
                loop {
                    let res = outbound::flush_queued(peer, &mut dstbuf[..]);

                    let TunnResult::WriteToNetwork(packet) = res else {
                        break;
                    };

                    if let Err(err) = sock.send_to(packet, &addr) {
                        tracing::warn!(message = "Failed to flush queue", error = ?err, dst = ?addr);
                    }
                }
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
                let mut flush = false;

                #[allow(clippy::indexing_slicing)]
                let parsed_packet = match verify_incoming(
                    self.device.rate_limiter.as_deref(),
                    conn.peer_ip,
                    rcvbuf[..read_bytes].as_ref(),
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

                let res = handle_verified_packet(&conn.peer, parsed_packet, &mut dstbuf[..]);

                match res {
                    TunnResult::Done => {}
                    TunnResult::Err(e) => match e {
                        WireGuardError::DuplicateCounter => {
                            tracing::error!(message="Decapsulate error",
                                error=?e)
                        }
                        _ => {
                            tracing::error!(message="Decapsulate error",
                            error=?e)
                        }
                    },
                    TunnResult::WriteToNetwork(packet) => {
                        // Respond to handshake packets
                        flush = true;
                        if let Err(err) = conn.sock.send(packet) {
                            tracing::warn!(message="Failed to write packet", error = ?err);
                        }
                    }
                    TunnResult::WriteToTunnel(mut packet) => {
                        if let Some(callback) =
                            &self.device.config.firewall_process_inbound_callback
                        {
                            if !callback(&conn.peer.public_key.0, packet.payload_mut()) {
                                continue;
                            }
                        }

                        match RoutableIp::check(packet, &conn.peer) {
                            Ok(packet) => {
                                _ = packet.write_to(self.device.iface.as_ref());
                                tracing::trace!(
                                    message = "Writing packet to tunnel",
                                    packet_length = packet.len(),
                                    src_addr = ?packet.src_addr(),
                                );
                            }
                            Err(packet) => {
                                tracing::debug!(
                                    message = "Dropping packet from outside of allowed IPs",
                                    src_addr = ?packet.src_addr(),
                                );
                            }
                        }
                    }
                }

                if flush {
                    // Flush pending queue
                    loop {
                        let res = outbound::flush_queued(&conn.peer, &mut dstbuf[..]);
                        let TunnResult::WriteToNetwork(packet) = res else {
                            break;
                        };
                        if let Err(err) = conn.sock.send(packet) {
                            tracing::warn!(message="Failed to flush queue", error = ?err);
                        }
                    }
                }
            } else {
                // Avoid spin in case of the EOF on a shutdown socket
                return Ok(ControlFlow::Break(()));
            }
        }

        Ok(ControlFlow::Continue(()))
    }
}

struct Conn {
    peer: Arc<Peer>,
    sock: Socket,
    peer_ip: Option<IpAddr>,
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
