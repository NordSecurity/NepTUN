use std::{
    io,
    mem::MaybeUninit,
    net::{IpAddr, SocketAddr},
    ops::ControlFlow,
    os::fd::{AsFd, BorrowedFd},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use nix::poll::PollFlags;
use parking_lot::Mutex;
use socket2::Socket;

use crate::{
    device::{
        data_poll::{self, DataPoll, Event},
        dev_lock::Lock,
        packet_workers::{BatchSender, TunPacket},
        peer::Peer,
        waker::Waker,
        Device, Error, Resume, MAX_PKT_SIZE,
    },
    noise::{
        rate_limiter::RateLimiter, Decapsulated, Packet, PacketData, RxResult, Tunn, TunnResult,
    },
};

/// Drain batch size limit to prevent a busy socket from starving the others
const MAX_DRAIN_BATCH: usize = 128;

pub(super) struct Inbound {
    device: Arc<Lock<Device>>,
    stop: Arc<AtomicBool>,
    waker: Arc<Waker>,
    tun: BatchSender<TunPacket>,
}

impl Inbound {
    pub fn new(
        device: Arc<Lock<Device>>,
        stop: Arc<AtomicBool>,
        waker: Arc<Waker>,
        tun: BatchSender<TunPacket>,
    ) -> Self {
        Self {
            device,
            stop,
            waker,
            tun,
        }
    }

    pub fn run(mut self) {
        if let Err(e) = self.main_loop() {
            tracing::error!(message = "Critical inbound thread failure, closing device", error = ?e);
            self.device.read().trigger_exit();
        }
    }

    fn main_loop(&mut self) -> Result<(), Error> {
        let mut rcvbuf = [0u8; MAX_PKT_SIZE];
        let mut dstbuf = [0u8; MAX_PKT_SIZE];

        while !self.stop.load(Ordering::Relaxed) {
            if let Resume::OnWake = self.inner_loop(&mut rcvbuf, &mut dstbuf)? {
                // the device read guard is dropped at this point, so parking here doesn't block writers
                data_poll::park_on(&self.waker)?;
            }
        }

        Ok(())
    }

    fn inner_loop(
        &mut self,
        rcvbuf: &mut [u8; MAX_PKT_SIZE],
        dstbuf: &mut [u8; MAX_PKT_SIZE],
    ) -> Result<Resume, Error> {
        // Inner loop runs under the device read lock guard
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

        let mut poll = DataPoll::with_fd_data(&self.waker, view.polled_sockets());

        loop {
            // Park the thread while waiting for the packets to arrive
            if let Event::Woken = poll.wait()? {
                return Ok(Resume::Now);
            }

            let flow = view.process_ready(&poll, rcvbuf, dstbuf, &mut self.tun)?;
            self.tun.flush()?;
            if flow.is_break() {
                return Ok(Resume::Now);
            }
        }
    }
}

/// Borrowed view of the device with UDP sockets open, plus owned connected sockets
///
/// Note that the `conns` are owned, so that the sockets aren't borrowed from the peers' locked endpoints.
/// Borrowing would keep the endpoint locks held while waiting for a wake, which the control plane sends
/// only after taking a write lock on an endpoint, resulting in a deadlock.
struct InboundView<'a> {
    device: &'a Device,
    waker: &'a Waker,
    udp4: &'a Socket,
    udp6: &'a Socket,
    conns: Vec<Conn>,
}

/// Reason for the [`InboundView`] creation failure
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

    fn polled_sockets(&self) -> impl Iterator<Item = (BorrowedFd<'_>, PolledSocket<'_>)> + '_ {
        let anon = IntoIterator::into_iter([self.udp4, self.udp6])
            .map(|sock| (sock.as_fd(), PolledSocket::Anon(sock)));
        let conns = self
            .conns
            .iter()
            .map(|conn| (conn.sock.as_fd(), PolledSocket::Conn(conn)));

        anon.chain(conns)
    }

    /// Returns [`ControlFlow::Break`] if the view needs rebuilding
    fn process_ready(
        &self,
        poll: &DataPoll<'_, PolledSocket<'_>>,
        rcvbuf: &mut [u8; MAX_PKT_SIZE],
        dstbuf: &mut [u8; MAX_PKT_SIZE],
        tun: &mut BatchSender<TunPacket>,
    ) -> Result<ControlFlow<()>, Error> {
        let mut invalidated = false;

        for (polled_socket, revents) in poll.ready() {
            if revents.contains(PollFlags::POLLNVAL) {
                return Err(Error::InternalError(format!(
                    "Polled an invalid fd on {}",
                    polled_socket.kind()
                )));
            }

            if revents.contains(PollFlags::POLLHUP) {
                // connected socket was shut down by the control plane
                invalidated = true;
                continue;
            }

            if revents.contains(PollFlags::POLLERR) {
                match polled_socket {
                    PolledSocket::Conn(conn) => {
                        let error = conn.sock.take_error();
                        tracing::debug!(message = "Connected socket failed", error = ?error);
                        self.request_disconnect(&conn.peer);
                    }
                    PolledSocket::Anon(sock) => {
                        let error = sock.take_error();
                        tracing::warn!(message = "UDP socket error", error = ?error);
                    }
                }
                continue;
            }

            if revents.contains(PollFlags::POLLIN) {
                let result = match polled_socket {
                    PolledSocket::Anon(sock) => self.drain_anon(sock, rcvbuf, dstbuf, tun)?,
                    PolledSocket::Conn(conn) => self.drain_conn(conn, rcvbuf, dstbuf, tun)?,
                };

                if result.is_break() {
                    return Ok(ControlFlow::Break(()));
                }
            }
        }

        Ok(if invalidated {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        })
    }

    fn drain_anon(
        &self,
        sock: &Socket,
        rcvbuf: &mut [u8; MAX_PKT_SIZE],
        dstbuf: &mut [u8; MAX_PKT_SIZE],
        tun: &mut BatchSender<TunPacket>,
    ) -> Result<ControlFlow<()>, Error> {
        for _ in 0..MAX_DRAIN_BATCH {
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

            if !self.deliver_data(peer, data, &mut dstbuf[..], tun)? {
                continue;
            }

            if peer.needs_endpoint_update(sock_addr) && peer.request_endpoint(sock_addr) {
                self.device.notify_control();
            }
        }

        Ok(ControlFlow::Continue(()))
    }

    fn drain_conn(
        &self,
        conn: &Conn,
        rcvbuf: &mut [u8; MAX_PKT_SIZE],
        dstbuf: &mut [u8; MAX_PKT_SIZE],
        tun: &mut BatchSender<TunPacket>,
    ) -> Result<ControlFlow<()>, Error> {
        for _ in 0..MAX_DRAIN_BATCH {
            if self.waker.is_pending() {
                self.waker.ack();
                return Ok(ControlFlow::Break(()));
            }

            // Safety: socket2 promises not to write uninitialised bytes into the buffer.
            let recv_buf =
                unsafe { &mut *(&mut rcvbuf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };

            let read_bytes = match conn.sock.recv(recv_buf) {
                Ok(0) => break, // empty datagram or EOF after a local shutdown (next poll reports it as POLLHUP)
                Ok(n) => n,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => break,
                    io::ErrorKind::Interrupted => continue,
                    _ => {
                        tracing::warn!(message = "Connected socket recv failed", error = ?e);
                        self.request_disconnect(&conn.peer);
                        break;
                    }
                },
            };

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

            let _needs_update = self.deliver_data(&conn.peer, data, &mut dstbuf[..], tun)?;

            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
            if _needs_update {
                conn.peer.conn_watch.on_conn_receive();
            }
        }

        Ok(ControlFlow::Continue(()))
    }

    /// Decrypts a data packet and queues it to the tunnel
    ///
    /// Returns `true` if the packet should update peer's endpoint
    fn deliver_data(
        &self,
        peer: &Arc<Peer>,
        data: PacketData<'_>,
        dstbuf: &mut [u8],
        tun: &mut BatchSender<TunPacket>,
    ) -> Result<bool, Error> {
        let RxResult {
            decapsulated,
            queue_ready,
        } = decapsulate(&peer.tunnel, data, dstbuf);

        if queue_ready && peer.request_flush() {
            self.device.notify_control();
        }

        match decapsulated {
            Ok(Decapsulated::Keepalive) => Ok(true),
            Ok(Decapsulated::IpPacket(packet, src_addr)) => {
                if let Some(packet) = TunPacket::new(packet, Arc::clone(peer), src_addr) {
                    tun.push(packet)?;
                }
                Ok(true)
            }
            Err(e) => {
                tracing::warn!(message = "Failed to handle packet", error = ?e);
                Ok(false)
            }
        }
    }

    fn request_disconnect(&self, peer: &Peer) {
        if peer.request_disconnect() {
            self.device.notify_control();
        }
    }
}

/// [`Peer`]'s connected socket
struct Conn {
    peer: Arc<Peer>,
    sock: Socket,
    peer_addr: SocketAddr,
}

enum PolledSocket<'a> {
    Anon(&'a Socket),
    Conn(&'a Conn),
}

impl PolledSocket<'_> {
    fn kind(&self) -> &'static str {
        match self {
            PolledSocket::Anon(_) => "anonymous UDP socket",
            PolledSocket::Conn(_) => "connected peer socket",
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

fn decapsulate<'a>(
    tunnel: &Mutex<Tunn>,
    packet: PacketData<'_>,
    dst: &'a mut [u8],
) -> RxResult<'a> {
    let rx = match tunnel.lock().begin_rx(packet) {
        Ok(rx) => rx,
        Err(e) => return e.into(),
    };

    // Tunnel lock is released at this point
    match rx.open(dst) {
        Ok(opened) => tunnel.lock().commit_rx(opened),
        Err(e) => e.into(),
    }
}
