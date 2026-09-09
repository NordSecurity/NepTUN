use std::{
    io::{self, Write},
    mem::MaybeUninit,
    ops::ControlFlow,
    os::fd::AsFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use nix::poll::{PollFd, PollFlags};
use socket2::Socket;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    device::{
        dev_lock::Lock,
        peer::Peer,
        tun::TunSocket,
        waker::{poll_retry, Waker},
        Device, DeviceHandle, Error, MAX_PKT_SIZE,
    },
    noise::{handshake::parse_handshake_anon, rate_limiter::RateLimiter, Packet, Tunn, TunnResult},
    x25519,
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
        if let Err(e) = self.run_inner() {
            tracing::error!(message = "Critical inbound thread failure, closing device", error = ?e);
            let mut d = self.device.read();
            DeviceHandle::close_device(&mut d);
        }
    }

    // TODO: add missing timers handling

    fn run_inner(&self) -> Result<(), Error> {
        let mut rcvbuf = [0u8; MAX_PKT_SIZE];
        let mut dstbuf = [0u8; MAX_PKT_SIZE];

        while !self.stop.load(Ordering::Relaxed) {
            let Some(snap) = self.take_snapshot()? else {
                continue;
            };

            let mut poll_set = PollSet::new(&snap, &self.waker);

            // Sockets readiness loop
            loop {
                poll_retry(poll_set.as_mut_slice())?;

                if poll_set.woken() {
                    self.waker.ack();
                    break;
                }

                let mut resnapshot = false;

                for (slot, revents) in poll_set.ready() {
                    if revents.contains(PollFlags::POLLNVAL) {
                        return Err(Error::InternalError(format!(
                            "Polled an invalid fd on {}",
                            slot.kind()
                        )));
                    }

                    if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP) {
                        match slot {
                            Slot::Conn(peer, _) => {
                                tracing::debug!(message = "Connected socket failed", revents = ?revents);
                                let _ = peer.shutdown_endpoint();
                                resnapshot = true;
                            }
                            Slot::Anon(_) => {
                                tracing::warn!(message = "UDP socket invalidated", revents = ?revents);
                                resnapshot = true;
                            }
                        }
                        continue;
                    }

                    if revents.contains(PollFlags::POLLIN) {
                        if revents.contains(PollFlags::POLLIN) {
                            let result = match slot {
                                Slot::Anon(sock) => {
                                    self.drain_anon(sock, &snap, &mut rcvbuf, &mut dstbuf)?
                                }
                                Slot::Conn(peer, sock) => {
                                    self.drain_conn(peer, sock, &snap, &mut rcvbuf, &mut dstbuf)?
                                }
                            };

                            if result.is_break() {
                                resnapshot = true;
                                break;
                            }
                        }
                    }
                }

                if resnapshot {
                    break;
                }
            }
        }

        Ok(())
    }

    // TODO: ensure every change to any of the snaphot data notifies inbound
    fn take_snapshot(&self) -> Result<Option<Snapshot>, Error> {
        let (iface, fw_callback, key_pair, rate_limiter, udp4, udp6, conns) = {
            let d = self.device.read();

            let conns = d
                .peers
                .values()
                .filter_map(|peer| {
                    let conn = peer.endpoint().conn.as_ref()?.try_clone().ok()?;
                    Some((Arc::clone(peer), conn))
                })
                .collect();

            (
                d.iface.clone(),
                d.config.firewall_process_inbound_callback.clone(),
                d.key_pair.clone(),
                d.rate_limiter.clone(),
                d.udp4.clone(),
                d.udp6.clone(),
                conns,
            )
        };

        let (Some(udp4), Some(udp6)) = (udp4, udp6) else {
            tracing::debug!(message = "Not connected, parked until sockets are opened.");
            self.waker.wait()?;
            return Ok(None);
        };

        let Some(key_pair) = key_pair else {
            tracing::trace!("Empty key pair");
            self.waker.wait()?;
            return Ok(None);
        };

        Ok(Some(Snapshot {
            iface,
            fw_callback,
            key_pair,
            rate_limiter,
            udp4,
            udp6,
            conns,
        }))
    }

    // TODO: ensure off-lock decrypt on anon skt processing
    // TODO: refactor into dedicated methods like for outbound
    fn drain_anon(
        &self,
        sock: &Socket,
        snap: &Snapshot, // TODO: ony pass the relevant part of the snap
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
            let parsed_packet = match snap.rate_limiter {
                Some(ref rate_limiter) => {
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
                    let (private_key, public_key) = &snap.key_pair;
                    parse_handshake_anon(private_key, public_key, p)
                        .ok()
                        .and_then(|hh| {
                            let d = self.device.read();
                            d.peers
                                .get(&x25519::PublicKey::from(hh.peer_static_public))
                                .map(|p| p.clone())
                        })
                }
                Packet::HandshakeResponse(p) => {
                    let d = self.device.read();
                    d.peers_by_idx
                        .get(&(p.receiver_idx >> 8))
                        .map(|p| p.clone())
                }
                Packet::PacketCookieReply(p) => {
                    let d = self.device.read();
                    d.peers_by_idx
                        .get(&(p.receiver_idx >> 8))
                        .map(|p| p.clone())
                }
                Packet::PacketData(p) => {
                    let d = self.device.read();
                    d.peers_by_idx
                        .get(&(p.receiver_idx >> 8))
                        .map(|p| p.clone())
                }
            };

            let peer = match peer {
                None => continue,
                Some(peer) => peer,
            };

            let mut flush = false; // Are there packets to send from the queue?
            let res = {
                let mut tun = peer.tunnel.lock();
                tun.handle_verified_packet(parsed_packet, &mut dstbuf[..])
            };
            match res {
                TunnResult::Done => {}
                TunnResult::Err(err) => {
                    tracing::warn!(message = "Failed to handle packet", error = ?err);
                    continue;
                }
                TunnResult::WriteToNetwork(packet) => {
                    flush = true;
                    if let Err(err) = snap.udp4.send_to(packet, &addr) {
                        tracing::warn!(message = "Failed to send packet", error = ?err, dst = ?addr);
                    }
                }
                TunnResult::WriteToTunnel(packet, addr) => {
                    if let Some(ref callback) = snap.fw_callback {
                        if !callback(&peer.public_key.0, packet) {
                            continue;
                        }
                    }

                    if peer.is_allowed_ip(addr) {
                        _ = snap.iface.as_ref().write(packet);
                        tracing::trace!(
                            message = "Writing packet to tunnel",
                            interface = ?snap.iface.name(),
                            packet_length = packet.len(),
                            src_addr = ?addr,
                            public_key = peer.public_key.1
                        );
                    }
                }
            };

            if flush {
                // Flush pending queue
                loop {
                    let res = {
                        let mut tun = peer.tunnel.lock();
                        tun.decapsulate(None, &[], &mut dstbuf[..])
                    };

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
                let d = self.device.read();

                if d.config.use_connected_socket {
                    if let Err(e) = peer.connect_endpoint(d.listen_port, d.config.skt_buffer_size) {
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
        peer: &Peer,
        sock: &Socket,
        snap: &Snapshot, // TODO: ony pass the relevant part of the snap
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

            let n = match sock.recv(recv_buf) {
                Ok(n) => n,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => break,
                    io::ErrorKind::Interrupted => continue,
                    _ => {
                        tracing::warn!(message = "Connected socket recv failed", error = ?e);
                        let _ = peer.shutdown_endpoint();
                        return Ok(ControlFlow::Break(()));
                    }
                },
            };

            if n > 0 {
                let datagram = &rcvbuf[..n];
                match Tunn::parse_incoming_packet(datagram) {
                    Ok(Packet::PacketData(p)) => {
                        // Off-lock decrypt, short lock just to clone the session
                        let session = peer.tunnel.lock().session_for_index(p.receiver_idx);
                        if let Some(session) = session {
                            match session.decrypt(p, dstbuf) {
                                Ok(plain) if !plain.is_empty() => {
                                    if let Some(len) = Tunn::decapsulated_packet_len(plain) {
                                        let packet = &mut plain[..len];

                                        if let Some(ref callback) = snap.fw_callback {
                                            if !callback(&peer.public_key.0, packet) {
                                                continue;
                                            }
                                        }

                                        let Some(src_addr) = Tunn::src_address(packet) else {
                                            continue;
                                        };

                                        if peer.is_allowed_ip(src_addr) {
                                            _ = snap.iface.as_ref().write(packet);
                                            tracing::trace!(
                                                message = "Writing packet to tunnel",
                                                packet_length = len,
                                                src_addr = ?src_addr,
                                            );
                                        }
                                    }
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    tracing::trace!(message = "decrypt failed", error = ?e)
                                }
                            }
                        }
                    }
                    // Handshake / cookie
                    Ok(_) => {
                        let res = {
                            let mut tun = peer.tunnel.lock();
                            tun.decapsulate(None, datagram, dstbuf)
                        };
                        match res {
                            TunnResult::WriteToNetwork(packet) => {
                                let _ = sock.send(packet);
                                // drain pre-handshake queued packets
                                loop {
                                    let r = {
                                        let mut tun = peer.tunnel.lock();
                                        tun.decapsulate(None, &[], dstbuf)
                                    };
                                    match r {
                                        TunnResult::WriteToNetwork(p2) => {
                                            let _ = sock.send(p2);
                                        }
                                        _ => break,
                                    }
                                }
                            }
                            oth => {
                                tracing::warn!(message = "Unexpected result from decapsulate", result = ?oth)
                            }
                        }
                    }
                    Err(_) => {}
                }
            } else {
                // Avoid spin in case of the EOF on a shutdown socket
                return Ok(ControlFlow::Break(()));
            }
        }

        Ok(ControlFlow::Continue(()))
    }
}

// TODO: refactor - snapshot consists of two parts with different usage, split them
struct Snapshot {
    iface: Arc<TunSocket>,
    fw_callback: Option<Arc<dyn Fn(&[u8; 32], &mut [u8]) -> bool + Send + Sync>>,
    key_pair: (StaticSecret, PublicKey),
    rate_limiter: Option<Arc<RateLimiter>>,
    // ----
    udp4: Arc<Socket>,
    udp6: Arc<Socket>,
    conns: Vec<(Arc<Peer>, Socket)>,
}

enum Slot<'a> {
    Anon(&'a Socket),
    Conn(&'a Peer, &'a Socket),
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
    fn new(snap: &'a Snapshot, waker: &'a Waker) -> Self {
        // TODO: ony pass the relevant part of the snap
        // 3 pfds are always present: a waker and two anonymous UDP sockets
        let capacity = 3 + snap.conns.len();
        let mut pfds = Vec::with_capacity(capacity);
        let mut slots = Vec::with_capacity(capacity);

        // Push Waker's PollFd first, it has no corresponding slot
        pfds.push(PollFd::new(waker.wait_fd(), PollFlags::POLLIN));

        // Push anonymous UDP sockets' PollFds and their corresponding anon slots
        for sock in [&snap.udp4, &snap.udp6] {
            pfds.push(PollFd::new(sock.as_fd(), PollFlags::POLLIN));
            slots.push(Slot::Anon(sock));
        }

        // Push connected UDP sockets' PollFds and their corresponding conn slots
        for (peer, sock) in &snap.conns {
            pfds.push(PollFd::new(sock.as_fd(), PollFlags::POLLIN));
            slots.push(Slot::Conn(peer, sock));
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
