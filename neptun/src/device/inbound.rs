use std::{
    io::{self, Write},
    mem::MaybeUninit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use nix::sys::socket;
use socket2::Socket;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    device::{
        dev_lock::Lock, peer::Peer, tun::TunSocket, waker::Waker, Device, Error, MAX_PKT_SIZE,
    },
    noise::{
        handshake::parse_handshake_anon,
        rate_limiter::{self, RateLimiter},
        Packet, Tunn, TunnResult,
    },
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

    pub fn run(self) {
        // for now this only handles data coming from connected socket on a single peer it happens to obtain first,
        // relying on the bootstrapping performed in the handler registered with register_udp_handler(),
        // replaces connected socket handler from register_read_conn_skt_handler()

        // TODO: add proper multi-peer support / conn skt's peer sharding (demuxing)
        // TODO: add firewall support
        // TODO: ensure tunn packet queue flushing
        // TODO: (2nd step) consider moving anonymous socket data processing here (Apple!)

        let (iface, fw_callback) = {
            let d = self.device.read();
            (
                d.iface.clone(),
                d.config.firewall_process_inbound_callback.clone(),
            )
        };

        let rcvbuf = [0u8; MAX_PKT_SIZE];
        let dstbuf = [0u8; MAX_PKT_SIZE];

        self.handle_packet_loop(iface, fw_callback, rcvbuf, dstbuf);

        // let bound: Option<(Arc<Peer>, socket2::Socket)> = None;
        // handle_packet_loop_single_conn_peer(device, iface, rcvbuf, dstbuf, bound, stop);
    }

    fn handle_packet_loop(
        self,
        iface: Arc<TunSocket>,
        fw_callback: Option<Arc<dyn Fn(&[u8; 32], &mut [u8]) -> bool + Send + Sync>>,
        mut rcvbuf: [u8; MAX_PKT_SIZE],
        mut dstbuf: [u8; MAX_PKT_SIZE],
    ) {
        while !self.stop.load(Ordering::Relaxed) {
            let udp4 = {
                let d = self.device.read();
                d.udp4.clone()
            };

            let Some(udp4) = udp4 else {
                tracing::error!("Not connected");
                continue;
            };

            let (key_pair, rate_limiter) = {
                let d = self.device.read();
                (d.key_pair.clone(), d.rate_limiter.clone())
            };

            let Some(key_pair) = key_pair.as_ref() else {
                tracing::trace!("Empty key pair");
                std::thread::sleep(Duration::from_millis(100));
                continue; // return Action::Exit;
            };

            // Safety: the `recv_from` implementation promises not to write uninitialised
            // bytes to the buffer, so this casting is safe.
            let src_buf = unsafe { &mut *(&mut rcvbuf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };

            let Ok((packet_len, addr)) = udp4.recv_from(src_buf) else {
                continue;
            };

            let packet = match rcvbuf.get(..packet_len) {
                Some(p) => p,
                None => {
                    tracing::error!("Buffer size different from packet length");
                    continue;
                }
            };

            let sock = match addr.as_socket() {
                Some(s) => s,
                None => {
                    tracing::warn!("Invalid socket address family");
                    continue;
                }
            };
            // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
            let parsed_packet = match rate_limiter {
                Some(ref rate_limiter) => {
                    match rate_limiter.verify_packet(Some(sock.ip()), packet, &mut dstbuf) {
                        Ok(packet) => packet,
                        Err(TunnResult::WriteToNetwork(cookie)) => {
                            if let Err(err) = udp4.send_to(cookie, &addr) {
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
                    let (private_key, public_key) = key_pair;
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
                    if let Err(err) = udp4.send_to(packet, &addr) {
                        tracing::warn!(message = "Failed to send packet", error = ?err, dst = ?addr);
                    }
                }
                TunnResult::WriteToTunnel(packet, addr) => {
                    if let Some(ref callback) = fw_callback {
                        if !callback(&peer.public_key.0, packet) {
                            continue;
                        }
                    }

                    if peer.is_allowed_ip(addr) {
                        _ = iface.as_ref().write(packet);
                        tracing::trace!(
                            message = "Writing packet to tunnel",
                            interface = ?iface.name(),
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

                    if let Err(err) = udp4.send_to(packet, &addr) {
                        tracing::warn!(message = "Failed to flush queue", error = ?err, dst = ?addr);
                    }
                }
            }

            peer.set_endpoint(sock);
        }
    }

    fn handle_packet_loop_single_conn_peer(
        self,
        iface: Arc<TunSocket>,
        mut rcvbuf: [u8; MAX_PKT_SIZE],
        mut dstbuf: [u8; MAX_PKT_SIZE],
        mut bound: Option<(Arc<Peer>, socket2::Socket)>,
    ) -> () {
        while !self.stop.load(Ordering::Relaxed) {
            if bound.is_none() {
                bound = {
                    let d = self.device.read();
                    d.peers.values().next().and_then(|p| {
                        p.endpoint()
                            .conn
                            .as_ref()
                            .and_then(|c| c.try_clone().ok())
                            .map(|c| (p.clone(), c))
                    })
                };

                if bound.is_none() {
                    std::thread::sleep(Duration::from_millis(50)); // TODO: fix magic number
                    continue;
                }
            }

            let mut reset = false;

            {
                let Some((peer, conn)) = bound.as_ref() else {
                    continue;
                };

                // Safety: socket2 promises not to write uninitialised bytes into the buffer.
                let recv_buf =
                    unsafe { &mut *(&mut rcvbuf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };

                let n = match conn.recv(recv_buf) {
                    Ok(n) => n,
                    Err(e) => match e.kind() {
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                            0 // SO_RCVTIMEO fired: re-check `stop`
                        }
                        _ => {
                            reset = true;
                            0
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
                                match session.decrypt(p, &mut dstbuf) {
                                    Ok(plain) if !plain.is_empty() => {
                                        if let Some(len) = Tunn::decapsulated_packet_len(plain) {
                                            let _ = iface.as_ref().write(&plain[..len]);
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
                                tun.decapsulate(None, datagram, &mut dstbuf)
                            };
                            match res {
                                TunnResult::WriteToNetwork(packet) => {
                                    let _ = conn.send(packet);
                                    // drain pre-handshake queued packets
                                    loop {
                                        let mut out = [0u8; MAX_PKT_SIZE];
                                        let r = {
                                            let mut tun = peer.tunnel.lock();
                                            tun.decapsulate(None, &[], &mut out)
                                        };
                                        match r {
                                            TunnResult::WriteToNetwork(p2) => {
                                                let _ = conn.send(p2);
                                            }
                                            _ => break,
                                        }
                                    }
                                }
                                TunnResult::WriteToTunnel(packet, _addr) => {
                                    let _ = iface.as_ref().write(packet);
                                }
                                _ => {}
                            }
                        }
                        Err(_) => {}
                    }
                }
            }

            if reset {
                bound = None;
            }
        }
    }
}
