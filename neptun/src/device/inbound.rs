use std::{
    io::{self, Write},
    mem::MaybeUninit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
use std::thread::{self, JoinHandle};

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
use dispatch2::{
    DispatchGroup, DispatchQueue, DispatchQueueGlobalPriority, DispatchRetained,
    GlobalQueueIdentifier,
};

use crate::{
    device::{dev_lock::Lock, peer::Peer, Device, MAX_PKT_SIZE},
    noise::{Packet, Tunn, TunnResult},
};

pub struct Inbound;

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
type InboundThread = JoinHandle<()>;
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
type InboundThread = DispatchRetained<DispatchGroup>;

impl Inbound {
    pub fn start(device: Arc<Lock<Device>>, stop: Arc<AtomicBool>) -> InboundThread {
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        let thread = {
            let group = DispatchGroup::new();
            // TODO: check if it is better to use serial queue (rather than the global queue)
            let queue = DispatchQueue::global_queue(GlobalQueueIdentifier::Priority(
                DispatchQueueGlobalPriority::High,
            ));

            group.exec_async(&queue, move || Inbound::data_thread(device, stop));
            group
        };

        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        let thread = {
            thread::Builder::new()
                .name("neptun-in".to_string())
                .spawn(move || Inbound::data_thread(device, stop))
                .unwrap()
        };

        thread
    }

    fn data_thread(device: Arc<Lock<Device>>, stop: Arc<AtomicBool>) {
        let (iface, fw_callback) = {
            let d = device.read();
            (
                d.iface.clone(),
                d.config.firewall_process_inbound_callback.clone(),
            )
        };

        let mut rcvbuf = [0u8; MAX_PKT_SIZE];
        let mut dstbuf = [0u8; MAX_PKT_SIZE];

        let mut bound: Option<(Arc<Peer>, socket2::Socket)> = None;

        while !stop.load(Ordering::Relaxed) {
            if bound.is_none() {
                bound = {
                    let d = device.read();
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
                let Some((private_key, public_key)) = device.read().key_pair.as_ref() else {
                    tracing::error!("Empty key pair");
                    continue;
                };

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

                // TODO: add multiple peers handling

                // TODO: add firewall callback

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

        // TODO: handle anonymous sockets with rate limiting (cookie handling moved to control plane)
    }
}
