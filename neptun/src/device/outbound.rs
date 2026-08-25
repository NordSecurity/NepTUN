use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
use std::thread::{self, JoinHandle};

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
use dispatch2::{
    DispatchGroup, DispatchQueue, DispatchQueueGlobalPriority, DispatchRetained,
    GlobalQueueIdentifier,
};

use crate::{
    device::{
        dev_lock::Lock, peer::Peer, tun::TunSocket, Device, Error, IfaceReadResult, MAX_PKT_SIZE,
        WG_HEADER_OFFSET,
    },
    noise::Tunn,
};

pub struct Outbound;

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
type OutboundThread = JoinHandle<()>;
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
type OutboundThread = DispatchRetained<DispatchGroup>;

impl Outbound {
    pub fn start(device: Arc<Lock<Device>>, stop: Arc<AtomicBool>) -> OutboundThread {
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        let thread = {
            let group = DispatchGroup::new();
            // TODO: check if it is better to use serial queue (rather than the global queue)
            let queue = DispatchQueue::global_queue(GlobalQueueIdentifier::Priority(
                DispatchQueueGlobalPriority::High,
            ));

            group.exec_async(&queue, move || Outbound::data_thread(device, stop));
            group
        };

        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        let thread = {
            thread::Builder::new()
                .name("neptun-out ".to_string())
                .spawn(move || Outbound::data_thread(device, stop))
                .unwrap()
        };

        thread
    }

    fn data_thread(device: Arc<Lock<Device>>, stop: Arc<AtomicBool>) {
        let (iface, mtu, fw_callback, udp4, udp6) = {
            let d = device.read();
            (
                d.iface.clone(),
                d.mtu.clone(),
                d.config.firewall_process_outbound_callback.clone(),
                d.udp4.clone(),
                d.udp6.clone(),
            )
        };

        let (udp4, udp6) = match (udp4.as_ref(), udp6.as_ref()) {
            (Some(udp4), Some(udp6)) => (udp4, udp6),
            _ => {
                tracing::error!("Not connected");
                return; // TODO: Action::Continue
            }
        };

        let mut buf = [0u8; MAX_PKT_SIZE];

        // Cached clone of the peer's connected socket (appears after the first handshake).
        let mut conn: Option<socket2::Socket> = None;

        while !stop.load(Ordering::Relaxed) {
            let mtu = mtu.load(Ordering::Relaxed);

            let IfaceReadResult::Packet { payload, peer } =
                read_tun_packet(&iface, &mut buf, mtu, &device)
            else {
                // TODO: ensure correct action on different IfaceReadResult variants
                continue;
            };

            let payload_len = payload.len();

            if payload_len == 0 {
                continue;
            }

            if let Some(callback) = &fw_callback {
                if !callback(&peer.public_key.0, payload, &mut iface.as_ref()) {
                    continue;
                }
            }

            let session = {
                match peer.tunnel.lock().current_session() {
                    Some(s) => s,
                    None => {
                        peer.request_handshake();
                        continue;
                    }
                }
            };

            // TODO: consider reversing logic - only use connected sockets if supposed to
            //  if (use_conn_skt && !peer.endpoint.conn) -> continue

            match session.encrypt(payload_len, &mut buf) {
                Ok(packet) => send_packet(&peer, packet, udp4, udp6),
                Err(e) => tracing::trace!(message = "encrypt failed", error = ?e),
            }

            // TODO: last sent packet should update timers accordingly as per protocol spec - how can this be achieved
            // efficiently if the data plane does not know about timers?

            // TODO: what about packet queueing prior to establishing a handshake (and how will they be dequeued and sent)?

            // TODO: how should this thread be stopped and cleaned up? at the moment it must receive a new packet in order
            // to be able to recheck its `stop` flag - a timeout on iface.read?

            // TODO: handling multiple peers
        }
    }
}

fn read_tun_packet<'a>(
    iface: &Arc<TunSocket>,
    buf: &'a mut [u8; MAX_PKT_SIZE],
    mtu: usize,
    device: &Arc<Lock<Device>>,
) -> IfaceReadResult<'a> {
    if mtu + WG_HEADER_OFFSET > MAX_PKT_SIZE {
        tracing::error!("Insufficient packet buffer size");
        return IfaceReadResult::Fatal;
    }

    #[allow(clippy::indexing_slicing)]
    // guaranteed by the above check
    match iface.read(&mut buf[WG_HEADER_OFFSET..WG_HEADER_OFFSET + mtu]) {
        Ok(payload) => match Tunn::dst_address(payload) {
            None => IfaceReadResult::Skip,
            Some(dst_addr) => {
                let d = device.read();
                match d.peers_by_ip.find(dst_addr) {
                    None => IfaceReadResult::Skip,
                    Some(peer) => IfaceReadResult::Packet {
                        payload,
                        peer: peer.clone(),
                    },
                }
            }
        },
        Err(Error::IfaceRead(e)) => match e.kind() {
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => IfaceReadResult::Exhausted,
            _ => {
                tracing::error!(message = "Fatal read error on tun interface: errno", error = ?e);
                IfaceReadResult::Fatal
            }
        },
        Err(e) => {
            tracing::error!(message = "Unexpected error on tun interface", error = ?e);
            IfaceReadResult::Fatal
        }
    }
}

fn send_packet(
    peer: &Arc<Peer>,
    packet: &mut [u8],
    udp4: &socket2::Socket,
    udp6: &socket2::Socket,
) {
    let endpoint = peer.endpoint();
    if let Some(conn) = endpoint.conn.as_ref() {
        match conn.send(packet) {
            Ok(_) => {
                tracing::trace!(
                    "Pkt -> ConnSock ({:?}), len: {}",
                    endpoint.addr,
                    packet.len()
                );
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                tracing::debug!(message = "Connected socket send buffer full, dropping packet", error = ?err);
            }
            Err(err) => {
                tracing::debug!(message = "Failed to send packet with the connected socket", error = ?err);
                drop(endpoint);
                peer.shutdown_endpoint();
            }
        }
    } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
        if let Err(err) = udp4.send_to(packet, &addr.into()) {
            tracing::warn!(message = "Failed to write packet to network v4", error = ?err, dst = ?addr);
        } else {
            tracing::trace!(message = "Writing packet to network v4", packet_length = packet.len(), src_addr = ?addr, public_key = peer.public_key.1);
        }
    } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
        if let Err(err) = udp6.send_to(packet, &addr.into()) {
            tracing::warn!(message = "Failed to write packet to network v6", error = ?err, dst = ?addr);
        } else {
            tracing::trace!(message = "Writing packet to network v6", packet_length = packet.len(), src_addr = ?addr, public_key = peer.public_key.1);
        }
    } else {
        tracing::error!("No endpoint");
    }
}
