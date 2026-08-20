use std::{
    io,
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
        dev_lock::Lock, tun::TunSocket, Device, Error, IfaceReadResult, MAX_PKT_SIZE,
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
        let (iface, mtu, fw_callback) = {
            let d = device.read();
            (
                d.iface.clone(),
                d.mtu.clone(),
                d.config.firewall_process_outbound_callback.clone(),
            )
        };

        let mut buf = [0u8; MAX_PKT_SIZE];

        // Cached clone of the peer's connected socket (appears after the first handshake).
        let mut conn: Option<socket2::Socket> = None;

        while !stop.load(Ordering::Relaxed) {
            let mtu = mtu.load(Ordering::Relaxed);

            let IfaceReadResult::Packet { payload, peer } =
                read_packet(&iface, &mut buf, mtu, &device)
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

            if conn.is_none() {
                conn = peer
                    .endpoint()
                    .conn
                    .as_ref()
                    .and_then(|c| c.try_clone().ok())
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

            let Some(sock) = conn.as_ref() else {
                continue;
            };

            match session.encrypt(payload_len, &mut buf) {
                Ok(packet) => {
                    if let Err(e) = sock.send(packet) {
                        tracing::trace!(message = "packet sent failed", error = ?e);
                        conn = None;
                    }
                }
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

fn read_packet<'a>(
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
