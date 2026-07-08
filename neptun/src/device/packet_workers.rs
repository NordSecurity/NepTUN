//! Inter-thread packet processing machinery used on non-Apple platforms.
//!
//! On non-Apple targets, packet processing crosses thread boundaries: the
//! event-loop handlers read packets and dispatch batches through bounded
//! channels to dedicated worker threads. This module owns the channels, the
//! batch types, and the worker thread bodies.
//!
//! Apple targets process packets inline and do not use this module at all.

use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender};

use super::{
    encapsulate_and_send, read_packet, send_to_peer, Action, CheckedMtu, DeviceConfig,
    IfaceReadResult, MAX_PKT_SIZE, WG_HEADER_OFFSET,
};
use crate::device::allowed_ips::AllowedIps;
use crate::device::packet_slot::{PacketSlot, SlotState};
use crate::device::peer::Peer;
use crate::device::tun::TunSocket;
use crate::noise::{ReservedNonce, TunnResult};

const CHANNEL_SIZE: usize = 500;
const MAX_INTERTHREAD_BATCHED_PKTS: usize = 50;

pub(super) struct PacketWorkers {
    pub max_batched_pkts: usize,

    tunnel_to_socket_tx: Sender<Vec<NetworkTaskData>>,
    tunnel_to_socket_rx: Receiver<Vec<NetworkTaskData>>,

    socket_to_tunnel_tx: Sender<Vec<TunnelWorkerData>>,
    socket_to_tunnel_rx: Receiver<Vec<TunnelWorkerData>>,

    close_network_worker_tx: Option<Sender<()>>,
    close_tun_worker_tx: Option<Sender<()>>,
}

struct NetworkTaskData {
    data: [u8; MAX_PKT_SIZE],
    buf_len: usize,
    peer: Arc<Peer>,
    iface: Arc<TunSocket>,
    /// The AEAD nonce reserved for this packet at staging time together with the slot
    /// in the order tracking queue for send.
    reserved: Option<(ReservedNonce, Arc<PacketSlot>)>,
}

impl NetworkTaskData {
    /// Resolve this task's ordering slot without encrypting or sending anything, and
    /// immediately drop any `Failed` slots currently at the head of the peer's queue.
    fn abandon(&self) {
        if let Some((_, slot)) = &self.reserved {
            slot.set_state(SlotState::Failed);
            self.peer.tx_queue.drain_failed_head();
        }
    }
}

pub(super) struct TunnelWorkerData {
    pub buffer: [u8; MAX_PKT_SIZE],
    pub peer: Arc<Peer>,
    pub iface: Arc<TunSocket>,
    pub addr: IpAddr,
    pub buf_len: usize,
}

enum BatchResult {
    Continue,
    Exhausted,
    Fatal,
}

impl PacketWorkers {
    pub fn new(config: &DeviceConfig) -> Self {
        let max_batched_pkts = config
            .max_inter_thread_batched_pkts
            .unwrap_or(MAX_INTERTHREAD_BATCHED_PKTS);

        let channel_size = config.inter_thread_channel_size.unwrap_or(CHANNEL_SIZE);
        let (tunnel_to_socket_tx, tunnel_to_socket_rx) = crossbeam_channel::bounded(channel_size);
        let (socket_to_tunnel_tx, socket_to_tunnel_rx) = crossbeam_channel::bounded(channel_size);

        Self {
            max_batched_pkts,
            tunnel_to_socket_tx,
            tunnel_to_socket_rx,
            socket_to_tunnel_tx,
            socket_to_tunnel_rx,
            close_network_worker_tx: None,
            close_tun_worker_tx: None,
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(close_network_worker_tx) = &self.close_network_worker_tx {
            for _ in 0..num_cpus::get_physical() {
                if let Err(e) = close_network_worker_tx.try_send(()) {
                    tracing::error!("Unable to close network thread {e}");
                }
            }
        }
        if let Some(close_tun_worker_tx) = &self.close_tun_worker_tx {
            if let Err(e) = close_tun_worker_tx.try_send(()) {
                tracing::error!("Unable to close tun thread {e}");
            }
        }
    }

    pub fn start(
        &mut self,
        udp4: Arc<socket2::Socket>,
        udp6: Arc<socket2::Socket>,
        config: &DeviceConfig,
    ) {
        // Construct a different closing channel per thread
        let (close_network_worker_tx, close_network_worker_rx) =
            crossbeam_channel::bounded(num_cpus::get_physical() * 5);
        let (close_tun_worker_tx, close_tun_worker_rx) = crossbeam_channel::bounded(5);

        self.close_network_worker_tx = Some(close_network_worker_tx);
        self.close_tun_worker_tx = Some(close_tun_worker_tx);

        for _ in 0..num_cpus::get_physical() {
            let tunnel_to_socket_rx = self.tunnel_to_socket_rx.clone();
            let close_chan_clone = close_network_worker_rx.clone();
            let udp4_c = udp4.clone();
            let udp6_c = udp6.clone();
            let fw_callback = config
                .firewall_process_outbound_callback
                .as_ref()
                .map(|f| f.clone());
            thread::spawn(move || {
                write_to_socket_worker(
                    tunnel_to_socket_rx,
                    close_chan_clone,
                    udp4_c,
                    udp6_c,
                    fw_callback,
                )
            });
        }

        let socket_to_tunnel_rx = self.socket_to_tunnel_rx.clone();
        let fw_callback = config.firewall_process_inbound_callback.clone();
        thread::spawn(move || {
            write_to_tun_worker(socket_to_tunnel_rx, close_tun_worker_rx, fw_callback)
        });
    }

    /// Reads packets from the iface in batches and dispatches each batch to the
    /// network worker threads via the outbound channel. Returns `Action::Exit`
    /// only on a fatal iface read error; otherwise drains until the iface
    /// reports `WouldBlock`/`Interrupted`.
    pub fn dispatch_iface_read(
        &self,
        iface: &Arc<TunSocket>,
        mtu: &CheckedMtu,
        peers: &AllowedIps<Arc<Peer>>,
    ) -> Action {
        loop {
            let (batched_pkts, result) = read_iface_batch(iface, mtu, peers, self.max_batched_pkts);

            match result {
                BatchResult::Fatal => return Action::Exit,
                BatchResult::Continue | BatchResult::Exhausted => {
                    if let Err(e) = self.tunnel_to_socket_tx.send(batched_pkts) {
                        tracing::warn!("Unable to forward data onto network worker {e}");
                        // The staged slots have already been pushed onto their peers' queues and leaving them `Unencrypted`
                        // would make subsequent packets stall
                        let batch = e.into_inner();
                        for element in &batch {
                            element.abandon();
                        }
                    }
                    if matches!(result, BatchResult::Exhausted) {
                        break;
                    }
                }
            }
        }

        Action::Continue
    }

    /// Submit a batch of decapsulated packets to the inbound worker for
    /// writing to the tun interface.
    pub fn submit_inbound(&self, batch: Vec<TunnelWorkerData>) {
        if let Err(e) = self.socket_to_tunnel_tx.send(batch) {
            tracing::warn!("Unable to forward data onto tunnel worker {e}");
        }
    }
}

fn read_iface_batch(
    iface: &Arc<TunSocket>,
    mtu: &CheckedMtu,
    peers: &AllowedIps<Arc<Peer>>,
    max_batched_pkts: usize,
) -> (Vec<NetworkTaskData>, BatchResult) {
    let mut batched_pkts = Vec::with_capacity(max_batched_pkts);

    for _ in 0..batched_pkts.capacity() {
        let mut buffer = [0u8; MAX_PKT_SIZE];
        match read_packet(iface, &mut buffer, mtu, peers) {
            IfaceReadResult::Exhausted => return (batched_pkts, BatchResult::Exhausted),
            IfaceReadResult::Fatal => return (batched_pkts, BatchResult::Fatal),
            IfaceReadResult::Skip => continue,
            IfaceReadResult::Packet { payload, peer } => {
                let len = payload.len();

                // Reserve the nonce and push the ordering slot, so that the order in which packets are sent
                // per each peer is the same order in which the packets were read off the tun device
                let reserved = peer.tunnel.lock().reserve_send_nonce().map(|reserved| {
                    let slot = Arc::new(PacketSlot::new());
                    peer.tx_queue.push(slot.clone());
                    (reserved, slot)
                });

                batched_pkts.push(NetworkTaskData {
                    data: buffer,
                    buf_len: len,
                    peer,
                    iface: iface.clone(),
                    reserved,
                });
            }
        }
    }

    (batched_pkts, BatchResult::Continue)
}

fn write_to_socket_worker(
    tunnel_to_socket_rx: Receiver<Vec<NetworkTaskData>>,
    close_chan: Receiver<()>,
    udp4: Arc<socket2::Socket>,
    udp6: Arc<socket2::Socket>,
    firewall_process_outbound_callback: Option<
        Arc<dyn Fn(&[u8; 32], &mut [u8], &mut dyn std::io::Write) -> bool + Send + Sync>,
    >,
) {
    loop {
        crossbeam_channel::select! {
            recv(tunnel_to_socket_rx) -> element => {
                if let Ok(mut batched_pkts) = element {
                    for element in batched_pkts.iter_mut() {
                        let len = element.buf_len;

                        let firewall_passed = match &firewall_process_outbound_callback {
                            Some(callback) => {
                                match element.data.get_mut(WG_HEADER_OFFSET..len + WG_HEADER_OFFSET) {
                                    Some(buffer) => callback(
                                        &element.peer.public_key.0,
                                        buffer,
                                        &mut element.iface.as_ref(),
                                    ),
                                    None => false,
                                }
                            }
                            None => true,
                        };

                        if !firewall_passed {
                            // A packet dropped here must still resolve its slot to prevent a stall
                            if let Some((_, slot)) = &element.reserved {
                                slot.set_state(SlotState::Failed);
                                commit_ready(&element.peer, &udp4, &udp6);
                            }
                            continue;
                        }

                        match &element.reserved {
                            Some((reserved, slot)) => {
                                encrypt_into_slot(
                                    &element.peer,
                                    &mut element.data[..],
                                    len,
                                    reserved,
                                    slot,
                                );

                                // Make an attempt to become a committer for this peer and flush ready slots from the queue
                                commit_ready(&element.peer, &udp4, &udp6);
                            }
                            None => {
                                encapsulate_and_send(&element.peer, &mut element.data[..], len, &udp4, &udp6);
                            }
                        }
                    }
                }
            }
            recv(close_chan) -> _n => {
                break;
            }
        }
    }
}

/// Attempts to become a peer's committer and drain ready slots from the queue,
/// stopping at the first slot that's still `Unencrypted` (or an empty queue).
fn commit_ready(peer: &Arc<Peer>, udp4: &socket2::Socket, udp6: &socket2::Socket) {
    peer.tx_queue.drain_ready(|slot| {
        slot.with_state(|state| {
            if let SlotState::Encrypted { buffer, len } = state {
                send_to_peer(peer, &buffer[..*len], udp4, udp6);
            }
        })
    });
}

/// Encrypts a packet using the nonce reserved for it at staging time, and stores the result in
/// its `PacketSlot`.
fn encrypt_into_slot(
    peer: &Arc<Peer>,
    buf: &mut [u8],
    payload_len: usize,
    reserved: &ReservedNonce,
    slot: &Arc<PacketSlot>,
) {
    let res = {
        let mut tun = peer.tunnel.lock();
        tun.encapsulate_with_reserved_nonce(reserved, payload_len, buf)
    };

    let state = match res {
        TunnResult::WriteToNetwork(packet) => {
            let mut buffer = [0u8; MAX_PKT_SIZE];
            let len = packet.len();
            match buffer.get_mut(..len) {
                Some(dst) => {
                    dst.copy_from_slice(packet);
                    SlotState::Encrypted { buffer, len }
                }
                None => SlotState::Failed,
            }
        }
        TunnResult::Err(e) => {
            tracing::error!(message = "Encapsulation error", error = ?e, public_key = peer.public_key.1);
            SlotState::Failed
        }
        TunnResult::Done | TunnResult::WriteToTunnel(..) => SlotState::Failed,
    };

    slot.set_state(state);
}

fn write_to_tun_worker(
    socket_to_tunnel_rx: Receiver<Vec<TunnelWorkerData>>,
    close_chan: Receiver<()>,
    firewall_process_inbound_callback: Option<
        Arc<dyn Fn(&[u8; 32], &mut [u8]) -> bool + Send + Sync>,
    >,
) {
    loop {
        crossbeam_channel::select! {
            recv(socket_to_tunnel_rx) -> batched_pkts => {
                if let Ok(batched_pkts) = batched_pkts {
                    for mut t in batched_pkts {
                        let peer = t.peer;

                        let buffer = match t.buffer.get_mut(..t.buf_len) {
                            Some(b) => b,
                            None => {
                                tracing::warn!("Length is greater than buffer space");
                                continue
                            },
                        };
                        if let Some(callback) = &firewall_process_inbound_callback {
                            if !callback(&peer.public_key.0, buffer) {
                                continue;
                            }
                        }
                        if peer.is_allowed_ip(t.addr) {
                            _ = t.iface.as_ref().write(buffer);
                            tracing::trace!(
                                message = "Writing packet to tunnel",
                                packet_length = t.buf_len,
                                src_addr = ?t.addr,
                                public_key = peer.public_key.1
                            );
                        }
                    }
                }
            }
            recv(close_chan) -> _n => {
                break;
            }
        }
    }
}
