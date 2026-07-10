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
use crate::device::packet_slot::PacketSlot;
use crate::device::peer::Peer;
use crate::device::tun::TunSocket;
use crate::noise::errors::WireGuardError;
use crate::noise::{ReservedNonce, TunnResult};

const CHANNEL_SIZE: usize = 500;
const MAX_INTERTHREAD_BATCHED_PKTS: usize = 50;

/// Metadata a `PacketSlot` holds once a worker has encrypted it (`SlotState::Ready` for Tx side).
/// The encrypted bytes live in the slot's own buffer; only the length is carried here.
pub type TxReady = usize;

/// Metadata a `PacketSlot` holds once a worker has decrypted it (`SlotState::Ready` for Rx side).
/// The plaintext lives in the slot's own buffer at `[WG_HEADER_OFFSET..WG_HEADER_OFFSET + len]`;
/// the length and source address are carried here.
pub type RxReady = (usize, IpAddr);

pub(super) struct PacketWorkers {
    pub max_batched_pkts: usize,

    tunnel_to_socket_tx: Sender<Vec<NetworkTaskData>>,
    tunnel_to_socket_rx: Receiver<Vec<NetworkTaskData>>,

    socket_to_tunnel_tx: Sender<Vec<TunWriteData>>,
    socket_to_tunnel_rx: Receiver<Vec<TunWriteData>>,

    decrypt_queue_tx: Sender<Vec<DecryptTaskData>>,
    decrypt_queue_rx: Receiver<Vec<DecryptTaskData>>,

    close_network_worker_tx: Option<Sender<()>>,
    close_tun_worker_tx: Option<Sender<()>>,
    close_decrypt_worker_tx: Option<Sender<()>>,
}

struct NetworkTaskData {
    slot: Arc<PacketSlot<TxReady>>,
    buf_len: usize,
    peer: Arc<Peer>,
    iface: Arc<TunSocket>,
    /// The AEAD nonce reserved for this packet at staging time. `None` when no session was
    /// available at staging time, in which case the slot is not part of the ordering queue.
    reserved: Option<ReservedNonce>,
}

impl NetworkTaskData {
    /// Resolve this task's ordering slot without encrypting or sending anything, and
    /// immediately drop any `Failed` slots currently at the head of the peer's queue.
    fn abandon(&self) {
        if self.reserved.is_some() {
            self.slot.fail();
            self.peer.tx_queue.drain_failed_head();
        }
    }
}

/// A datagram staged for parallel decryption on a peer's connected socket,
/// staged into the ordering slot its plaintext will land in in place.
pub(super) struct DecryptTaskData {
    pub slot: Arc<PacketSlot<RxReady>>,
    pub buf_len: usize,
    pub peer: Arc<Peer>,
    pub iface: Arc<TunSocket>,
}

/// A decrypted, in-order packet handed from a peer's rx committer to the TUN writer.
/// The plaintext lives in `slot`'s buffer; the writer reads it straight from there.
struct TunWriteData {
    slot: Arc<PacketSlot<RxReady>>,
    peer: Arc<Peer>,
    iface: Arc<TunSocket>,
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
        let (decrypt_queue_tx, decrypt_queue_rx) = crossbeam_channel::bounded(channel_size);

        Self {
            max_batched_pkts,
            tunnel_to_socket_tx,
            tunnel_to_socket_rx,
            socket_to_tunnel_tx,
            socket_to_tunnel_rx,
            decrypt_queue_tx,
            decrypt_queue_rx,
            close_network_worker_tx: None,
            close_tun_worker_tx: None,
            close_decrypt_worker_tx: None,
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
        if let Some(close_decrypt_worker_tx) = &self.close_decrypt_worker_tx {
            for _ in 0..num_cpus::get_physical() {
                if let Err(e) = close_decrypt_worker_tx.try_send(()) {
                    tracing::error!("Unable to close decrypt thread {e}");
                }
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
        let (close_decrypt_worker_tx, close_decrypt_worker_rx) =
            crossbeam_channel::bounded(num_cpus::get_physical() * 5);

        self.close_network_worker_tx = Some(close_network_worker_tx);
        self.close_tun_worker_tx = Some(close_tun_worker_tx);
        self.close_decrypt_worker_tx = Some(close_decrypt_worker_tx);

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

        for _ in 0..num_cpus::get_physical() {
            let decrypt_queue_rx = self.decrypt_queue_rx.clone();
            let close_chan_clone = close_decrypt_worker_rx.clone();
            let socket_to_tunnel_tx = self.socket_to_tunnel_tx.clone();
            thread::spawn(move || {
                decrypt_worker(decrypt_queue_rx, close_chan_clone, socket_to_tunnel_tx)
            });
        }
    }

    pub fn submit_for_decrypt(&self, batch: Vec<DecryptTaskData>) {
        if let Err(e) = self.decrypt_queue_tx.send(batch) {
            tracing::warn!("Unable to forward data onto decrypt worker {e}");
        }
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

                // The slot owns the buffer the worker encrypts in place.
                let slot = Arc::new(PacketSlot::new());
                if !slot.stage(&buffer[..WG_HEADER_OFFSET + len]) {
                    tracing::warn!("Packet larger than slot buffer, dropping");
                    continue;
                }

                // Reserve the nonce and push the ordering slot, so that the order in which packets are sent
                // per each peer is the same order in which the packets were read off the tun device
                let reserved = peer.tunnel.lock().reserve_send_nonce();
                if reserved.is_some() {
                    peer.tx_queue.push(slot.clone());
                };

                batched_pkts.push(NetworkTaskData {
                    slot,
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
                if let Ok(batched_pkts) = element {
                    for element in batched_pkts {
                        let len = element.buf_len;

                        let firewall_passed = match &firewall_process_outbound_callback {
                            Some(callback) => element.slot.with_buffer_mut(|buffer| {
                                match buffer.get_mut(WG_HEADER_OFFSET..len + WG_HEADER_OFFSET) {
                                    Some(payload) => callback(
                                        &element.peer.public_key.0,
                                        payload,
                                        &mut element.iface.as_ref(),
                                    ),
                                    None => false,
                                }
                            }),
                            None => true,
                        };

                        if !firewall_passed {
                            // A packet dropped here must still resolve its slot to prevent a stall
                            if element.reserved.is_some() {
                                element.slot.fail();
                                commit_ready(&element.peer, &udp4, &udp6);
                            }
                            continue;
                        }

                        match &element.reserved {
                            Some(reserved) => {
                                encrypt_into_slot(&element.peer, len, reserved, &element.slot);

                                // Make an attempt to become a committer for this peer and flush ready slots from the queue
                                commit_ready(&element.peer, &udp4, &udp6);
                            }
                            None => {
                                // No session at staging time and thus no ordering slot: encrypt
                                // in the slot buffer and send directly, order not preserved.
                                element.slot.with_buffer_mut(|buffer| {
                                    encapsulate_and_send(&element.peer, &mut buffer[..], len, &udp4, &udp6);
                                });
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
/// stopping at the first slot that's still `Pending` (or an empty queue).
fn commit_ready(peer: &Arc<Peer>, udp4: &socket2::Socket, udp6: &socket2::Socket) {
    peer.tx_queue.drain_ready(|buffer, len| {
        send_to_peer(peer, &buffer[..*len], udp4, udp6);
    });
}

/// Encrypts the packet already staged in `slot`'s buffer in place using the nonce reserved for
/// it at staging time, and publishes the encrypted length back into the slot.
fn encrypt_into_slot(
    peer: &Arc<Peer>,
    payload_len: usize,
    reserved: &ReservedNonce,
    slot: &Arc<PacketSlot<TxReady>>,
) {
    let result = slot.with_buffer_mut(|buffer| {
        let res = {
            let mut tun = peer.tunnel.lock();
            tun.encapsulate_with_reserved_nonce(reserved, payload_len, &mut buffer[..])
        };

        match res {
            TunnResult::WriteToNetwork(packet) => Ok(packet.len()),
            TunnResult::Err(e) => {
                tracing::error!(message = "Encapsulation error", error = ?e, public_key = peer.public_key.1);
                Err(())
            }
            TunnResult::Done | TunnResult::WriteToTunnel(..) => Err(()),
        }
    });

    slot.finish(result);
}

fn write_to_tun_worker(
    socket_to_tunnel_rx: Receiver<Vec<TunWriteData>>,
    close_chan: Receiver<()>,
    firewall_process_inbound_callback: Option<
        Arc<dyn Fn(&[u8; 32], &mut [u8]) -> bool + Send + Sync>,
    >,
) {
    loop {
        crossbeam_channel::select! {
            recv(socket_to_tunnel_rx) -> batched_pkts => {
                if let Ok(batched_pkts) = batched_pkts {
                    for t in batched_pkts {
                        let peer = &t.peer;

                        // The decrypted plaintext lives in the slot buffer at
                        // `[WG_HEADER_OFFSET..WG_HEADER_OFFSET + len]`.
                        let (len, addr) = match t.slot.with_meta(|meta| *meta) {
                            Some(m) => m,
                            None => continue,
                        };

                        let written = t.slot.with_buffer_mut(|buffer| {
                            let payload = match buffer.get_mut(WG_HEADER_OFFSET..WG_HEADER_OFFSET + len) {
                                Some(b) => b,
                                None => {
                                    tracing::warn!("Length is greater than buffer space");
                                    return false;
                                }
                            };
                            if let Some(callback) = &firewall_process_inbound_callback {
                                if !callback(&peer.public_key.0, payload) {
                                    return false;
                                }
                            }
                            if peer.is_allowed_ip(addr) {
                                _ = t.iface.as_ref().write(payload);
                                return true;
                            }
                            false
                        });

                        if written {
                            tracing::trace!(
                                message = "Writing packet to tunnel",
                                packet_length = len,
                                src_addr = ?addr,
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

fn decrypt_worker(
    decrypt_queue_rx: Receiver<Vec<DecryptTaskData>>,
    close_chan: Receiver<()>,
    socket_to_tunnel_tx: Sender<Vec<TunWriteData>>,
) {
    loop {
        crossbeam_channel::select! {
            recv(decrypt_queue_rx) -> batch => {
                if let Ok(batch) = batch {
                    for item in batch {
                        decrypt_into_slot(&item.peer, item.buf_len, &item.slot);

                        // Make an attempt to become a committer for this peer and flush ready slots from the queue
                        rx_commit_ready(&item.peer, &item.iface, &socket_to_tunnel_tx);
                    }
                }
            }
            recv(close_chan) -> _n => {
                break;
            }
        }
    }
}

/// Attempts to become a peer's rx committer, draining in-order decrypted slots and forwarding
/// them to the TUN writer in a single batch.
fn rx_commit_ready(
    peer: &Arc<Peer>,
    iface: &Arc<TunSocket>,
    socket_to_tunnel_tx: &Sender<Vec<TunWriteData>>,
) {
    let mut batch: Vec<TunWriteData> = Vec::new();
    peer.rx_queue.drain_ready_slots(|slot| {
        batch.push(TunWriteData {
            slot: slot.clone(),
            peer: peer.clone(),
            iface: iface.clone(),
        });
    });

    if !batch.is_empty() {
        if let Err(e) = socket_to_tunnel_tx.send(batch) {
            tracing::warn!("Unable to forward data onto tunnel worker {e}");
        }
    }
}

/// Decrypts the datagram already staged in `slot`'s buffer in place, publishing the plaintext
/// length and source address back into the slot on success.
fn decrypt_into_slot(peer: &Arc<Peer>, datagram_len: usize, slot: &Arc<PacketSlot<RxReady>>) {
    let result = slot.with_buffer_mut(|buffer| {
        let res = {
            let mut tun = peer.tunnel.lock();
            tun.decapsulate_in_place(&mut buffer[..], datagram_len)
        };

        match res {
            TunnResult::WriteToTunnel(packet, addr) => Ok((packet.len(), addr)),
            // A keepalive: decrypted successfully, nothing to deliver - not an error.
            TunnResult::Done => Err(()),
            TunnResult::Err(e) => {
                match e {
                    WireGuardError::DuplicateCounter => {
                        // TODO(LLT-6071): revert back to having error level for all error types
                        tracing::debug!(message = "Decapsulate error", error = ?e, public_key = peer.public_key.1);
                    }
                    _ => {
                        tracing::error!(message = "Decapsulate error", error = ?e, public_key = peer.public_key.1);
                    }
                }
                Err(())
            }
            _ => Err(()),
        }
    });

    slot.finish(result);
}
