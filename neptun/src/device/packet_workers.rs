//! Worker threads for UDP sends and TUN writes

use std::{
    io::Write,
    mem,
    net::{IpAddr, SocketAddr},
    sync::{
        mpsc::{self, Receiver, SyncSender},
        Arc,
    },
};

use parking_lot::RwLock;
use socket2::Socket;

use crate::device::{peer::Peer, tun::TunSocket, waker::Waker, Error, MAX_PKT_SIZE};

/// Maximum packets in a batch
const MAX_BATCH: usize = 64;
/// Maximum batches in a channel
const CHANNEL_SIZE: usize = 16;

/// IPv4 and IPv6 listen sockets
pub(super) type NetSockets = RwLock<Option<(Arc<Socket>, Arc<Socket>)>>;

type InboundFirewall = Arc<dyn Fn(&[u8; 32], &mut [u8]) -> bool + Send + Sync>;

/// Encrypted packet for the network
pub(super) struct NetPacket {
    data: [u8; MAX_PKT_SIZE],
    len: usize,
    peer: Arc<Peer>,
}

impl NetPacket {
    pub fn new(packet: &[u8], peer: Arc<Peer>) -> Option<Self> {
        let mut data = [0u8; MAX_PKT_SIZE];
        data.get_mut(..packet.len())?.copy_from_slice(packet);
        Some(Self {
            data,
            len: packet.len(),
            peer,
        })
    }
}

/// Decrypted packet for the TUN
pub(super) struct TunPacket {
    data: [u8; MAX_PKT_SIZE],
    len: usize,
    peer: Arc<Peer>,
    src_addr: IpAddr,
}

impl TunPacket {
    pub fn new(packet: &[u8], peer: Arc<Peer>, src_addr: IpAddr) -> Option<Self> {
        let mut data = [0u8; MAX_PKT_SIZE];
        data.get_mut(..packet.len())?.copy_from_slice(packet);
        Some(Self {
            data,
            len: packet.len(),
            peer,
            src_addr,
        })
    }
}

/// Producer end of a worker channel
pub(super) struct BatchSender<T> {
    tx: SyncSender<Vec<T>>,
    batch: Vec<T>,
}

impl<T> BatchSender<T> {
    /// Adds a packet; sends a full batch
    pub fn push(&mut self, packet: T) -> Result<(), Error> {
        self.batch.push(packet);
        if self.batch.len() < MAX_BATCH {
            return Ok(());
        }
        self.flush()
    }

    /// Sends the batch
    pub fn flush(&mut self) -> Result<(), Error> {
        if self.batch.is_empty() {
            return Ok(());
        }
        let batch = mem::replace(&mut self.batch, Vec::with_capacity(MAX_BATCH));
        self.tx
            .send(batch)
            .map_err(|_| Error::InternalError("Packet worker stopped".to_owned()))
    }
}

/// Bounded channel to a worker
pub(super) fn channel<T>() -> (BatchSender<T>, Receiver<Vec<T>>) {
    let (tx, rx) = mpsc::sync_channel(CHANNEL_SIZE);
    (
        BatchSender {
            tx,
            batch: Vec::with_capacity(MAX_BATCH),
        },
        rx,
    )
}

/// Sends packets to the network until the channel disconnects
pub(super) fn network_worker(
    rx: Receiver<Vec<NetPacket>>,
    sockets: Arc<NetSockets>,
    control: Arc<Waker>,
) {
    while let Ok(batch) = rx.recv() {
        let sockets = sockets.read();
        let Some((udp4, udp6)) = sockets.as_ref() else {
            tracing::debug!("No listen sockets, {} packets dropped", batch.len());
            continue;
        };
        for packet in &batch {
            if let Some(data) = packet.data.get(..packet.len) {
                send_packet(&packet.peer, data, udp4, udp6, &control);
            }
        }
    }
}

/// Writes packets to the TUN until the channel disconnects
pub(super) fn tun_worker(
    rx: Receiver<Vec<TunPacket>>,
    iface: Arc<TunSocket>,
    firewall: Option<InboundFirewall>,
) {
    while let Ok(mut batch) = rx.recv() {
        for TunPacket {
            data,
            len,
            peer,
            src_addr,
        } in batch.iter_mut()
        {
            let Some(packet) = data.get_mut(..*len) else {
                continue;
            };
            if let Some(callback) = &firewall {
                if !callback(peer.public_key.as_bytes(), packet) {
                    continue;
                }
            }
            if peer.is_allowed_ip(*src_addr) {
                _ = iface.as_ref().write(packet);
                tracing::trace!(message = "Writing packet to tunnel", packet_length = packet.len(), src_addr = ?src_addr, peer = %peer.public_key);
            } else {
                tracing::debug!(message = "Dropping packet from outside of allowed IPs", src_addr = ?src_addr);
            }
        }
    }
}

fn send_packet(peer: &Arc<Peer>, packet: &[u8], udp4: &Socket, udp6: &Socket, control: &Waker) {
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
            Err(err) if err.raw_os_error() == Some(libc::ENOBUFS) => {
                tracing::debug!(message = "Connected socket interface queue full, dropping packet", error = ?err);
            }
            Err(err) => {
                tracing::debug!(message = "Failed to send packet with the connected socket", error = ?err);
                if peer.request_disconnect() {
                    control.wake();
                }
            }
        }
    } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
        if let Err(err) = udp4.send_to(packet, &addr.into()) {
            tracing::warn!(message = "Failed to write packet to network v4", error = ?err, dst = ?addr);
        } else {
            tracing::trace!(message = "Writing packet to network v4", packet_length = packet.len(), src_addr = ?addr, peer = %peer.public_key);
        }
    } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
        if let Err(err) = udp6.send_to(packet, &addr.into()) {
            tracing::warn!(message = "Failed to write packet to network v6", error = ?err, dst = ?addr);
        } else {
            tracing::trace!(message = "Writing packet to network v6", packet_length = packet.len(), src_addr = ?addr, peer = %peer.public_key);
        }
    } else {
        tracing::error!("No endpoint");
    }
}
