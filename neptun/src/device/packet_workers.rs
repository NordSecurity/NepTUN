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

/// Maximum number of packets in a batch
const MAX_BATCH_SIZE: usize = 64;

/// Maximum number of batches in a queue
const QUEUE_SIZE: usize = 16;

/// IPv4 and IPv6 listen sockets
pub(super) type NetSockets = RwLock<Option<(Arc<Socket>, Arc<Socket>)>>;

type InboundFirewall = Arc<dyn Fn(&[u8; 32], &mut [u8]) -> bool + Send + Sync>;

/// Encrypted outgoing packet to be sent over a UDP socket
pub(super) struct EncryptedPacket {
    data: [u8; MAX_PKT_SIZE],
    len: usize,
    peer: Arc<Peer>,
}

impl EncryptedPacket {
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

/// Decrypted incoming packet to be written to the TUN interface
pub(super) struct DecryptedPacket {
    data: [u8; MAX_PKT_SIZE],
    len: usize,
    peer: Arc<Peer>,
    src_addr: IpAddr,
}

impl DecryptedPacket {
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

/// Collects packets into batches for a packet worker
pub(super) struct Batcher<T> {
    sender: SyncSender<Vec<T>>,
    batch: Vec<T>,
}

impl<T> Batcher<T> {
    /// Runs `f` with the current batch and queues what's left once `f` succeeds
    /// or discards it on error
    pub fn with_batch<R>(
        &mut self,
        f: impl FnOnce(&mut Batch<'_, T>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        match f(&mut Batch(self)) {
            Ok(value) => {
                self.flush()?;
                Ok(value)
            }
            Err(e) => {
                self.batch.clear();
                Err(e)
            }
        }
    }

    fn push(&mut self, packet: T) -> Result<(), Error> {
        self.batch.push(packet);
        if self.batch.len() < MAX_BATCH_SIZE {
            return Ok(());
        }
        self.flush()
    }

    fn flush(&mut self) -> Result<(), Error> {
        if self.batch.is_empty() {
            return Ok(());
        }
        let batch = mem::replace(&mut self.batch, Vec::with_capacity(MAX_BATCH_SIZE));
        self.sender
            .send(batch)
            .map_err(|_| Error::InternalError("Packet worker stopped".to_owned()))
    }
}

/// Handle for adding packets
pub(super) struct Batch<'a, T>(&'a mut Batcher<T>);

impl<T> Batch<'_, T> {
    /// Adds a packet to the batch and queues it to the packet worker once the batch is full
    pub fn push(&mut self, packet: T) -> Result<(), Error> {
        self.0.push(packet)
    }
}

/// Bounded queue of packet batches (implemented with [`mpsc::sync_channel`]),
/// returned with its batcher
pub(super) fn batch_queue<T>() -> (Batcher<T>, Receiver<Vec<T>>) {
    let (sender, receiver) = mpsc::sync_channel(QUEUE_SIZE);
    (
        Batcher {
            sender,
            batch: Vec::with_capacity(MAX_BATCH_SIZE),
        },
        receiver,
    )
}

/// Drains the queue and sends the packets to the network
pub(super) fn network_worker(
    queue: Receiver<Vec<EncryptedPacket>>,
    sockets: Arc<NetSockets>,
    control_waker: Arc<Waker>,
) {
    while let Ok(batch) = queue.recv() {
        let sockets = sockets.read();
        let Some((udp4, udp6)) = sockets.as_ref() else {
            tracing::debug!("No listen sockets, {} packets dropped", batch.len());
            continue;
        };
        for packet in &batch {
            if let Some(data) = packet.data.get(..packet.len) {
                send_packet(&packet.peer, data, udp4, udp6, &control_waker);
            }
        }
    }
}

/// Drains the queue and writes the packets to the TUN interface
///
/// Packets rejected by the inbound firewall or outside of the peer's allowed IPs are dropped
pub(super) fn tun_worker(
    queue: Receiver<Vec<DecryptedPacket>>,
    iface: Arc<TunSocket>,
    firewall: Option<InboundFirewall>,
) {
    while let Ok(mut batch) = queue.recv() {
        for DecryptedPacket {
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
                tracing::trace!(
                    message = "Writing packet to tunnel",
                    interface = ?iface.name(),
                    packet_length = packet.len(),
                    src_addr = ?src_addr,
                    peer = %peer.public_key
                );
            } else {
                tracing::debug!(
                    message = "Dropping packet from outside of allowed IPs",
                    src_addr = ?src_addr
                );
            }
        }
    }
}

/// Sends a packet over a UDP socket
fn send_packet(
    peer: &Arc<Peer>,
    packet: &[u8],
    udp4: &Socket,
    udp6: &Socket,
    control_waker: &Waker,
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
            Err(err) if err.raw_os_error() == Some(libc::ENOBUFS) => {
                tracing::debug!(message = "Connected socket interface queue full, dropping packet", error = ?err);
            }
            Err(err) => {
                tracing::debug!(message = "Failed to send packet with the connected socket", error = ?err);
                if peer.request_disconnect() {
                    control_waker.wake();
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

#[cfg(test)]
mod tests {
    use std::sync::mpsc::TryRecvError;

    use super::*;

    #[test]
    fn full_batches_are_queued_in_order_and_the_rest_on_success() {
        let (mut batcher, queue) = batch_queue();

        batcher
            .with_batch(|batch| {
                for i in 0..MAX_BATCH_SIZE + 3 {
                    batch.push(i)?;
                }

                // A full batch is queued without waiting for the closure to return
                assert_eq!(
                    queue.try_recv(),
                    Ok((0..MAX_BATCH_SIZE).collect::<Vec<_>>())
                );

                Ok(())
            })
            .unwrap();

        assert_eq!(
            queue.try_recv(),
            Ok((MAX_BATCH_SIZE..MAX_BATCH_SIZE + 3).collect::<Vec<_>>())
        );
        assert_eq!(queue.try_recv(), Err(TryRecvError::Empty));
    }

    #[test]
    fn failure_returns_the_error_and_discards_unqueued_packets() {
        let (mut batcher, queue) = batch_queue();

        let result = batcher.with_batch(|batch| {
            for i in 0..MAX_BATCH_SIZE + 3 {
                batch.push(i)?;
            }
            Err::<(), _>(Error::InternalError("closure failed".to_owned()))
        });

        assert!(matches!(result, Err(Error::InternalError(msg)) if msg == "closure failed"));

        // The full batch was queued before the failure
        assert_eq!(
            queue.try_recv(),
            Ok((0..MAX_BATCH_SIZE).collect::<Vec<_>>())
        );

        // Run a successful closure to trigger flush and show that the leftover packets were cleared
        batcher.with_batch(|_| Ok(())).unwrap();
        assert_eq!(queue.try_recv(), Err(TryRecvError::Empty));
    }

    #[test]
    fn stopped_worker_fails_the_batcher() {
        let (mut batcher, queue) = batch_queue();
        drop(queue);

        let result = batcher.with_batch(|batch| batch.push(0));
        assert!(matches!(result, Err(Error::InternalError(_))));
    }
}
