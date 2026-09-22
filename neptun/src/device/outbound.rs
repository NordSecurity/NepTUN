use std::{
    io,
    net::SocketAddr,
    ops::ControlFlow,
    os::fd::AsFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use nix::poll::{PollFd, PollFlags};
use parking_lot::MutexGuard;
use socket2::Socket;

use crate::{
    device::{
        dev_lock::Lock,
        peer::Peer,
        tun::TunSocket,
        waker::{poll_retry, Resume, Waker},
        Device, DeviceHandle, Error, IfaceReadResult, MAX_PKT_SIZE, WG_HEADER_OFFSET,
    },
    noise::{
        errors::WireGuardError,
        session::{Session, DATA_OFFSET},
        Tunn, TunnResult, TxCommit, TxIntent,
    },
};

/// Outbound path state
enum TxPath<'p> {
    Ready(Arc<Session>),
    Blocked(BlockedTx<'p>),
}

/// Describes locked tunnel
struct BlockedTx<'p> {
    guard: MutexGuard<'p, Tunn>,
}

impl<'p> BlockedTx<'p> {
    #[inline]
    fn queue_and_init<'a>(mut self, src_len: usize, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.guard.queue_and_init(src_len, dst)
    }
}

fn begin_tx(peer: &Peer) -> TxPath<'_> {
    let guard = peer.tunnel.lock();
    let intent = guard.begin_tx();
    match intent {
        TxIntent::Ready(session) => {
            drop(guard);
            TxPath::Ready(session)
        }
        TxIntent::RequiresHandshake => TxPath::Blocked(BlockedTx { guard }),
    }
}

pub(crate) fn encapsulate_in_place<'a>(
    peer: &Peer,
    src_len: usize,
    dst: &'a mut [u8],
) -> TunnResult<'a> {
    let session = match begin_tx(peer) {
        TxPath::Ready(session) => session,
        TxPath::Blocked(blocked) => return blocked.queue_and_init(src_len, dst),
    };

    // Tunnel lock is released at this point
    let packet = match session.format_packet_data(src_len, dst) {
        Ok(packet) => packet,
        Err(e) => return TunnResult::Err(e),
    };

    let commit = TxCommit::for_packet(packet.len(), src_len);

    // Reacquiring tunnel lock
    peer.tunnel.lock().commit_tx(commit);
    TunnResult::WriteToNetwork(packet)
}

pub(crate) fn flush_queued<'a>(peer: &Peer, dst: &'a mut [u8]) -> TunnResult<'a> {
    let payload = match peer.tunnel.lock().dequeue_packet() {
        Some(p) => p,
        None => return TunnResult::Done,
    };
    let payload_len = payload.len();

    match dst.get_mut(DATA_OFFSET..DATA_OFFSET + payload_len) {
        Some(d) => d.copy_from_slice(&payload),
        None => {
            peer.tunnel.lock().requeue_packet(payload);
            return TunnResult::Err(WireGuardError::InvalidLength);
        }
    }

    match encapsulate_in_place(peer, payload_len, dst) {
        TunnResult::Err(e) => {
            peer.tunnel.lock().requeue_packet(payload);
            TunnResult::Err(e)
        }
        other => other,
    }
}

struct CheckedMtu(usize);

impl CheckedMtu {
    fn new(mtu: usize) -> Option<Self> {
        match mtu.checked_add(WG_HEADER_OFFSET) {
            Some(s) if s <= MAX_PKT_SIZE => Some(Self(mtu)),
            _ => None,
        }
    }

    fn get(&self) -> usize {
        self.0
    }
}

pub(super) struct Outbound {
    device: Arc<Lock<Device>>,
    stop: Arc<AtomicBool>,
    waker: Arc<Waker>,
}

impl Outbound {
    pub fn new(device: Arc<Lock<Device>>, stop: Arc<AtomicBool>, waker: Arc<Waker>) -> Self {
        Self {
            device,
            stop,
            waker,
        }
    }

    pub fn run(&self) {
        if let Err(e) = self.run_thread_main_loop() {
            tracing::error!(message = "Critical outbound thread failure, closing device", error = ?e);
            let mut d = self.device.read();
            DeviceHandle::close_device(&mut d);
        }
    }

    fn run_thread_main_loop(&self) -> Result<(), Error> {
        let mut buf = [0u8; MAX_PKT_SIZE];

        while !self.stop.load(Ordering::Relaxed) {
            // the guard is released before this returns, so parking here is safe
            if let Resume::OnWake = self.run_inner_loop(&mut buf)? {
                self.waker.wait()?;
            }
        }

        Ok(())
    }

    fn run_inner_loop(&self, buf: &mut [u8; MAX_PKT_SIZE]) -> Result<Resume, Error> {
        let device = self.device.read();

        // Inner loop runs under the device read lock guard
        let Some(view) = OutboundView::new(&device, &self.waker) else {
            tracing::debug!(message = "Not connected, parked until sockets are opened.");
            return Ok(Resume::OnWake);
        };

        let mut pfds = new_pfds(&device.iface, &self.waker);

        loop {
            // Park the thread while waiting for the packets to arrive
            if let ControlFlow::Break(resume) = view.wait_for_tun(&mut pfds)? {
                return Ok(resume);
            }

            // Process TUN packets
            if view.drain_tun(buf)?.is_break() {
                return Ok(Resume::Now);
            }
        }
    }
}

struct OutboundView<'a> {
    device: &'a Device,
    waker: &'a Waker,
    udp4: &'a Socket,
    udp6: &'a Socket,
}

impl<'a> OutboundView<'a> {
    fn new(device: &'a Device, waker: &'a Waker) -> Option<Self> {
        let (Some(udp4), Some(udp6)) = (device.udp4.as_deref(), device.udp6.as_deref()) else {
            return None;
        };

        Some(Self {
            device,
            waker,
            udp4,
            udp6,
        })
    }

    fn drain_tun(&self, buf: &mut [u8; MAX_PKT_SIZE]) -> Result<ControlFlow<()>, Error> {
        let mtu = match CheckedMtu::new(self.device.mtu.load(Ordering::Relaxed)) {
            Some(m) => m,
            None => {
                return Err(Error::InternalError(
                    "Insufficient packet buffer size".to_owned(),
                ))
            }
        };

        let fw_callback = self
            .device
            .config
            .firewall_process_outbound_callback
            .as_ref();

        loop {
            if self.waker.is_pending() {
                self.waker.ack();
                return Ok(ControlFlow::Break(()));
            }

            let (payload, peer) = match self.read_tun_packet(buf, &mtu) {
                IfaceReadResult::Packet { payload, peer } => (payload, peer),
                IfaceReadResult::Skip => continue,
                IfaceReadResult::Exhausted => return Ok(ControlFlow::Continue(())),
                IfaceReadResult::Fatal(e) => return Err(e),
            };

            if let Some(callback) = fw_callback {
                if !callback(&peer.public_key.0, payload, &mut self.device.iface.as_ref()) {
                    continue;
                }
            }

            let res = encapsulate_in_place(&peer, payload.len(), buf);

            match res {
                TunnResult::Done => {}
                TunnResult::Err(e) => {
                    tracing::error!(message = "Encapsulate error",
                        error = ?e,
                        public_key = peer.public_key.1);
                }
                TunnResult::WriteToNetwork(packet) => {
                    self.send_packet(&peer, packet);
                }
                _ => {
                    tracing::error!("Unexpected result from encapsulate");
                }
            }
        }
    }

    fn wait_for_tun(&self, pfds: &mut Pfds<'_>) -> Result<ControlFlow<Resume>, Error> {
        poll_retry(pfds.as_mut_slice())?;

        // On waker signal sent, this breaks out of TUN waiting loop
        // causing the thread to re-evaluate its stop flag
        if !pfds.get_revents(PfdIndex::Waker).is_empty() {
            self.waker.ack();
            return Ok(ControlFlow::Break(Resume::Now));
        }

        let tun_revents = pfds.get_revents(PfdIndex::Tun);

        if tun_revents.contains(PollFlags::POLLNVAL) {
            return Err(Error::InternalError(
                "Polled an invalid TUN fd (fd not open)".to_owned(),
            ));
        }

        // On TUN iface change break out of TUN waiting loop to re-read the Device config
        if tun_revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP) {
            tracing::warn!(message = "TUN iface invalidated", revents = ?tun_revents);
            return Ok(ControlFlow::Break(Resume::OnWake));
        }

        Ok(ControlFlow::Continue(()))
    }

    fn read_tun_packet<'b>(
        &self,
        buf: &'b mut [u8; MAX_PKT_SIZE],
        mtu: &CheckedMtu,
    ) -> IfaceReadResult<'b> {
        #[allow(clippy::indexing_slicing)]
        // buf is [u8; MAX_PKT_SIZE] and CheckedMtu guarantees mtu + WG_HEADER_OFFSET <= MAX_PKT_SIZE
        match self
            .device
            .iface
            .read(&mut buf[WG_HEADER_OFFSET..WG_HEADER_OFFSET + mtu.get()])
        {
            Ok(payload) => match Tunn::dst_address(payload) {
                None => IfaceReadResult::Skip,
                Some(dst_addr) => match self.device.peers_by_ip.find(dst_addr) {
                    None => IfaceReadResult::Skip,
                    Some(peer) => IfaceReadResult::Packet {
                        payload,
                        peer: peer.clone(),
                    },
                },
            },
            Err(Error::IfaceRead(e)) => match e.kind() {
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => {
                    IfaceReadResult::Exhausted
                }
                _ => {
                    tracing::error!(message = "Fatal read error on tun interface: errno", error = ?e);
                    IfaceReadResult::Fatal(Error::IfaceRead(e))
                }
            },
            Err(e) => {
                tracing::error!(message = "Unexpected error on tun interface", error = ?e);
                IfaceReadResult::Fatal(e)
            }
        }
    }

    fn send_packet(&self, peer: &Arc<Peer>, packet: &mut [u8]) {
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
                    if peer.shutdown_endpoint() {
                        self.device.notify_inbound();
                    }
                }
            }
        } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
            if let Err(err) = self.udp4.send_to(packet, &addr.into()) {
                tracing::warn!(message = "Failed to write packet to network v4", error = ?err, dst = ?addr);
            } else {
                tracing::trace!(message = "Writing packet to network v4", packet_length = packet.len(), src_addr = ?addr, public_key = peer.public_key.1);
            }
        } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
            if let Err(err) = self.udp6.send_to(packet, &addr.into()) {
                tracing::warn!(message = "Failed to write packet to network v6", error = ?err, dst = ?addr);
            } else {
                tracing::trace!(message = "Writing packet to network v6", packet_length = packet.len(), src_addr = ?addr, public_key = peer.public_key.1);
            }
        } else {
            tracing::error!("No endpoint");
        }
    }
}

/// PollFd count in the [`Pfds`] must be equal to number of [`PfdIndex`] variants
const PFD_COUNT: usize = 2;

/// Exhaustive list of outbound [`PollFd`]s
enum PfdIndex {
    Tun,
    Waker,
}

/// Create a set of outbound [`PollFd`]s ([`TunSocket`] and [`Waker`])
fn new_pfds<'a>(tun: &'a TunSocket, waker: &'a Waker) -> Pfds<'a> {
    let tun_pfd = PollFd::new(tun.as_fd(), PollFlags::POLLIN);
    let waker_pfd = PollFd::new(waker.wait_fd(), PollFlags::POLLIN);

    Pfds::new([
        tun_pfd,   // PfdIndex::Tun
        waker_pfd, // PfdIndex::Waker
    ])
}

/// A set of [`PollFd`]s used by IN/OUT data plane threads
pub(crate) struct Pfds<'a> {
    pfds: [PollFd<'a>; PFD_COUNT],
}

impl<'a> Pfds<'a> {
    /// Create a set of [`PollFd`]s
    fn new(pfds: [PollFd<'a>; PFD_COUNT]) -> Self {
        Self { pfds }
    }

    /// Reads return events from the [`PollFd`] set
    fn get_revents(&self, idx: PfdIndex) -> PollFlags {
        // PfdIndex enum is used as an indexer to self.pfds, which is defined as a slice
        // containing exactly that many elements as there are PfdIndex's variants
        #[allow(clippy::indexing_slicing)]
        self.pfds[idx as usize]
            .revents()
            .unwrap_or(PollFlags::empty())
    }

    fn as_mut_slice(&mut self) -> &mut [PollFd<'a>] {
        &mut self.pfds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_mtu_accepts_mtu_within_bounds() {
        let mtu = MAX_PKT_SIZE - WG_HEADER_OFFSET;
        assert!(CheckedMtu::new(mtu).is_some());
    }

    #[test]
    fn checked_mtu_boundary_over_limit_is_rejected() {
        let mtu = MAX_PKT_SIZE - WG_HEADER_OFFSET + 1;
        assert!(CheckedMtu::new(mtu).is_none());
    }

    #[test]
    fn checked_mtu_get_returns_original_value() {
        let mtu = 1420;
        let checked = CheckedMtu::new(mtu).unwrap();
        assert_eq!(checked.get(), mtu);
    }
}
