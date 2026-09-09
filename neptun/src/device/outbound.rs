use std::{
    io,
    net::SocketAddr,
    ops::ControlFlow,
    os::fd::AsFd,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

use nix::poll::{PollFd, PollFlags};
use socket2::Socket;

use crate::{
    device::{
        dev_lock::Lock,
        peer::Peer,
        tun::TunSocket,
        waker::{self, poll_retry, Waker},
        Device, DeviceHandle, Error, IfaceReadResult, MAX_PKT_SIZE, WG_HEADER_OFFSET,
    },
    noise::{Tunn, TunnResult},
};

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
        if let Err(e) = self.run_inner() {
            tracing::error!(message = "Critical outbound thread failure, closing device", error = ?e);
            let mut d = self.device.read();
            DeviceHandle::close_device(&mut d);
        }
    }

    fn run_inner(&self) -> Result<(), Error> {
        let mut buf = [0u8; MAX_PKT_SIZE];

        while !self.stop.load(Ordering::Relaxed) {
            // TODO: refactor to snapshot as for inbound
            // TODO: ensure every change to any of the snaphot data notifies inbound
            let (iface, mtu, fw_callback, udp4, udp6) = {
                let d = self.device.read();
                (
                    d.iface.clone(),
                    d.mtu.clone(),
                    d.config.firewall_process_outbound_callback.clone(),
                    d.udp4.clone(),
                    d.udp6.clone(),
                )
            };

            let (Some(udp4), Some(udp6)) = (udp4, udp6) else {
                tracing::debug!(message = "Not connected, parked until sockets are opened.");
                self.waker.wait()?;
                continue;
            };

            let mut pfds = new_pfds(&iface, &self.waker);

            // TUN readiness loop
            loop {
                // Park the thread while waiting for the packets to arrive
                if self.wait_for_tun(&mut pfds)?.is_break() {
                    break;
                }

                // Process TUN packets
                if self
                    .drain_tun(&iface, &mtu, &mut buf, &fw_callback, &udp4, &udp6)?
                    .is_break()
                {
                    break;
                }
            }
        }

        Ok(())
    }

    fn drain_tun(
        &self,
        iface: &Arc<TunSocket>,
        mtu: &Arc<AtomicUsize>,
        buf: &mut [u8; MAX_PKT_SIZE],
        fw_callback: &Option<
            Arc<dyn Fn(&[u8; 32], &mut [u8], &mut dyn std::io::Write) -> bool + Send + Sync>,
        >,
        udp4: &Arc<Socket>,
        udp6: &Arc<Socket>,
    ) -> Result<ControlFlow<()>, Error> {
        let mtu = mtu.load(Ordering::Relaxed);

        loop {
            if self.waker.is_pending() {
                self.waker.ack();
                return Ok(ControlFlow::Break(()));
            }

            let (payload, peer) = match self.read_tun_packet(iface, buf, mtu) {
                IfaceReadResult::Packet { payload, peer } => (payload, peer),
                IfaceReadResult::Skip => continue,
                IfaceReadResult::Exhausted => return Ok(ControlFlow::Continue(())),
                IfaceReadResult::Fatal(e) => return Err(e),
            };

            if let Some(callback) = fw_callback {
                if !callback(&peer.public_key.0, payload, &mut iface.as_ref()) {
                    continue;
                }
            }

            let session = {
                // Bind to a local variable, so that the tunnel's MutexGuard is dropped immediately after
                // acquiring the session
                let current = peer.tunnel.lock().current_session();
                match current {
                    Some(s) => s,
                    None => {
                        // Queue packet if session is not yet established
                        {
                            let mut tun = peer.tunnel.lock();
                            tun.queue_packet(payload);
                        }

                        // TODO: want_handshake waits up to 250 ms for the timer state machine to tick, consider
                        //  using trigger_yield() to raise a notification event instead
                        peer.request_handshake();
                        continue;
                    }
                }
            };

            let payload_len = payload.len();
            match session.encrypt(payload_len, buf) {
                TunnResult::WriteToNetwork(packet) => {
                    // Advance timers and append tx_bytes
                    {
                        let mut tun = peer.tunnel.lock();
                        tun.timer_tick_data_packet_sent();
                        tun.append_tx_bytes(payload_len);
                    }
                    self.send_packet(&peer, packet, udp4, udp6);
                }
                TunnResult::Err(e) => {
                    tracing::error!(message = "Encryption error",
                        error = ?e,
                        public_key = peer.public_key.1); // TODO: mask public key
                }
                _ => {
                    tracing::error!("Unexpected result from encrypt");
                }
            }
        }
    }

    fn wait_for_tun(&self, pfds: &mut Pfds<'_>) -> Result<ControlFlow<()>, Error> {
        poll_retry(pfds.as_mut_slice())?;

        // On waker signal sent, this breaks out of TUN waiting loop
        // causing the thread to re-evaluate its stop flag
        if !pfds.get_revents(PfdIndex::Waker).is_empty() {
            self.waker.ack();
            return Ok(ControlFlow::Break(()));
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
            self.waker.wait()?;
            return Ok(ControlFlow::Break(()));
        }

        Ok(ControlFlow::Continue(()))
    }

    fn read_tun_packet<'a>(
        &self,
        iface: &Arc<TunSocket>,
        buf: &'a mut [u8; MAX_PKT_SIZE],
        mtu: usize,
    ) -> IfaceReadResult<'a> {
        if mtu + WG_HEADER_OFFSET > MAX_PKT_SIZE {
            tracing::error!("Insufficient packet buffer size");
            return IfaceReadResult::Fatal(Error::InternalError(
                "Insufficient packet buffer size".to_owned(),
            ));
        }

        #[allow(clippy::indexing_slicing)]
        // guaranteed by the above check
        match iface.read(&mut buf[WG_HEADER_OFFSET..WG_HEADER_OFFSET + mtu]) {
            Ok(payload) => match Tunn::dst_address(payload) {
                None => IfaceReadResult::Skip,
                Some(dst_addr) => {
                    // TODO: Check if using ArcSwap can be used to fully remove read lock from the hot path and if it brings meaningful gain
                    let d = self.device.read();
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

    fn send_packet(
        &self,
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
                    if peer.shutdown_endpoint() {
                        self.device.read().notify_inbound();
                    }
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
}

/// Exhaustive list of outbound [`PollFd`]s
enum PfdIndex {
    Tun,
    Waker,
}

impl From<PfdIndex> for usize {
    fn from(value: PfdIndex) -> Self {
        value as usize
    }
}

/// Wrapper over a set of outbound [`PollFd`]s (TUN iface and waker)
type Pfds<'a> = waker::Pfds<'a, PfdIndex, 2>;

/// Create a set of outbound [`PollFd`]s ([`TunSocket`] and [`Waker`])
fn new_pfds<'a>(tun: &'a Arc<TunSocket>, waker: &'a Arc<Waker>) -> Pfds<'a> {
    let tun_pfd = PollFd::new(tun.as_fd(), PollFlags::POLLIN);
    let waker_pfd = PollFd::new(waker.wait_fd(), PollFlags::POLLIN);

    Pfds::new([
        tun_pfd,   // PfdIndex::Tun
        waker_pfd, // PfdIndex::Waker
    ])
}
