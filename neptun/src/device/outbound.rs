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

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
use std::thread::{self, JoinHandle};

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
use dispatch2::{DispatchGroup, DispatchQueue, DispatchQueueAttr, DispatchRetained, DispatchTime};

use crate::{
    device::{
        dev_lock::Lock, peer::Peer, tun::TunSocket, waker::Waker, DataPlane, Device, Error,
        IfaceReadResult, MAX_PKT_SIZE, WG_HEADER_OFFSET,
    },
    noise::{Tunn, TunnResult},
};

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
type OutboundThread = JoinHandle<()>;
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
type OutboundThread = DispatchRetained<DispatchGroup>;

const TUN: usize = 0;
const WAKE: usize = 1;
const ERR_FLAGS: PollFlags = PollFlags::POLLERR
    .union(PollFlags::POLLHUP)
    .union(PollFlags::POLLNVAL);

pub(super) struct Outbound {
    thread: OutboundThread,
}

impl Outbound {
    pub fn start(
        device: Arc<Lock<Device>>,
        stop: Arc<AtomicBool>,
        waker: Arc<Waker>,
    ) -> Result<Outbound, Error> {
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        let thread = {
            let group = DispatchGroup::new();
            let queue = DispatchQueue::new("neptun-out", DispatchQueueAttr::SERIAL);
            // TODO: ensure P-core preference for execution
            group.exec_async(&queue, move || Outbound::data_thread(device, stop, waker));
            group
        };

        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        let thread = {
            thread::Builder::new()
                .name("neptun-out".to_string())
                .spawn(move || Outbound::data_thread(device, stop, waker))?
        };

        Ok(Self { thread })
    }

    fn data_thread(device: Arc<Lock<Device>>, stop: Arc<AtomicBool>, waker: Arc<Waker>) {
        if let Err(e) = Self::run(device.clone(), stop, waker) {
            DataPlane::close_device(&device, e);
        }
    }

    fn run(
        device: Arc<Lock<Device>>,
        stop: Arc<AtomicBool>,
        waker: Arc<Waker>,
    ) -> Result<(), Error> {
        let mut buf = [0u8; MAX_PKT_SIZE];

        while !stop.load(Ordering::Relaxed) {
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

            let (Some(udp4), Some(udp6)) = (udp4, udp6) else {
                tracing::debug!(message = "Not connected, parked until sockets are opened.");
                poll_waker(&waker)?;
                continue;
            };

            let mut pfds = [
                PollFd::new(iface.as_fd(), PollFlags::POLLIN),
                PollFd::new(waker.wait_fd(), PollFlags::POLLIN),
            ];

            loop {
                DataPlane::poll(&mut pfds)?;

                // TODO: any better way instead of array and indexing? maybe a struct?
                let wake_revents = pfds[WAKE].revents().unwrap_or(PollFlags::empty());
                let tun_revents = pfds[TUN].revents().unwrap_or(PollFlags::empty());

                if !wake_revents.is_empty() {
                    waker.ack();
                    break;
                }

                if tun_revents.intersects(ERR_FLAGS) {
                    // The current TUN iface is gone, park until a new iface config is signalled
                    tracing::warn!(message = "TUN iface invalidated", revents = ?tun_revents);
                    // TODO: what if this never happens? would setting a timeout increase robustness?
                    poll_waker(&waker)?;
                    break;
                }

                // TODO: what is the exact meaning of this?
                if !tun_revents.contains(PollFlags::POLLIN) {
                    continue;
                }

                if drain_tun(
                    &device,
                    &iface,
                    &mtu,
                    &mut buf,
                    &fw_callback,
                    &udp4,
                    &udp6,
                    &waker,
                )?
                .is_break()
                {
                    break;
                }
            }
        }

        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
    pub(crate) fn join(self) {
        if let Err(e) = self.thread.join() {
            tracing::error!(message = "Unable to gracefully close outbound thread.", error = ?e);
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    pub(crate) fn join(self) {
        let _ = self.thread.wait(DispatchTime::FOREVER);
    }
}

fn drain_tun(
    device: &Arc<Lock<Device>>,
    iface: &Arc<TunSocket>,
    mtu: &Arc<AtomicUsize>,
    buf: &mut [u8; MAX_PKT_SIZE],
    fw_callback: &Option<
        Arc<dyn Fn(&[u8; 32], &mut [u8], &mut dyn std::io::Write) -> bool + Send + Sync>,
    >,
    udp4: &Arc<Socket>,
    udp6: &Arc<Socket>,
    waker: &Arc<Waker>,
) -> Result<ControlFlow<()>, Error> {
    let mtu = mtu.load(Ordering::Relaxed);

    loop {
        if waker.is_pending() {
            waker.ack();
            return Ok(ControlFlow::Break(()));
        }

        let (payload, peer) = match read_tun_packet(iface, buf, mtu, device) {
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
                send_packet(&peer, packet, udp4, udp6);
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

fn read_tun_packet<'a>(
    iface: &Arc<TunSocket>,
    buf: &'a mut [u8; MAX_PKT_SIZE],
    mtu: usize,
    device: &Arc<Lock<Device>>,
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

/// Blocks until the waker receives a signal.
fn poll_waker(waker: &Waker) -> Result<(), Error> {
    let mut pfds = [PollFd::new(waker.wait_fd(), PollFlags::POLLIN)];
    DataPlane::poll(&mut pfds)?;
    waker.ack();
    Ok(())
}
