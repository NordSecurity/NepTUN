use std::{
    io,
    ops::ControlFlow,
    os::fd::AsFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use nix::poll::PollFlags;
use parking_lot::Mutex;

use crate::{
    device::{
        data_poll::{self, DataPoll, Event},
        dev_lock::Lock,
        packet_workers::{Batch, Batcher, EncryptedPacket},
        waker::Waker,
        Device, Error, IfaceReadResult, Resume, MAX_PKT_SIZE, WG_HEADER_OFFSET,
    },
    noise::{errors::WireGuardError, NoSession, Tunn},
};

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

/// Packet encapsulation result
enum TxResult<'a> {
    Packet(&'a mut [u8]),
    Queued,
    NeedsHandshake,
    Err(WireGuardError),
}

impl From<NoSession> for TxResult<'_> {
    fn from(value: NoSession) -> Self {
        match value {
            NoSession::Queued => Self::Queued,
            NoSession::NeedsHandshake => Self::NeedsHandshake,
            NoSession::Err(e) => Self::Err(e),
        }
    }
}

pub(super) struct Outbound {
    device: Arc<Lock<Device>>,
    stop: Arc<AtomicBool>,
    waker: Arc<Waker>,
    batcher: Batcher<EncryptedPacket>,
}

impl Outbound {
    pub fn new(
        device: Arc<Lock<Device>>,
        stop: Arc<AtomicBool>,
        waker: Arc<Waker>,
        batcher: Batcher<EncryptedPacket>,
    ) -> Self {
        Self {
            device,
            stop,
            waker,
            batcher,
        }
    }

    pub fn run(mut self) {
        if let Err(e) = self.main_loop() {
            tracing::error!(message = "Critical outbound thread failure, closing device", error = ?e);
            self.device.read().trigger_exit();
        }
    }

    fn main_loop(&mut self) -> Result<(), Error> {
        let mut buf = [0u8; MAX_PKT_SIZE];

        while !self.stop.load(Ordering::Relaxed) {
            if let Resume::OnWake = self.inner_loop(&mut buf)? {
                // the device read guard is dropped at this point, so parking here doesn't block writers
                data_poll::park_on(&self.waker)?;
            }
        }

        Ok(())
    }

    fn inner_loop(&mut self, buf: &mut [u8; MAX_PKT_SIZE]) -> Result<Resume, Error> {
        // Inner loop runs under the device read lock guard
        let device = self.device.read();

        let Some(view) = OutboundView::new(&device, &self.waker) else {
            tracing::debug!(message = "Not connected, parked until sockets are opened.");
            return Ok(Resume::OnWake);
        };

        let mut poll = DataPoll::new(&self.waker, device.iface.as_fd());

        loop {
            // Park the thread while waiting for the packets to arrive
            if let Event::Woken = poll.wait()? {
                return Ok(Resume::Now);
            }

            if self
                .batcher
                .with_batch(|batch| view.process_ready(&poll, buf, batch))?
                .is_break()
            {
                return Ok(Resume::Now);
            }
        }
    }
}

/// Borrowed view of the device with UDP sockets open
struct OutboundView<'a> {
    device: &'a Device,
    waker: &'a Waker,
}

impl<'a> OutboundView<'a> {
    fn new(device: &'a Device, waker: &'a Waker) -> Option<Self> {
        if device.udp4.is_none() || device.udp6.is_none() {
            return None;
        }

        Some(Self { device, waker })
    }

    fn process_ready(
        &self,
        poll: &DataPoll<'_, ()>,
        buf: &mut [u8; MAX_PKT_SIZE],
        batch: &mut Batch<'_, EncryptedPacket>,
    ) -> Result<ControlFlow<()>, Error> {
        for (_, revents) in poll.ready() {
            if revents.contains(PollFlags::POLLNVAL) {
                return Err(Error::InternalError(
                    "Polled an invalid TUN fd (fd not open)".to_owned(),
                ));
            }

            if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP) {
                return Err(Error::InternalError(format!(
                    "TUN iface invalidated: {revents:?}"
                )));
            }
        }

        self.drain_tun(buf, batch)
    }

    fn drain_tun(
        &self,
        buf: &mut [u8; MAX_PKT_SIZE],
        batch: &mut Batch<'_, EncryptedPacket>,
    ) -> Result<ControlFlow<()>, Error> {
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
                if !callback(
                    peer.public_key.as_bytes(),
                    payload,
                    &mut self.device.iface.as_ref(),
                ) {
                    continue;
                }
            }

            let res = encapsulate(&peer.tunnel, payload.len(), buf);

            match res {
                TxResult::Packet(packet) => {
                    if let Some(packet) = EncryptedPacket::new(packet, peer) {
                        batch.push(packet)?;
                    }
                }
                TxResult::Queued => {}
                TxResult::NeedsHandshake => {
                    if peer.request_handshake() {
                        self.device.notify_control();
                    }
                }
                TxResult::Err(e) => {
                    tracing::error!(message = "Encapsulate error",
                        error = ?e,
                        peer = %peer.public_key);
                }
            }
        }
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
            Ok([]) => IfaceReadResult::Exhausted,
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
}

fn encapsulate<'a>(tunnel: &Mutex<Tunn>, src_len: usize, dst: &'a mut [u8]) -> TxResult<'a> {
    let tx = match tunnel.lock().begin_tx(src_len, dst) {
        Ok(tx) => tx,
        Err(no_session) => return no_session.into(),
    };

    // Tunnel lock is released at this point
    match tx.seal(dst) {
        Ok(sealed) => TxResult::Packet(tunnel.lock().commit_tx(sealed)),
        Err(e) => TxResult::Err(e),
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
