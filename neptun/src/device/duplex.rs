//! Data plane single thread: one loop handles traffic in both directions
//!
//! See ['DataPlaneLayout::Single`](super::DataPlaneLayout::Single)

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use nix::poll::PollFlags;

use crate::device::{
    dev_lock::Lock,
    inbound::{InboundView, PollSet},
    outbound::{check_tun_revents, OutboundView},
    waker::{poll_retry, Resume, Waker},
    Device, Error, MAX_PKT_SIZE,
};

pub(super) struct Duplex {
    device: Arc<Lock<Device>>,
    stop: Arc<AtomicBool>,
    waker: Arc<Waker>,
}

impl Duplex {
    pub fn new(device: Arc<Lock<Device>>, stop: Arc<AtomicBool>, waker: Arc<Waker>) -> Self {
        Self {
            device,
            stop,
            waker,
        }
    }

    pub fn run(&self) {
        if let Err(e) = self.run_thread_main_loop() {
            tracing::error!(message = "Critical data plane thread failure, closing device", error = ?e);
            self.device.read().trigger_exit();
        }
    }

    pub fn run_thread_main_loop(&self) -> Result<(), Error> {
        let mut rcvbuf = [0u8; MAX_PKT_SIZE];
        let mut dstbuf = [0u8; MAX_PKT_SIZE];

        while !self.stop.load(Ordering::Relaxed) {
            if let Resume::OnWake = self.run_inner_loop(&mut rcvbuf, &mut dstbuf)? {
                self.waker.wait()?;
            }
        }

        Ok(())
    }

    fn run_inner_loop(
        &self,
        rcvbuf: &mut [u8; MAX_PKT_SIZE],
        dstbuf: &mut [u8; MAX_PKT_SIZE],
    ) -> Result<Resume, Error> {
        let device = self.device.read();

        let inbound = match InboundView::new(&device, &self.waker) {
            Ok(v) => v,
            Err(e) => {
                e.log();
                return Ok(Resume::OnWake);
            }
        };

        // Both views need the same sockets, so this fails only if the inbound one did
        let Some(outbound) = OutboundView::new(&device, &self.waker) else {
            return Ok(Resume::OnWake);
        };

        let mut poll_set = PollSet::with_tun(&inbound, &device.iface);

        // Each drain stops after MAX_DRAIN_PACKETS, so that neither direction starves the other
        loop {
            poll_retry(poll_set.as_mut_slice())?;

            if poll_set.woken() {
                self.waker.ack();
                return Ok(Resume::Now);
            }

            if inbound.process_ready(&poll_set, rcvbuf, dstbuf)?.is_break() {
                return Ok(Resume::Now);
            }

            let tun_revents = poll_set.tun_revents();
            check_tun_revents(tun_revents)?;

            // Inbound drain is done at this point, its receive buffer is reused
            if tun_revents.contains(PollFlags::POLLIN) && outbound.drain_tun(rcvbuf)?.is_break() {
                return Ok(Resume::Now);
            }
        }
    }
}
