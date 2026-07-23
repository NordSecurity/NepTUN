use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};

use super::wake::{Wake, CMD_RELOAD, CMD_SHUTDOWN};
use super::{
    encapsulate_and_send, read_packet, CheckedMtu, Device, IfaceReadResult, MAX_ITR, MAX_PKT_SIZE,
};
use crate::device::tun::TunSocket;
use crate::device::Lock;

pub(super) struct Outbound {
    device: Arc<Lock<Device>>,
    iface: Arc<TunSocket>,
    wake: Arc<Wake>,
    dst_buf: [u8; MAX_PKT_SIZE],
}

impl Outbound {
    pub(super) fn new(device: Arc<Lock<Device>>, iface: Arc<TunSocket>, wake: Arc<Wake>) -> Self {
        Self {
            device,
            iface,
            wake,
            dst_buf: [0u8; MAX_PKT_SIZE],
        }
    }

    pub(super) fn run(mut self) {
        let poll = match Poll::new() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("OUT poll create failed: {e}");
                return;
            }
        };
        if let Err(e) = poll.add(self.iface.as_raw_fd(), Src::Tun) {
            tracing::error!("OUT add tun failed: {e}");
            return;
        }
        if let Err(e) = poll.add(self.wake.fd(), Src::Wake) {
            tracing::error!("OUT add wake failed: {e}");
            return;
        }

        let mut evbuf = vec![nix_epoll_event(); 8];
        let mut ready = Vec::with_capacity(8);

        loop {
            if poll.wait(&mut evbuf, &mut ready).is_err() {
                continue;
            }
            for src in ready.drain(..) {
                match src {
                    Src::Tun => {
                        if self.drain_tun().is_break() {
                            return;
                        }
                    }
                    Src::Wake => match self.wake.take() {
                        CMD_SHUTDOWN => return,
                        CMD_RELOAD => {
                            // reload = respawn; treat as shutdown of this thread
                            return;
                        }
                        _ => {}
                    },
                }
            }
        }
    }

    // Drain the tun until WouldBlock or MAX_ITR. One Device read-guard per batch.
    fn drain_tun(&mut self) -> std::ops::ControlFlow<()> {
        let d = self.device.read();

        let mtu = match CheckedMtu::new(d.mtu.load(Ordering::Relaxed)) {
            Some(m) => m,
            None => return std::ops::ControlFlow::Break(()),
        };
        let (udp4, udp6) = match (d.udp4.as_ref(), d.udp6.as_ref()) {
            (Some(a), Some(b)) => (a.clone(), b.clone()),
            _ => return std::ops::ControlFlow::Continue(()),
        };

        for _ in 0..MAX_ITR {
            match read_packet(&self.iface, &mut self.dst_buf, &mtu, &d.peers_by_ip) {
                IfaceReadResult::Exhausted => break,
                IfaceReadResult::Fatal => return std::ops::ControlFlow::Break(()),
                IfaceReadResult::Skip => continue,
                IfaceReadResult::Packet { payload, peer } => {
                    let len = payload.len();

                    if let Some(cb) = &d.config.firewall_process_outbound_callback {
                        if !cb(&peer.public_key.0, payload, &mut self.iface.as_ref()) {
                            continue;
                        }
                    }

                    if !peer.has_session() {
                        peer.set_want_handshake();
                    }

                    encapsulate_and_send(&peer, &mut self.dst_buf[..], len, &udp4, &udp6);
                }
            }
        }
        std::ops::ControlFlow::Continue(())
    }
}

fn nix_epoll_event() -> EpollEvent {
    EpollEvent::empty()
}

/// Readiness source tag for the OUT thread's epoll set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Src {
    Tun,
    Wake,
}

impl Src {
    fn to_u64(self) -> u64 {
        match self {
            Src::Tun => 1,
            Src::Wake => 2,
        }
    }
    fn from_u64(v: u64) -> Option<Self> {
        match v {
            1 => Some(Src::Tun),
            2 => Some(Src::Wake),
            _ => None,
        }
    }
}

struct Poll {
    epoll: Epoll,
}

impl Poll {
    fn new() -> io::Result<Self> {
        Ok(Self {
            epoll: Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?,
        })
    }
    fn add(&self, fd: RawFd, src: Src) -> io::Result<()> {
        let ev = EpollEvent::new(EpollFlags::EPOLLIN, src.to_u64());
        self.epoll.add(unsafe { borrow(fd) }, ev)?;
        Ok(())
    }
    fn wait(&self, buf: &mut [EpollEvent], out: &mut Vec<Src>) -> io::Result<usize> {
        out.clear();
        let n = match self.epoll.wait(buf, EpollTimeout::NONE) {
            Ok(n) => n,
            Err(nix::errno::Errno::EINTR) => 0,
            Err(e) => return Err(e.into()),
        };
        #[allow(clippy::indexing_slicing)]
        for ev in &buf[..n] {
            if let Some(src) = Src::from_u64(ev.data()) {
                out.push(src);
            }
        }
        Ok(n)
    }
}

unsafe fn borrow(fd: RawFd) -> BorrowedFd<'static> {
    BorrowedFd::borrow_raw(fd)
}
