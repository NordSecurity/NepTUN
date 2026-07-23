use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU8, Ordering};

use nix::sys::eventfd::{EfdFlags, EventFd};

pub const CMD_NONE: u8 = 0;
pub const CMD_SHUTDOWN: u8 = 1;
pub const CMD_RELOAD: u8 = 2;
pub const CMD_REBIND_UDP: u8 = 3;

pub struct Wake {
    efd: EventFd,
    cmd: AtomicU8,
}

impl Wake {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            efd: EventFd::from_flags(EfdFlags::EFD_NONBLOCK | EfdFlags::EFD_CLOEXEC)?,
            cmd: AtomicU8::new(CMD_NONE),
        })
    }

    pub fn fd(&self) -> RawFd {
        self.efd.as_raw_fd()
    }

    pub fn signal(&self, cmd: u8) {
        self.cmd.store(cmd, Ordering::Release);
        let _ = self.efd.write(1);
    }

    // Called after epoll reports Src::Wake. Drains the counter and returns the
    // pending command.
    pub fn take(&self) -> u8 {
        let _ = self.efd.read();
        self.cmd.swap(CMD_NONE, Ordering::AcqRel)
    }

    pub fn signal_poke(&self) {
        let _ = self.efd.write(1);
    }
}
