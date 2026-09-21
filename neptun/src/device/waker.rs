//! Waker used for data plane threads signalling.
//!
//! Implemented with a pipe for portability (eventfd is not available on Darwin).

use libc::{F_GETFL, F_SETFL, O_NONBLOCK};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout};
use std::io::{self, PipeReader, PipeWriter, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::device::Error;

pub struct Waker {
    reader: PipeReader,
    writer: PipeWriter,
    pending: AtomicBool,
}

impl Waker {
    pub fn new() -> Result<Self, Error> {
        let (reader, writer) = io::pipe()?;
        set_non_blocking(reader.as_raw_fd())?;
        set_non_blocking(writer.as_raw_fd())?;
        Ok(Self {
            reader,
            writer,
            pending: AtomicBool::new(false),
        })
    }

    pub fn wait_fd(&self) -> BorrowedFd<'_> {
        self.reader.as_fd()
    }

    // TODO: fix error handling
    pub fn wake(&self) {
        if self.pending.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = (&self.writer).write(&[1u8]);
    }

    // TODO: fix error handling
    // Acknowledges reception of a sent signal
    pub fn ack(&self) {
        self.pending.store(false, Ordering::Release);

        let mut buf = [0u8; 1];
        let _ = (&self.reader).read(&mut buf);
    }

    // Checks if the waker signal was already sent and not yet read
    pub fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Relaxed)
    }

    /// Blocks until the waker receives a signal.
    pub fn wait(&self) -> Result<(), Error> {
        let mut pfds = [PollFd::new(self.wait_fd(), PollFlags::POLLIN)];
        poll_retry(&mut pfds)?;
        self.ack();
        Ok(())
    }
}

fn set_non_blocking(fd: RawFd) -> Result<(), Error> {
    match unsafe { libc::fcntl(fd, F_GETFL) } {
        -1 => Err(Error::FCntl(io::Error::last_os_error())),
        flags => match unsafe { libc::fcntl(fd, F_SETFL, flags | O_NONBLOCK) } {
            -1 => Err(Error::FCntl(io::Error::last_os_error())),
            _ => Ok(()),
        },
    }
}

/// Run [`nix::poll::poll`] in a loop, retrying on an interrupted syscall ([`Errno::EINTR`])
pub fn poll_retry(pfds: &mut [PollFd<'_>]) -> Result<(), Error> {
    loop {
        match nix::poll::poll(pfds, PollTimeout::NONE) {
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(Error::Poll(e.into())),
        }
    }
}
