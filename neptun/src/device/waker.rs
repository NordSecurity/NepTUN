//! Waker used for data plane threads signalling.
//!
//! Implemented with a pipe for portability (eventfd is not available on Darwin).

use libc::{F_GETFL, F_SETFL, O_NONBLOCK};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout};
use std::io::{self, PipeReader, PipeWriter, Read, Write};
use std::marker::PhantomData;
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

    pub fn wake(&self) {
        if self.pending.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = (&self.writer).write(&[1u8]);
    }

    pub fn ack(&self) {
        self.pending.store(false, Ordering::Release);

        let mut buf = [0u8; 1];
        let _ = (&self.reader).read(&mut buf);
    }

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

// TODO: very similar to tun_... implementations
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

/// Generic wrapper over a set of [`PollFd`]s used by IN/OUT data plane threads
pub(crate) struct Pfds<'a, Idx, const N: usize> {
    pfds: [PollFd<'a>; N],
    _index: PhantomData<Idx>,
}

impl<'a, Idx: Into<usize>, const N: usize> Pfds<'a, Idx, N> {
    /// Create a set of [`PollFd`]s
    pub(crate) fn new(pfds: [PollFd<'a>; N]) -> Self {
        Self {
            pfds,
            _index: PhantomData,
        }
    }

    /// Reads return events from the [`PollFd`] set
    pub(crate) fn get_revents(&self, idx: Idx) -> PollFlags {
        self.pfds[idx.into()].revents().unwrap_or(PollFlags::empty())
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [PollFd<'a>] {
        &mut self.pfds
    }
}
