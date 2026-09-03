//! Waker used for data plane threads signalling.
//!
//! Implemented with a pipe for portability (eventfd is not available on Darwin).

use libc::{fcntl, F_GETFL, F_SETFL, O_NONBLOCK};
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
        // TODO: is Ordering::Relaxed appropriate here?
        self.pending.load(Ordering::Relaxed)
    }
}

// TODO: very similar to tun_... implementations
fn set_non_blocking(fd: RawFd) -> Result<(), Error> {
    match unsafe { fcntl(fd, F_GETFL) } {
        -1 => Err(Error::FCntl(io::Error::last_os_error())),
        flags => match unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } {
            -1 => Err(Error::FCntl(io::Error::last_os_error())),
            _ => Ok(()),
        },
    }
}
