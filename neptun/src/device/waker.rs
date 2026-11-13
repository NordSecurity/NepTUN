use libc::{F_GETFL, F_SETFL, O_NONBLOCK};
use std::io::{self, PipeReader, PipeWriter, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::device::Error;

/// Wakes a thread waiting on its fd
///
/// Implemented with a pipe for portability (eventfd is not available on Darwin)
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

    /// Signals the thread
    ///
    /// If a signal is already pending, subsequent calls to this method do nothing
    /// (signal coalescing behavior)
    pub fn wake(&self) {
        if self.pending.swap(true, Ordering::AcqRel) {
            return;
        }

        loop {
            match (&self.writer).write(&[1u8]) {
                Ok(_) => return,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return, // waker's pipe is full, so the signal will still wake the waiting thread
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.pending.store(false, Ordering::Release);
                    tracing::error!(message = "Failed to send wake signal", error = ?e);
                    return;
                }
            }
        }
    }

    /// Acknowledges reception of a sent signal
    pub fn ack(&self) {
        let mut buf = [0u8; 8];
        loop {
            match (&self.reader).read(&mut buf) {
                Ok(0) => {
                    tracing::error!("Waker pipe closed");
                    break;
                }
                Ok(n) if n < buf.len() => break, // the pipe is drained at this point
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    tracing::error!(message = "Failed to drain the waker", error = ?e);
                    break;
                }
            }
        }

        self.pending.swap(false, Ordering::AcqRel);
    }

    /// Checks if a signal was sent and not yet acked
    pub fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Relaxed)
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

#[cfg(test)]
mod tests {
    use super::*;
    use nix::poll::{PollFd, PollFlags, PollTimeout};

    fn has_byte(waker: &Waker) -> bool {
        let mut pfds = [PollFd::new(waker.wait_fd(), PollFlags::POLLIN)];
        nix::poll::poll(&mut pfds, PollTimeout::ZERO).unwrap() == 1
    }

    #[test]
    fn wakes_are_coalesced_and_ack_clears_signal() {
        let waker = Waker::new().unwrap();
        waker.wake();
        waker.wake();
        assert!(waker.is_pending() && has_byte(&waker));
        waker.ack();
        assert!(!waker.is_pending() && !has_byte(&waker))
    }

    #[test]
    fn unconditional_ack_doesnt_swallow_subsequent_wake() {
        let waker = Waker::new().unwrap();
        waker.ack();
        waker.wake();
        assert!(waker.is_pending() && has_byte(&waker));
    }
}
