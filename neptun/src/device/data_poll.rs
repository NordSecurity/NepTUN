use std::os::fd::BorrowedFd;

use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout},
};

use crate::device::{waker::Waker, Error};

/// Reason the wait ended
pub(super) enum Event {
    /// The waker was signaled
    Woken,
    /// At least one polled fd is ready
    Ready,
}

/// `poll(2)` over a fixed set of fds, interruptible by a [`Waker`]
pub(super) struct DataPoll<'a, D> {
    /// Interrupts the wait
    waker: &'a Waker,
    /// `poll(2)` input/output; `pfds[0]` is the `waker`'s fd, `pfds[i + 1]` corresponds to `fd_data[i]`
    pfds: Vec<PollFd<'a>>,
    /// Data associated with each polled fd
    fd_data: Vec<D>,
}

impl<'a, D> DataPoll<'a, D> {
    /// Polls each fd with its associated data
    pub(super) fn with_fd_data(
        waker: &'a Waker,
        fds: impl IntoIterator<Item = (BorrowedFd<'a>, D)>,
    ) -> Self {
        let fds = fds.into_iter();
        let (len, _) = fds.size_hint();

        let mut pfds = Vec::with_capacity(len + 1);
        let mut fd_data = Vec::with_capacity(len);

        pfds.push(PollFd::new(waker.wait_fd(), PollFlags::POLLIN));
        for (fd, data) in fds {
            pfds.push(PollFd::new(fd, PollFlags::POLLIN));
            fd_data.push(data);
        }

        Self {
            waker,
            pfds,
            fd_data,
        }
    }

    /// Blocks until the waker or a polled fd is ready; a wake is acked and takes precedence over ready fds
    ///
    /// Fails on a `poll(2)` error or an invalid waker fd
    pub(super) fn wait(&mut self) -> Result<Event, Error> {
        poll_retry(&mut self.pfds)?;

        let revents = self
            .pfds
            .first()
            .and_then(PollFd::revents)
            .unwrap_or(PollFlags::empty());

        if revents.intersects(PollFlags::POLLNVAL | PollFlags::POLLERR | PollFlags::POLLHUP) {
            return Err(Error::InternalError(format!(
                "Waker's fd invalidated: {revents:?}"
            )));
        }

        if revents.contains(PollFlags::POLLIN) {
            self.waker.ack();
            return Ok(Event::Woken);
        }

        Ok(Event::Ready)
    }

    /// Data and `revents` of each polled fd reported as ready by the last wait
    pub(super) fn ready(&self) -> impl Iterator<Item = (&D, PollFlags)> + '_ {
        self.pfds
            .iter()
            .skip(1) // skip waker's PollFd
            .zip(&self.fd_data)
            .filter_map(|(pfd, data)| {
                let revents = pfd.revents().unwrap_or(PollFlags::empty());
                (!revents.is_empty()).then_some((data, revents))
            })
    }
}

impl<'a> DataPoll<'a, ()> {
    /// Polls a single fd
    pub(super) fn new(waker: &'a Waker, fd: BorrowedFd<'a>) -> Self {
        Self::with_fd_data(waker, std::iter::once((fd, ())))
    }
}

/// Blocks until a signal is pending, then acks it
pub(super) fn park_on(waker: &Waker) -> Result<(), Error> {
    DataPoll::<()>::with_fd_data(waker, std::iter::empty()).wait()?;
    Ok(())
}

/// Run [`nix::poll::poll`] in a loop, retrying on an interrupted syscall ([`Errno::EINTR`])
fn poll_retry(pfds: &mut [PollFd<'_>]) -> Result<(), Error> {
    loop {
        match nix::poll::poll(pfds, PollTimeout::NONE) {
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(Error::Poll(e.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::{fd::AsFd, unix::net::UnixDatagram};

    #[test]
    fn signaled_waker_is_reported_and_acked() {
        let waker = Waker::new().unwrap();
        waker.wake();

        let mut poll = DataPoll::<()>::with_fd_data(&waker, std::iter::empty());
        assert!(matches!(poll.wait().unwrap(), Event::Woken));
        assert!(!waker.is_pending());
    }

    #[test]
    fn ready_fd_is_reported_with_its_data() {
        let waker = Waker::new().unwrap();
        let (tx, rx) = UnixDatagram::pair().unwrap();
        let (_idle_tx, idle) = UnixDatagram::pair().unwrap();
        tx.send(b"x").unwrap();

        let mut poll =
            DataPoll::with_fd_data(&waker, vec![(idle.as_fd(), "idle"), (rx.as_fd(), "rx")]);
        assert!(matches!(poll.wait().unwrap(), Event::Ready));

        let ready: Vec<_> = poll
            .ready()
            .map(|(data, revents)| (*data, revents.contains(PollFlags::POLLIN)))
            .collect();
        assert_eq!(ready, vec![("rx", true)]);
    }

    #[test]
    fn waker_takes_precedence_over_ready_fds() {
        let waker = Waker::new().unwrap();
        let (tx, rx) = UnixDatagram::pair().unwrap();
        tx.send(b"x").unwrap();
        waker.wake();

        let mut poll = DataPoll::new(&waker, rx.as_fd());
        assert!(matches!(poll.wait().unwrap(), Event::Woken));
    }

    #[test]
    fn park_on_returns_and_acks_after_wake() {
        let waker = Waker::new().unwrap();
        waker.wake();

        park_on(&waker).unwrap();
        assert!(!waker.is_pending());
    }
}
