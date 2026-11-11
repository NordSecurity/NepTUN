//! Test-only [`MakeExternalNeptun`] which records the sockets currently registered with it.

use std::collections::HashSet;
use std::os::fd::RawFd;
use std::sync::Arc;

use parking_lot::Mutex;

use super::{ExternalGuard, MakeExternalNeptun};

#[derive(Default)]
struct State {
    registered: HashSet<RawFd>,
    /// Sockets which were already closed by the time their guard was dropped
    closed_before_unregister: Vec<RawFd>,
}

#[derive(Default, Clone)]
pub(crate) struct RecordingProtect {
    state: Arc<Mutex<State>>,
}

impl RecordingProtect {
    pub(crate) fn registered(&self) -> HashSet<RawFd> {
        self.state.lock().registered.clone()
    }

    pub(crate) fn assert_unregistered_before_close(&self) {
        let closed = &self.state.lock().closed_before_unregister;
        assert!(
            closed.is_empty(),
            "sockets were closed before being unregistered: {:?}",
            closed
        );
    }
}

struct Unregister {
    fd: RawFd,
    state: Arc<Mutex<State>>,
}

impl Drop for Unregister {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        state.registered.remove(&self.fd);
        // Safe: F_GETFD only queries the descriptor flags
        if unsafe { libc::fcntl(self.fd, libc::F_GETFD) } == -1 {
            state.closed_before_unregister.push(self.fd);
        }
    }
}

impl MakeExternalNeptun for RecordingProtect {
    fn make_external(&self, socket: RawFd) -> ExternalGuard {
        // A stale entry for a closed socket whose fd number got reused would show up here
        assert!(
            self.state.lock().registered.insert(socket),
            "socket {} is already registered",
            socket
        );
        ExternalGuard::new(Unregister {
            fd: socket,
            state: self.state.clone(),
        })
    }
}
