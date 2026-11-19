// Copyright (c) 2026 Nord Security. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// The minimum time between two attempts to make a connected socket for a
/// peer. The setup of a socket is expensive (the embedding application binds
/// it to an interface), and without a limit, a socket that cannot be made or
/// that closes again would be made for each packet on the listen socket.
const MIN_CONNECT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Default)]
pub(crate) struct ConnWatch {
    on_listen_socket: AtomicBool,
    on_connected_socket: AtomicBool,
    last_connect_attempt: Mutex<Option<Instant>>,
}

impl ConnWatch {
    /// An authenticated packet came from the peer on a listen socket, while
    /// the peer had a connected socket
    pub(crate) fn on_listen_receive(&self) {
        if !self.on_listen_socket.load(Relaxed) {
            self.on_listen_socket.store(true, Relaxed);
        }
    }

    /// An authenticated packet came from the peer on its connected socket
    pub(crate) fn on_conn_receive(&self) {
        if !self.on_connected_socket.load(Relaxed) {
            self.on_connected_socket.store(true, Relaxed);
        }
    }

    /// Returns `true` when an attempt to make a connected socket is permitted
    /// now, and records the attempt.
    pub(crate) fn connect_permitted(&self) -> bool {
        let mut last = self.last_connect_attempt.lock();
        let now = Instant::now();
        if last.is_some_and(|at| now.duration_since(at) < MIN_CONNECT_INTERVAL) {
            return false;
        }
        *last = Some(now);
        true
    }

    /// Call this one time in each timer period. Returns `true` when the
    /// connected socket must be closed: in the period, the packets of the
    /// peer came on a listen socket and none came on the connected socket.
    pub(crate) fn is_stale(&self) -> bool {
        let on_listen_socket = self.on_listen_socket.swap(false, Relaxed);
        let on_connected_socket = self.on_connected_socket.swap(false, Relaxed);
        on_listen_socket && !on_connected_socket
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_when_the_peer_uses_only_the_listen_socket() {
        let watch = ConnWatch::default();
        // No packet at all, for example traffic that only sends: not stale
        assert!(!watch.is_stale());
        // The usual state: packets on the connected socket
        watch.on_conn_receive();
        assert!(!watch.is_stale());
        // Packets on the two sockets, for example directly after the connection
        watch.on_listen_receive();
        watch.on_conn_receive();
        assert!(!watch.is_stale());
        // Packets on the listen socket only
        watch.on_listen_receive();
        assert!(watch.is_stale());
        // Each period starts again
        assert!(!watch.is_stale());
    }

    #[test]
    fn connect_attempts_have_a_minimum_interval() {
        let watch = ConnWatch::default();
        assert!(watch.connect_permitted());
        assert!(!watch.connect_permitted());
        *watch.last_connect_attempt.lock() = Instant::now().checked_sub(MIN_CONNECT_INTERVAL);
        assert!(watch.connect_permitted());
    }
}
