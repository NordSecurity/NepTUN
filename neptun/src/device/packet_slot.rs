//! Per-packet synchronization point for preserving per-peer packet send order after parallel
//! encryption handled by workers.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;

use super::MAX_PKT_SIZE;

pub(super) enum SlotState {
    Unencrypted,
    Encrypted {
        buffer: [u8; MAX_PKT_SIZE],
        len: usize,
    },
    Failed,
}

pub(super) struct PacketSlot {
    state: Mutex<SlotState>,
}

impl PacketSlot {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(SlotState::Unencrypted),
        }
    }

    pub(super) fn set_state(&self, state: SlotState) {
        *self.state.lock() = state;
    }

    fn is_unencrypted(&self) -> bool {
        matches!(&*self.state.lock(), SlotState::Unencrypted)
    }

    fn is_failed(&self) -> bool {
        matches!(&*self.state.lock(), SlotState::Failed)
    }

    pub(super) fn with_state<R>(&self, f: impl FnOnce(&SlotState) -> R) -> R {
        f(&self.state.lock())
    }
}

/// The per-peer ordering queue
///
/// Implemented with a SPSC crossbeam_channel, leveraging on the FIFO ordering maintained between a
/// single sender and receiver.
pub(super) struct PeerTxQueue {
    sender: Sender<Arc<PacketSlot>>,
    receiver: Receiver<Arc<PacketSlot>>,
    // The current queue head is cached after dequeue as crossbeam_channel does not allow to simply
    // peek a next item to be received
    peeked: Mutex<Option<Arc<PacketSlot>>>,
    // Ensures that at most one worker is draining this queue at a time
    committing: AtomicBool,
}

impl PeerTxQueue {
    pub(super) fn new() -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();
        Self {
            sender,
            receiver,
            peeked: Mutex::new(None),
            committing: AtomicBool::new(false),
        }
    }

    pub(super) fn push(&self, slot: Arc<PacketSlot>) {
        let _ = self.sender.send(slot);
    }

    fn peek(&self) -> Option<Arc<PacketSlot>> {
        let mut peeked = self.peeked.lock();
        if peeked.is_none() {
            *peeked = self.receiver.try_recv().ok();
        }
        peeked.clone()
    }

    fn drop_peeked(&self) {
        *self.peeked.lock() = None;
    }

    fn try_acquire_committer(&self) -> bool {
        self.committing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    fn release_committer(&self) {
        self.committing.store(false, Ordering::Release);
    }

    /// Drains each packet from the peer's queue for processing until it reaches an `Unencrypted`
    /// slot.
    ///
    /// A queue can be drained by a single worker at a time (no-op if another worker is draining a
    /// queue already, so it is safe to call from any worker as soon as it finished encrypting a
    /// slot for this peer).
    pub(super) fn drain_ready(&self, mut on_ready: impl FnMut(&PacketSlot)) {
        if !self.try_acquire_committer() {
            return;
        }

        loop {
            while let Some(slot) = self.peek() {
                if slot.is_unencrypted() {
                    break;
                }
                self.drop_peeked();
                on_ready(&slot);
            }

            self.release_committer();

            // Another worker that finished encrypting at this moment may have lost the race to
            // reclaim the committer role that has just been released.
            //
            // A single re-check after releasing is made to ensure this newly completed packet is
            // never missed - if the queue head is now ready, either the current thread will
            // reclaim the committer role and will keep draining, or another thread has already
            // acquired the committer role and will proceed with queue draining.
            match self.peek() {
                Some(slot) if !slot.is_unencrypted() && self.try_acquire_committer() => continue,
                _ => break,
            }
        }
    }

    /// Pops abandoned (`Failed`) slots from the head of the queue without touching any sockets,
    /// stopping at the first slot that is `Encrypted` (which must be sent by a socket-holding
    /// committer via `drain_ready`) or `Unencrypted` (which a worker will eventually resolve).
    ///
    /// Intended for callers that marked slots `Failed` outside a worker context and want to
    /// release the `Arc<PacketSlot>` refs from the queue immediately (without waiting for the next
    /// successful `drain_ready` call for this peer).
    ///
    pub(super) fn drain_failed_head(&self) {
        if !self.try_acquire_committer() {
            return;
        }

        while let Some(slot) = self.peek() {
            if !slot.is_failed() {
                break;
            }
            self.drop_peeked();
        }

        self.release_committer();
    }
}
