//! Per-packet synchronization point for preserving per-peer packet send/receive order after
//! parallel encryption/decryption handled by workers.
//!
//! Each [`PacketSlot`] owns an inline packet buffer. A worker that picks up a staged packet
//! decrypts/encrypts it *in place* inside the slot's own buffer and then marks the slot
//! [`SlotState::Ready`] (carrying only lightweight metadata such as the packet length) or
//! [`SlotState::Failed`]. The peer's committer later drains ready slots in queue order and
//! reads the finished packet straight out of the slot buffer, so no packet payload is ever
//! copied between the worker and the committer.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;

use super::MAX_PKT_SIZE;

/// The processing state of a slot.
pub(super) enum SlotState<M> {
    Pending,
    Ready(M),
    Failed,
}

/// A single ordering slot owning the packet buffer that a worker fills in place.
struct SlotInner<M> {
    state: SlotState<M>,
    buffer: [u8; MAX_PKT_SIZE],
}

pub(super) struct PacketSlot<M> {
    inner: Mutex<SlotInner<M>>,
}

impl<M> PacketSlot<M> {
    pub(super) fn new() -> Self {
        Self {
            inner: Mutex::new(SlotInner {
                state: SlotState::Pending,
                buffer: [0u8; MAX_PKT_SIZE],
            }),
        }
    }

    /// Copies `src` into the front of this slot's buffer, leaving the slot `Pending`.
    pub(super) fn stage(&self, src: &[u8]) -> bool {
        let mut inner = self.inner.lock();
        match inner.buffer.get_mut(..src.len()) {
            Some(dst) => {
                dst.copy_from_slice(src);
                true
            }
            None => false,
        }
    }

    /// Runs `f` against this slot's buffer, giving the worker mutable access to perform
    /// in-place encryption/decryption. The slot state is left untouched; the worker must
    /// call [`PacketSlot::finish`] afterwards to publish the result.
    pub(super) fn with_buffer_mut<R>(&self, f: impl FnOnce(&mut [u8; MAX_PKT_SIZE]) -> R) -> R {
        let mut inner = self.inner.lock();
        f(&mut inner.buffer)
    }

    /// Publishes the outcome of processing this slot: `Ready(meta)` on success or `Failed`.
    pub(super) fn finish(&self, result: Result<M, ()>) {
        let mut inner = self.inner.lock();
        inner.state = match result {
            Ok(meta) => SlotState::Ready(meta),
            Err(()) => SlotState::Failed,
        };
    }

    /// Marks this slot `Failed` without touching the buffer.
    pub(super) fn fail(&self) {
        self.inner.lock().state = SlotState::Failed;
    }

    /// Runs `f` against this slot's metadata if it is `Ready`, returning `None` otherwise.
    pub(super) fn with_meta<R>(&self, f: impl FnOnce(&M) -> R) -> Option<R> {
        let inner = self.inner.lock();
        match &inner.state {
            SlotState::Ready(meta) => Some(f(meta)),
            _ => None,
        }
    }

    fn is_pending(&self) -> bool {
        matches!(self.inner.lock().state, SlotState::Pending)
    }

    fn is_failed(&self) -> bool {
        matches!(self.inner.lock().state, SlotState::Failed)
    }
}

/// The per-peer ordering queue
///
/// Implemented with a SPSC crossbeam_channel, leveraging on the FIFO ordering maintained between a
/// single sender and receiver.
pub(super) struct PacketQueue<M> {
    sender: Sender<Arc<PacketSlot<M>>>,
    receiver: Receiver<Arc<PacketSlot<M>>>,
    // The current queue head is cached after dequeue as crossbeam_channel does not allow to simply
    // peek a next item to be received
    peeked: Mutex<Option<Arc<PacketSlot<M>>>>,
    // Ensures that at most one worker is draining this queue at a time
    committing: AtomicBool,
}

impl<M> PacketQueue<M> {
    pub(super) fn new() -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();
        Self {
            sender,
            receiver,
            peeked: Mutex::new(None),
            committing: AtomicBool::new(false),
        }
    }

    pub(super) fn push(&self, slot: Arc<PacketSlot<M>>) {
        let _ = self.sender.send(slot);
    }

    fn peek(&self) -> Option<Arc<PacketSlot<M>>> {
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

    /// Drains each finished packet from the peer's queue in order until it reaches a slot that
    /// is still `Pending`.
    ///
    /// For every `Ready` slot, `on_ready` is invoked with the slot's buffer and its metadata;
    /// `Failed` slots are simply dropped.
    /// A queue can be drained by a single worker at a time (no-op if another worker is draining
    /// already), so it is safe to call from any worker as soon as it finished processing a slot
    /// for this peer.
    pub(super) fn drain_ready(&self, mut on_ready: impl FnMut(&[u8], &M)) {
        if !self.try_acquire_committer() {
            return;
        }

        loop {
            while let Some(slot) = self.peek() {
                {
                    let inner = slot.inner.lock();
                    match &inner.state {
                        SlotState::Pending => break,
                        SlotState::Ready(meta) => on_ready(&inner.buffer, meta),
                        SlotState::Failed => {}
                    }
                }
                self.drop_peeked();
            }

            self.release_committer();

            // Another worker that finished processing at this moment may have lost the race to
            // reclaim the committer role that has just been released.
            //
            // A single re-check after releasing is made to ensure this newly completed packet is
            // never missed - if the queue head is now ready, either the current thread will
            // reclaim the committer role and will keep draining, or another thread has already
            // acquired the committer role and will proceed with queue draining.
            match self.peek() {
                Some(slot) if !slot.is_pending() && self.try_acquire_committer() => continue,
                _ => break,
            }
        }
    }

    /// Drains each finished packet from the peer's queue in order until it reaches a slot that is
    /// still `Pending`, invoking `on_ready` with the owning `Arc<PacketSlot>` for every `Ready`
    /// slot (so the caller can retain the slot beyond this call, e.g. to hand it to another
    /// thread). `Failed` slots are dropped. Committer discipline matches [`Self::drain_ready`].
    pub(super) fn drain_ready_slots(&self, mut on_ready: impl FnMut(&Arc<PacketSlot<M>>)) {
        if !self.try_acquire_committer() {
            return;
        }

        loop {
            while let Some(slot) = self.peek() {
                {
                    let inner = slot.inner.lock();
                    match &inner.state {
                        SlotState::Pending => break,
                        SlotState::Ready(_) => {}
                        SlotState::Failed => {
                            drop(inner);
                            self.drop_peeked();
                            continue;
                        }
                    }
                }
                on_ready(&slot);
                self.drop_peeked();
            }

            self.release_committer();

            match self.peek() {
                Some(slot) if !slot.is_pending() && self.try_acquire_committer() => continue,
                _ => break,
            }
        }
    }

    /// Pops abandoned (`Failed`) slots from the head of the queue without touching any sockets,
    /// stopping at the first slot that is `Ready` (which must be committed by a socket-holding
    /// committer via `drain_ready`) or `Pending` (which a worker will eventually resolve).
    ///
    /// Intended for callers that marked slots `Failed` outside a worker context and want to
    /// release the `Arc<PacketSlot>` refs from the queue immediately (without waiting for the next
    /// successful `drain_ready` call for this peer).
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
