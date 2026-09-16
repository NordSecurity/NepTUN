use std::sync::Arc;

use parking_lot::MutexGuard;

use crate::{
    device::peer::Peer,
    noise::{session::Session, Tunn, TunnResult, TxCommit, TxIntent},
};

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
use crate::noise::{errors::WireGuardError, session::DATA_OFFSET};

/// Outbound path state
enum TxPath<'p> {
    Ready(Arc<Session>),
    Blocked(BlockedTx<'p>),
}

/// Describes locked tunnel
struct BlockedTx<'p> {
    guard: MutexGuard<'p, Tunn>,
}

impl<'p> BlockedTx<'p> {
    #[inline]
    fn queue_and_init<'a>(mut self, src_len: usize, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.guard.queue_and_init(src_len, dst)
    }
}

fn begin_tx(peer: &Peer) -> TxPath<'_> {
    let guard = peer.tunnel.lock();
    let intent = guard.begin_tx();
    match intent {
        TxIntent::Ready(session) => {
            drop(guard);
            TxPath::Ready(session)
        }
        TxIntent::RequiresHandshake => TxPath::Blocked(BlockedTx { guard }),
    }
}

pub(crate) fn encapsulate_in_place<'a>(
    peer: &Peer,
    src_len: usize,
    dst: &'a mut [u8],
) -> TunnResult<'a> {
    let session = match begin_tx(peer) {
        TxPath::Ready(session) => session,
        TxPath::Blocked(blocked) => return blocked.queue_and_init(src_len, dst),
    };

    // Tunnel lock is released at this point
    let packet = match session.format_packet_data(src_len, dst) {
        Ok(packet) => packet,
        Err(e) => return TunnResult::Err(e),
    };

    let commit = TxCommit::for_packet(packet.len(), src_len);

    // Reacquiring tunnel lock
    peer.tunnel.lock().commit_tx(commit);
    TunnResult::WriteToNetwork(packet)
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
pub(crate) fn flush_queued<'a>(peer: &Peer, dst: &'a mut [u8]) -> TunnResult<'a> {
    let payload = match peer.tunnel.lock().dequeue_packet() {
        Some(p) => p,
        None => return TunnResult::Done,
    };
    let payload_len = payload.len();

    match dst.get_mut(DATA_OFFSET..DATA_OFFSET + payload_len) {
        Some(d) => d.copy_from_slice(&payload),
        None => {
            peer.tunnel.lock().requeue_packet(payload);
            return TunnResult::Err(WireGuardError::InvalidLength);
        }
    }

    match encapsulate_in_place(peer, payload_len, dst) {
        TunnResult::Err(e) => {
            peer.tunnel.lock().requeue_packet(payload);
            TunnResult::Err(e)
        }
        other => other,
    }
}
