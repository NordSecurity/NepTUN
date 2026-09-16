use std::sync::Arc;

use parking_lot::MutexGuard;

use crate::{
    device::peer::Peer,
    noise::{
        errors::WireGuardError,
        packet::{self, Decapsulated},
        session::Session,
        Packet, PacketData, RxCommit, Tunn, TunnResult,
    },
};

/// Inbound path state
enum RxPath<'p, 'd> {
    Data {
        session: Arc<Session>,
        packet: PacketData<'d>,
        commit: RxCommit,
    },
    NoSession,
    Control(ControlRx<'p, 'd>),
}

struct ControlRx<'p, 'd> {
    guard: MutexGuard<'p, Tunn>,
    packet: Packet<'d>,
}

impl<'p, 'd> ControlRx<'p, 'd> {
    #[inline]
    fn handle<'a>(self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let ControlRx { mut guard, packet } = self;
        guard.handle_verified_packet(packet, dst)
    }
}

pub(crate) fn handle_verified_packet<'a, 'd>(
    peer: &Peer,
    packet: Packet<'d>,
    dst: &'a mut [u8],
) -> TunnResult<'a> {
    let (session, packet, commit) = match begin_rx(peer, packet) {
        RxPath::Data {
            session,
            packet,
            commit,
        } => (session, packet, commit),
        RxPath::NoSession => {
            tracing::trace!("No current session available");
            return TunnResult::Err(WireGuardError::NoCurrentSession);
        }
        RxPath::Control(control) => return control.handle(dst),
    };

    // Tunnel lock is released at this point
    let decapsulated = match session
        .receive_packet_data(packet, dst)
        .and_then(|p| packet::parse_inbound_ip(p))
    {
        Ok(d) => d,
        Err(e) => {
            commit.discard();
            return TunnResult::Err(e);
        }
    };

    // Reacquiring tunnel lock
    peer.tunnel.lock().commit_rx(commit, &decapsulated);

    match decapsulated {
        Decapsulated::Keepalive => TunnResult::Done,
        Decapsulated::Ip(packet) => TunnResult::WriteToTunnel(packet),
    }
}

fn begin_rx<'p, 'd>(peer: &'p Peer, packet: Packet<'d>) -> RxPath<'p, 'd> {
    let guard = peer.tunnel.lock();
    match packet {
        Packet::PacketData(p) => match guard.begin_rx_data(&p) {
            Some((session, commit)) => {
                drop(guard);
                RxPath::Data {
                    session,
                    packet: p,
                    commit,
                }
            }
            None => {
                drop(guard);
                RxPath::NoSession
            }
        },
        control => RxPath::Control(ControlRx {
            guard,
            packet: control,
        }),
    }
}
