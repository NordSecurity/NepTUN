use std::collections::HashMap;
use std::io;
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::sync::Arc;

use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
use socket2::Socket;

use super::wake::{Wake, CMD_REBIND_UDP, CMD_RELOAD, CMD_SHUTDOWN};
use super::{Device, Lock, MAX_ITR, MAX_PKT_SIZE};
use crate::device::peer::Peer;
use crate::device::tun::TunSocket;
use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::x25519;

pub(super) struct Inbound {
    device: Arc<Lock<Device>>,
    iface: Arc<TunSocket>,
    wake: Arc<Wake>,
    poll: Poll,
    conn_fds: HashMap<u32, i32>, // peer idx -> conn socket raw fd (registered in poll)
    udp_fds: Vec<i32>,           // currently-registered udp4/udp6 raw fds
    src_buf: [u8; MAX_PKT_SIZE],
    dst_buf: [u8; MAX_PKT_SIZE],
    conn_removals: Arc<crossbeam_queue::SegQueue<u32>>,
}

impl Inbound {
    pub(super) fn new(
        device: Arc<Lock<Device>>,
        iface: Arc<TunSocket>,
        wake: Arc<Wake>,
        conn_removals: Arc<crossbeam_queue::SegQueue<u32>>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            device,
            iface,
            wake,
            poll: Poll::new()?,
            conn_fds: HashMap::new(),
            udp_fds: Vec::new(),
            src_buf: [0u8; MAX_PKT_SIZE],
            dst_buf: [0u8; MAX_PKT_SIZE],
            conn_removals,
        })
    }

    pub(super) fn run(mut self) {
        self.register_udp();

        if self.poll.add(self.wake.fd(), Src::Wake).is_err() {
            tracing::error!("IN add wake failed");
            return;
        }

        let mut evbuf = vec![nix::sys::epoll::EpollEvent::empty(); 16];
        let mut ready = Vec::with_capacity(16);

        loop {
            if self.poll.wait(&mut evbuf, &mut ready).is_err() {
                continue;
            }
            self.drain_removals();
            for src in std::mem::take(&mut ready) {
                match src {
                    Src::Udp4 | Src::Udp6 => self.drain_bootstrap(src),
                    Src::Conn(idx) => self.drain_conn(idx),
                    Src::Wake => match self.wake.take() {
                        CMD_SHUTDOWN | CMD_RELOAD => return,
                        CMD_REBIND_UDP => self.register_udp(),
                        _ => {}
                    },
                }
            }
        }
    }

    // (Re)register the current udp4/udp6 sockets, removing any stale ones first
    fn register_udp(&mut self) {
        for fd in self.udp_fds.drain(..) {
            let _ = self.poll.remove(fd);
        }
        let d = self.device.read();
        if let (Some(u4), Some(u6)) = (d.udp4.as_ref(), d.udp6.as_ref()) {
            let f4 = u4.as_raw_fd();
            let f6 = u6.as_raw_fd();
            if self.poll.add(f4, Src::Udp4).is_ok() {
                self.udp_fds.push(f4);
            }
            if self.poll.add(f6, Src::Udp6).is_ok() {
                self.udp_fds.push(f6);
            }
        }
    }

    fn drain_removals(&mut self) {
        while let Some(idx) = self.conn_removals.pop() {
            if let Some(fd) = self.conn_fds.remove(&idx) {
                let _ = self.poll.remove(fd);
            }
        }
    }

    // Connected-socket fast path: peer known from fd tag, decrypt, write to tun.
    fn drain_conn(&mut self, idx: u32) {
        let d = self.device.read();
        let peer = match d.peers_by_idx.get(&idx).cloned() {
            Some(p) => p,
            None => return,
        };
        let peer_addr = match peer.endpoint().addr {
            Some(a) => a.ip(),
            None => return,
        };
        let conn = match peer.endpoint().conn.as_ref().map(|c| c.try_clone()) {
            Some(Ok(c)) => c,
            _ => return,
        };
        let fw = d.config.firewall_process_inbound_callback.clone();
        drop(d);

        let iface = self.iface.clone();
        for _ in 0..MAX_ITR {
            let src =
                unsafe { &mut *(&mut self.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
            let n = match conn.recv(src) {
                Ok(n) => n,
                Err(_) => break, // WouldBlock -> drained
            };

            let mut flush = false;
            let res = {
                let mut tun = peer.tunnel.lock();
                #[allow(clippy::indexing_slicing)] // TODO: verify!
                tun.decapsulate(Some(peer_addr), &self.src_buf[..n], &mut self.dst_buf[..])
            };
            match res {
                TunnResult::Done => {}
                TunnResult::Err(WireGuardError::DuplicateCounter) => {
                    tracing::debug!(message = "Decapsulate", pk = peer.public_key.1)
                }
                TunnResult::Err(e) => {
                    tracing::error!(message = "Decapsulate", error = ?e, pk = peer.public_key.1)
                }
                TunnResult::WriteToNetwork(pkt) => {
                    flush = true;
                    let _ = conn.send(pkt);
                }
                TunnResult::WriteToTunnel(pkt, addr) => {
                    Self::write_tun(&iface, &peer, pkt, addr, &fw)
                }
            }
            if flush {
                self.flush_conn(&peer, &conn);
            }
        }
    }

    // Anonymous path on udp4/udp6
    fn drain_bootstrap(&mut self, which: Src) {
        let (udp, sk, pk, rate, use_conn, listen_port, buf_sz, fw) = {
            let d = self.device.read();
            let udp = match which {
                Src::Udp4 => d.udp4.clone(),
                _ => d.udp6.clone(),
            };
            let udp = match udp {
                Some(u) => u,
                None => return,
            };
            let (sk, pk) = match d.key_pair.as_ref() {
                Some((s, p)) => (s.clone(), *p),
                None => return,
            };
            (
                udp,
                sk,
                pk,
                d.rate_limiter.clone(),
                d.config.use_connected_socket,
                d.listen_port,
                d.config.skt_buffer_size,
                d.config.firewall_process_inbound_callback.clone(),
            )
        };

        let iface = self.iface.clone();

        let mut iter = MAX_ITR;
        let src = unsafe { &mut *(&mut self.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
        while let Ok((len, addr)) = udp.recv_from(src) {
            let packet = match self.src_buf.get(..len) {
                Some(p) => p,
                None => continue,
            };
            let sock = match addr.as_socket() {
                Some(s) => s,
                None => continue,
            };

            let parsed = match rate.as_ref() {
                Some(rl) => match rl.verify_packet(Some(sock.ip()), packet, &mut self.dst_buf) {
                    Ok(p) => p,
                    Err(TunnResult::WriteToNetwork(cookie)) => {
                        let _ = udp.send_to(cookie, &addr);
                        continue;
                    }
                    Err(_) => continue,
                },
                None => match Tunn::parse_incoming_packet(packet) {
                    Ok(p) => p,
                    Err(_) => continue,
                },
            };

            let peer = {
                let d = self.device.read();
                match &parsed {
                    Packet::HandshakeInit(p) => {
                        parse_handshake_anon(&sk, &pk, p).ok().and_then(|hh| {
                            d.peers
                                .get(&x25519::PublicKey::from(hh.peer_static_public))
                                .cloned()
                        })
                    }
                    Packet::HandshakeResponse(p) => {
                        d.peers_by_idx.get(&(p.receiver_idx >> 8)).cloned()
                    }
                    Packet::PacketCookieReply(p) => {
                        d.peers_by_idx.get(&(p.receiver_idx >> 8)).cloned()
                    }
                    Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)).cloned(),
                }
            };

            let peer = match peer {
                Some(p) => p.clone(),
                None => continue,
            };

            let mut flush = false;
            let res = {
                let mut tun = peer.tunnel.lock();
                tun.handle_verified_packet(parsed, &mut self.dst_buf[..])
            };
            match res {
                TunnResult::Done => {}
                TunnResult::Err(e) => {
                    tracing::warn!(message = "handle_verified_packet", error = ?e);
                    continue;
                }
                TunnResult::WriteToNetwork(pkt) => {
                    flush = true;
                    let _ = udp.send_to(pkt, &addr);
                }
                TunnResult::WriteToTunnel(pkt, ip) => Self::write_tun(&iface, &peer, pkt, ip, &fw),
            }
            if flush {
                loop {
                    let res = {
                        let mut tun = peer.tunnel.lock();
                        tun.decapsulate(None, &[], &mut self.dst_buf[..])
                    };
                    let TunnResult::WriteToNetwork(pkt) = res else {
                        break;
                    };
                    let _ = udp.send_to(pkt, &addr);
                }
            }

            peer.set_endpoint(sock);
            if use_conn {
                self.establish_conn(&peer, listen_port, buf_sz);
            }

            iter -= 1;
            if iter == 0 {
                break;
            }
        }
    }

    fn establish_conn(&mut self, peer: &Arc<Peer>, port: u16, buf_sz: Option<usize>) {
        if self.conn_fds.contains_key(&peer.index()) {
            return;
        }
        match peer.connect_endpoint(port, buf_sz) {
            Ok(sock) => {
                let fd = sock.as_raw_fd();
                if self.poll.add(fd, Src::Conn(peer.index())).is_ok() {
                    self.conn_fds.insert(peer.index(), fd);
                    // sock dropped here; the fd stays open via endpoint.conn clone.
                } else {
                    tracing::error!("IN failed to register conn socket");
                    peer.shutdown_endpoint();
                }
            }
            Err(e) => tracing::error!("connect_endpoint failed: {e}"),
        }
    }

    fn write_tun(
        mut iface: &TunSocket,
        peer: &Arc<Peer>,
        pkt: &mut [u8],
        addr: IpAddr,
        fw: &Option<Arc<dyn Fn(&[u8; 32], &mut [u8]) -> bool + Send + Sync>>,
    ) {
        if let Some(cb) = fw {
            if !cb(&peer.public_key.0, pkt) {
                return;
            }
        }
        if peer.is_allowed_ip(addr) {
            let _ = iface.write(pkt);
        }
    }

    fn flush_conn(&mut self, peer: &Arc<Peer>, conn: &Socket) {
        loop {
            let res = {
                let mut tun = peer.tunnel.lock();
                tun.decapsulate(None, &[], &mut self.dst_buf[..])
            };
            let TunnResult::WriteToNetwork(pkt) = res else {
                break;
            };
            let _ = conn.send(pkt);
        }
    }
}

/// Readiness source tag for the IN thread's epoll set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Src {
    Udp4,
    Udp6,
    Conn(u32),
    Wake,
}

impl Src {
    fn to_u64(self) -> u64 {
        match self {
            Src::Udp4 => 1,
            Src::Udp6 => 2,
            Src::Wake => 3,
            // tag class 4 in high nibble, peer idx in low 32 bits
            Src::Conn(idx) => (4u64 << 32) | idx as u64,
        }
    }

    fn from_u64(v: u64) -> Option<Self> {
        match v >> 32 {
            0 if v == 1 => Some(Src::Udp4),
            0 if v == 2 => Some(Src::Udp6),
            0 if v == 3 => Some(Src::Wake),
            4 => Some(Src::Conn(v as u32)),
            _ => None,
        }
    }
}

/// Minimal level-triggered epoll owned by the IN thread. Watches udp4/udp6, the
/// per-peer connected sockets, and the wake eventfd. The fds stay open via the
/// Device for the poll set's lifetime, so this poller never closes them.
struct Poll {
    epoll: Epoll,
}

impl Poll {
    fn new() -> io::Result<Self> {
        Ok(Self {
            epoll: Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?,
        })
    }

    fn add(&self, fd: RawFd, src: Src) -> io::Result<()> {
        let ev = EpollEvent::new(EpollFlags::EPOLLIN, src.to_u64());
        self.epoll.add(unsafe { borrow(fd) }, ev)?;
        Ok(())
    }

    fn remove(&self, fd: RawFd) -> io::Result<()> {
        self.epoll.delete(unsafe { borrow(fd) })?;
        Ok(())
    }

    // Blocks until at least one fd is ready; fills `out` with the ready tags.
    fn wait(&self, buf: &mut [EpollEvent], out: &mut Vec<Src>) -> io::Result<usize> {
        out.clear();
        let n = match self.epoll.wait(buf, EpollTimeout::NONE) {
            Ok(n) => n,
            Err(nix::errno::Errno::EINTR) => 0,
            Err(e) => return Err(e.into()),
        };
        #[allow(clippy::indexing_slicing)]
        for ev in &buf[..n] {
            if let Some(src) = Src::from_u64(ev.data()) {
                out.push(src);
            }
        }
        Ok(n)
    }
}

// nix's Epoll API needs an AsFd; the Device owns the fds for the poll's
// lifetime, so the poller never closes them.
unsafe fn borrow(fd: RawFd) -> BorrowedFd<'static> {
    BorrowedFd::borrow_raw(fd)
}
