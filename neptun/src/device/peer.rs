// Copyright (c) 2024 Nord Security. All rights reserved.
// Copyright (c) 2019-2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::{Mutex, RwLock};
use socket2::{Domain, Protocol, Type};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Coarse read timeout on the connected data socket so the IN data thread wakes periodically
/// to check the shutdown flag (and lets the control thread drive timers independently).
const DATA_SOCKET_READ_TIMEOUT: Duration = Duration::from_millis(250);

use crate::device::{modify_skt_buffer_size, AllowedIps, Error, MakeExternalNeptun};
use crate::noise::Tunn;

use std::os::fd::{AsFd, AsRawFd};

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
    pub conn: Option<socket2::Socket>,
}

pub struct Peer {
    /// The associated tunnel struct
    pub(crate) tunnel: Mutex<Tunn>,
    /// Public key of this peer in raw bytes and hex formats
    pub(crate) public_key: ([u8; 32], String),
    /// The index the tunnel uses
    index: u32,
    endpoint: RwLock<Endpoint>,
    allowed_ips: RwLock<AllowedIps<()>>,
    preshared_key: RwLock<Option<[u8; 32]>>,
    protect: Arc<dyn MakeExternalNeptun>,
    /// Set by the OUT (encrypt) data thread when it has data to send but no current session,
    /// so the control thread initiates a handshake on its next tick. Keeps handshake work out
    /// of the hot encrypt loop.
    want_handshake: AtomicBool,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct AllowedIP {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl FromStr for AllowedIP {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: Vec<&str> = s.split('/').collect();
        if ip.len() != 2 {
            return Err("Invalid IP format".to_owned());
        }
        // Due to above condition, this is index access is safe
        #[allow(clippy::indexing_slicing)]
        let (addr, cidr) = (ip[0].parse::<IpAddr>(), ip[1].parse::<u8>());
        match (addr, cidr) {
            (Ok(addr @ IpAddr::V4(_)), Ok(cidr)) if cidr <= 32 => Ok(AllowedIP { addr, cidr }),
            (Ok(addr @ IpAddr::V6(_)), Ok(cidr)) if cidr <= 128 => Ok(AllowedIP { addr, cidr }),
            _ => Err("Invalid IP format".to_owned()),
        }
    }
}

impl Peer {
    pub fn new(
        tunnel: Tunn,
        index: u32,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        preshared_key: Option<[u8; 32]>,
        protect: Arc<dyn MakeExternalNeptun>,
    ) -> Peer {
        let pub_key = tunnel.peer_static_public();
        let mut public_key_hex = String::with_capacity(32);
        for byte in pub_key.as_bytes() {
            let pub_symbol = format!("{:02X}", byte);
            public_key_hex.push_str(&pub_symbol);
        }

        Peer {
            tunnel: Mutex::new(tunnel),
            public_key: (pub_key.to_bytes(), public_key_hex),
            index,
            endpoint: RwLock::new(Endpoint {
                addr: endpoint,
                conn: None,
            }),
            allowed_ips: RwLock::new(allowed_ips.iter().map(|ip| (ip, ())).collect()),
            preshared_key: RwLock::new(preshared_key),
            protect,
            want_handshake: AtomicBool::new(false),
        }
    }

    /// OUT thread → control thread signal: data is waiting but there is no session yet.
    pub fn request_handshake(&self) {
        self.want_handshake.store(true, Ordering::Relaxed);
    }

    /// Control thread: consume a pending handshake request (returns true once per request).
    pub fn take_handshake_request(&self) -> bool {
        self.want_handshake.swap(false, Ordering::Relaxed)
    }

    pub fn endpoint(&self) -> parking_lot::RwLockReadGuard<'_, Endpoint> {
        self.endpoint.read()
    }

    pub fn shutdown_endpoint(&self) {
        if let Some(conn) = self.endpoint.write().conn.take() {
            tracing::info!("Disconnecting from endpoint");
            if let Err(e) = conn.shutdown(Shutdown::Both) {
                tracing::error!("Error in conn shutdown {}", e);
            }
        }
    }

    pub fn set_endpoint(&self, addr: SocketAddr) {
        let mut endpoint = self.endpoint.write();
        if endpoint.addr == Some(addr) {
            return;
        }
        if let Some(conn) = endpoint.conn.take() {
            if let Err(e) = conn.shutdown(Shutdown::Both) {
                tracing::error!("Error in conn shutdown {}", e);
            }
        }
        endpoint.addr = Some(addr);
    }

    pub fn connect_endpoint(
        &self,
        port: u16,
        skt_buffer_size: Option<usize>,
    ) -> Result<socket2::Socket, Error> {
        let mut endpoint = self.endpoint.write();

        if endpoint.conn.is_some() {
            return Err(Error::Connect("Connected".to_owned()));
        }

        let addr = endpoint.addr.ok_or_else(||
            {
                tracing::warn!("Requested to connect_endpoint without endpoint specified. Falling back to unconnected sockets");
                Error::InternalError(
                    "Peer endpoint was not specified".to_owned(),
                )
            }
        )?;

        let udp_conn =
            socket2::Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        udp_conn.set_reuse_address(true)?;
        let bind_addr = if addr.is_ipv4() {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()
        };
        udp_conn.bind(&bind_addr)?;
        // PoC two-thread model: the connected socket is the data-path socket, used with
        // BLOCKING recv/send (one thread per direction). A coarse read timeout lets the IN
        // thread wake to check the shutdown flag.
        udp_conn.set_nonblocking(false)?;
        udp_conn.set_read_timeout(Some(DATA_SOCKET_READ_TIMEOUT))?;
        // fw_mark is being set inside make_external(), so no need to set it twice as in Cloudflare's repo.
        self.protect.make_external(udp_conn.as_raw_fd());
        // Also mind that all socket setup functions should be called before .connect().
        udp_conn.connect(&addr.into())?;

        // PoC: enable UDP GRO on the data socket. The kernel coalesces inbound WireGuard datagrams
        // into one large buffer at the GRO layer, collapsing the per-packet NET_RX softirq cost
        // that otherwise caps download throughput on a single (little) core. The IN thread reads
        // the coalesced buffer via recvmsg + the UDP_GRO control message (gso_size) and splits it.
        // Best-effort: if it fails, recvmsg simply never produces the cmsg and we fall back to
        // single-datagram reads. (UDP_SEGMENT/GSO on send is set per-sendmsg as a cmsg, not here.)
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            const SOL_UDP: libc::c_int = 17;
            const UDP_GRO: libc::c_int = 104;
            let on: libc::c_int = 1;
            let rc = unsafe {
                libc::setsockopt(
                    udp_conn.as_raw_fd(),
                    SOL_UDP,
                    UDP_GRO,
                    &on as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                tracing::warn!(
                    message = "UDP_GRO setsockopt failed; continuing without RX coalescing",
                    error = ?std::io::Error::last_os_error()
                );
            }
        }

        tracing::info!(
            message="Connected endpoint",
            port=port,
            endpoint=?addr
        );

        endpoint.conn = Some(udp_conn.try_clone()?);

        // Log exactly which local (bound) and remote (connected) addresses/ports the data
        // socket uses, plus udp4's listen_port for comparison. If the bound port != listen_port,
        // the peer sees the phone at two source ports (udp4 vs conn) and roams between them.
        let local = udp_conn.local_addr().ok().and_then(|a| a.as_socket());
        let remote = udp_conn.peer_addr().ok().and_then(|a| a.as_socket());
        tracing::info!(
            message = "connected data socket addresses",
            bound = ?local,
            connected_to = ?remote,
            bound_port = local.map(|a| a.port()),
            listen_port = port,
            port_matches_udp4 = local.map(|a| a.port()) == Some(port),
        );
        if local.map(|a| a.port()) != Some(port) {
            tracing::warn!(
                message = "PORT MISMATCH: connected data socket local port != udp4/listen_port",
                bound = ?local,
                listen_port = port,
            );
        }

        if let Some(buffer_size) = skt_buffer_size {
            modify_skt_buffer_size(udp_conn.as_fd(), buffer_size);
        }

        Ok(udp_conn)
    }

    pub fn is_allowed_ip<I: Into<IpAddr>>(&self, addr: I) -> bool {
        self.allowed_ips.read().find(addr.into()).is_some()
    }

    pub fn allowed_ips(&self) -> Vec<AllowedIP> {
        self.allowed_ips
            .read()
            .iter()
            .map(|(_, ip, cidr)| AllowedIP { addr: ip, cidr })
            .collect()
    }

    pub fn add_allowed_ips(&self, new_allowed_ips: &[AllowedIP]) {
        let mut allowed_ips = self.allowed_ips.write();

        for AllowedIP { addr, cidr } in new_allowed_ips {
            allowed_ips.insert(*addr, *cidr as u32, ());
        }
    }

    pub fn set_allowed_ips(&self, allowed_ips: &[AllowedIP]) {
        *self.allowed_ips.write() = allowed_ips.iter().map(|ip| (ip, ())).collect();
    }

    pub fn preshared_key(&self) -> Option<[u8; 32]> {
        *self.preshared_key.read()
    }

    /// Be carefull using this one, as it locks tunnel
    pub fn set_preshared_key(&self, key: [u8; 32]) {
        let key = if key == [0; 32] { None } else { Some(key) };

        *self.preshared_key.write() = key;

        self.tunnel.lock().set_preshared_key(key);
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Introduced this test to prevent LLT-5351 recurring in the future:
    #[test]
    fn test_connect_endpoint() {
        let a_secret_key = StaticSecret::random_from_rng(rand::rngs::StdRng::from_entropy());

        let b_secret_key = StaticSecret::random_from_rng(rand::rngs::StdRng::from_entropy());
        let b_public_key = PublicKey::from(&b_secret_key);

        let tunnel = Tunn::new(a_secret_key, b_public_key, None, None, 0, None).unwrap();
        let peer = Peer::new(
            tunnel,
            0,
            Some(SocketAddr::new(IpAddr::from([1, 2, 3, 4]), 54321)),
            &[],
            None,
            Arc::new(crate::device::MakeExternalNeptunNoop),
        );

        peer.connect_endpoint(12345, None).unwrap();
    }
}
