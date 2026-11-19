// Copyright (c) 2024 Nord Security. All rights reserved.
// Copyright (c) 2019-2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::{Mutex, RwLock};
use socket2::{Domain, Protocol, Type};

use std::ops::Deref;
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
use std::os::fd::AsFd;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::device::{AllowedIps, Error, MakeExternalNeptun};
use crate::noise::Tunn;
use crate::serialization::PubKey;

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
use crate::device::modify_skt_buffer_size;

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
    pub conn: Option<ProtectedSocket>,
}

pub struct Peer {
    /// The associated tunnel struct
    pub(crate) tunnel: Mutex<Tunn>,
    /// Public key of this peer. Masked when logged; use `as_bytes()` for the
    /// raw key material.
    pub(crate) public_key: PubKey,
    /// The index the tunnel uses
    index: u32,
    endpoint: RwLock<Endpoint>,
    allowed_ips: RwLock<AllowedIps<()>>,
    preshared_key: RwLock<Option<[u8; 32]>>,
    protect: Arc<dyn MakeExternalNeptun>,
    /// Finds connected sockets that do not receive
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    pub(crate) conn_watch: crate::device::conn_watch::ConnWatch,
    // control plane fields
    handshake_requested: AtomicBool,
    flush_requested: AtomicBool,
    endpoint_requested: AtomicBool,
    requested_endpoint: Mutex<Option<SocketAddr>>,
    disconnect_requested: AtomicBool,
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

        Peer {
            tunnel: Mutex::new(tunnel),
            public_key: PubKey::from(pub_key),
            index,
            endpoint: RwLock::new(Endpoint {
                addr: endpoint,
                conn: None,
            }),
            allowed_ips: RwLock::new(allowed_ips.iter().map(|ip| (ip, ())).collect()),
            preshared_key: RwLock::new(preshared_key),
            protect,
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
            conn_watch: Default::default(),
            handshake_requested: AtomicBool::new(false),
            flush_requested: AtomicBool::new(false),
            endpoint_requested: AtomicBool::new(false),
            requested_endpoint: Mutex::new(None),
            disconnect_requested: AtomicBool::new(false),
        }
    }

    /// Requests the control plane to initiate a handshake
    ///
    /// Returns `true` if there was no pending request, so that the control plane needs to be woken
    pub(crate) fn request_handshake(&self) -> bool {
        !self.handshake_requested.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn take_handshake_request(&self) -> bool {
        self.handshake_requested.swap(false, Ordering::AcqRel)
    }

    /// Requests the control plane to send the queued packets
    ///
    /// Returns `true` if there was no pending request, so that the control plane needs to be woken
    pub(crate) fn request_flush(&self) -> bool {
        !self.flush_requested.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn take_flush_request(&self) -> bool {
        self.flush_requested.swap(false, Ordering::AcqRel)
    }

    pub(crate) fn needs_endpoint_update(&self, addr: SocketAddr) -> bool {
        let endpoint = self.endpoint.read();

        let has_conn = endpoint.conn.is_some();

        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        if has_conn {
            self.conn_watch.on_listen_receive();
        }

        endpoint.addr != Some(addr) || (!has_conn && wants_conn(addr))
    }

    /// Requests the control plane to update the endpoint (latest request wins)
    ///
    /// Returns `true` if there was no pending request, so that the control plane needs to be woken
    pub(crate) fn request_endpoint(&self, addr: SocketAddr) -> bool {
        *self.requested_endpoint.lock() = Some(addr);
        !self.endpoint_requested.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn take_endpoint_request(&self) -> Option<SocketAddr> {
        if !self.endpoint_requested.swap(false, Ordering::AcqRel) {
            return None;
        }
        self.requested_endpoint.lock().take()
    }

    pub fn endpoint(&self) -> parking_lot::RwLockReadGuard<'_, Endpoint> {
        self.endpoint.read()
    }

    /// Removes the peer's connected socket.
    ///
    /// Returns `false` if the peer didn't have a connected socket.
    pub fn shutdown_endpoint(&self) -> bool {
        let conn = self.endpoint.write().conn.take();
        let Some(conn) = conn else {
            return false;
        };
        tracing::info!("Disconnecting from endpoint");
        if let Err(e) = conn.shutdown(Shutdown::Both) {
            tracing::error!("Error in conn shutdown {}", e);
        }
        true
    }

    /// Sets an endpoint on the peer.
    ///
    /// Returns `true` if the peer had a connected socket and it was removed, `false` otherwise.
    pub fn set_endpoint(&self, addr: SocketAddr) -> bool {
        // avoid the unnecessary write lock, which contends with the outbound thread's endpoint reads
        if self.endpoint.read().addr == Some(addr) {
            return false;
        }

        let old_conn = {
            let mut endpoint = self.endpoint.write();

            // re-check - read guard was released above
            if endpoint.addr == Some(addr) {
                return false;
            }
            endpoint.addr = Some(addr);
            endpoint.conn.take()
        };

        let Some(conn) = old_conn else {
            return false;
        };
        if let Err(e) = conn.shutdown(Shutdown::Both) {
            tracing::error!("Error in conn shutdown {}", e);
        }
        true
    }

    /// On Apple platforms, it is optimal to rely on the kernel autotuning of the socket size.
    /// Hence, setting `skt_buffer_size` won't have any effect for Apple platforms.
    pub fn connect_endpoint(
        &self,
        port: u16,
        #[cfg_attr(
            any(target_os = "macos", target_os = "ios", target_os = "tvos"),
            allow(unused_variables)
        )]
        skt_buffer_size: Option<usize>,
    ) -> Result<(), Error> {
        let addr = {
            let endpoint = self.endpoint.read();
            if endpoint.conn.is_some() {
                return Err(Error::Connect("Connected".to_owned()));
            }
            let addr = endpoint.addr.ok_or_else(|| {
                tracing::warn!("Requested to connect_endpoint without endpoint specified. Falling back to anonymous sockets.");
                Error::InternalError("Peer endpoint was not specified".to_owned())
            })?;
            if !wants_conn(addr) {
                return Err(Error::Connect("Loopback endpoint".to_owned()));
            }
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
            if !self.conn_watch.connect_permitted() {
                return Err(Error::Connect("Connect rate limited".to_owned()));
            }
            addr
        };

        // Socket is set up without the endpoint lock, so it does not block data plane's endpoint reads
        let udp_conn =
            socket2::Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        udp_conn.set_reuse_address(true)?;
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        udp_conn.set_reuse_port(true)?;
        let bind_addr = if addr.is_ipv4() {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()
        };
        udp_conn.bind(&bind_addr)?;
        udp_conn.set_nonblocking(true)?;

        // fw_mark is being set inside make_external() called inside new()
        let udp_conn = ProtectedSocket::new(udp_conn, Arc::clone(&self.protect));
        // Also mind that all socket setup functions should be called before .connect().
        udp_conn.connect(&addr.into())?;

        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        if let Some(buffer_size) = skt_buffer_size {
            modify_skt_buffer_size(udp_conn.as_fd(), buffer_size);
        }

        {
            let mut endpoint = self.endpoint.write();
            if endpoint.conn.is_some() {
                return Err(Error::Connect("Connected".to_owned()));
            }
            if endpoint.addr != Some(addr) {
                return Err(Error::Connect(
                    "Endpoint changed while connecting".to_owned(),
                ));
            }
            endpoint.conn = Some(udp_conn);
        }

        tracing::info!(
            message="Connected endpoint",
            port=port,
            endpoint=?addr
        );

        Ok(())
    }

    /// Requests the control plane to remove the connected socket
    ///
    /// Returns `true` if there was no pending request, so that the control plane needs to be woken
    pub(crate) fn request_disconnect(&self) -> bool {
        !self.disconnect_requested.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn take_disconnect_request(&self) -> bool {
        self.disconnect_requested.swap(false, Ordering::AcqRel)
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

pub struct ProtectedSocket {
    socket: socket2::Socket,
    protect: Arc<dyn MakeExternalNeptun>,
}

impl ProtectedSocket {
    fn new(socket: socket2::Socket, protect: Arc<dyn MakeExternalNeptun>) -> Self {
        protect.make_external(socket.as_raw_fd());
        Self { socket, protect }
    }
}

impl Deref for ProtectedSocket {
    type Target = socket2::Socket;

    fn deref(&self) -> &socket2::Socket {
        &self.socket
    }
}

impl Drop for ProtectedSocket {
    fn drop(&mut self) {
        self.protect.clean(self.socket.as_raw_fd());
    }
}

impl std::fmt::Debug for ProtectedSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.socket.fmt(f)
    }
}

fn wants_conn(addr: SocketAddr) -> bool {
    !cfg!(any(target_os = "macos", target_os = "ios", target_os = "tvos"))
        || !addr.ip().to_canonical().is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Introduced this test to prevent LLT-5351 recurring in the future:
    #[test]
    fn test_connect_endpoint() {
        let a_secret_key = StaticSecret::random_from_rng(rand_core::OsRng);

        let b_secret_key = StaticSecret::random_from_rng(rand_core::OsRng);
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
