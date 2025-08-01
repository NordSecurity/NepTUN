// Copyright (c) 2024 Nord Security. All rights reserved.
// Copyright (c) 2019-2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::{Mutex, RwLock};
use socket2::{Domain, Protocol, Type};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::Arc;

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
        }
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
        udp_conn.set_nonblocking(true)?;
        // fw_mark is being set inside make_external(), so no need to set it twice as in Cloudflare's repo.
        self.protect.make_external(udp_conn.as_raw_fd());
        // Also mind that all socket setup functions should be called before .connect().
        udp_conn.connect(&addr.into())?;

        tracing::info!(
            message="Connected endpoint",
            port=port,
            endpoint=?addr
        );

        endpoint.conn = Some(udp_conn.try_clone()?);

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
            .map(|(_, ip, cidr)| AllowedIP {
                addr: ip,
                cidr: cidr,
            })
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
        self.preshared_key.read().clone()
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
        let a_secret_key = StaticSecret::random_from_rng(&mut rand::rngs::StdRng::from_entropy());

        let b_secret_key = StaticSecret::random_from_rng(&mut rand::rngs::StdRng::from_entropy());
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
