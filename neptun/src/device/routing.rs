use std::{
    io::{self, Write},
    net::IpAddr,
};

use crate::device::peer::Peer;
use crate::device::tun::TunSocket;
use crate::noise::packet::InboundIp;

/// A validated IP packet whose source address is inside the peer's allowed IPs.
#[derive(Debug)]
pub struct RoutableIp<'a> {
    inner: InboundIp<'a>,
}

impl<'a> RoutableIp<'a> {
    #[inline]
    pub fn check(packet: InboundIp<'a>, peer: &Peer) -> Result<Self, InboundIp<'a>> {
        if peer.is_allowed_ip(packet.src_addr()) {
            Ok(Self { inner: packet })
        } else {
            Err(packet)
        }
    }

    #[inline(always)]
    pub fn src_addr(&self) -> IpAddr {
        self.inner.src_addr()
    }

    #[inline(always)]
    pub fn payload(&self) -> &[u8] {
        self.inner.payload()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    pub fn write_to(&self, iface: &TunSocket) -> io::Result<usize> {
        let mut tun: &TunSocket = iface;
        tun.write(self.payload())
    }
}
