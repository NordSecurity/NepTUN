//! Typestate for inbound packet buffers

use std::{convert::TryInto, net::IpAddr};

use crate::noise::errors::WireGuardError;

pub(crate) const IPV4_MIN_HEADER_SIZE: usize = 20;
pub(crate) const IPV4_LEN_OFF: usize = 2;
pub(crate) const IPV4_SRC_IP_OFF: usize = 12;
pub(crate) const IPV4_DST_IP_OFF: usize = 16;
pub(crate) const IPV4_IP_SZ: usize = 4;

pub(crate) const IPV6_MIN_HEADER_SIZE: usize = 40;
pub(crate) const IPV6_LEN_OFF: usize = 4;
pub(crate) const IPV6_SRC_IP_OFF: usize = 8;
pub(crate) const IPV6_DST_IP_OFF: usize = 24;
pub(crate) const IPV6_IP_SZ: usize = 16;

pub(crate) const IP_LEN_SZ: usize = 2;

/// Authenticated and decrypted buffer, but whose contents have not been inspected.
#[repr(transparent)]
#[derive(Debug)]
pub struct Plaintext<'a>(&'a mut [u8]);

impl<'a> Plaintext<'a> {
    #[inline(always)]
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self(buf)
    }

    #[inline(always)]
    fn into_inner(self) -> &'a mut [u8] {
        self.0
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Validated IP packet, already truncated to its declared length
/// and its source address parsed out.
///
/// Carries no proof about routing.
#[derive(Debug)]
pub struct InboundIp<'a> {
    payload: &'a mut [u8],
    src_addr: IpAddr,
}

impl<'a> InboundIp<'a> {
    #[inline(always)]
    pub fn src_addr(&self) -> IpAddr {
        self.src_addr
    }

    #[inline(always)]
    pub fn payload(&self) -> &[u8] {
        self.payload
    }

    #[inline(always)]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.payload
    }

    #[inline(always)]
    pub fn into_payload(self) -> &'a mut [u8] {
        self.payload
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

// Parsed inbound IP packet
#[derive(Debug)]
pub enum Decapsulated<'a> {
    Keepalive,
    Ip(InboundIp<'a>),
}

// TODO: fn name doesn't suggest in any way it can return WireGuardError - consider fixing this
#[inline(always)]
fn read_u16_be(buf: &[u8], off: usize) -> Result<u16, WireGuardError> {
    let bytes: [u8; IP_LEN_SZ] = buf
        .get(off..off + IP_LEN_SZ)
        .and_then(|s| s.try_into().ok())
        .ok_or(WireGuardError::InvalidPacket)?;
    Ok(u16::from_be_bytes(bytes))
}

#[inline(always)]
fn read_addr<const N: usize>(buf: &[u8], off: usize) -> Result<[u8; N], WireGuardError> {
    buf.get(off..off + N)
        .and_then(|s| s.try_into().ok())
        .ok_or(WireGuardError::InvalidPacket)
}

// Verifies IP packet and truncates it to the length declared in its header.
#[inline]
pub fn parse_inbound_ip(plain_text: Plaintext<'_>) -> Result<Decapsulated<'_>, WireGuardError> {
    let buf = plain_text.into_inner();

    let version = match buf.first() {
        // A zero-length payload is a keepalive packet
        None => return Ok(Decapsulated::Keepalive),
        Some(first) => first >> 4,
    };

    let (min_header, declared_len, src_addr) = match version {
        4 if buf.len() >= IPV4_MIN_HEADER_SIZE => (
            IPV4_MIN_HEADER_SIZE,
            read_u16_be(buf, IPV4_LEN_OFF)? as usize,
            IpAddr::from(read_addr::<IPV4_IP_SZ>(buf, IPV4_SRC_IP_OFF)?),
        ),
        6 if buf.len() >= IPV6_MIN_HEADER_SIZE => (
            IPV6_MIN_HEADER_SIZE,
            read_u16_be(buf, IPV6_LEN_OFF)? as usize + IPV6_MIN_HEADER_SIZE,
            IpAddr::from(read_addr::<IPV6_IP_SZ>(buf, IPV6_SRC_IP_OFF)?),
        ),
        _ => return Err(WireGuardError::InvalidPacket),
    };

    if declared_len < min_header {
        return Err(WireGuardError::InvalidPacket);
    }

    let payload = buf
        .get_mut(..declared_len)
        .ok_or(WireGuardError::InvalidPacket)?;

    Ok(Decapsulated::Ip(InboundIp { payload, src_addr }))
}

pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= IPV4_MIN_HEADER_SIZE => Some(IpAddr::from(
            read_addr::<IPV4_IP_SZ>(packet, IPV4_DST_IP_OFF).ok()?,
        )),
        6 if packet.len() >= IPV6_MIN_HEADER_SIZE => Some(IpAddr::from(
            read_addr::<IPV6_IP_SZ>(packet, IPV6_DST_IP_OFF).ok()?,
        )),
        _ => None,
    }
}
