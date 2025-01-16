use std::{
    net::{SocketAddr, SocketAddrV4},
    time::Duration,
};

use neptun::noise::{Tunn, TunnResult};
use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Packet, MutableIpv4Packet},
    udp::{self, MutableUdpPacket, UdpPacket},
    Packet,
};
use tokio::net::UdpSocket;

use crate::types::{RecvType, SendType, XRayError, XRayResult};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const HANDSHAKE_MAX_TRIES: usize = 5;

pub struct Client {
    pub addr: SocketAddrV4,
    pub tunn: Option<Tunn>,
    pub sock: UdpSocket,
    buf: Vec<u8>,
}

impl Client {
    pub fn new(addr: SocketAddrV4, tunn: Option<Tunn>, sock: UdpSocket) -> Self {
        Self {
            addr,
            tunn,
            sock,
            buf: vec![0; 4096],
        }
    }

    pub async fn do_handshake(&mut self, wg_addr: SocketAddrV4) -> XRayResult<()> {
        println!("Handshake: starting");
        for _ in 0..HANDSHAKE_MAX_TRIES {
            match self.try_handshake(wg_addr).await {
                Ok(_) => {
                    println!("Handshake: done");
                    return Ok(());
                }
                Err(XRayError::HandshakeTimedOut) => {
                    println!("Handshake timed out")
                }
                Err(err) => {
                    println!("Handshake failed");
                    return Err(err);
                }
            }
        }
        println!("Could not establish handshake");
        Err(XRayError::HandshakeTimedOut)
    }

    async fn try_handshake(&mut self, wg_addr: SocketAddrV4) -> XRayResult<()> {
        let tunn = self
            .tunn
            .as_mut()
            .expect("This function should only be called on clients with a Tunn object");
        match tunn.format_handshake_initiation(&mut self.buf, true) {
            TunnResult::WriteToNetwork(packet) => {
                self.sock.send_to(packet, wg_addr).await?;
            }
            unexpected => {
                return Err(XRayError::UnexpectedTunnResult(format!("{unexpected:?}")));
            }
        }
        let mut handshake_buf = vec![0; 512];
        tokio::time::timeout(HANDSHAKE_TIMEOUT, self.recv_handshake(&mut handshake_buf))
            .await
            .map_err(|_| XRayError::HandshakeTimedOut)??;
        Ok(())
    }

    async fn recv_handshake(&mut self, buf: &mut [u8]) -> XRayResult<()> {
        loop {
            if let Ok(recv_type) = self.recv_encrypted(buf).await {
                if matches!(recv_type, RecvType::HandshakeResponse) {
                    return Ok(());
                }
            }
        }
    }

    pub async fn send_packet(
        &mut self,
        sock_dst: SocketAddrV4,
        packet_dst: SocketAddrV4,
        payload: &[u8],
    ) -> XRayResult<SendType> {
        if self.tunn.is_some() {
            self.send_encrypted(sock_dst, packet_dst, payload).await
        } else {
            self.send_plaintext(sock_dst, payload).await
        }
    }

    pub async fn recv_packet(&mut self, buf: &mut [u8]) -> XRayResult<RecvType> {
        if self.tunn.is_some() {
            self.recv_encrypted(buf).await
        } else {
            self.recv_plaintext(buf).await
        }
    }

    pub async fn tick_timers(&mut self, wg_addr: SocketAddrV4) {
        if let Some(ref mut tunn) = &mut self.tunn {
            match tunn.update_timers(&mut self.buf) {
                TunnResult::Done => (),
                TunnResult::WriteToNetwork(packet) => {
                    if let Err(e) = self.sock.send_to(packet, wg_addr).await {
                        println!("Update Tunn timers failed to send to socket: {:?}", e);
                    }
                }
                TunnResult::Err(e) => {
                    println!("Failed to update Tunn timers: {:?}", e);
                }
                unexpected_result => println!(
                    "Update Tunn timers returned unexpected result: {:?}",
                    unexpected_result
                ),
            }
        }
    }

    async fn send_encrypted(
        &mut self,
        sock_dst: SocketAddrV4,
        packet_dst: SocketAddrV4,
        payload: &[u8],
    ) -> XRayResult<SendType> {
        let tunn = &mut self
            .tunn
            .as_mut()
            .expect("This function should only be called on clients with a Tunn object");
        let packet = Self::make_udp_packet(self.addr, packet_dst, payload)?;
        let tr = tunn.encapsulate(&packet, &mut self.buf);
        let (send_type, packet): (SendType, &[u8]) = match tr {
            TunnResult::Done => (SendType::None, &[]),
            TunnResult::WriteToNetwork(p) => match p[0] {
                1 => (SendType::HandshakeInitiation, p),
                2 => (SendType::HandshakeResponse, p),
                4 => (SendType::Data, p),
                unexpected => return Err(XRayError::UnexpectedPacketType(unexpected)),
            },
            unexpected => return Err(XRayError::from(unexpected)),
        };
        if !matches!(send_type, SendType::None) {
            self.sock.send_to(packet, sock_dst).await?;
        }
        Ok(send_type)
    }

    async fn send_plaintext(&mut self, dst: SocketAddrV4, payload: &[u8]) -> XRayResult<SendType> {
        self.sock.send_to(payload, dst).await?;
        Ok(SendType::Plaintext)
    }

    async fn recv_encrypted(&mut self, buf: &mut [u8]) -> XRayResult<RecvType> {
        let (mut bytes_read, from) = self.sock.recv_from(&mut self.buf).await?;
        let from = match from {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => return Err(XRayError::Ipv6),
        };
        let mut ret = match self.buf[0] {
            1 => RecvType::HandshakeInitiation,
            2 => RecvType::HandshakeResponse,
            4 => RecvType::Data { length: 0 },
            unexpected => return Err(XRayError::UnexpectedPacketType(unexpected)),
        };
        let mut decap_buf = vec![0; 1024];
        loop {
            let tr = self
                .tunn
                .as_mut()
                .expect("This function should only be called on clients with a Tunn object")
                .decapsulate(None, &self.buf[0..bytes_read], &mut decap_buf);
            match tr {
                TunnResult::Done => break,
                TunnResult::WriteToNetwork(p) => {
                    self.sock.send_to(p, from).await?;
                    bytes_read = 0;
                }
                TunnResult::WriteToTunnelV4(p, _) => {
                    let (_, payload_start, payload_end) = Self::parse_udp_packet(p)?;
                    assert!(buf.len() >= payload_end - payload_start);
                    buf[0..payload_end - payload_start]
                        .copy_from_slice(&p[payload_start..payload_end]);
                    ret = RecvType::Data {
                        length: payload_end - payload_start,
                    };
                    bytes_read = 0;
                }
                unexpected => return Err(XRayError::from(unexpected)),
            }
        }
        Ok(ret)
    }

    async fn recv_plaintext(&mut self, buf: &mut [u8]) -> XRayResult<RecvType> {
        let (length, from) = self.sock.recv_from(buf).await?;
        match from {
            SocketAddr::V4(_) => Ok(RecvType::Data { length }),
            SocketAddr::V6(_) => Err(XRayError::Ipv6),
        }
    }

    fn make_udp_packet(
        src: SocketAddrV4,
        dst: SocketAddrV4,
        payload: &[u8],
    ) -> XRayResult<Vec<u8>> {
        let len = 28 + payload.len(); // IP header (20 bytes) + UDP heder (8 bytes) + payload length
        let mut udp_packet = vec![0; len];
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut udp_packet).ok_or(XRayError::PacketParse)?;
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(len as u16);
            ipv4.set_ttl(20);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4.set_source(*src.ip());
            ipv4.set_destination(*dst.ip());
            ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));
        }
        {
            let mut udp =
                MutableUdpPacket::new(&mut udp_packet[20..]).ok_or(XRayError::PacketParse)?;
            udp.set_source(src.port());
            udp.set_destination(dst.port());
            udp.set_length(8 + payload.len() as u16);
            udp.set_payload(payload);
            udp.set_checksum(udp::ipv4_checksum(&udp.to_immutable(), src.ip(), dst.ip()));
        }
        Ok(udp_packet)
    }

    pub fn parse_udp_packet(packet: &[u8]) -> XRayResult<(SocketAddrV4, usize, usize)> {
        let ip_packet = Ipv4Packet::new(packet).ok_or(XRayError::PacketParse)?;
        let udp_packet = UdpPacket::new(ip_packet.payload()).ok_or(XRayError::PacketParse)?;
        let from = SocketAddrV4::new(ip_packet.get_source(), udp_packet.get_source());
        let payload_start = (ip_packet.get_header_length() as usize * 4) + 8;
        Ok((
            from,
            payload_start,
            payload_start + udp_packet.payload().len(),
        ))
    }
}
