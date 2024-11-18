use std::net::{SocketAddr, SocketAddrV4};

use neptun::noise::{Tunn, TunnResult};
use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Packet, MutableIpv4Packet},
    udp::{MutableUdpPacket, UdpPacket},
    Packet,
};
use tokio::net::UdpSocket;

use crate::utils::{RecvType, SendType};

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

    pub async fn do_handshake(&mut self, wg_addr: SocketAddrV4) {
        println!("Handshake: starting");
        let tunn = self.tunn.as_mut().unwrap();
        match tunn.format_handshake_initiation(&mut self.buf, true) {
            TunnResult::WriteToNetwork(packet) => {
                self.sock.send_to(packet, wg_addr).await.unwrap();
            }
            unexpected => println!("Received unexpected TunnResult: {unexpected:?}"),
        }
        let mut handshake_buf = vec![0; 512];
        loop {
            let recv_type = self.recv_encrypted(&mut handshake_buf).await;
            if matches!(recv_type, RecvType::Handshake) {
                break;
            }
        }
        println!("Handshake: done");
    }

    pub async fn send_packet(
        &mut self,
        sock_dst: SocketAddrV4,
        packet_dst: SocketAddrV4,
        payload: &[u8],
    ) -> SendType {
        if self.tunn.is_some() {
            self.send_encrypted(sock_dst, packet_dst, payload).await
        } else {
            self.send_plaintext(sock_dst, payload).await
        }
    }

    pub async fn recv_packet(&mut self, buf: &mut [u8]) -> RecvType {
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
    ) -> SendType {
        let tunn = &mut self.tunn.as_mut().unwrap();
        let packet = Self::make_udp_packet(self.addr, packet_dst, payload);
        let tr = tunn.encapsulate(&packet, &mut self.buf);
        let (send_type, packet): (SendType, &[u8]) = match tr {
            TunnResult::Done => (SendType::None, &[]),
            TunnResult::WriteToNetwork(p) => match p[0] {
                1 => (SendType::Handshake, p),
                4 => (SendType::Data, p),
                unexpected => panic!("Unexpected packet type {unexpected}"),
            },
            TunnResult::WriteToTunnelV4(p, _) => (SendType::Tunn, p),
            unexpected => panic!("Unexpected TunnResult: {unexpected:?}"),
        };
        if !matches!(send_type, SendType::None) {
            self.sock.send_to(packet, sock_dst).await.unwrap();
        }
        send_type
    }

    async fn send_plaintext(&mut self, dst: SocketAddrV4, payload: &[u8]) -> SendType {
        self.sock.send_to(payload, dst).await.unwrap();
        SendType::Plaintext
    }

    async fn recv_encrypted(&mut self, buf: &mut [u8]) -> RecvType {
        let (mut bytes_read, from) = self.sock.recv_from(&mut self.buf).await.unwrap();
        let from = match from {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("IPv6 not supported"),
        };
        let mut ret = if self.buf[0] == 2 {
            RecvType::Handshake
        } else if self.buf[0] == 4 {
            RecvType::Data { from, length: 0 }
        } else {
            panic!("Unexpected packet type {}", self.buf[0])
        };
        let mut decap_buf = vec![0; 1024];
        loop {
            let tr = self.tunn.as_mut().unwrap().decapsulate(
                None,
                &self.buf[0..bytes_read],
                &mut decap_buf,
            );
            match tr {
                TunnResult::Done => break,
                TunnResult::WriteToNetwork(p) => {
                    self.sock.send_to(p, from).await.unwrap();
                    bytes_read = 0;
                }
                TunnResult::WriteToTunnelV4(p, _) => {
                    let (pfrom, payload_start, payload_end) = Self::parse_udp_packet(p);
                    assert!(buf.len() >= payload_end - payload_start);
                    buf.iter_mut()
                        .zip(p[payload_start..payload_end].iter())
                        .for_each(|(b, p)| *b = *p);
                    ret = RecvType::Data {
                        from: pfrom,
                        length: payload_end - payload_start,
                    };
                    break;
                }
                unexpected => panic!("Unexpected TunnResult: {unexpected:?}"),
            }
        }
        ret
    }

    async fn recv_plaintext(&mut self, buf: &mut [u8]) -> RecvType {
        let (bytes_read, from) = self.sock.recv_from(buf).await.unwrap();
        let from = match from {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("IPv6 not supported"),
        };
        RecvType::Data {
            length: bytes_read,
            from,
        }
    }

    fn make_udp_packet(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let len = 28 + payload.len(); // IP header (20 bytes) + UDP heder (8 bytes) + payload length
        let mut udp_packet = vec![0; len];
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut udp_packet).unwrap();
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
            let mut udp = MutableUdpPacket::new(&mut udp_packet[20..]).unwrap();
            udp.set_source(src.port());
            udp.set_destination(dst.port());
            udp.set_length(8 + payload.len() as u16);
            udp.set_payload(payload);
            // TODO: Calculate checksum
            udp.set_checksum(0);
        }
        udp_packet
    }

    fn parse_udp_packet(packet: &[u8]) -> (SocketAddrV4, usize, usize) {
        let ip_packet = Ipv4Packet::new(packet).unwrap();
        let udp_packet = UdpPacket::new(ip_packet.payload()).unwrap();
        let from = SocketAddrV4::new(ip_packet.get_source(), udp_packet.get_source());
        let payload_start = (ip_packet.get_header_length() as usize * 4) + 8;
        (
            from,
            payload_start,
            payload_start + udp_packet.payload().len(),
        )
    }
}
