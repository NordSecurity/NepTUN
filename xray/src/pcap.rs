use std::{net::SocketAddrV4, path::Path};

use neptun::noise::Tunn;
use pcap::Capture;
use pnet::packet::{
    ethernet::EtherTypes, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, sll2::SLL2Packet,
    udp::UdpPacket, Packet,
};

use crate::{client::Client, types::Packet as XrayPacket, types::XRayResult};

#[derive(Debug)]
pub struct PcapPacket {
    pub ts: u128,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub was_decrypted: bool,
    pub send_index: u64,
}

pub fn process_pcap<P: AsRef<Path>>(pcap_path: P, mut tunn: Tunn) -> XRayResult<Vec<PcapPacket>> {
    let mut packets = Vec::new();

    let mut capture = Capture::from_file(pcap_path)?;
    let mut decrypt_buf = vec![0; 1024];

    while let Ok(packet) = capture.next_packet() {
        let ts = packet.header.ts;
        let ts = ts.tv_sec as u128 * 1_000_000 + ts.tv_usec as u128;
        if let Some(packet) = process_packet(packet.data, ts, &mut tunn, &mut decrypt_buf) {
            packets.push(packet);
        }
    }

    Ok(packets)
}

fn process_packet(
    packet_data: &[u8],
    ts: u128,
    tunn: &mut Tunn,
    buf: &mut [u8],
) -> Option<PcapPacket> {
    let sll2_packet = match SLL2Packet::new(packet_data) {
        Some(packet) if matches!(packet.get_protocol_type(), EtherTypes::Ipv4) => packet,
        _ => return None,
    };

    let ipv4_packet = match Ipv4Packet::new(sll2_packet.payload()) {
        Some(packet) if matches!(packet.get_next_level_protocol(), IpNextHeaderProtocols::Udp) => {
            packet
        }
        _ => return None,
    };

    let udp_packet = match UdpPacket::new(ipv4_packet.payload()) {
        Some(packet) => packet,
        _ => return None,
    };

    let src = SocketAddrV4::new(ipv4_packet.get_source(), udp_packet.get_source());
    let dst = SocketAddrV4::new(ipv4_packet.get_destination(), udp_packet.get_destination());

    process_udp_packet(&udp_packet, tunn, buf).map(|(was_decrypted, send_index)| PcapPacket {
        ts,
        src,
        dst,
        was_decrypted,
        send_index,
    })
}

fn process_udp_packet(
    udp_packet: &UdpPacket,
    tunn: &mut Tunn,
    buf: &mut [u8],
) -> Option<(bool, u64)> {
    if udp_packet.payload().len() == XrayPacket::send_size() {
        let send_index = extract_send_index(udp_packet.payload());
        Some((false, send_index))
    } else if udp_packet.payload().starts_with(&[4, 0, 0, 0]) {
        let decrypted_packet = match tunn.decrypt(udp_packet.payload(), buf) {
            Ok(packet) => packet,
            Err(_) => return None,
        };
        match Client::parse_udp_packet(decrypted_packet) {
            Ok((_, start, end)) if end - start == XrayPacket::send_size() => {
                let send_index = extract_send_index(&decrypted_packet[start..]);
                Some((true, send_index))
            }
            _ => None,
        }
    } else {
        None
    }
}

fn extract_send_index(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(
        bytes[0..8]
            .try_into()
            .expect("Slice should have exactly 8 bytes"),
    )
}
