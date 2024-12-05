use std::net::SocketAddrV4;

use neptun::noise::Tunn;
use pcap::Capture;
use pnet::packet::{ipv4::Ipv4Packet, sll2::SLL2Packet, udp::UdpPacket, Packet as _};

use crate::{client::Client, utils::Packet, XRayResult};

#[derive(Debug)]
pub struct PcapPacket {
    pub ts: u128,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub was_decrypted: bool,
    pub send_index: u64,
}

pub fn process_pcap(pcap_path: &str, mut tunn: Tunn) -> XRayResult<Vec<PcapPacket>> {
    let mut packets = Vec::new();

    let mut capture = Capture::from_file(pcap_path)?;
    let mut decrypt_buf = vec![0; 1024];

    'top_level: while let Ok(packet) = capture.next_packet() {
        let ts = packet.header.ts;
        let ts = ts.tv_sec as u128 * 1_000_000 + ts.tv_usec as u128;
        if let Some(sll2_packet) = SLL2Packet::new(packet.data) {
            if let Some(ipv4_packet) = Ipv4Packet::new(sll2_packet.payload()) {
                if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                    let (was_decrypted, send_index) =
                        if udp_packet.payload().len() == Packet::send_size() {
                            let send_index = u64::from_le_bytes(
                                udp_packet.payload()[0..8]
                                    .try_into()
                                    .expect("Slice should have exactly 8 bytes"),
                            );
                            (false, send_index)
                        } else if udp_packet.payload().starts_with(&[4, 0, 0, 0]) {
                            let decrypted_packet =
                                match tunn.decrypt(udp_packet.payload(), &mut decrypt_buf) {
                                    Ok(packet) => packet,
                                    Err(_) => continue 'top_level,
                                };
                            let (_, start, end) = Client::parse_udp_packet(decrypted_packet)?;
                            if end - start != Packet::send_size() {
                                continue 'top_level;
                            }
                            let send_index = u64::from_le_bytes(
                                decrypted_packet[start..start + 8]
                                    .try_into()
                                    .expect("Packet should have a valid index"),
                            );
                            (true, send_index)
                        } else {
                            continue 'top_level;
                        };
                    let packet = PcapPacket {
                        ts,
                        src: SocketAddrV4::new(ipv4_packet.get_source(), udp_packet.get_source()),
                        dst: SocketAddrV4::new(
                            ipv4_packet.get_destination(),
                            udp_packet.get_destination(),
                        ),
                        was_decrypted,
                        send_index,
                    };
                    packets.push(packet);
                }
            }
        }
    }

    Ok(packets)
}
