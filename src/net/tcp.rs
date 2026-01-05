use std::io::{Cursor, Write};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use crate::custom_module::manycastr::{address, Address};
use crate::net::{calculate_checksum, IPv4Packet, IPv6Packet, PacketPayload, PseudoHeader};

/// A TCPPacket <https://en.wikipedia.org/wiki/Transmission_Control_Protocol>
#[derive(Debug)]
pub struct TCPPacket {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    // offset and reserved are combined into a single u8 (reserved is all 0's)
    pub offset: u8,
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub pointer: u16,
    pub body: Vec<u8>,
}

/// Parsing from bytes to TCPPacket
impl From<&[u8]> for TCPPacket {
    fn from(data: &[u8]) -> Self {
        let mut data = Cursor::new(data);
        TCPPacket {
            sport: data.read_u16::<NetworkEndian>().unwrap(),
            dport: data.read_u16::<NetworkEndian>().unwrap(),
            seq: data.read_u32::<NetworkEndian>().unwrap(),
            ack: data.read_u32::<NetworkEndian>().unwrap(),
            offset: data.read_u8().unwrap(),
            flags: data.read_u8().unwrap(),
            window_size: data.read_u16::<NetworkEndian>().unwrap(),
            checksum: data.read_u16::<NetworkEndian>().unwrap(),
            pointer: data.read_u16::<NetworkEndian>().unwrap(),
            body: data.into_inner()[8..].to_vec(),
        }
    }
}

impl From<&TCPPacket> for Vec<u8> {
    fn from(packet: &TCPPacket) -> Self {
        let mut wtr = vec![];

        wtr.write_u16::<NetworkEndian>(packet.sport)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u16::<NetworkEndian>(packet.dport)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u32::<NetworkEndian>(packet.seq)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u32::<NetworkEndian>(packet.ack)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u8(packet.offset)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u8(packet.flags)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u16::<NetworkEndian>(packet.window_size)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u16::<NetworkEndian>(packet.checksum)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u16::<NetworkEndian>(packet.pointer)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_all(&packet.body)
            .expect("Unable to write to byte buffer for TCP packet");

        wtr
    }
}

impl TCPPacket {
    /// Create a basic TCP SYN/ACK packet with checksum
    pub fn tcp_syn_ack(
        src: &Address,
        dst: &Address,
        sport: u16,
        dport: u16,
        ack: u32,
        ttl: u8,
        info_url: &str,
    ) -> Vec<u8> {
        let mut tcp_packet = Self {
            sport,
            dport,
            seq: 0, // Sequence number is not reflected
            ack,
            offset: 0b01010000, // Offset 5 for minimum TCP header length (0101) + 0000 for reserved
            flags: 0b00010010,  // SYN and ACK flags
            checksum: 0,
            pointer: 0,
            body: info_url.bytes().collect(),
            window_size: 0,
        };

        // Turn everything into a vec of bytes and calculate checksum
        let tcp_bytes: Vec<u8> = (&tcp_packet).into();

        let pseudo_header = PseudoHeader::new(src, dst, 6, tcp_bytes.len() as u32);
        tcp_packet.checksum = calculate_checksum(&tcp_bytes, &pseudo_header);

        match (&src.value, &dst.value) {
            (Some(address::Value::V6(_)), Some(address::Value::V6(_))) => {
                let v6_packet = IPv6Packet {
                    payload_length: tcp_bytes.len() as u16,
                    flow_label: 15037,
                    next_header: 6, // TCP
                    hop_limit: ttl,
                    src: src.into(),
                    dst: dst.into(),
                    payload: PacketPayload::Tcp { value: tcp_packet },
                };
                (&v6_packet).into()
            }
            (Some(address::Value::V4(_)), Some(address::Value::V4(_))) => {
                let v4_packet = IPv4Packet {
                    length: 20 + tcp_bytes.len() as u16,
                    identifier: 15037,
                    ttl,
                    src: src.into(),
                    dst: dst.into(),
                    payload: PacketPayload::Tcp { value: tcp_packet },
                    options: None,
                };
                (&v4_packet).into()
            }
            _ => panic!("IP version mismatch or invalid address in tcp_syn_ack"),
        }
    }
}
