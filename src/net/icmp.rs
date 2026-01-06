use crate::custom_module::manycastr::{address, Address};
use crate::net::{record_route_option, IPv4Packet, IPv6Packet, PacketPayload};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Write};

/// An ICMP Packet (ping packet) <https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#header_rest>
#[derive(Debug)]
pub struct ICMPPacket {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub icmp_identifier: u16,
    pub sequence_number: u16,
    pub payload: Vec<u8>,
}

/// Parsing from bytes to ICMPPacket
impl From<&[u8]> for ICMPPacket {
    fn from(data: &[u8]) -> Self {
        let mut data = Cursor::new(data);
        ICMPPacket {
            icmp_type: data.read_u8().unwrap(),
            code: data.read_u8().unwrap(),
            checksum: data.read_u16::<NetworkEndian>().unwrap(),
            icmp_identifier: data.read_u16::<NetworkEndian>().unwrap(),
            sequence_number: data.read_u16::<NetworkEndian>().unwrap(),
            payload: data.into_inner()[8..].to_vec(),
        }
    }
}

/// Convert ICMP Packet into a vector of bytes
impl From<&ICMPPacket> for Vec<u8> {
    fn from(packet: &ICMPPacket) -> Self {
        let mut wtr = vec![];
        wtr.write_u8(packet.icmp_type)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_u8(packet.code)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_u16::<NetworkEndian>(packet.checksum)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_u16::<NetworkEndian>(packet.icmp_identifier)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_u16::<NetworkEndian>(packet.sequence_number)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_all(&packet.payload)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr
    }
}

impl ICMPPacket {
    /// Create a basic ICMP ECHO_REQUEST (8.0) packet with checksum.
    ///
    /// # Arguments
    /// * 'icmp_identifier' - the identifier for the ICMP header
    /// * 'sequence_number' - the sequence number for the ICMP header
    /// * 'body' - the ICMP payload
    /// * 'src' - the source address of the packet
    /// * 'dst' - the destination address of the packet
    /// * 'ttl' - the time to live of the packet
    pub fn echo_request(
        icmp_identifier: u16,
        sequence_number: u16,
        body: Vec<u8>,
        src: &Address,
        dst: &Address,
        ttl: u8,
    ) -> Vec<u8> {
        let body_len = body.len() as u16;

        match (src.value, dst.value) {
            (Some(address::Value::V4(src)), Some(address::Value::V4(dst))) => {
                let mut packet = ICMPPacket {
                    icmp_type: 8, // ICMPv4 Echo Request
                    code: 0,
                    checksum: 0,
                    icmp_identifier,
                    sequence_number,
                    payload: body,
                };

                // V4 Checksum: ICMP packet bytes
                let icmp_bytes: Vec<u8> = (&packet).into();
                packet.checksum = ICMPPacket::calc_checksum(&icmp_bytes);

                let v4_packet = IPv4Packet {
                    length: 20 + 8 + body_len,
                    identifier: 15037,
                    ttl,
                    src,
                    dst,
                    payload: PacketPayload::Icmp { value: packet },
                    options: None,
                };
                (&v4_packet).into()
            }

            (Some(address::Value::V6(src)), Some(address::Value::V6(dst))) => {
                let src_u128 = (src.high as u128) << 64 | (src.low as u128);
                let dst_u128 = (dst.high as u128) << 64 | (dst.low as u128);
                let mut packet = ICMPPacket {
                    icmp_type: 128,
                    code: 0,
                    checksum: 0,
                    icmp_identifier,
                    sequence_number,
                    payload: body,
                };
                let icmp_bytes: Vec<u8> = (&packet).into();

                // Pseudo-header calculation
                let mut pseudo = Vec::new();
                pseudo.write_u128::<NetworkEndian>(src_u128).unwrap();
                pseudo.write_u128::<NetworkEndian>(dst_u128).unwrap();
                pseudo
                    .write_u32::<NetworkEndian>((8 + packet.payload.len()) as u32)
                    .unwrap();
                pseudo.extend_from_slice(&[0, 0, 0, 58]);
                pseudo.extend(icmp_bytes);

                packet.checksum = ICMPPacket::calc_checksum(&pseudo);

                let v6_packet = IPv6Packet {
                    payload_length: 8 + (packet.payload.len() as u16),
                    flow_label: 15037,
                    next_header: 58,
                    hop_limit: ttl,
                    src: src_u128,
                    dst: dst_u128,
                    payload: PacketPayload::Icmp { value: packet },
                };
                (&v6_packet).into()
            }

            _ => panic!("Source and Destination IP versions must match"),
        }
    }

    /// Create an ICMPv4 packet with Record Route option and checksum.
    pub fn record_route_icmpv4(
        icmp_identifier: u16,
        sequence_number: u16,
        payload: Vec<u8>,
        src: u32,
        dst: u32,
        ttl: u8,
    ) -> Vec<u8> {
        let body_len = payload.len() as u16;
        let mut packet = ICMPPacket {
            icmp_type: 8, // Echo Request
            code: 0,
            checksum: 0,
            icmp_identifier,
            sequence_number,
            payload,
        };

        // Turn everything into a vec of bytes and calculate checksum
        let icmp_bytes: Vec<u8> = (&packet).into();
        packet.checksum = ICMPPacket::calc_checksum(&icmp_bytes);

        let options = record_route_option();
        let v4_packet = IPv4Packet {
            length: 20 + 8 + body_len + options.len() as u16, // IP header (20) + ICMP header (8) + body length + options length
            identifier: 15037,
            ttl,
            src,
            dst,
            options: Some(options),
            payload: PacketPayload::Icmp { value: packet },
        };

        (&v4_packet).into()
    }

    /// Calculate the ICMP Checksum.
    ///
    /// This calculation covers the entire ICMP  message (16-bit one's complement).
    /// Works for both ICMPv4 and ICMPv6
    pub(crate) fn calc_checksum(buffer: &[u8]) -> u16 {
        let mut cursor = Cursor::new(buffer);
        let mut sum: u32 = 0;
        while let Ok(word) = cursor.read_u16::<NetworkEndian>() {
            // Sum all 16-bit words
            sum += u32::from(word);
        }
        if let Ok(byte) = cursor.read_u8() {
            // If there is a byte left, sum it
            sum += u32::from(byte);
        }
        while sum >> 16 > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !sum as u16
    }
}
