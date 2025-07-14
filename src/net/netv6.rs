use std::io::{Cursor, Write};
use super::byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use super::{ICMPPacket, PacketPayload};

/// A struct detailing an IPv6Packet <https://en.wikipedia.org/wiki/IPv6>
#[derive(Debug)]
pub struct IPv6Packet {
    // pub version: u8,                 // 4-bit Version
    // pub traffic_class: u8,           // 8-bit Traffic Class
    // pub flow_label: u32,             // 20-bit Flow Label
    pub payload_length: u16,    // 16-bit Payload Length
    pub next_header: u8,        // 8-bit Next Header
    pub hop_limit: u8,          // 8-bit Hop Limit
    pub src: u128,              // 128-bit Source Address
    pub dst: u128,              // 128-bit Destination Address
    pub payload: PacketPayload, // Payload
}

/// Convert bytes into an IPv6Packet
impl From<&[u8]> for IPv6Packet {
    fn from(data: &[u8]) -> Self {
        let mut cursor = Cursor::new(data);
        let _version_traffic_flow: u32 = cursor.read_u32::<NetworkEndian>().unwrap();
        let payload_length = cursor.read_u16::<NetworkEndian>().unwrap();
        let next_header = cursor.read_u8().unwrap();
        let hop_limit = cursor.read_u8().unwrap();

        let source_address = cursor.read_u128::<NetworkEndian>().unwrap();
        let destination_address = cursor.read_u128::<NetworkEndian>().unwrap();
        let payload_bytes = &cursor.into_inner()[40..]; // IPv6 header is 40 bytes

        // Implement PacketPayload based on the next_header value
        let payload = match next_header {
            //TODO extension headers
            58 => {
                // ICMPv6
                PacketPayload::ICMP {
                    value: super::ICMPPacket::from(payload_bytes),
                }
            }
            17 => {
                // UDP
                if payload_bytes.len() < 8 {
                    PacketPayload::Unimplemented
                } else {
                    PacketPayload::UDP {
                        value: super::UDPPacket::from(payload_bytes),
                    }
                }
            }
            6 => {
                // TCP
                if payload_bytes.len() < 20 {
                    PacketPayload::Unimplemented
                } else {
                    PacketPayload::TCP {
                        value: super::TCPPacket::from(payload_bytes),
                    }
                }
            }
            _ => PacketPayload::Unimplemented,
        };

        IPv6Packet {
            // version: (version_traffic_class >> 12) as u8,
            // traffic_class: ((version_traffic_class >> 4) & 0xFF) as u8,
            // flow_label,
            payload_length,
            next_header,
            hop_limit,
            src: source_address,
            dst: destination_address,
            payload,
        }
    }
}

/// Convert an IPv6Packet into bytes
impl Into<Vec<u8>> for &IPv6Packet {
    fn into(self) -> Vec<u8> {
        let mut wtr = vec![];
        // Write traffic class 0x60 and flow label 0x003a7d
        wtr.write_u32::<NetworkEndian>(0x60003a7d)
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.payload_length)
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u8(self.next_header)
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u8(self.hop_limit)
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u128::<NetworkEndian>(self.src)
            .expect("Unable to write source address to byte buffer for IPv6Packet");
        wtr.write_u128::<NetworkEndian>(self.dst)
            .expect("Unable to write destination address to byte buffer for IPv6Packet");

        let payload = match &self.payload {
            PacketPayload::ICMP { value } => value.into(),
            PacketPayload::UDP { value } => value.into(),
            PacketPayload::TCP { value } => value.into(),
            PacketPayload::Unimplemented => vec![],
        };
        
        wtr.write_all(&payload)
            .expect("Unable to write payload to byte buffer for IPv6Packet");
        
        wtr
    }
}

impl ICMPPacket {
    /// Create an ICMPv6 echo request packet with checksum
    ///
    /// # Arguments
    ///
    /// * 'identifier' - the identifier for this packet
    ///
    /// * 'sequence_number' - the sequence number for this packet
    ///
    /// * 'body' - the payload of the packet
    ///
    /// * 'source_address' - the source address of the packet
    ///
    /// * 'destination_address' - the destination address of the packet
    ///
    /// * 'hop_limit' - the hop limit (TTL) of the packet
    ///
    /// * 'info_url' - URL encoded in packet payload (e.g., opt-out URL)
    pub fn echo_request_v6(
        identifier: u16,
        sequence_number: u16,
        body: Vec<u8>,
        src: u128,
        dst: u128,
        hop_limit: u8,
        info_url: &str,
    ) -> Vec<u8> {
        let body_len = body.len() as u16;
        let mut packet = ICMPPacket {
            icmp_type: 128,
            code: 0,
            checksum: 0,
            identifier,
            sequence_number,
            body,
        };
        let icmp_bytes: Vec<u8> = (&packet).into();

        // Append a pseudo header to the ICMP packet bytes
        let mut psuedo_header: Vec<u8> = Vec::new();
        psuedo_header
            .write_u128::<NetworkEndian>(src)
            .expect("Unable to write to byte buffer for PseudoHeader");
        psuedo_header
            .write_u128::<NetworkEndian>(dst)
            .expect("Unable to write to byte buffer for PseudoHeader");
        psuedo_header
            .write_u32::<NetworkEndian>((8 + body_len + info_url.bytes().len() as u16) as u32) // ICMP length
            .expect("Unable to write to byte buffer for PseudoHeader"); // Length of ICMP header + body
        psuedo_header.write_u8(0).unwrap(); // zeroes
        psuedo_header.write_u8(0).unwrap(); // zeroes
        psuedo_header.write_u8(0).unwrap(); // zeroes
        psuedo_header.write_u8(58).unwrap(); // next header (58 => ICMPv6)
        psuedo_header.extend(icmp_bytes); // Add the ICMP packet bytes
        psuedo_header.extend(info_url.bytes()); // Add the INFO_URL bytes
        packet.checksum = ICMPPacket::calc_checksum(psuedo_header.as_slice()); // Calculate the checksum

        let v6_packet = IPv6Packet {
            payload_length: 8 + body_len + info_url.bytes().len() as u16, // ICMP header (8 bytes) + body length
            next_header: 58,                                              // ICMPv6
            hop_limit,
            src,
            dst,
            payload: PacketPayload::ICMP { value: packet },
        };

        let mut bytes: Vec<u8> = (&v6_packet).into();
        bytes.extend(info_url.bytes());

        bytes
    }
}