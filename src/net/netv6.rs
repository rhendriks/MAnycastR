use super::byteorder::{LittleEndian, NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};
use std::io::Write;
use std::net::Ipv6Addr;
use crate::net::PacketPayload;

/// A struct detailing an IPv6Packet <https://en.wikipedia.org/wiki/IPv6>
#[derive(Debug)]
pub struct IPv6Packet {
    // pub version: u8,             // 4-bit Version
    // pub traffic_class: u8,       // 8-bit Traffic Class
    // pub flow_label: u32,         // 20-bit Flow Label
    pub payload_length: u16,     // 16-bit Payload Length
    // pub next_header: u8,         // 8-bit Next Header
    // pub hop_limit: u8,           // 8-bit Hop Limit
    pub source_address: Ipv6Addr,
    pub destination_address: Ipv6Addr,
    pub payload: PacketPayload,
}

/// Convert list of u8 (i.e. received bytes) into an IPv6Packet
impl From<&[u8]> for IPv6Packet {
    fn from(data: &[u8]) -> Self {
        let mut cursor = Cursor::new(data);
        cursor.set_position(4); // Payload length
        let payload_length = cursor.read_u16::<NetworkEndian>().unwrap();
        // TODO can use payload_length to determine extension headers / making sure packet can be parsed into icmp/udp/tcp
        let next_header = cursor.read_u8().unwrap();
        // TODO can use next header to see what kind of payload it is carrying (icmp/udp/tcp)
        let hop_limit = cursor.read_u8().unwrap(); // Hop limit (similar to TTL)

        let source_address = Ipv6Addr::new(
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap()
        );

        let destination_address = Ipv6Addr::new(
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap(),
            cursor.read_u16::<NetworkEndian>().unwrap()
        );

        // TODO extension headers

        let payload_bytes = &cursor.into_inner()[40..]; // IPv6 header is 40 bytes

        // Implement PacketPayload based on the next_header value
        let payload = match next_header { //TODO
            1 => {
                // ICMPv6 implementation here
                PacketPayload::Unimplemented
            },
            17 => {
                // UDP implementation here
                PacketPayload::Unimplemented
            },
            6 => {
                // TCP implementation here
                PacketPayload::Unimplemented
            },
            _ => PacketPayload::Unimplemented,
        };

        IPv6Packet {
            // version: (version_traffic_class >> 12) as u8,
            // traffic_class: ((version_traffic_class >> 4) & 0xFF) as u8,
            // flow_label,
            payload_length,
            // next_header,
            // hop_limit,
            source_address,
            destination_address,
            payload,
        }
    }
}