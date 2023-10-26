use super::byteorder::{LittleEndian, NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};
use std::io::Write;
use std::net::Ipv6Addr;
use super::PacketPayload;

/// A struct detailing an IPv6Packet <https://en.wikipedia.org/wiki/IPv6>
#[derive(Debug)]
pub struct IPv6Packet {
    // pub version: u8,             // 4-bit Version
    // pub traffic_class: u8,       // 8-bit Traffic Class
    // pub flow_label: u32,         // 20-bit Flow Label
    pub payload_length: u16,      // 16-bit Payload Length
    // pub next_header: u8,         // 8-bit Next Header
    pub hop_limit: u8,           // 8-bit Hop Limit
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

        // TODO anycast ipv6?

        let payload_bytes = &cursor.into_inner()[40..]; // IPv6 header is 40 bytes

        // Implement PacketPayload based on the next_header value
        let payload = match next_header { //TODO extension headers
            1 => { // ICMPv6
                // ICMPv6 implementation here
                PacketPayload::Unimplemented
            },
            17 => { // UDP
                if payload_bytes.len() < 8 { PacketPayload::Unimplemented }
                else {
                    PacketPayload::UDP {
                        value: super::UDPPacket::from(payload_bytes),
                    }
                }
            },
            6 => { // TCP
                if payload_bytes.len() < 20 { PacketPayload::Unimplemented }
                else {
                    PacketPayload::TCP {
                        value: super::TCPPacket::from(payload_bytes),
                    }
                }
            },
            _ => PacketPayload::Unimplemented,
        };

        IPv6Packet {
            // version: (version_traffic_class >> 12) as u8,
            // traffic_class: ((version_traffic_class >> 4) & 0xFF) as u8,
            // flow_label,
            payload_length,
            // next_header,
            hop_limit,
            source_address,
            destination_address,
            payload,
        }
    }
}

// TODO calculate checksum for udp/tcp with ipv6header
/// Struct defining a pseudo header (ipv6) that is used by both TCP and UDP to calculate their checksum
#[derive(Debug)]
pub struct PseudoHeaderv6 {
    pub source_address: u128,
    pub destination_address: u128,
    pub length: u32,  // TCP/UDP header + data length
    // pub zeros: u24, // 24 0's
    pub next_header: u8  // 6 for TCP, 17 for UDP
}

/// Converting PsuedoHeaderv6 to bytes
impl Into<Vec<u8>> for PseudoHeaderv6 {
    fn into(self) -> Vec<u8> {
        let mut wtr = vec![];
        wtr.write_u128::<NetworkEndian>(self.source_address)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u128::<NetworkEndian>(self.destination_address)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u32::<NetworkEndian>(self.length)
            .expect("Unable to write to byte buffer for PseudoHeader");
        // wtr.write_u24(self.zeroes) // TODO needed?
        //     .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u8(self.next_header)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr
    }
}

/// Calculate the checksum for an IPv6 UDP/TCP packet.
///
/// # Arguments
///
/// * 'buffer' - the UDP/TCP packet as bytes (without the IPv4 header)
///
/// * 'pseudo_header' - the pseudo header for this packet
pub fn calculate_checksum_v6(buffer: &[u8], pseudo_header: &PseudoHeaderv6) -> u16 { // TODO untested
    // Convert the PseudoHeaderv6 to a byte vector manually // TODO use Into<Vec<u8>> for PseudoHeaderv6
    let mut pseudo_header_bytes = vec![];
    pseudo_header_bytes.write_u128::<NetworkEndian>(pseudo_header.source_address)
        .expect("Failed to write source_address to pseudo-header");
    pseudo_header_bytes.write_u128::<NetworkEndian>(pseudo_header.destination_address)
        .expect("Failed to write destination_address to pseudo-header");
    pseudo_header_bytes.write_u32::<NetworkEndian>(pseudo_header.length)
        .expect("Failed to write length to pseudo-header");
    pseudo_header_bytes.write_u8(pseudo_header.next_header)
        .expect("Failed to write next_header to pseudo-header");

    // Concatenate the pseudo-header bytes and the UDP/TCP packet bytes
    let mut data = pseudo_header_bytes;
    data.extend_from_slice(buffer);

    // Divide the concatenated data into 16-bit words and calculate the sum
    let mut sum = 0u32;
    for i in (0..data.len()).step_by(2) {
        let word = u16::from_le_bytes([data[i], data[i + 1]]);
        sum = sum.wrapping_add(u32::from(word));
    }

    // Take the one's complement of the sum
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // The result is the 16-bit checksum
    !sum as u16
}

