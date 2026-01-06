extern crate byteorder;
use std::io::{Cursor, Read, Write};

use crate::custom_module::manycastr::{address, Address, RecordedHops};
pub(crate) use crate::net::icmp::ICMPPacket;
use crate::net::tcp::TCPPacket;
pub(crate) use crate::net::udp::{DNSAnswer, DNSRecord, TXTRecord, UDPPacket};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};

mod icmp;
pub(crate) mod packet;
mod tcp;
mod udp;

/// Enum representing either an IPv4 or IPv6 packet.
#[derive(Debug)]
pub enum IPPacket {
    V4(IPv4Packet),
    V6(IPv6Packet),
}

/// Methods for IPPacket
impl IPPacket {
    /// Returns the source IP address.
    pub fn src(&self) -> Address {
        match self {
            IPPacket::V4(packet) => Address::from(packet.src),
            IPPacket::V6(packet) => Address::from(packet.src),
        }
    }

    /// Returns the destination IP address.
    pub fn dst(&self) -> Address {
        match self {
            IPPacket::V4(packet) => Address::from(packet.dst),
            IPPacket::V6(packet) => Address::from(packet.dst),
        }
    }

    /// Returns the Time To Live (IPv4) or Hop Limit (IPv6).
    pub fn ttl(&self) -> u8 {
        match self {
            IPPacket::V4(packet) => packet.ttl,
            IPPacket::V6(packet) => packet.hop_limit,
        }
    }

    /// Returns a reference to the payload.
    pub fn payload(&self) -> &PacketPayload {
        match self {
            IPPacket::V4(packet) => &packet.payload,
            IPPacket::V6(packet) => &packet.payload,
        }
    }
}

/// A struct detailing an IPv4Packet <https://en.wikipedia.org/wiki/Internet_Protocol_version_4>
#[derive(Debug)]
pub struct IPv4Packet {
    pub length: u16,              // 16-bit Total Length
    pub ttl: u8,                  // 8-bit Time To Live
    pub src: u32,                 // 32-bit Source IP Address
    pub dst: u32,                 // 32-bit Destination IP Address
    pub payload: PacketPayload,   // Payload
    pub identifier: u16,          // 16-bit Identification
    pub options: Option<Vec<u8>>, // Optional options field (variable length)
}

/// Convert list of u8 (i.e. received bytes) into an IPv4Packet
impl From<&[u8]> for IPv4Packet {
    fn from(data: &[u8]) -> Self {
        let mut cursor = Cursor::new(data);
        // Get header length, which is the 4 right bits in the first byte (hence & 0xF)
        // header length is in number of 32 bits i.e. 4 bytes (hence *4)
        let ihl: usize = ((cursor.read_u8().unwrap() & 0xF) * 4).into(); // Total Length
        let identifier = cursor.read_u16::<NetworkEndian>().unwrap(); // Identification
        cursor.set_position(8); // Time To Live
        let ttl = cursor.read_u8().unwrap();
        let packet_type = cursor.read_u8().unwrap(); // Protocol
        cursor.set_position(12); // Address fields
        let src = cursor.read_u32::<NetworkEndian>().unwrap(); // Source IP Address
        let dst = cursor.read_u32::<NetworkEndian>().unwrap(); // Destination IP Address

        // If the header length is longer than the data, the packet is incomplete
        if ihl > data.len() {
            return IPv4Packet {
                length: ihl as u16,
                ttl,
                src,
                dst,
                payload: PacketPayload::Unimplemented,
                identifier,
                options: None,
            };
        }

        // If the header length is greater than 20 bytes, read the options field
        let options = (ihl > 20)
            .then(|| {
                let mut bytes = vec![0; ihl - 20];
                cursor.read_exact(&mut bytes).ok().map(|_| bytes)
            })
            .flatten();

        let payload_start = cursor.position() as usize;
        let payload_bytes = &data[payload_start..];

        let payload = match packet_type {
            1 => {
                if payload_bytes.len() < 8 {
                    PacketPayload::Unimplemented
                } else {
                    PacketPayload::Icmp {
                        value: ICMPPacket::from(payload_bytes),
                    }
                }
            }
            17 => {
                if payload_bytes.len() < 8 {
                    PacketPayload::Unimplemented
                } else {
                    PacketPayload::Udp {
                        value: UDPPacket::from(payload_bytes),
                    }
                }
            }
            6 => {
                if payload_bytes.len() < 20 {
                    PacketPayload::Unimplemented
                } else {
                    PacketPayload::Tcp {
                        value: TCPPacket::from(payload_bytes),
                    }
                }
            }
            _ => PacketPayload::Unimplemented,
        };

        IPv4Packet {
            length: ihl as u16,
            ttl,
            src,
            dst,
            payload,
            identifier,
            options,
        }
    }
}

/// Convert IPv4Packet into a vector of bytes
impl From<&IPv4Packet> for Vec<u8> {
    fn from(packet: &IPv4Packet) -> Self {
        let (payload_type, payload) = match &packet.payload {
            PacketPayload::Icmp { value } => (1, value.into()),
            PacketPayload::Udp { value } => (17, value.into()),
            PacketPayload::Tcp { value } => (6, value.into()),
            PacketPayload::Unimplemented => (0, vec![]),
        };

        // Pad options to a multiple of 4 bytes if they exist
        let mut options = packet.options.clone().unwrap_or_default();
        while !options.len().is_multiple_of(4) {
            options.push(1); // Padding with NOP (1)
        }

        // Calculate header length (IHL) including options if they exist
        let options_length = options.len();
        let total_header_length = 20 + options_length; // Base header length (20 bytes) + options length
        let ihl = (total_header_length / 4) as u8;

        let mut wtr = Vec::with_capacity(total_header_length);
        wtr.write_u8((4 << 4) | ihl)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Version (4) and header length (5)
        wtr.write_u8(0x00)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Type of Service
        wtr.write_u16::<NetworkEndian>(packet.length)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Total Length
        wtr.write_u16::<NetworkEndian>(packet.identifier)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Identification
        wtr.write_u16::<NetworkEndian>(0x0000)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Flags (0) and Fragment Offset (0)
        wtr.write_u8(packet.ttl)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Time To Live
        wtr.write_u8(payload_type)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Protocol (ICMP)
        wtr.write_u16::<NetworkEndian>(0x0000)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Header Checksum
        wtr.write_u32::<NetworkEndian>(packet.src)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Source IP Address
        wtr.write_u32::<NetworkEndian>(packet.dst)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Destination IP Address

        // Write options (will be empty if none)
        wtr.write_all(&options)
            .expect("Unable to write to byte buffer for IPv4 packet");

        // Calculate and write the checksum
        let checksum = ICMPPacket::calc_checksum(&wtr);
        let mut cursor = Cursor::new(wtr);
        cursor.set_position(10); // Checksum position
        cursor.write_u16::<NetworkEndian>(checksum).unwrap();

        cursor.set_position(total_header_length as u64); // Skip the IP header

        // Add the payload
        cursor
            .write_all(&payload)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Payload

        cursor.into_inner()
    }
}

/// Create a Record Route option for IPv4 packets (maximum 9 addresses).
fn record_route_option() -> Vec<u8> {
    let mut option = vec![1]; // Start with NOP for 4-byte alignment, then Record Route option
    option.push(7); // Option type: Record Route
    option.push(39); // Option length: 39 bytes (maximum for Record Route)
    option.push(4); // Pointer: starts at 4 (first address)
    option.extend(vec![0; 36]); // 9 addresses (4 bytes each) initialized to zero
    option
}

/// Convert a record route option byte array into a vector of IP addresses.
pub fn parse_record_route_option(data: &[u8]) -> Option<RecordedHops> {
    if data.len() < 3 || data[0] != 7 {
        return None; // Not a valid Record Route option
    }

    let mut addresses = vec![];
    let mut cursor = Cursor::new(data);
    // Skip the first 3 bytes (option type, length, pointer)
    cursor.set_position(3);
    while cursor.position() < data.len() as u64 {
        if let Ok(addr) = cursor.read_u32::<NetworkEndian>() {
            if addr != 0 {
                addresses.push(Address::from(addr));
            }
        } else {
            break;
        }
    }

    Some(RecordedHops { hops: addresses })
}

/// A struct detailing an IPv6Packet <https://en.wikipedia.org/wiki/IPv6>
#[derive(Debug)]
pub struct IPv6Packet {
    // pub version: u8,                 // 4-bit Version
    // pub traffic_class: u8,           // 8-bit Traffic Class
    pub flow_label: u32,        // 20-bit Flow Label
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
        let flow_label = _version_traffic_flow & 0x000FFFFF; // Lower 20 bits
        let payload_length = cursor.read_u16::<NetworkEndian>().unwrap();
        let next_header = cursor.read_u8().unwrap();
        let hop_limit = cursor.read_u8().unwrap();

        let src = cursor.read_u128::<NetworkEndian>().unwrap(); // Source Address
        let dst = cursor.read_u128::<NetworkEndian>().unwrap(); // Destination Address
        let payload = &cursor.into_inner()[40..]; // IPv6 header is 40 bytes

        // Implement PacketPayload based on the next_header value
        let payload = match next_header {
            58 => {
                // ICMPv6
                PacketPayload::Icmp {
                    value: ICMPPacket::from(payload),
                }
            }
            17 => {
                // UDP
                if payload.len() < 8 {
                    PacketPayload::Unimplemented
                } else {
                    PacketPayload::Udp {
                        value: UDPPacket::from(payload),
                    }
                }
            }
            6 => {
                // TCP
                if payload.len() < 20 {
                    PacketPayload::Unimplemented
                } else {
                    PacketPayload::Tcp {
                        value: TCPPacket::from(payload),
                    }
                }
            }
            _ => PacketPayload::Unimplemented, // Extension headers
        };

        IPv6Packet {
            // version: (version_traffic_class >> 12) as u8,
            // traffic_class: ((version_traffic_class >> 4) & 0xFF) as u8,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            src,
            dst,
            payload,
        }
    }
}

/// Convert an IPv6Packet into bytes
impl From<&IPv6Packet> for Vec<u8> {
    fn from(packet: &IPv6Packet) -> Self {
        let mut wtr = vec![];
        // Write traffic class 0x60 and flow label 0x003a7d
        wtr.write_u32::<NetworkEndian>(0x60003a7d)
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(packet.payload_length)
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u8(packet.next_header)
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u8(packet.hop_limit)
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u128::<NetworkEndian>(packet.src)
            .expect("Unable to write source address to byte buffer for IPv6Packet");
        wtr.write_u128::<NetworkEndian>(packet.dst)
            .expect("Unable to write destination address to byte buffer for IPv6Packet");

        let payload = match &packet.payload {
            PacketPayload::Icmp { value } => value.into(),
            PacketPayload::Udp { value } => value.into(),
            PacketPayload::Tcp { value } => value.into(),
            PacketPayload::Unimplemented => vec![],
        };

        wtr.write_all(&payload)
            .expect("Unable to write payload to byte buffer for IPv6Packet");

        wtr
    }
}

/// Definition of the IPV4Packet payload (either ICMPv4, UDP, TCP, or unimplemented)
#[derive(Debug)]
pub enum PacketPayload {
    Icmp { value: ICMPPacket },
    Udp { value: UDPPacket },
    Tcp { value: TCPPacket },
    Unimplemented,
}

/// Convert a packet payload to bytes
impl From<PacketPayload> for Vec<u8> {
    fn from(payload: PacketPayload) -> Self {
        match payload {
            PacketPayload::Icmp { value } => (&value).into(),
            PacketPayload::Udp { value } => (&value).into(),
            PacketPayload::Tcp { value } => (&value).into(),
            PacketPayload::Unimplemented => vec![],
        }
    }
}

/// Struct defining the IPv4 pseudo-header for checksum calculation.
#[derive(Debug)]
pub struct PseudoHeaderV4 {
    pub src: u32,
    pub dst: u32,
    pub protocol: u8,
    pub length: u16,
}

/// Converting PsuedoHeader to bytes
impl From<&PseudoHeaderV4> for Vec<u8> {
    fn from(header: &PseudoHeaderV4) -> Self {
        let mut wtr = vec![];
        wtr.write_u32::<NetworkEndian>(header.src)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u32::<NetworkEndian>(header.dst)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u8(0) // 8 bits of zeroes
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u8(header.protocol)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u16::<NetworkEndian>(header.length)
            .expect("Unable to write to byte buffer for PseudoHeader");

        wtr
    }
}

/// Struct defining the IPv6 pseudo-header for checksum calculation.
#[derive(Debug)]
pub struct PseudoHeaderV6 {
    pub src: u128,
    pub dst: u128,
    pub upper_layer_packet_length: u32,
    pub next_header: u8,
}

/// Converting PsuedoHeaderv6 to bytes
impl From<&PseudoHeaderV6> for Vec<u8> {
    fn from(header: &PseudoHeaderV6) -> Self {
        let mut wtr = vec![];
        wtr.write_u128::<NetworkEndian>(header.src)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u128::<NetworkEndian>(header.dst)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u32::<NetworkEndian>(header.upper_layer_packet_length)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u24::<NetworkEndian>(0) // zeroes
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u8(header.next_header)
            .expect("Unable to write to byte buffer for PseudoHeader");

        wtr
    }
}

/// Struct defining a pseudo header that is used by both TCP and UDP to calculate their checksum
#[derive(Debug)]
pub enum PseudoHeader {
    V4(PseudoHeaderV4),
    V6(PseudoHeaderV6),
}

impl PseudoHeader {
    pub fn new(src_addr: &Address, dst_addr: &Address, protocol: u8, packet_length: u32) -> Self {
        match (&src_addr.value, &dst_addr.value) {
            (Some(address::Value::V6(_)), Some(address::Value::V6(_))) => {
                Self::V6(PseudoHeaderV6 {
                    src: src_addr.into(),
                    dst: dst_addr.into(),
                    upper_layer_packet_length: packet_length,
                    next_header: protocol,
                })
            }
            (Some(address::Value::V4(_)), Some(address::Value::V4(_))) => {
                Self::V4(PseudoHeaderV4 {
                    src: src_addr.into(),
                    dst: dst_addr.into(),
                    protocol,
                    length: packet_length as u16,
                })
            }
            (s, d) => panic!(
                "IP version mismatch or invalid address type: src={:?}, dst={:?}",
                s, d
            ),
        }
    }
}

/// Convert PseudoHeader to bytes
impl From<&PseudoHeader> for Vec<u8> {
    fn from(header: &PseudoHeader) -> Self {
        match header {
            PseudoHeader::V4(header) => header.into(),
            PseudoHeader::V6(header) => header.into(),
        }
    }
}

/// Calculate the checksum for a UDP/TCP packet.
///
/// # Arguments
///
/// * 'buffer' - the UDP/TCP packet as bytes (without the IP header)
///
/// * 'pseudo_header' - the pseudo header for this packet (IPv4 or IPv6)
pub fn calculate_checksum(buffer: &[u8], pseudo_header: &PseudoHeader) -> u16 {
    let mut sum = 0u32;
    let mut packet: Vec<u8> = pseudo_header.into();
    packet.extend_from_slice(buffer);

    // Sum the packet buffer
    let packet_len = packet.len();
    for chunk in packet.chunks_exact(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum += u32::from(word);
    }

    // If the packet length is odd, add the last byte as a half-word (padded with 0)
    if !packet_len.is_multiple_of(2) {
        sum += u32::from(packet[packet_len - 1]) << 8;
    }

    // Fold the sum to 16 bits by adding the carry
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Return the one's complement of the sum
    !(sum as u16)
}
