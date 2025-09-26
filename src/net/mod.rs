extern crate byteorder;
use std::io::{Cursor, Read, Write};

use crate::custom_module::manycastr::Address;
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use prost::bytes::Buf;

pub(crate) mod packet;

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

    /// Returns IP identifier (IPv4), flow label (IPv6)
    pub(crate) fn identifier(&self) -> u16 {
        match self {
            IPPacket::V4(packet) => packet.identifier,
            IPPacket::V6(packet) => packet.flow_label as u16,
        }
    }
}

/// A struct detailing an IPv4Packet <https://en.wikipedia.org/wiki/Internet_Protocol_version_4>
#[derive(Debug)]
pub struct IPv4Packet {
    pub length: u16,            // 16-bit Total Length
    pub ttl: u8,                // 8-bit Time To Live
    pub src: u32,               // 32-bit Source IP Address
    pub dst: u32,               // 32-bit Destination IP Address
    pub payload: PacketPayload, // Payload
    pub identifier: u16,        // 16-bit Identification
}

/// Convert list of u8 (i.e. received bytes) into an IPv4Packet
impl From<&[u8]> for IPv4Packet {
    fn from(data: &[u8]) -> Self {
        let mut cursor = Cursor::new(data);
        // Get header length, which is the 4 right bits in the first byte (hence & 0xF)
        // header length is in number of 32 bits i.e. 4 bytes (hence *4)
        let header_length: usize = ((cursor.read_u8().unwrap() & 0xF) * 4).into(); // Total Length
        let identifier = cursor.read_u16::<NetworkEndian>().unwrap(); // Identification
        cursor.set_position(8); // Time To Live
        let ttl = cursor.read_u8().unwrap();
        let packet_type = cursor.read_u8().unwrap(); // Protocol
        cursor.set_position(12); // Address fields
        let src = cursor.read_u32::<NetworkEndian>().unwrap(); // Source IP Address
        let dst = cursor.read_u32::<NetworkEndian>().unwrap(); // Destination IP Address

        // If the header length is longer than the data, the packet is incomplete
        if header_length > data.len() {
            return IPv4Packet {
                length: header_length as u16,
                ttl,
                src,
                dst,
                payload: PacketPayload::Unimplemented,
                identifier,
            };
        }

        let payload_bytes = &cursor.into_inner()[header_length..];
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
            length: header_length as u16,
            ttl,
            src,
            dst,
            payload,
            identifier,
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

        let mut wtr = vec![];
        wtr.write_u8(0x45)
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

        // Calculate and write the checksum
        let checksum = ICMPPacket::calc_checksum(&wtr); // Calculate checksum
        let mut cursor = Cursor::new(wtr);
        cursor.set_position(10); // Skip version (1 byte) and header length (1 byte)
        cursor.write_u16::<NetworkEndian>(checksum).unwrap();

        // Add the payload
        cursor.set_position(20); // Skip the header
        cursor
            .write_all(&payload)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Payload

        cursor.into_inner()
    }
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
    /// Creates a new PseudoHeader (V4 or V6) based on the address types.
    pub fn new(src_addr: &Address, dst_addr: &Address, protocol: u8, packet_length: u32) -> Self {
        if src_addr.is_v6() {
            Self::V6(PseudoHeaderV6 {
                src: src_addr.get_v6(),
                dst: dst_addr.get_v6(),
                upper_layer_packet_length: packet_length, // Length field is 32 bits for IPv6
                next_header: protocol,
            })
        } else {
            Self::V4(PseudoHeaderV4 {
                src: src_addr.get_v4(),
                dst: dst_addr.get_v4(),
                protocol,
                length: packet_length as u16, // Length field is 16 bits for IPv4
            })
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

/// An ICMP Packet (ping packet) <https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#header_rest>
#[derive(Debug)]
pub struct ICMPPacket {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub icmp_identifier: u16,
    pub sequence_number: u16,
    pub body: Vec<u8>,
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
            body: data.into_inner()[8..].to_vec(),
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
        wtr.write_all(&packet.body)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr
    }
}

impl ICMPPacket {
    /// Create a basic ICMPv4 ECHO_REQUEST (8.0) packet with checksum.
    ///
    /// # Arguments
    ///
    /// * 'identifier' - the identifier for the ICMP header
    ///
    /// * 'sequence_number' - the sequence number for the ICMP header
    ///
    /// * 'body' - the ICMP payload
    ///
    /// * 'src' - the source address of the packet
    ///
    /// * 'dst' - the destination address of the packet
    ///
    /// * 'ttl' - the time to live of the packet
    ///
    /// * 'info_url' - the URL to be added to the packet payload (e.g., opt-out URL)
    pub fn echo_request(
        icmp_identifier: u16,
        sequence_number: u16,
        body: Vec<u8>,
        src: u32,
        dst: u32,
        ttl: u8,
        info_url: &str,
    ) -> Vec<u8> {
        let body_len = body.len() as u16;
        let mut packet = ICMPPacket {
            icmp_type: 8,
            code: 0,
            checksum: 0,
            icmp_identifier,
            sequence_number,
            body,
        };

        // Turn everything into a vec of bytes and calculate checksum
        let mut icmp_bytes: Vec<u8> = (&packet).into();
        icmp_bytes.extend(info_url.bytes());
        packet.checksum = ICMPPacket::calc_checksum(&icmp_bytes);

        let v4_packet = IPv4Packet {
            length: 20 + 8 + body_len + info_url.len() as u16,
            identifier: 15037,
            ttl,
            src,
            dst,
            payload: PacketPayload::Icmp { value: packet },
        };

        let mut bytes: Vec<u8> = (&v4_packet).into();
        bytes.extend(info_url.bytes());

        bytes
    }

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
    /// * 'src' - the source address of the packet
    ///
    /// * 'dst' - the destination address of the packet
    ///
    /// * 'hop_limit' - the hop limit (TTL) of the packet
    ///
    /// * 'info_url' - URL encoded in packet payload (e.g., opt-out URL)
    pub fn echo_request_v6(
        icmp_identifier: u16,
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
            icmp_identifier,
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
            .write_u32::<NetworkEndian>((8 + body_len + info_url.len() as u16) as u32) // ICMP length
            .expect("Unable to write to byte buffer for PseudoHeader"); // Length of ICMP header + body
        psuedo_header.write_u8(0).unwrap(); // zeroes
        psuedo_header.write_u8(0).unwrap(); // zeroes
        psuedo_header.write_u8(0).unwrap(); // zeroes
        psuedo_header.write_u8(58).unwrap(); // next header (58 => ICMPv6)
        psuedo_header.extend(icmp_bytes); // Add the ICMP packet bytes
        psuedo_header.extend(info_url.bytes()); // Add the INFO_URL bytes
        packet.checksum = ICMPPacket::calc_checksum(psuedo_header.as_slice()); // Calculate the checksum

        let v6_packet = IPv6Packet {
            payload_length: 8 + body_len + info_url.len() as u16, // ICMP header (8 bytes) + body length
            flow_label: 15037,
            next_header: 58, // ICMPv6
            hop_limit,
            src,
            dst,
            payload: PacketPayload::Icmp { value: packet },
        };

        let mut bytes: Vec<u8> = (&v6_packet).into();
        bytes.extend(info_url.bytes());

        bytes
    }

    /// Calculate the ICMP Checksum.
    ///
    /// This calculation covers the entire ICMP  message (16-bit one's complement).
    /// Works for both ICMPv4 and ICMPv6
    fn calc_checksum(buffer: &[u8]) -> u16 {
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

/// An UDPPacket (UDP packet) <https://en.wikipedia.org/wiki/User_Datagram_Protocol>
#[derive(Debug)]
pub struct UDPPacket {
    pub sport: u16,
    pub dport: u16,
    pub length: u16,
    pub checksum: u16,
    pub body: Vec<u8>,
}

/// Parsing from bytes into UDPPacket
impl From<&[u8]> for UDPPacket {
    fn from(data: &[u8]) -> Self {
        let mut data = Cursor::new(data);
        UDPPacket {
            sport: data.read_u16::<NetworkEndian>().unwrap(),
            dport: data.read_u16::<NetworkEndian>().unwrap(),
            length: data.read_u16::<NetworkEndian>().unwrap(),
            checksum: data.read_u16::<NetworkEndian>().unwrap(),
            body: data.into_inner()[8..].to_vec(),
        }
    }
}

/// Convert UDPPacket into a vector of bytes
impl From<&UDPPacket> for Vec<u8> {
    fn from(packet: &UDPPacket) -> Self {
        let mut wtr = vec![];
        wtr.write_u16::<NetworkEndian>(packet.sport)
            .expect("Unable to write to byte buffer for UDP packet");
        wtr.write_u16::<NetworkEndian>(packet.dport)
            .expect("Unable to write to byte buffer for UDP packet");
        wtr.write_u16::<NetworkEndian>(packet.length)
            .expect("Unable to write to byte buffer for UDP packet");
        wtr.write_u16::<NetworkEndian>(packet.checksum)
            .expect("Unable to write to byte buffer for UDP packet");
        wtr.write_all(&packet.body)
            .expect("Unable to write to byte buffer for UDP packet");

        wtr
    }
}

/// DNS request body
#[allow(dead_code)]
#[derive(Debug)]
pub struct DNSRecord {
    pub transaction_id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answer: u16,
    pub authority: u16,
    pub additional: u16,
    pub domain: String,
    pub record_type: u16,
    pub class: u16,
    pub body: Vec<u8>, // Possible answer sections
}

/// DNS answer body
#[allow(dead_code)]
#[derive(Debug)]
pub struct DNSAnswer {
    pub domain: String,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data_length: u16,
    pub data: Vec<u8>,
}

/// DNS TXT data record
#[allow(dead_code)]
#[derive(Debug)]
pub struct TXTRecord {
    pub txt_length: u8,
    pub txt: String,
}

/// Read a DNS name that is contained in a DNS response.
/// Returns the domain name string of the A record reply.
fn read_dns_name(data: &mut Cursor<&[u8]>) -> String {
    let mut result = String::new();
    loop {
        if !data.has_remaining() {
            break;
        }
        let label_len = data.read_u8().unwrap();
        // If label length is 0, it is the end of the string
        if label_len == 0 {
            break;
        }
        // If the first two bytes of the label length is set to 11, it points to a different position
        if label_len & 0xC0 == 0xC0 {
            // The offset is the pointer to the previous domain name
            let offset = ((label_len as u16 & 0x3F) << 8) | data.read_u8().unwrap() as u16;
            data.set_position(offset as u64);
            result.push_str(&read_dns_name(data));
            break;
        }
        // Read the label
        let mut label_bytes = vec![0; label_len as usize];

        match data.read_exact(&mut label_bytes) {
            Ok(()) => {}
            Err(_) => {
                return "Invalid domain name".to_string();
            }
        }

        let label = String::from_utf8_lossy(&label_bytes).to_string();
        result.push_str(&label);
        result.push('.');
    }
    // Remove the trailing '.' if there is one
    if result.ends_with('.') {
        result.pop();
    }
    result
}

/// Parsing from bytes into a DNS A record
impl From<&[u8]> for DNSRecord {
    fn from(data: &[u8]) -> Self {
        let mut data = Cursor::new(data);

        let transaction_id = data.read_u16::<NetworkEndian>().unwrap();
        let flags = data.read_u16::<NetworkEndian>().unwrap();
        let questions = data.read_u16::<NetworkEndian>().unwrap();
        let answer = data.read_u16::<NetworkEndian>().unwrap();
        let authority = data.read_u16::<NetworkEndian>().unwrap();
        let additional = data.read_u16::<NetworkEndian>().unwrap();
        let domain = read_dns_name(&mut data);

        let (record_type, class, body) = if data.remaining() >= 4 {
            let record_type = data.read_u16::<NetworkEndian>().unwrap();
            let class = data.read_u16::<NetworkEndian>().unwrap();
            let body = data.clone().into_inner()[data.position() as usize..].to_vec();
            (record_type, class, body)
        } else {
            let record_type = 0;
            let class = 0;
            let body = vec![];
            (record_type, class, body)
        };

        DNSRecord {
            transaction_id,
            flags,
            questions,
            answer,
            authority,
            additional,
            domain,
            record_type,
            class,
            body,
        }
    }
}

/// Parsing from bytes into a DNS A record
impl From<&[u8]> for DNSAnswer {
    fn from(data: &[u8]) -> Self {
        let mut data = Cursor::new(data);

        // Make sure data has the required length
        if data.remaining() < 10 {
            return DNSAnswer {
                domain: "Invalid DNS record".to_string(),
                record_type: 0,
                class: 0,
                ttl: 0,
                data_length: 0,
                data: vec![],
            };
        }

        DNSAnswer {
            domain: data.read_u16::<NetworkEndian>().unwrap().to_string(), //read_dns_name(&mut data), // Two bytes that are a pointer to the domain name of the request record
            record_type: data.read_u16::<NetworkEndian>().unwrap(),
            class: data.read_u16::<NetworkEndian>().unwrap(),
            ttl: data.read_u32::<NetworkEndian>().unwrap(),
            data_length: data.read_u16::<NetworkEndian>().unwrap(),
            data: data.clone().into_inner()[data.position() as usize..].to_vec(),
        }
    }
}

/// Parsing from bytes into a DNS TXT record
impl From<&[u8]> for TXTRecord {
    fn from(data: &[u8]) -> Self {
        let mut data = Cursor::new(data);
        // Make sure txt_length is not out of bounds
        if data.remaining() < 1 {
            return TXTRecord {
                txt_length: 0,
                txt: "Invalid TXT record".to_string(),
            };
        }

        let txt_length = data.read_u8().unwrap();

        // Make sure txt_length is not out of bounds
        if txt_length as usize > data.remaining() {
            return TXTRecord {
                txt_length,
                txt: "Invalid TXT record".to_string(),
            };
        }

        TXTRecord {
            txt_length,
            // txt: read_dns_name(&mut data),
            txt: String::from_utf8_lossy(&data.into_inner()[1..(1 + txt_length as u64) as usize])
                .to_string(),
        }
    }
}

impl UDPPacket {
    /// Create a UDP packet with a DNS A record request.
    /// In the domain of the A record, we encode the transmit time, source and destination addresses, sender worker ID, and source port.
    pub fn dns_request(
        src: &Address,
        dst: &Address,
        sport: u16,
        domain_name: &str,
        tx_time: u64,
        tx_id: u32,
        ttl: u8,
    ) -> Vec<u8> {
        let dns_packet =
            Self::create_a_record_request(domain_name, tx_time, src, dst, tx_id, sport);
        let udp_length = (8 + dns_packet.len()) as u16;

        let mut udp_packet = Self {
            sport,
            dport: 53u16, // DNS port
            length: udp_length,
            checksum: 0,
            body: dns_packet,
        };

        let udp_bytes: Vec<u8> = (&udp_packet).into();

        let pseudo_header = PseudoHeader::new(
            src,
            dst,
            17, // UDP protocol
            udp_length as u32,
        );
        udp_packet.checksum = calculate_checksum(&udp_bytes, &pseudo_header);

        if src.is_v6() {
            (&IPv6Packet {
                payload_length: udp_length,
                flow_label: 15037,
                next_header: 17, // UDP
                hop_limit: ttl,
                src: src.get_v6(),
                dst: dst.get_v6(),
                payload: PacketPayload::Udp { value: udp_packet },
            })
                .into()
        } else {
            (&IPv4Packet {
                length: 20 + udp_length,
                identifier: 15037,
                ttl,
                src: src.get_v4(),
                dst: dst.get_v4(),
                payload: PacketPayload::Udp { value: udp_packet },
            })
                .into()
        }
    }

    /// Creating a DNS A Record Request body <http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm>
    fn create_a_record_request(
        domain_name: &str,
        tx_time: u64,
        src: &Address,
        dst: &Address,
        tx_id: u32,
        sport: u16,
    ) -> Vec<u8> {
        // Max length of DNS domain name is 253 character
        // Each label has a max length of 63 characters
        // 20 + 10 + 10 + 3 + 5 + (4 '-' symbols) = 52 characters at most for subdomain
        let subdomain = if src.is_v6() {
            format!(
                "{}.{}.{}.{}.{}.{}",
                tx_time,
                src.get_v6(),
                dst.get_v6(),
                tx_id,
                sport,
                domain_name
            )
        } else {
            format!(
                "{}.{}.{}.{}.{}.{}",
                tx_time,
                src.get_v4(),
                dst.get_v4(),
                tx_id,
                sport,
                domain_name
            )
        };
        let mut dns_body: Vec<u8> = Vec::new();

        // DNS Header
        dns_body
            .write_u16::<byteorder::BigEndian>(tx_id as u16)
            .unwrap(); // Transaction ID
        dns_body.write_u16::<byteorder::BigEndian>(0x0100).unwrap(); // Flags (Standard query, recursion desired)
        dns_body.write_u16::<byteorder::BigEndian>(0x0001).unwrap(); // Number of questions
        dns_body.write_u16::<byteorder::BigEndian>(0x0000).unwrap(); // Number of answer RRs
        dns_body.write_u16::<byteorder::BigEndian>(0x0000).unwrap(); // Number of authority RRs
        dns_body.write_u16::<byteorder::BigEndian>(0x0000).unwrap(); // Number of additional RRs

        // DNS Question
        for label in subdomain.split('.') {
            dns_body.push(label.len() as u8);
            dns_body.write_all(label.as_bytes()).unwrap();
        }
        dns_body.push(0); // Terminate the QNAME
        dns_body.write_u16::<byteorder::BigEndian>(0x0001).unwrap(); // QTYPE (A record)
        dns_body.write_u16::<byteorder::BigEndian>(0x0001).unwrap(); // QCLASS (IN)

        dns_body
    }

    /// Create a UDP packet with a CHAOS TXT record request.
    pub fn chaos_request(
        src: &Address,
        dst: &Address,
        sport: u16,
        tx: u32,
        chaos: &str,
    ) -> Vec<u8> {
        let dns_body = Self::create_chaos_request(tx, chaos);
        let udp_length = 8 + dns_body.len() as u32;

        let mut udp_packet = Self {
            sport,
            dport: 53u16,
            length: udp_length as u16,
            checksum: 0,
            body: dns_body,
        };

        let udp_bytes: Vec<u8> = (&udp_packet).into();

        let pseudo_header = PseudoHeader::new(
            src, dst, 17, // UDP protocol
            udp_length,
        );

        udp_packet.checksum = calculate_checksum(&udp_bytes, &pseudo_header);

        if src.is_v6() {
            // Create the IPv6 packet
            let v6_packet = IPv6Packet {
                payload_length: udp_length as u16,
                flow_label: 15037,
                next_header: 17, // UDP
                hop_limit: 255,
                src: src.get_v6(),
                dst: dst.get_v6(),
                payload: PacketPayload::Udp { value: udp_packet },
            };
            (&v6_packet).into()
        } else {
            // Create the IPv4 packet
            let v4_packet = IPv4Packet {
                length: 20 + udp_length as u16,
                identifier: 15037,
                ttl: 255,
                src: src.get_v4(),
                dst: dst.get_v4(),
                payload: PacketPayload::Udp { value: udp_packet },
            };
            (&v4_packet).into()
        }
    }

    /// Creating a DNS TXT record request body for id.orchestrator CHAOS request
    fn create_chaos_request(tx_id: u32, chaos: &str) -> Vec<u8> {
        let mut dns_body: Vec<u8> = Vec::new();

        // DNS Header
        dns_body.write_u32::<byteorder::BigEndian>(tx_id).unwrap(); // Transaction ID
        dns_body.write_u16::<byteorder::BigEndian>(0x0100).unwrap(); // Flags (Standard query, recursion desired)
        dns_body.write_u16::<byteorder::BigEndian>(0x0001).unwrap(); // Number of questions
        dns_body.write_u16::<byteorder::BigEndian>(0x0000).unwrap(); // Number of answer RRs
        dns_body.write_u16::<byteorder::BigEndian>(0x0000).unwrap(); // Number of authority RRs
        dns_body.write_u16::<byteorder::BigEndian>(0x0000).unwrap(); // Number of additional RRs

        // DNS Question (id.orchestrator)
        for label in chaos.split('.') {
            dns_body.push(label.len() as u8);
            dns_body.write_all(label.as_bytes()).unwrap();
        }
        dns_body.push(0); // Terminate the QNAME
        dns_body.write_u16::<byteorder::BigEndian>(0x0010).unwrap(); // QTYPE (TXT record)
        dns_body.write_u16::<byteorder::BigEndian>(0x0003).unwrap(); // QCLASS (CHAOS)

        dns_body
    }
}

/// Get the length of a given domain in bytes
/// TODO test this function
#[allow(dead_code)]
pub fn get_domain_bytes_length(domain: &str) -> u32 {
    if domain == "." {
        return 1;
    }
    let mut length = 1; // null terminator byte
    for label in domain.split('.') {
        length += label.len() as u32 + 1; // +1 for the label length byte
    }
    length
}

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
        let mut packet = Self {
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
        let bytes: Vec<u8> = (&packet).into();

        let pseudo_header = PseudoHeader::new(
            src,
            dst,
            6,                  // TCP protocol
            bytes.len() as u32, // Length of the TCP header and data (measured in octets)
        );
        packet.checksum = calculate_checksum(&bytes, &pseudo_header);

        if src.is_v6() {
            // Create the IPv6 packet
            let v6_packet = IPv6Packet {
                payload_length: bytes.len() as u16,
                flow_label: 15037,
                next_header: 6, // TCP
                hop_limit: ttl,
                src: src.get_v6(),
                dst: dst.get_v6(),
                payload: PacketPayload::Tcp { value: packet },
            };
            (&v6_packet).into()
        } else {
            // Create the IPv4 packet
            let v4_packet = IPv4Packet {
                length: 20 + bytes.len() as u16,
                identifier: 15037,
                ttl,
                src: src.get_v4(),
                dst: dst.get_v4(),
                payload: PacketPayload::Tcp { value: packet },
            };

            (&v4_packet).into()
        }
    }
}
