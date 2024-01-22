use super::byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Write};
use std::net::Ipv6Addr;
use super::{ICMPPacket, INFO_URL, PacketPayload};

/// A struct detailing an IPv6Packet <https://en.wikipedia.org/wiki/IPv6>
#[derive(Debug)]
pub struct IPv6Packet {
    // pub version: u8,             // 4-bit Version
    // pub traffic_class: u8,       // 8-bit Traffic Class
    // pub flow_label: u32,         // 20-bit Flow Label
    pub payload_length: u16,      // 16-bit Payload Length
    pub next_header: u8,         // 8-bit Next Header
    pub hop_limit: u8,           // 8-bit Hop Limit
    pub source_address: Ipv6Addr, // TODO why not u128 for these addresses?
    pub destination_address: Ipv6Addr,
    pub payload: PacketPayload,
}

impl Into<Vec<u8>> for PacketPayload {
    fn into(self) -> Vec<u8> {
        match self {
            PacketPayload::ICMP { value } => (&value).into(),
            PacketPayload::UDP { value } => (&value).into(),
            PacketPayload::TCP { value } => (&value).into(),
            PacketPayload::Unimplemented => vec![],
        }
    }
}

/// Convert list of u8 (i.e. received bytes) into an IPv6Packet
impl From<&[u8]> for IPv6Packet {
    fn from(data: &[u8]) -> Self {
        let mut cursor = Cursor::new(data);
        let _version_traffic_flow: u32 = cursor.read_u32::<NetworkEndian>().unwrap();
        let payload_length = cursor.read_u16::<NetworkEndian>().unwrap();
        let next_header = cursor.read_u8().unwrap();
        let hop_limit = cursor.read_u8().unwrap();

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
        let payload_bytes = &cursor.into_inner()[40..]; // IPv6 header is 40 bytes

        // Implement PacketPayload based on the next_header value
        let payload = match next_header { //TODO extension headers
            58 => { // ICMPv6
                PacketPayload::ICMP {
                    value: super::ICMPPacket::from(payload_bytes),
                }
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
            next_header,
            hop_limit,
            source_address,
            destination_address,
            payload,
        }
    }
}

impl Into<Vec<u8>> for IPv6Packet {
    fn into(self) -> Vec<u8> {
        let mut wtr = vec![];
        // Write traffic class 0x60 and flow label 0x000000
        wtr.write_u32::<NetworkEndian>(0x60000000)
            .expect("Unable to write to byte buffer for IPv6Packet");

        wtr.write_u16::<NetworkEndian>(self.payload_length)
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u8(self.next_header)
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u8(self.hop_limit)
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.source_address.segments()[0])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.source_address.segments()[1])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.source_address.segments()[2])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.source_address.segments()[3])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.source_address.segments()[4])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.source_address.segments()[5])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.source_address.segments()[6])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.source_address.segments()[7])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.destination_address.segments()[0])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.destination_address.segments()[1])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.destination_address.segments()[2])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.destination_address.segments()[3])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.destination_address.segments()[4])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.destination_address.segments()[5])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.destination_address.segments()[6])
            .expect("Unable to write to byte buffer for IPv6Packet");
        wtr.write_u16::<NetworkEndian>(self.destination_address.segments()[7])
            .expect("Unable to write to byte buffer for IPv6Packet");

        let payload_bytes: Vec<u8> = self.payload.into();
        wtr.write_all(&*payload_bytes).expect("Unable to write to byte buffer for IPv4 packet"); // Payload

        // wtr.write(self.payload.into())
        //     .expect("Unable to write to byte buffer for IPv6Packet");
        // wtr.extend(self.payload.into());

        wtr
    }
}

impl ICMPPacket {
    pub fn echo_request_v6(identifier: u16, sequence_number: u16, body: Vec<u8>, source_address: u128, destination_address: u128) -> Vec<u8> {
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
        psuedo_header.write_u128::<NetworkEndian>(source_address)
            .expect("Unable to write to byte buffer for PseudoHeader");
        psuedo_header.write_u128::<NetworkEndian>(destination_address)
            .expect("Unable to write to byte buffer for PseudoHeader");
        psuedo_header.write_u32::<NetworkEndian>((8 + body_len + INFO_URL.bytes().len() as u16) as u32)// ICMP length
            .expect("Unable to write to byte buffer for PseudoHeader"); // Length of ICMP header + body
        psuedo_header.write_u8(0).unwrap(); // zeroes
        psuedo_header.write_u8(0).unwrap(); // zeroes
        psuedo_header.write_u8(0).unwrap(); // zeroes
        psuedo_header.write_u8(58).unwrap(); // next header (58 => ICMPv6)
        psuedo_header.extend(icmp_bytes); // Add the ICMP packet bytes
        psuedo_header.extend(INFO_URL.bytes()); // Add the INFO_URL bytes
        packet.checksum = ICMPPacket::calc_checksum(psuedo_header.as_slice()); // Calculate the checksum

        let v6_packet = IPv6Packet {
            payload_length: 8 + body_len + INFO_URL.bytes().len() as u16, // ICMP header (8 bytes) + body length
            next_header: 58, // ICMPv6
            hop_limit: 64,
            source_address: Ipv6Addr::from(source_address),
            destination_address: Ipv6Addr::from(destination_address),
            payload: PacketPayload::ICMP { value: packet.into(), },
        };

        let mut bytes: Vec<u8> = v6_packet.into();
        bytes.extend(INFO_URL.bytes());

        bytes
    }
}

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
        wtr.write_u8(self.next_header)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr
    }
}

/// Calculate the checksum for an IPv6 UDP/TCP packet.
///
/// # Arguments
///
/// * 'buffer' - the UDP/TCP packet as bytes (without the IPv6 header)
///
/// * 'pseudo_header' - the pseudo header for this packet
pub fn calculate_checksum_v6(buffer: &[u8], pseudo_header: &PseudoHeaderv6) -> u16 { // TODO wrong checksum since a recent change
    let packet_len = buffer.len();
    let mut sum = 0u32;

    // Sum the pseudo header source address (128 bits split into 4x 32 bits)
    sum = sum.wrapping_add((pseudo_header.source_address >> 96) as u32);
    sum = sum.wrapping_add(((pseudo_header.source_address >> 64) & 0xFFFF_FFFF) as u32);
    sum = sum.wrapping_add(((pseudo_header.source_address >> 32) & 0xFFFF_FFFF) as u32);
    sum = sum.wrapping_add((pseudo_header.source_address & 0xFFFF_FFFF) as u32);

    // Sum the pseudo header destination address (128 bits split into 4x 32 bits)
    sum = sum.wrapping_add((pseudo_header.destination_address >> 96) as u32);
    sum = sum.wrapping_add(((pseudo_header.destination_address >> 64) & 0xFFFF_FFFF) as u32);
    sum = sum.wrapping_add(((pseudo_header.destination_address >> 32) & 0xFFFF_FFFF) as u32);
    sum = sum.wrapping_add((pseudo_header.destination_address & 0xFFFF_FFFF) as u32);

    sum = sum.wrapping_add(u32::from(pseudo_header.length));
    sum = sum.wrapping_add(u32::from(pseudo_header.next_header));

    // Sum the packet
    let mut i = 0;
    while i < packet_len - 1 {
        let word = u16::from_be_bytes([buffer[i], buffer[i + 1]]);
        sum = sum.wrapping_add(u32::from(word));
        i += 2;
    }

    // If the packet length is odd, add the last byte as a half-word
    if packet_len % 2 != 0 {
        sum = sum.wrapping_add(u32::from(buffer[packet_len - 1]) << 8);
    }

    // Fold the sum to 16 bits by adding the carry
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}


impl super::UDPPacket {
    /// Create a basic UDP packet with checksum.
    pub fn udp_request_v6(source_address: u128, destination_address: u128,
                       source_port: u16, destination_port: u16, body: Vec<u8>) -> Vec<u8> {

        let udp_length = (8 + body.len() + INFO_URL.bytes().len()) as u32;

        let mut packet = Self {
            source_port,
            destination_port,
            length: udp_length as u16,
            checksum: 0,
            body,
        };

        let mut bytes: Vec<u8> = (&packet).into();
        bytes.extend(INFO_URL.bytes()); // Add INFO_URL

        let pseudo_header = PseudoHeaderv6 {
            source_address,
            destination_address,
            // zeroes: 0,
            next_header: 17,
            length: udp_length,
        };

        packet.checksum = calculate_checksum_v6(&bytes, &pseudo_header);

        // Put the checksum at the right position in the packet (calling into() again is also
        // possible but is likely slower).
        let mut cursor = Cursor::new(bytes);
        cursor.set_position(6); // Skip source port (2 bytes), destination port (2 bytes), udp length (2 bytes)
        cursor.write_u16::<NetworkEndian>(packet.checksum).unwrap();

        // Return the vec
        cursor.into_inner()
    }

    /// Create a UDP packet with a DNS A record request. In the domain of the A record, we encode: transmit_time,
    /// source_address, destination_address, client_id, source_port, destination_port
    pub fn dns_request_v6(
        source_address: u128,
        destination_address: u128,
        source_port: u16,
        body: Vec<u8>,
        domain_name: &str,
        transmit_time: u64,
        client_id: u8
    ) -> Vec<u8> {
        let destination_port = 53u16;

        let dns_body = Self::create_dns_a_record_request_v6(domain_name, transmit_time,
                                                         source_address, destination_address, client_id, source_port);

        let udp_length = (8 + body.len() + dns_body.len()) as u32;

        let mut packet = Self {
            source_port,
            destination_port,
            length: udp_length as u16,
            checksum: 0,
            body,
        };

        let mut bytes: Vec<u8> = (&packet).into();

        bytes.extend(dns_body);

        let pseudo_header = PseudoHeaderv6 {
            source_address,
            destination_address,
            // zeroes: 0,
            next_header: 17,
            length: udp_length,
        };

        packet.checksum = calculate_checksum_v6(&bytes, &pseudo_header);

        // Put the checksum at the right position in the packet
        let mut cursor = Cursor::new(bytes);
        cursor.set_position(6); // Skip source port (2 bytes), destination port (2 bytes), udp length (2 bytes)
        cursor.write_u16::<NetworkEndian>(packet.checksum).unwrap();

        // Return the vec
        cursor.into_inner()
    }

    /// Creating a DNS A Record Request body <http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm>
    fn create_dns_a_record_request_v6(
        domain_name: &str,
        transmit_time: u64,
        source_address: u128,
        destination_address: u128,
        client_id: u8,
        source_port: u16,
    ) -> Vec<u8> {
        // Max length of DNS domain name is 253 characters

        // Each label has a max length of 63 characters
        // 20 + 10 + 10 + 3 + 5 + (4 '-' symbols) = 52 characters at most for subdomain
        // u128 highest value has 39 digits
        let subdomain = format!("{}.{}.{}.{}.{}.{}", transmit_time, source_address,
                                destination_address, client_id, source_port, domain_name);
        let mut dns_body: Vec<u8> = Vec::new();

        // DNS Header
        dns_body.write_u8(client_id)
            .expect("Unable to write to byte buffer for UDP packet"); // Transaction ID first 8 bits
        dns_body.write_u8(0x12).unwrap(); // Transaction ID last 8 bits
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
}

impl super::TCPPacket {
    /// Create a basic TCP SYN/ACK packet with checksum
    pub fn tcp_syn_ack_v6(source_address: u128, destination_address: u128,
                       source_port: u16, destination_port: u16, seq: u32, ack:u32, body: Vec<u8>) -> Vec<u8> {
        let mut packet = Self {
            source_port,
            destination_port,
            seq,
            ack,
            offset: 0b01010000, // Offset 5 for minimum TCP header length (0101) + 0000 for reserved
            flags: 0b00010010, // SYN and ACK flags
            checksum: 0,
            pointer: 0,
            body,
            window_size: 0
        };

        let mut bytes: Vec<u8> = (&packet).into();
        bytes.extend(INFO_URL.bytes()); // Add INFO_URL

        let pseudo_header = PseudoHeaderv6 {
            source_address,
            destination_address,
            // zeroes: 0,
            next_header: 6, // TCP
            length: bytes.len() as u32, // the length of the TCP header and data (measured in octets)
        };

        packet.checksum = calculate_checksum_v6(&bytes, &pseudo_header);

        // Put the checksum at the right position in the packet
        let mut cursor = Cursor::new(bytes);
        cursor.set_position(16); // Skip source port (2 bytes), destination port (2 bytes), seq (4 bytes), ack (4 bytes), offset/reserved (1 byte), flags (1 bytes), window (2 bytes)
        cursor.write_u16::<NetworkEndian>(packet.checksum).unwrap();

        // Return the vec
        cursor.into_inner()
    }
}
