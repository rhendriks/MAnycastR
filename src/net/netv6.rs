use super::byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};
use std::net::Ipv6Addr;
use byteorder::{BigEndian, LittleEndian};
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
    pub source_address: Ipv6Addr,
    pub destination_address: Ipv6Addr,
    pub payload: PacketPayload,
}

/// Convert list of u8 (i.e. received bytes) into an IPv6Packet
impl From<&[u8]> for IPv6Packet {
    fn from(data: &[u8]) -> Self {
        // TODO current socket does not forward ipv6 header (future: implement pcap for rust sockets https://lib.rs/crates/pcap)

        for byte in data {
            print!("{:02X} ", byte);
        }
        println!();

        for byte in data {
            print!("{:08b} ", byte);
        }
        println!(); // Add a newline after printing all bytes


        println!("data: {:?}", data);
        let mut cursor = Cursor::new(data);

        // TODO make sure version == 6 -> ipv6 code

        let version_traffic_flow: u32 = cursor.read_u32::<NetworkEndian>().unwrap();
        let payload_length = cursor.read_u16::<NetworkEndian>().unwrap();
        let next_header = cursor.read_u8().unwrap();
        let hop_limit = cursor.read_u8().unwrap();

        // Extract the source and destination addresses
        // let mut source_address_bytes = [0u8; 16];
        // cursor.read_exact(&mut source_address_bytes).unwrap();
        // let source_address = Ipv6Addr::from(source_address_bytes);
        //
        // let mut destination_address_bytes = [0u8; 16];
        // cursor.read_exact(&mut destination_address_bytes).unwrap();
        // let destination_address = Ipv6Addr::from(destination_address_bytes);

        println!("version_traffic_flow: {}", version_traffic_flow);

        // cursor.set_position(4); // Payload length
        // let payload_length = cursor.read_u16::<NetworkEndian>().unwrap();
        println!("payload_length: {}", payload_length);
        // TODO can use payload_length to determine extension headers / making sure packet can be parsed into icmp/udp/tcp
        // let next_header = cursor.read_u8().unwrap();
        println!("next_header: {}", next_header);
        // let hop_limit = cursor.read_u8().unwrap(); // Hop limit (similar to TTL)
        println!("hop_limit: {}", hop_limit);

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
        println!("source_address: {}", source_address.to_string());

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
        println!("destination_address: {}", destination_address.to_string());

        // TODO anycast ipv6?

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

impl ICMPPacket {
    pub fn echo_request_v6(identifier: u16, sequence_number: u16, body: Vec<u8>) -> Vec<u8> {
        let mut packet = ICMPPacket {
            icmp_type: 128,
            code: 0,
            checksum: 0,
            identifier,
            sequence_number,
            body,
        };

        // Turn everything into a vec of bytes and calculate checksum
        let mut bytes: Vec<u8> = (&packet).into();
        bytes.extend(INFO_URL.bytes());
        packet.checksum = ICMPPacket::calc_checksum(&bytes);

        // Put the checksum at the right position in the packet (calling into() again is also
        // possible but is likely slower).
        let mut cursor = Cursor::new(bytes);
        cursor.set_position(2); // Skip icmp_type (1 byte) and code (1 byte)
        cursor.write_u16::<LittleEndian>(packet.checksum).unwrap();

        // Return the vec
        cursor.into_inner()
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
// pub fn calculate_checksum_v6(buffer: &[u8], pseudo_header: &PseudoHeaderv6) -> u16 { // TODO untested
//     // Convert the PseudoHeaderv6 to a byte vector manually // TODO use Into<Vec<u8>> for PseudoHeaderv6
//     let mut pseudo_header_bytes = vec![];
//     pseudo_header_bytes.write_u128::<NetworkEndian>(pseudo_header.source_address)
//         .expect("Failed to write source_address to pseudo-header");
//     pseudo_header_bytes.write_u128::<NetworkEndian>(pseudo_header.destination_address)
//         .expect("Failed to write destination_address to pseudo-header");
//     pseudo_header_bytes.write_u32::<NetworkEndian>(pseudo_header.length)
//         .expect("Failed to write length to pseudo-header");
//     // Write 24 zeroes
//     pseudo_header_bytes.write_u16::<NetworkEndian>(0)
//         .expect("Failed to write zeroes field to pseudo-header");
//     pseudo_header_bytes.write_u8::<>(0)
//         .expect("Failed to write zeroes field to pseudo-header");
//     pseudo_header_bytes.write_u8(pseudo_header.next_header)
//         .expect("Failed to write next_header to pseudo-header");
//
//     // Concatenate the pseudo-header bytes and the UDP/TCP packet bytes
//     let mut data = pseudo_header_bytes;
//     data.extend_from_slice(buffer);
//
//     // Divide the concatenated data into 16-bit words and calculate the sum
//     let mut sum = 0u32;
//
//     // If the data length is odd, add a zero byte to the end
//     if data.len() % 2 != 0 {
//         data.push(0);
//     }
//
//     for i in (0..data.len()).step_by(2) {
//         let word = u16::from_le_bytes([data[i], data[i + 1]]);
//         sum = sum.wrapping_add(u32::from(word));
//     }
//
//     // Take the one's complement of the sum
//     while (sum >> 16) > 0 {
//         sum = (sum & 0xFFFF) + (sum >> 16);
//     }
//
//     // The result is the 16-bit checksum
//     !sum as u16
// }

pub fn calculate_checksum_v6(buffer: &[u8], pseudo_header: &PseudoHeaderv6) -> u16 {
    let packet_len = buffer.len();
    let mut sum = 0u32;

    // Sum the pseudo header source address (128 bits split into 4x 32 bits)
    sum += (pseudo_header.source_address >> 96) as u32;
    sum += ((pseudo_header.source_address >> 64) & 0xFFFF_FFFF) as u32;
    sum += ((pseudo_header.source_address >> 32) & 0xFFFF_FFFF) as u32;
    sum += (pseudo_header.source_address & 0xFFFF_FFFF) as u32;

    // Sum the pseudo header destination address (128 bits split into 4x 32 bits)
    sum += (pseudo_header.destination_address >> 96) as u32;
    sum += ((pseudo_header.destination_address >> 64) & 0xFFFF_FFFF) as u32;
    sum += ((pseudo_header.destination_address >> 32) & 0xFFFF_FFFF) as u32;
    sum += (pseudo_header.destination_address & 0xFFFF_FFFF) as u32;

    sum += u32::from(pseudo_header.length);
    sum += u32::from(pseudo_header.next_header);

    // Sum the packet
    let mut i = 0;
    while i < packet_len - 1 {
        let word = u16::from_be_bytes([buffer[i], buffer[i + 1]]);
        sum += u32::from(word);
        i += 2;
    }

    // If the packet length is odd, add the last byte as a half-word
    if packet_len % 2 != 0 {
        sum += u32::from(buffer[packet_len - 1]) << 8;
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

        let udp_length = (8 + body.len() + INFO_URL.bytes().len()) as u32; // TODO check if this is correct

        let mut packet = Self {
            source_port,
            destination_port,
            length: udp_length as u16, // TODO check if this is correct
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
        // Max length of DNS domain name is 253 character

        // Each label has a max length of 63 characters
        // 20 + 10 + 10 + 3 + 5 + (4 '-' symbols) = 52 characters at most for subdomain
        let subdomain = format!("{}-{}-{}-{}-{}.{}", transmit_time, (source_address & 0xFFFFFFFFFFFFFFFF) as u32,
                                (destination_address & 0xFFFFFFFFFFFFFFFF) as u32, client_id, source_port, domain_name); // TODO verify this takes the 32 right most bits of the ipv6 addresses
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

    //TODO create CHAOS request
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
