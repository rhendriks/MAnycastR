use super::byteorder::{LittleEndian, NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use std::io::Write;
use std::net::Ipv4Addr;

// URL that explains it this packet is part of MAnycast and is for research purposes.
const INFO_URL: &str = "edu.nl/9qt8h";

/// *****
/// IPv4
/// ****

// A struct detailing an IPv4Packet https://en.wikipedia.org/wiki/Internet_Protocol_version_4
#[derive(Debug)]
pub struct IPv4Packet {
    pub ttl: u8,
    pub source_address: Ipv4Addr,
    pub destination_address: Ipv4Addr,
    pub payload: PacketPayload,
}

// Definition of a PacketPayload (either ICMPv4, or unimplemented)
#[derive(Debug)]
pub enum PacketPayload {
    ICMPv4 { value: ICMP4Packet },
    UDP {value: UDPPacket },
    TCP {value: TCPPacket },
    Unimplemented,
}

// Convert list of u8 (i.e. received bytes) into an IPv4Packet
impl From<&[u8]> for IPv4Packet {
    fn from(data: &[u8]) -> Self {
        let mut cursor = Cursor::new(data);
        // Get header length, which is the 4 right bits in the first byte (hence & 0xF)
        // header length is in number of 32 bits i.e. 4 bytes (hence *4)
        let header_length: usize = ((cursor.read_u8().unwrap() & 0xF) * 4).into(); // Total Length

        cursor.set_position(8); // Time To Live
        let ttl = cursor.read_u8().unwrap();

        let packet_type = cursor.read_u8().unwrap(); // Protocol

        cursor.set_position(12); // Source IP Address
        let source_address = Ipv4Addr::from(cursor.read_u32::<NetworkEndian>().unwrap());
        let destination_address = Ipv4Addr::from(cursor.read_u32::<NetworkEndian>().unwrap()); // Destination IP Address

        let payload_bytes = &cursor.into_inner()[header_length..];
        let payload = match packet_type {
            1 => PacketPayload::ICMPv4 {
                value: ICMP4Packet::from(payload_bytes),
            },
            17 => PacketPayload::UDP {
                value: UDPPacket::from(payload_bytes),
            },
            6 => PacketPayload::TCP {
                value: TCPPacket::from(payload_bytes),
            },
            _ => PacketPayload::Unimplemented,
        };

        IPv4Packet {
            ttl,
            source_address,
            destination_address,
            payload,
        }
    }
}

/// *****
/// Pseudo header
/// ****

// TCP and UDP uses a pseudo header for calculating the checksum
#[derive(Debug)]
pub struct PseudoHeader {
    pub source_address: u32,
    pub destination_address: u32,
    pub zeroes: u8, // 8 bits of zeros
    pub protocol: u8, // 6 for TCP, 17 for UDP
    pub length: u16, // TCP/UDP header + data length
}

// Converting PsuedoHeader to bytes
impl Into<Vec<u8>> for PseudoHeader {
    fn into(self) -> Vec<u8> {
        let mut wtr = vec![];
        wtr.write_u32::<NetworkEndian>(self.source_address)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u32::<NetworkEndian>(self.destination_address)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u8(self.zeroes)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u8(self.protocol)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u16::<NetworkEndian>(self.length)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr
    }
}

// Calculate the checksum for UDP/TCP given the UDP/TCP header and payload in buffer, and a constructed pseudo header
pub fn calculate_checksum(buffer: &[u8], pseudoheader: &PseudoHeader) -> u16 {
    let packet_len = buffer.len();
    let mut sum = 0u32;

    // Sum the pseudo header
    sum += pseudoheader.source_address >> 16;
    sum += pseudoheader.source_address & 0xffff;
    sum += pseudoheader.destination_address >> 16;
    sum += pseudoheader.destination_address & 0xffff;
    sum += u32::from(pseudoheader.protocol);
    sum += u32::from(pseudoheader.length);

    // Sum the packet
    let mut i = 0;
    while i < packet_len - 1 {
        let mut rdr = Cursor::new(&buffer[i..]);
        sum += u32::from(rdr.read_u16::<NetworkEndian>().unwrap());
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

/// *****
/// ICMP
/// ****

// An ICMP4Packet (ping packet) https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#header_rest
#[derive(Debug)]
pub struct ICMP4Packet {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
    pub body: Vec<u8>,
}

// Parsing from bytes to ICMP4Packet
impl From<&[u8]> for ICMP4Packet {
    fn from(data: &[u8]) -> Self {
        let mut data = Cursor::new(data);
        ICMP4Packet {
            icmp_type: data.read_u8().unwrap(),
            code: data.read_u8().unwrap(),
            checksum: data.read_u16::<NetworkEndian>().unwrap(),
            identifier: data.read_u16::<NetworkEndian>().unwrap(),
            sequence_number: data.read_u16::<NetworkEndian>().unwrap(),
            body: data.into_inner()[8..].to_vec(),
        }
    }
}

// Convert ICMp4Packet into a vector of u8
impl Into<Vec<u8>> for &ICMP4Packet {
    fn into(self) -> Vec<u8> {
        let mut wtr = vec![];
        wtr.write_u8(self.icmp_type)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_u8(self.code)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_u16::<NetworkEndian>(self.checksum)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_u16::<NetworkEndian>(self.identifier)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_u16::<NetworkEndian>(self.sequence_number)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_all(&self.body)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr
    }
}

// Implementations for the ICMP4Packet type
impl ICMP4Packet {
    /// Create a basic ICMPv4 ECHO_REQUEST (8.0) packet with checksum
    /// Each packet will be created using received SEQUENCE_NUMBER, ID and CONTENT
    pub fn echo_request(identifier: u16, sequence_number: u16, body: Vec<u8>) -> Vec<u8> {
        let mut packet = ICMP4Packet {
            icmp_type: 8,
            code: 0,
            checksum: 0,
            identifier,
            sequence_number,
            body,
        };

        // Turn everything into a vec of bytes and calculate checksum
        let mut bytes: Vec<u8> = (&packet).into();
        bytes.extend(INFO_URL.bytes());
        packet.checksum = ICMP4Packet::calc_checksum(&bytes);

        // Put the checksum at the right position in the packet (calling into() again is also
        // possible but is likely slower).
        let mut cursor = Cursor::new(bytes);
        cursor.set_position(2); // Skip icmp_type (1 byte) and code (1 byte)
        cursor.write_u16::<LittleEndian>(packet.checksum).unwrap();

        // Return the vec
        cursor.into_inner()
    }

    /// Calc ICMP Checksum covers the entire ICMPv4 message (16-bit one's complement)
    fn calc_checksum(buffer: &[u8]) -> u16 {
        let mut cursor = Cursor::new(buffer);
        let mut sum: u32 = 0;
        while let Ok(word) = cursor.read_u16::<LittleEndian>() {
            sum += u32::from(word);
        }
        if let Ok(byte) = cursor.read_u8() {
            sum += u32::from(byte);
        }
        while sum >> 16 > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !sum as u16
    }
}

/// *****
/// UDP
/// ****

// An UDPPacket (UDP packet) https://en.wikipedia.org/wiki/User_Datagram_Protocol
#[derive(Debug)]
pub struct UDPPacket {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub body: Vec<u8>,
}

// Parsing from bytes into UDPPacket
impl From<&[u8]> for UDPPacket {
    fn from(data: &[u8]) -> Self {
        let mut data = Cursor::new(data);
        UDPPacket {
            source_port: data.read_u16::<NetworkEndian>().unwrap(),
            destination_port: data.read_u16::<NetworkEndian>().unwrap(),
            length: data.read_u16::<NetworkEndian>().unwrap(),
            checksum: data.read_u16::<NetworkEndian>().unwrap(),
            body: data.into_inner()[8..].to_vec(),
        }
    }
}

// Convert UDPPacket into a vector of u8
impl Into<Vec<u8>> for &UDPPacket {
    fn into(self) -> Vec<u8> {
        let mut wtr = vec![];
        wtr.write_u16::<NetworkEndian>(self.source_port)
            .expect("Unable to write to byte buffer for UDP packet");
        wtr.write_u16::<NetworkEndian>(self.destination_port)
            .expect("Unable to write to byte buffer for UDP packet");
        wtr.write_u16::<NetworkEndian>(self.length)
            .expect("Unable to write to byte buffer for UDP packet");
        wtr.write_u16::<NetworkEndian>(self.checksum)
            .expect("Unable to write to byte buffer for UDP packet");
        wtr.write_all(&self.body)
            .expect("Unable to write to byte buffer for UDP packet");
        wtr
    }
}

// Implementations for the UDPPacket type
impl UDPPacket {
    /// Create a basic UDP packet with checksum
    /// Each packet will be created using received SEQUENCE_NUMBER, ID and CONTENT
    pub fn udp_request(source_address: u32, destination_address: u32,
                       source_port: u16, destination_port: u16, body: Vec<u8>) -> Vec<u8> {

        let udp_length = (8 + body.len() + INFO_URL.bytes().len()) as u16;

        let mut packet = UDPPacket {
            source_port,
            destination_port,
            length: udp_length,
            checksum: 0,
            body,
        };

        let mut bytes: Vec<u8> = (&packet).into();
        bytes.extend(INFO_URL.bytes()); // Add INFO_URL

        let pseudo_header = PseudoHeader {
            source_address,
            destination_address,
            zeroes: 0,
            protocol: 17,
            length: udp_length,
        };

        packet.checksum = calculate_checksum(&bytes, &pseudo_header);

        // Put the checksum at the right position in the packet (calling into() again is also
        // possible but is likely slower).
        let mut cursor = Cursor::new(bytes);
        cursor.set_position(6); // Skip source port (2 bytes), destination port (2 bytes), udp length (2 bytes)
        cursor.write_u16::<NetworkEndian>(packet.checksum).unwrap();

        // Return the vec
        cursor.into_inner()
    }

    pub fn dns_request(source_address: u32, destination_address: u32, source_port: u16,
                       body: Vec<u8>, domain_name: &str, transmit_time: u64, client_id: u32,) -> Vec<u8> {
        let destination_port = 53 as u16;

        let dns_body = Self::create_dns_a_record_request(domain_name, transmit_time, client_id);

        let udp_length = (8 + body.len() + dns_body.len()) as u16;

        let mut packet = UDPPacket {
            source_port,
            destination_port,
            length: udp_length,
            checksum: 0,
            body,
        };

        let mut bytes: Vec<u8> = (&packet).into();

        bytes.extend(dns_body);

        let pseudo_header = PseudoHeader {
            source_address,
            destination_address,
            zeroes: 0,
            protocol: 17,
            length: udp_length,
        };

        packet.checksum = calculate_checksum(&bytes, &pseudo_header);

        // Put the checksum at the right position in the packet
        let mut cursor = Cursor::new(bytes);
        cursor.set_position(6); // Skip source port (2 bytes), destination port (2 bytes), udp length (2 bytes)
        cursor.write_u16::<NetworkEndian>(packet.checksum).unwrap();

        // Return the vec
        cursor.into_inner()
    }

    // http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
    fn create_dns_a_record_request(
        domain_name: &str,
        transmit_time: u64,
        client_id: u32,
    ) -> Vec<u8> {
        let subdomain = format!("{}-{}.{}", transmit_time, client_id, domain_name);
        let mut dns_body: Vec<u8> = Vec::new();

        // DNS Header
        dns_body.write_u16::<byteorder::BigEndian>(0x1234).unwrap(); // Transaction ID
        dns_body.write_u16::<byteorder::BigEndian>(0x0100).unwrap(); // Flags (Standard query, recursion desired)
        dns_body.write_u16::<byteorder::BigEndian>(0x0001).unwrap(); // Number of questions
        dns_body.write_u16::<byteorder::BigEndian>(0x0000).unwrap(); // Number of answer RRs
        dns_body.write_u16::<byteorder::BigEndian>(0x0000).unwrap(); // Number of authority RRs
        dns_body.write_u16::<byteorder::BigEndian>(0x0000).unwrap(); // Number of additional RRs

        // DNS Question // TODO not working?
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

/// *****
/// TCP
/// ****

// A TCPPacket https://en.wikipedia.org/wiki/Transmission_Control_Protocol
#[derive(Debug)]
pub struct TCPPacket {
    pub source_port: u16,
    pub destination_port: u16,
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

// Parsing from bytes to TCPPacket
impl From<&[u8]> for TCPPacket {
    fn from(data: &[u8]) -> Self {
        let mut data = Cursor::new(data);
        TCPPacket {
            source_port: data.read_u16::<NetworkEndian>().unwrap(),
            destination_port: data.read_u16::<NetworkEndian>().unwrap(),
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

// Convert TCPPacket into a vector of u8
impl Into<Vec<u8>> for &TCPPacket {
    fn into(self) -> Vec<u8> {
        let mut wtr = vec![];
        wtr.write_u16::<NetworkEndian>(self.source_port)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u16::<NetworkEndian>(self.destination_port)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u32::<NetworkEndian>(self.seq)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u32::<NetworkEndian>(self.ack)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u8(self.offset)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u8(self.flags)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u16::<NetworkEndian>(self.window_size)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u16::<NetworkEndian>(self.checksum)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_u16::<NetworkEndian>(self.pointer)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr.write_all(&self.body)
            .expect("Unable to write to byte buffer for TCP packet");
        wtr
    }
}

// Implementations for the TCPPacket type
impl TCPPacket {
    /// Create a basic UDP packet with checksum
    /// Each packet will be created using received SEQUENCE_NUMBER, ID and CONTENT
    pub fn tcp_syn_ack(source_address: u32, destination_address: u32,
                       source_port: u16, destination_port: u16, seq: u32, ack:u32, body: Vec<u8>) -> Vec<u8> {
        let mut packet = TCPPacket {
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

        let pseudo_header = PseudoHeader {
            source_address,
            destination_address,
            zeroes: 0,
            protocol: 6, // TCP
            length: bytes.len() as u16, // the length of the TCP header and data (measured in octets)
        };

        packet.checksum = calculate_checksum(&bytes, &pseudo_header);

        // Put the checksum at the right position in the packet
        let mut cursor = Cursor::new(bytes);
        cursor.set_position(16); // Skip source port (2 bytes), destination port (2 bytes), seq (4 bytes), ack (4 bytes), offset/reserved (1 byte), flags (1 bytes), window (2 bytes)
        cursor.write_u16::<NetworkEndian>(packet.checksum).unwrap();

        // Return the vec
        cursor.into_inner()
    }
}