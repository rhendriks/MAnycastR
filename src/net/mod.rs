extern crate byteorder;
use std::io::{Cursor, Read, Write};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use prost::bytes::Buf;

pub(crate) mod netv6;
pub(crate) mod packet;

/// A struct detailing an IPv4Packet <https://en.wikipedia.org/wiki/Internet_Protocol_version_4>
#[derive(Debug)]
pub struct IPv4Packet {
    pub length: u16,            // 16-bit Total Length
    pub ttl: u8,                // 8-bit Time To Live
    pub src: u32,               // 32-bit Source IP Address
    pub dst: u32,               // 32-bit Destination IP Address
    pub payload: PacketPayload, // Payload
}

/// Convert list of u8 (i.e. received bytes) into an IPv4Packet
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
        let source_address = cursor.read_u32::<NetworkEndian>().unwrap();
        let destination_address = cursor.read_u32::<NetworkEndian>().unwrap(); // Destination IP Address

        // If the header length is longer than the data, the packet is incomplete
        if header_length > data.len() {
            return IPv4Packet {
                length: header_length as u16,
                ttl,
                src: source_address,
                dst: destination_address,
                payload: PacketPayload::Unimplemented,
            };
        }

        let payload_bytes = &cursor.into_inner()[header_length..];
        let payload = match packet_type {
            1 => {
                if payload_bytes.len() < 8 {
                    PacketPayload::Unimplemented
                } else {
                    PacketPayload::ICMP {
                        value: ICMPPacket::from(payload_bytes),
                    }
                }
            }
            17 => {
                if payload_bytes.len() < 8 {
                    PacketPayload::Unimplemented
                } else {
                    PacketPayload::UDP {
                        value: UDPPacket::from(payload_bytes),
                    }
                }
            }
            6 => {
                if payload_bytes.len() < 20 {
                    PacketPayload::Unimplemented
                } else {
                    PacketPayload::TCP {
                        value: TCPPacket::from(payload_bytes),
                    }
                }
            }
            _ => PacketPayload::Unimplemented,
        };

        IPv4Packet {
            length: header_length as u16,
            ttl,
            src: source_address,
            dst: destination_address,
            payload,
        }
    }
}

/// Convert IPv4Packet into a vector of bytes
impl Into<Vec<u8>> for &IPv4Packet {
    fn into(self) -> Vec<u8> {
        let (payload_type, payload) = match &self.payload {
            PacketPayload::ICMP { value } => (1, value.into()),
            PacketPayload::UDP { value } => (17, value.into()),
            PacketPayload::TCP { value } => (6, value.into()),
            PacketPayload::Unimplemented => (0, vec![]),
        };

        let mut wtr = vec![];
        wtr.write_u8(0x45)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Version (4) and header length (5)
        wtr.write_u8(0x00)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Type of Service
        wtr.write_u16::<NetworkEndian>(self.length)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Total Length
        wtr.write_u16::<NetworkEndian>(0x3a7d)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Identification
        wtr.write_u16::<NetworkEndian>(0x0000)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Flags (0) and Fragment Offset (0)
        wtr.write_u8(self.ttl)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Time To Live
        wtr.write_u8(payload_type)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Protocol (ICMP)
        wtr.write_u16::<NetworkEndian>(0x0000)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Header Checksum
        wtr.write_u32::<NetworkEndian>(self.src)
            .expect("Unable to write to byte buffer for IPv4 packet"); // Source IP Address
        wtr.write_u32::<NetworkEndian>(self.dst)
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

/// Definition of the IPV4Packet payload (either ICMPv4, UDP, TCP, or unimplemented)
#[derive(Debug)]
pub enum PacketPayload {
    ICMP { value: ICMPPacket },
    UDP { value: UDPPacket },
    TCP { value: TCPPacket },
    Unimplemented,
}

/// Convert a packet payload to bytes
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

/// Struct defining a pseudo header that is used by both TCP and UDP to calculate their checksum
#[derive(Debug)]
pub struct PseudoHeader {
    pub src: u32,
    pub dst: u32,
    pub zeroes: u8,   // 8 bits of zeros
    pub protocol: u8, // 6 for TCP, 17 for UDP
    pub length: u16,  // TCP/UDP header + data length
}

/// Converting PsuedoHeader to bytes
impl Into<Vec<u8>> for PseudoHeader {
    fn into(self) -> Vec<u8> {
        let mut wtr = vec![];
        wtr.write_u32::<NetworkEndian>(self.src)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u32::<NetworkEndian>(self.dst)
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

/// Calculate the checksum for a UDP/TCP packet.
///
/// # Arguments
///
/// * 'buffer' - the UDP/TCP packet as bytes (without the IPv4 header)
///
/// * 'pseudo_header' - the pseudo header for this packet
pub fn calculate_checksum(buffer: &[u8], pseudo_header: &PseudoHeader) -> u16 {
    let packet_len = buffer.len();
    let mut sum = 0u32;

    // Sum the pseudo header
    sum += pseudo_header.src >> 16;
    sum += pseudo_header.src & 0xffff;
    sum += pseudo_header.dst >> 16;
    sum += pseudo_header.dst & 0xffff;
    sum += u32::from(pseudo_header.protocol);
    sum += u32::from(pseudo_header.length);

    // Sum the packet
    for chunk in buffer.chunks_exact(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum += u32::from(word);
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

/// An ICMP4Packet (ping packet) <https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#header_rest>
#[derive(Debug)]
pub struct ICMPPacket {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
    pub body: Vec<u8>,
}

/// Parsing from bytes to ICMP4Packet
impl From<&[u8]> for ICMPPacket {
    fn from(data: &[u8]) -> Self {
        let mut data = Cursor::new(data);
        ICMPPacket {
            icmp_type: data.read_u8().unwrap(),
            code: data.read_u8().unwrap(),
            checksum: data.read_u16::<NetworkEndian>().unwrap(),
            identifier: data.read_u16::<NetworkEndian>().unwrap(),
            sequence_number: data.read_u16::<NetworkEndian>().unwrap(),
            body: data.into_inner()[8..].to_vec(),
        }
    }
}

/// Convert ICMp4Packet into a vector of bytes
impl Into<Vec<u8>> for &ICMPPacket {
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
    /// * 'source_address' - the source address of the packet
    ///
    /// * 'destination_address' - the destination address of the packet
    ///
    /// * 'ttl' - the time to live of the packet
    ///
    /// * 'info_url' - the URL to be added to the packet payload (e.g., opt-out URL)
    pub fn echo_request(
        identifier: u16,
        sequence_number: u16,
        body: Vec<u8>,
        source_address: u32,
        destination_address: u32,
        ttl: u8,
        info_url: &str,
    ) -> Vec<u8> {
        let body_len = body.len() as u16;
        let mut packet = ICMPPacket {
            icmp_type: 8,
            code: 0,
            checksum: 0,
            identifier,
            sequence_number,
            body,
        };

        // Turn everything into a vec of bytes and calculate checksum
        let mut icmp_bytes: Vec<u8> = (&packet).into();
        icmp_bytes.extend(info_url.bytes());
        packet.checksum = ICMPPacket::calc_checksum(&icmp_bytes);

        let v4_packet = IPv4Packet {
            length: 20 + 8 + body_len + info_url.bytes().len() as u16,
            ttl,
            src: source_address,
            dst: destination_address,
            payload: PacketPayload::ICMP {
                value: packet.into(),
            },
        };

        let mut bytes: Vec<u8> = (&v4_packet).into();
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
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub body: Vec<u8>,
}

/// Parsing from bytes into UDPPacket
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

/// Convert UDPPacket into a vector of bytes
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
            let mut copy = data;
            copy.set_position(offset as u64);
            result.push_str(&read_dns_name(&mut copy));
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
    /// Create a basic UDP packet with checksum (v4 only).
    pub fn udp_request(
        source_address: u32,
        destination_address: u32,
        source_port: u16,
        destination_port: u16,
        body: Vec<u8>,
        info_url: &str,
    ) -> Vec<u8> {
        let length = (8 + body.len() + info_url.bytes().len()) as u16;

        let mut packet = Self {
            source_port,
            destination_port,
            length,
            checksum: 0,
            body,
        };
        let mut bytes: Vec<u8> = (&packet).into();
        bytes.extend(info_url.bytes()); // Add INFO_URL

        let pseudo_header = PseudoHeader {
            src: source_address,
            dst: destination_address,
            zeroes: 0,
            protocol: 17,
            length,
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

    /// Create a UDP packet with a DNS A record request. In the domain of the A record, we encode: transmit_time,
    /// source_address, destination_address, worker_id, source_port, destination_port
    pub fn dns_request(
        source_address: u32,
        destination_address: u32,
        source_port: u16,
        domain_name: &str,
        transmit_time: u64,
        worker_id: u32,
        ttl: u8,
    ) -> Vec<u8> {
        let dns_packet = Self::create_a_record_request(
            &domain_name,
            transmit_time,
            source_address,
            destination_address,
            worker_id,
            source_port,
        );
        let udp_length = (8 + dns_packet.len()) as u16;

        let mut udp_packet = Self {
            source_port,
            destination_port: 53u16, // DNS port
            length: udp_length,
            checksum: 0,
            body: dns_packet,
        };

        // Calculate the UDP checksum (using a pseudo header)
        let udp_bytes: Vec<u8> = (&udp_packet).into();
        let pseudo_header = PseudoHeader {
            src: source_address,
            dst: destination_address,
            zeroes: 0,
            protocol: 17,
            length: udp_length,
        };
        udp_packet.checksum = calculate_checksum(&udp_bytes, &pseudo_header);

        // Create the IPv4 packet
        let v4_packet = IPv4Packet {
            length: 20 + udp_length,
            ttl,
            src: source_address,
            dst: destination_address,
            payload: PacketPayload::UDP {
                value: udp_packet.into(),
            },
        };
        (&v4_packet).into()
    }

    /// Creating a DNS A Record Request body <http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm>
    fn create_a_record_request(
        domain_name: &str,
        transmit_time: u64,
        source_address: u32,
        destination_address: u32,
        worker_id: u32,
        source_port: u16,
    ) -> Vec<u8> {
        // Max length of DNS domain name is 253 character
        // Each label has a max length of 63 characters
        // 20 + 10 + 10 + 3 + 5 + (4 '-' symbols) = 52 characters at most for subdomain
        let subdomain = format!(
            "{}-{}-{}-{}-{}.{}",
            transmit_time, source_address, destination_address, worker_id, source_port, domain_name
        );
        let mut dns_body: Vec<u8> = Vec::new();

        // DNS Header
        dns_body.write_u16::<byteorder::BigEndian>(worker_id as u16).unwrap(); // Transaction ID
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
        source_address: u32,
        destination_address: u32,
        source_port: u16,
        worker_id: u32,
        chaos: &str,
    ) -> Vec<u8> {
        let dns_body = Self::create_chaos_request(worker_id, chaos);
        let udp_length = 8 + dns_body.len() as u32;

        let mut udp_packet = Self {
            source_port,
            destination_port: 53u16,
            length: udp_length as u16,
            checksum: 0,
            body: dns_body,
        };

        let udp_bytes: Vec<u8> = (&udp_packet).into();
        let pseudo_header = PseudoHeader {
            src: source_address,
            dst: destination_address,
            zeroes: 0,
            protocol: 17,
            length: udp_length as u16,
        };

        udp_packet.checksum = calculate_checksum(&udp_bytes, &pseudo_header);

        // Create the IPv4 packet
        let v4_packet = IPv4Packet {
            length: 20 + udp_length as u16,
            ttl: 255,
            src: source_address,
            dst: destination_address,
            payload: PacketPayload::UDP {
                value: udp_packet.into(),
            },
        };
        (&v4_packet).into()
    }

    /// Creating a DNS TXT record request body for id.orchestrator CHAOS request
    fn create_chaos_request(worker_id: u32, chaos: &str) -> Vec<u8> {
        let mut dns_body: Vec<u8> = Vec::new();

        // DNS Header
        dns_body
            .write_u32::<byteorder::BigEndian>(worker_id)
            .unwrap(); // Transaction ID
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
    let mut length = 0;
    for label in domain.split('.') {
        length += label.len() as u32 + 1; // Add the length of the label and the '.' separator
    }
    length
}

/// A TCPPacket <https://en.wikipedia.org/wiki/Transmission_Control_Protocol>
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

/// Parsing from bytes to TCPPacket
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

/// Convert TCPPacket into a vector of bytes
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

impl TCPPacket {
    /// Create a basic TCP SYN/ACK packet with checksum
    pub fn tcp_syn_ack(
        source_address: u32,
        destination_address: u32,
        source_port: u16,
        destination_port: u16,
        seq: u32,
        ack: u32,
        ttl: u8,
        info_url: &str,
    ) -> Vec<u8> {
        let mut packet = Self {
            source_port,
            destination_port,
            seq,
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
        let pseudo_header = PseudoHeader {
            src: source_address,
            dst: destination_address,
            zeroes: 0,
            protocol: 6,                // TCP
            length: bytes.len() as u16, // the length of the TCP header and data (measured in octets)
        };
        packet.checksum = calculate_checksum(&bytes, &pseudo_header);

        let v4_packet = IPv4Packet {
            length: 20 + bytes.len() as u16,
            ttl,
            src: source_address,
            dst: destination_address,
            payload: PacketPayload::TCP {
                value: packet.into(),
            },
        };

        (&v4_packet).into()
    }
}
