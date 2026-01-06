use crate::custom_module::manycastr::{address, Address};
use crate::net::{calculate_checksum, IPv4Packet, IPv6Packet, PacketPayload, PseudoHeader};
use crate::DNS_IDENTIFIER;
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use prost::bytes::Buf;
use std::io::{Cursor, Read, Write};

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

        let pseudo_header = PseudoHeader::new(src, dst, 17, udp_length as u32);
        udp_packet.checksum = calculate_checksum(&udp_bytes, &pseudo_header);

        match (&src.value, &dst.value) {
            (Some(address::Value::V6(_)), Some(address::Value::V6(_))) => {
                let v6_packet = IPv6Packet {
                    payload_length: udp_length,
                    flow_label: 15037,
                    next_header: 17, // UDP
                    hop_limit: ttl,
                    src: src.into(),
                    dst: dst.into(),
                    payload: PacketPayload::Udp { value: udp_packet },
                };
                (&v6_packet).into()
            }
            (Some(address::Value::V4(_)), Some(address::Value::V4(_))) => {
                let v4_packet = IPv4Packet {
                    length: 20 + udp_length,
                    identifier: 15037,
                    ttl,
                    src: src.into(),
                    dst: dst.into(),
                    payload: PacketPayload::Udp { value: udp_packet },
                    options: None,
                };
                (&v4_packet).into()
            }
            _ => panic!("IP version mismatch or unsupported address type in dns_request"),
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
        let src_num = src.to_numeric();
        let dst_num = dst.to_numeric();
        // Max length of DNS domain name is 253 character
        // Each label has a max length of 63 characters
        // 20 + 10 + 10 + 3 + 5 + (4 '-' symbols) = 52 characters at most for subdomain
        let subdomain = format!(
            "{}.{}.{}.{}.{}.{}",
            tx_time, src_num, dst_num, tx_id, sport, domain_name
        );
        let mut dns_body: Vec<u8> = Vec::new();

        // Transaction ID (6 bit identifer + 10 bit tx worker ID)
        let tx_id_raw: u16 = tx_id as u16;
        let encoded_tx_id = ((DNS_IDENTIFIER as u16) << 10) | (tx_id_raw & 0x03FF);

        // DNS Header
        dns_body
            .write_u16::<byteorder::BigEndian>(encoded_tx_id)
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

        let pseudo_header = PseudoHeader::new(src, dst, 17, udp_length);

        udp_packet.checksum = calculate_checksum(&udp_bytes, &pseudo_header);

        match (&src.value, &dst.value) {
            (Some(address::Value::V6(_)), Some(address::Value::V6(_))) => {
                let v6_packet = IPv6Packet {
                    payload_length: udp_length as u16,
                    flow_label: 15037,
                    next_header: 17, // UDP
                    hop_limit: 255,
                    src: src.into(),
                    dst: dst.into(),
                    payload: PacketPayload::Udp { value: udp_packet },
                };
                (&v6_packet).into()
            }
            (Some(address::Value::V4(_)), Some(address::Value::V4(_))) => {
                let v4_packet = IPv4Packet {
                    length: 20 + udp_length as u16,
                    identifier: 15037,
                    ttl: 255,
                    src: src.into(),
                    dst: dst.into(),
                    payload: PacketPayload::Udp { value: udp_packet },
                    options: None,
                };
                (&v4_packet).into()
            }
            _ => panic!("IP version mismatch or invalid address type in UDP packet construction"),
        }
    }

    /// Creating a DNS TXT record request for CHAOS
    fn create_chaos_request(tx_id: u32, chaos: &str) -> Vec<u8> {
        let mut dns_body: Vec<u8> = Vec::new();

        // Transaction ID (6 bit identifer + 10 bit tx worker ID)
        let tx_id_raw: u16 = tx_id as u16;
        let encoded_tx_id = ((DNS_IDENTIFIER as u16) << 10) | (tx_id_raw & 0x03FF);

        // DNS Header
        dns_body
            .write_u16::<byteorder::BigEndian>(encoded_tx_id)
            .unwrap(); // Transaction ID
        dns_body.write_u16::<byteorder::BigEndian>(0x0100).unwrap(); // Flags (Standard query, recursion desired)
        dns_body.write_u16::<byteorder::BigEndian>(0x0001).unwrap(); // Number of questions
        dns_body.write_u16::<byteorder::BigEndian>(0x0000).unwrap(); // Number of answer RRs
        dns_body.write_u16::<byteorder::BigEndian>(0x0000).unwrap(); // Number of authority RRs
        dns_body.write_u16::<byteorder::BigEndian>(0x0000).unwrap(); // Number of additional RRs

        // DNS Question
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
