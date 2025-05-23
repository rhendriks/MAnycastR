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
impl Into<Vec<u8>> for IPv6Packet {
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

        // Write the payload
        let payload_bytes: Vec<u8> = self.payload.into();
        wtr.write_all(&*payload_bytes)
            .expect("Unable to write to byte buffer for IPv6 packet"); // Payload

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

        let mut bytes: Vec<u8> = v6_packet.into();
        bytes.extend(info_url.bytes());

        bytes
    }
}

/// Struct defining a pseudo header (IPv6) that is used by both TCP and UDP to calculate their checksum
#[derive(Debug)]
pub struct PseudoHeaderv6 {
    pub src: u128,
    pub dst: u128,
    pub length: u32,     // TCP/UDP header + data length
    pub zeros: u32,      // 24 0's
    pub next_header: u8, // 6 for TCP, 17 for UDP
}

/// Converting PsuedoHeaderv6 to bytes
impl Into<Vec<u8>> for PseudoHeaderv6 {
    fn into(self) -> Vec<u8> {
        let mut wtr = vec![];
        wtr.write_u128::<NetworkEndian>(self.src)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u128::<NetworkEndian>(self.dst)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u32::<NetworkEndian>(self.length)
            .expect("Unable to write to byte buffer for PseudoHeader");
        wtr.write_u24::<NetworkEndian>(self.zeros)
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
pub fn calculate_checksum_v6(buffer_slice: &[u8], pseudo_header: PseudoHeaderv6) -> u16 {
    let mut packet: Vec<u8> = pseudo_header.into();
    packet.extend_from_slice(buffer_slice); // Append the UDP/TCP packet bytes
    let packet_len = packet.len();
    let mut sum = 0u32;

    // Sum the packet
    for chunk in packet.chunks_exact(2) {
        // Directly create u16 from the two bytes in network order (big-endian)
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum += u32::from(word);
    }

    // If the packet length is odd, add the last byte as a half-word
    if packet_len % 2 != 0 {
        sum += u32::from(packet[packet_len - 1]) << 8;
    }

    // Fold the sum to 16 bits by adding the carry
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

impl super::UDPPacket {
    /// Create a basic UDP packet with checksum.
    ///
    /// # Arguments
    ///
    /// * 'src' - the source address of the packet
    ///
    /// * 'dst' - the destination address of the packet
    ///
    /// * 'sport' - the source port of the packet
    ///
    /// * 'dport' - the destination port of the packet
    ///
    /// * 'body' - the payload of the packet
    ///
    /// * 'info_url' - URL encoded in packet payload (e.g., opt-out URL)
    pub fn udp_request_v6(
        src: u128,
        dst: u128,
        sport: u16,
        dport: u16,
        body: Vec<u8>,
        info_url: &str,
    ) -> Vec<u8> {
        // TODO add IP header
        let udp_length = (8 + body.len() + info_url.bytes().len()) as u32;

        let mut packet = Self {
            source_port: sport,
            destination_port: dport,
            length: udp_length as u16,
            checksum: 0,
            body,
        };

        let mut bytes: Vec<u8> = (&packet).into();
        bytes.extend(info_url.bytes()); // Add INFO_URL

        let pseudo_header = PseudoHeaderv6 {
            src,
            dst,
            zeros: 0,
            next_header: 17,
            length: udp_length,
        };

        packet.checksum = calculate_checksum_v6(&bytes, pseudo_header);

        // Put the checksum at the right position in the packet
        let mut cursor = Cursor::new(bytes);
        cursor.set_position(6); // Skip source port (2 bytes), destination port (2 bytes), udp length (2 bytes)
        cursor.write_u16::<NetworkEndian>(packet.checksum).unwrap();

        // Return the vec
        cursor.into_inner()
    }

    /// Create a UDP packet with a DNS A record request. In the domain of the A record, we encode: transmit_time,
    /// source_address, destination_address, worker_id, source_port, destination_port
    ///
    /// # Arguments
    ///
    /// * 'src' - the source address of the packet
    ///
    /// * 'dst' - the destination address of the packet
    ///
    /// * 'sport' - the source port of the packet
    ///
    /// * 'qname' - the domain name of the A record (excluding encoded values)
    ///
    /// * 'tx_time' - the time of transmission
    ///
    /// * 'worker_id' - the sender worker ID
    ///
    /// * 'hop_limit' - the hop limit (TTL) of the packet
    pub fn dns_request_v6(
        src: u128,
        dst: u128,
        sport: u16,
        qname: &str,
        tx_time: u64,
        worker_id: u32,
        hop_limit: u8,
    ) -> Vec<u8> {
        let destination_port = 53u16; // DNS port
        let dns_packet =
            Self::create_dns_a_record_request_v6(&qname, tx_time, src, dst, worker_id, sport);
        let udp_length = (8 + dns_packet.len()) as u32;

        let mut udp_packet = Self {
            source_port: sport,
            destination_port,
            length: udp_length as u16,
            checksum: 0,
            body: dns_packet,
        };

        // Calculate the UDP checksum (using a pseudo header)
        let udp_bytes: Vec<u8> = (&udp_packet).into();
        let pseudo_header = PseudoHeaderv6 {
            src,
            dst,
            zeros: 0,
            next_header: 17,
            length: udp_length,
        };
        udp_packet.checksum = calculate_checksum_v6(&udp_bytes, pseudo_header);

        // Create the IPv6 packet
        let v6_packet = IPv6Packet {
            payload_length: udp_length as u16,
            next_header: 17, // UDP
            hop_limit,
            src,
            dst,
            payload: PacketPayload::UDP { value: udp_packet },
        };

        v6_packet.into()
    }

    /// Creating the DNS body with the A record request
    ///
    /// # Arguments
    ///
    /// * 'domain_name' - the domain name of the A record (excluding encoded values)
    ///
    /// * 'tx_time' - the time of transmission
    ///
    /// * 'src' - the source address of the packet
    ///
    /// * 'dst' - the destination address of the packet
    ///
    /// * 'worker_id' - the sender worker ID
    ///
    /// * 'sport' - the source port of the packet
    fn create_dns_a_record_request_v6(
        domain_name: &str,
        tx_time: u64,
        src: u128,
        dst: u128,
        worker_id: u32,
        sport: u16,
    ) -> Vec<u8> {
        // Max length of DNS domain name is 253 characters

        // Each label has a max length of 63 characters
        // 20 + 10 + 10 + 3 + 5 + (4 '-' symbols) = 52 characters at most for subdomain
        // u128 highest value has 39 digits
        let subdomain = format!(
            "{}.{}.{}.{}.{}.{}",
            tx_time, src, dst, worker_id, sport, domain_name
        );
        let mut dns_body: Vec<u8> = Vec::new();
        // DNS Header
        dns_body
            .write_u32::<byteorder::BigEndian>(worker_id)
            .expect("Unable to write to byte buffer for UDP packet"); // Transaction ID
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
    pub fn chaos_request_v6(
        src: u128,
        dst: u128,
        sport: u16,
        worker_id: u32,
        chaos: &str,
    ) -> Vec<u8> {
        let destination_port = 53u16;
        let dns_body = Self::create_chaos_request(worker_id, chaos);
        let udp_length = 8 + dns_body.len() as u32;

        let mut udp_packet = Self {
            source_port: sport,
            destination_port,
            length: udp_length as u16,
            checksum: 0,
            body: dns_body,
        };

        let udp_bytes: Vec<u8> = (&udp_packet).into();

        let pseudo_header = PseudoHeaderv6 {
            src,
            dst,
            zeros: 0,
            length: udp_length,
            next_header: 17,
        };

        udp_packet.checksum = calculate_checksum_v6(&udp_bytes, pseudo_header);

        // Create the IPv6 packet
        let v6_packet = IPv6Packet {
            payload_length: udp_length as u16,
            next_header: 17, // UDP
            hop_limit: 255,
            src,
            dst,
            payload: PacketPayload::UDP { value: udp_packet },
        };

        v6_packet.into()
    }
}

impl super::TCPPacket {
    /// Create a basic TCPv6 SYN/ACK packet with checksum
    ///
    /// # Arguments
    ///
    /// * 'src' - the source address of the packet
    ///
    /// * 'dst' - the destination address of the packet
    ///
    /// * 'sport' - the source port of the packet
    ///
    /// * 'dport' - the destination port of the packet
    ///
    /// * 'seq' - the sequence number of the packet
    ///
    /// * 'ack' - the acknowledgment number of the packet
    ///
    /// * 'hop_limit' - the hop limit (TTL) of the packet
    ///
    /// * 'info_url' - URL encoded in packet payload (e.g., opt-out URL)
    pub fn tcp_syn_ack_v6(
        src: u128,
        dst: u128,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        hop_limit: u8,
        info_url: &str,
    ) -> Vec<u8> {
        let mut packet = Self {
            source_port: sport,
            destination_port: dport,
            seq,
            ack,
            offset: 0b01010000, // Offset 5 for minimum TCP header length (0101) + 0000 for reserved
            flags: 0b00010010,  // SYN and ACK flags
            checksum: 0,
            pointer: 0,
            body: info_url.bytes().collect(),
            window_size: 0,
        };

        let bytes: Vec<u8> = (&packet).into();
        let pseudo_header = PseudoHeaderv6 {
            src,
            dst,
            zeros: 0,
            next_header: 6,             // TCP
            length: bytes.len() as u32, // the length of the TCP header and data (measured in octets)
        };
        packet.checksum = calculate_checksum_v6(&bytes, pseudo_header);

        let v6_packet = IPv6Packet {
            payload_length: bytes.len() as u16,
            next_header: 6, // TCP
            hop_limit,
            src,
            dst,
            payload: PacketPayload::TCP { value: packet },
        };

        v6_packet.into()
    }
}
