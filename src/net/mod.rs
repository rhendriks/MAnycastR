use super::byteorder::{LittleEndian, NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};
use std::io::Write;
use std::net::Ipv4Addr;
use internet_checksum::checksum;

// URL that explains it this packet is part of MAnycast and is for research purposes.
const INFO_URL: &str = "edu.nl/9qt8h";

// A struct detailing an IPv4Packet
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
    Unimplemented, //TODO
}

// Convert list of u8 into an IPv4Packet
impl From<&[u8]> for IPv4Packet {
    fn from(data: &[u8]) -> Self {
        let mut cursor = Cursor::new(data);
        // Get header length, which is the 4 right bits in the first byte (hence & 0xF)
        // header length is in number of 32 bits i.e. 4 bytes (hence *4)
        let header_length: usize = ((cursor.read_u8().unwrap() & 0xF) * 4).into();

        cursor.set_position(8);
        let ttl = cursor.read_u8().unwrap();

        //cursor.set_position(9);
        let packet_type = cursor.read_u8().unwrap();

        cursor.set_position(12);
        let source_address = Ipv4Addr::from(cursor.read_u32::<NetworkEndian>().unwrap());
        let destination_address = Ipv4Addr::from(cursor.read_u32::<NetworkEndian>().unwrap());

        let payload_bytes = &cursor.into_inner()[header_length..];
        let payload = match packet_type { //TODO
            1 => PacketPayload::ICMPv4 {
                value: ICMP4Packet::from(payload_bytes),
            },
            _ => PacketPayload::Unimplemented, // TODO
        };

        IPv4Packet {
            ttl,
            source_address,
            destination_address,
            payload,
        }
    }
}

// An ICMP4Packet (ping packet)
#[derive(Debug)]
pub struct ICMP4Packet {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
    pub body: Vec<u8>,
}

// An UDPPacket (UDP packet)
#[derive(Debug)]
pub struct UDPPacket {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct TCPPacket;

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

// Convert UDPPacket into a vector of u8
impl Into<Vec<u8>> for &UDPPacket {
    fn into(self) -> Vec<u8> {
        let mut wtr = vec![];
        wtr.write_u16::<NetworkEndian>(self.source_port)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_u16::<NetworkEndian>(self.destination_port)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_u16::<NetworkEndian>(self.length)
            .expect("Unable to write to byte buffer for ICMP packet");
        wtr.write_u16::<NetworkEndian>(self.checksum)
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
    /// TODO L-> ICMPv6 it also covers a pseudo-header derived from portions of the IPv6 header.
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

// Implementations for the UDPPacket type
impl UDPPacket {
    /// Create a basic UDP packet with checksum
    /// Each packet will be created using received SEQUENCE_NUMBER, ID and CONTENT
    /// TODO udp also uses a psuedo header for calculating the checksum
    pub fn udp_request(source_addr: u32, dest_addr: u32,
        source_port: u16, destination_port: u16, body: Vec<u8>) -> Vec<u8> {

        let mut payload = INFO_URL.as_bytes().to_vec();
        payload.extend_from_slice(&body);

        let udp_length = 8 + body.len() + INFO_URL.bytes().len();

        let mut pseudo_header = [0u8; 12];
        pseudo_header[..4].copy_from_slice(&Ipv4Addr::from(source_addr).octets().as_slice());
        pseudo_header[4..8].copy_from_slice(&&Ipv4Addr::from(dest_addr).octets().as_slice());
        pseudo_header[8] = 0; // Protocol field (set to 0 for testing purposes)
        pseudo_header[9] = 17; // Protocol field (set to 17 for UDP)
        pseudo_header[10..12].copy_from_slice(&(udp_length as u16).to_be().to_be_bytes()); // TODO to_be might not be the right endian form
        // TODO can possible just remove .to_be() all together

        let mut packet = Vec::new();
        packet.extend_from_slice(&pseudo_header);
        packet.extend_from_slice(&(source_port as u16).to_be().to_be_bytes());
        packet.extend_from_slice(&(destination_port as u16).to_be().to_be_bytes());
        packet.extend_from_slice(&(udp_length as u16).to_be().to_be_bytes());
        packet.extend_from_slice(&[0u8, 0u8]); // Placeholder for checksum
        packet.extend_from_slice(&*payload);

        let checksum = Self::calc_checksum(&packet);

        packet[6..8].copy_from_slice(&(checksum as u16).to_be().to_be_bytes());

        packet
    }

    fn calc_checksum(packet: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;

        while i < packet.len() - 1 {
            let word = u16::from_be_bytes([packet[i], packet[i + 1]]);
            sum += u32::from(word);
            i += 2;
        }

        if packet.len() % 2 == 1 {
            sum += u32::from(packet[packet.len() - 1]) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    // // TODO verify this works
    // fn calc_checksum(buffer: &[u8]) -> u16 {
    //     let mut sum: u32 = 0;
    //     let length = buffer.len();
    //
    //     // Sum up all 16-bit words in the packet
    //     for i in (0..length).step_by(2) {
    //         let word = u16::from_be_bytes([buffer[i], buffer[i + 1]]);
    //         sum = sum.wrapping_add(u32::from(word));
    //     }
    //
    //     // If there is an odd number of bytes, add the last byte as a padding byte
    //     if length % 2 == 1 {
    //         sum = sum.wrapping_add(u32::from(buffer[length - 1]));
    //     }
    //
    //     // Fold the 32-bit sum to a 16-bit checksum
    //     while sum >> 16 != 0 {
    //         sum = (sum & 0xffff) + (sum >> 16);
    //     }
    //
    //     !sum as u16
    // }

}

// Implementations for the TCPPacket type
impl TCPPacket {
    // /// Create a TCP SYN/ACK packet with checksum
    // pub fn tcp_request(source_addr: u32, dest_addr: u32,
    //                    source_port: u16, destination_port: u16, seq_num: u32, ack_num: u32) -> Vec<u8> {
    //     let data_offset = 5; // Data offset in 32-bit words, which is 20 bytes
    //     let window_size: i32 = 4096; // Window size in bytes
    //     let mut tcp_header = [0u8; 20];
    //     let mut packet = Vec::new();
    //
    //     // Set the source and destination port numbers
    //     tcp_header[0..2].copy_from_slice(&source_port.to_be_bytes());
    //     tcp_header[2..4].copy_from_slice(&destination_port.to_be_bytes());
    //
    //     // Set the sequence and acknowledgement numbers
    //     tcp_header[4..8].copy_from_slice(&seq_num.to_be_bytes());
    //     tcp_header[8..12].copy_from_slice(&ack_num.to_be_bytes());
    //
    //     // Set the data offset and reserved bits
    //     tcp_header[12] = (data_offset << 4) as u8;
    //
    //     // Set the flags (SYN/ACK)
    //     tcp_header[13] = 0b00010010;
    //
    //     // Set the window size
    //     tcp_header[14..16].copy_from_slice(&window_size.to_be_bytes());
    //
    //     // Calculate the TCP checksum
    //     let pseudo_header = [
    //         (source_addr >> 24) as u8,
    //         (source_addr >> 16) as u8,
    //         (source_addr >> 8) as u8,
    //         (source_addr >> 0) as u8,
    //         (dest_addr >> 24) as u8,
    //         (dest_addr >> 16) as u8,
    //         (dest_addr >> 8) as u8,
    //         (dest_addr >> 0) as u8,
    //         0,
    //         6,
    //         0,
    //         (tcp_header.len() as u16).to_be_bytes()[0],
    //         (tcp_header.len() as u16).to_be_bytes()[1],
    //     ];
    //     let checksum_data = [pseudo_header, tcp_header].concat();
    //     let checksum = !checksum(&checksum_data);
    //
    //     // Set the TCP checksum
    //     tcp_header[16..18].copy_from_slice(&checksum.to_be_bytes());
    //
    //     // Add the TCP header to the packet
    //     packet.extend_from_slice(&tcp_header);
    //
    //     packet
    //
    // }
}
