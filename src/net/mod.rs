use super::byteorder::{LittleEndian, NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use std::io::Write;
use std::net::Ipv4Addr;

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
    pub fn udp_request(source_port: u16, destination_port: u16, body: Vec<u8>) -> Vec<u8> {
        let mut packet = UDPPacket {
            source_port,
            destination_port,
            // The UDP length field is the length of the UDP header (8) and the data (body + URL)
            length: (8 + body.len() + INFO_URL.bytes().len()) as u16,
            checksum: 0,
            body,
        };

        // Turn everything into a vec of bytes and calculate checksum
        let mut bytes: Vec<u8> = (&packet).into();
        bytes.extend(INFO_URL.bytes());

        // // TODO is the ICMP checksum valid for UDP? It says the checksum can be ignored and set to 0 for UDP
        // 'UDP checksum computation is optional for IPv4. If a checksum is not used it should be set to the value zero.'
        packet.checksum = UDPPacket::calc_checksum(&bytes);

        let mut cursor = Cursor::new(bytes);

        // Put the checksum at the right position in the packet (calling into() again is also
        // possible but is likely slower).
        cursor.set_position(6); // Skip source port (2 bytes), destination port (2 bytes), length (2 bytes)
        cursor.write_u16::<LittleEndian>(packet.checksum).unwrap();

        // Return the vec
        cursor.into_inner()

        // bytes
    }

    // TODO verify this works
    fn calc_checksum(buffer: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let length = buffer.len();

        // Sum up all 16-bit words in the packet
        for i in (0..length).step_by(2) {
            let word = u16::from_be_bytes([buffer[i], buffer[i + 1]]);
            sum = sum.wrapping_add(u32::from(word));
        }

        // If there is an odd number of bytes, add the last byte as a padding byte
        if length % 2 == 1 {
            sum = sum.wrapping_add(u32::from(buffer[length - 1]));
        }

        // Fold the 32-bit sum to a 16-bit checksum
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !sum as u16
    }

}
