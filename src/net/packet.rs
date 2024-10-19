use std::io;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use mac_address::get_mac_address;
use crate::custom_module::IP;
use crate::custom_module::verfploeter::{Origin, PingPayload};
use crate::custom_module::verfploeter::address::Value::{V4, V6};
use crate::net::{ICMPPacket, TCPPacket, UDPPacket};
use std::io::BufRead;
use mac_address::mac_address_by_name;

/// Returns the ethernet header to use for the outbound packets.
///
/// # Arguments
///
/// * 'is_ipv6' - whether we are using IPv6 or not
pub fn get_ethernet_header(
    is_ipv6: bool,
    if_name: Option<String>
) -> Vec<u8> {
    // Get the src MAC for interface, if provided
    let mac_src = if let Some(if_name) = if_name {
        if let Ok(Some(mac)) = mac_address_by_name(&if_name) {
            mac.bytes().to_vec()
        } else {
            panic!("No MAC address found for interface: {}", if_name);
        }
    } else {
        match get_mac_address() {
            Ok(Some(ma)) => {
                ma.bytes().to_vec()
            },
            Ok(None) => panic!("No MAC address found."),
            Err(e) => panic!("{:?}", e),
        }
    };

    // Run the sudo arp command (for the destination MAC addresses)
    let mut child = Command::new("cat")
        .arg("/proc/net/arp")
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to run command");
    // .stdout
    // .expect("Failed to capture stdout");

    let output = child.stdout.as_mut().expect("Failed to capture stdout");

    // Get the destination MAC addresses
    let mut mac_dst = vec![];
    let reader = io::BufReader::new(output);
    let mut lines = reader.lines();
    lines.next(); // Skip the first line (header)
    for line in lines {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 3 {
                mac_dst = parts[3].split(':').map(|s| u8::from_str_radix(s, 16).unwrap()).collect();
                break;
            }
        }
    }
    child.wait().expect("Failed to wait on child");

    // Construct the ethernet header
    let ether_type = if is_ipv6 {
        0x86DDu16
    } else {
        0x0800u16
    };
    let mut ethernet_header: Vec<u8> = Vec::new();
    ethernet_header.extend_from_slice(&mac_dst);
    ethernet_header.extend_from_slice(&mac_src);
    ethernet_header.extend_from_slice(&ether_type.to_be_bytes());

    ethernet_header
}

/// Creates a ping packet.
///
/// # Arguments
///
/// * 'origin' - the source address and ICMP identifier (dst port) we use for our probes
///
/// * 'dst' - the destination address for the ping packet
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'measurement_id' - the unique ID of the current measurement
///
/// # Returns
///
/// A ping packet (including the IP header) as a byte vector.
pub fn create_ping(
    origin: Origin,
    dst: IP,
    client_id: u8,
    measurement_id: u32,
    info_url: &str,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let src = IP::from(origin.src.expect("None IP address"));
    // Create ping payload
    let payload = PingPayload {
        tx_time,
        src: Some(src.clone().into()),
        dst: Some(dst.clone().into()),
        tx_client_id: client_id as u32,
    };

    // Create the ping payload bytes
    let mut payload_bytes: Vec<u8> = Vec::new();
    payload_bytes.extend_from_slice(&measurement_id.to_be_bytes()); // Bytes 0 - 3
    payload_bytes.extend_from_slice(&payload.tx_time.to_be_bytes()); // Bytes 4 - 11 *
    payload_bytes.extend_from_slice(&payload.tx_client_id.to_be_bytes()); // Bytes 12 - 15 *
    if let Some(source_address) = payload.src {
        match source_address.value {
            Some(V4(v4)) => payload_bytes.extend_from_slice(&v4.to_be_bytes()), // Bytes 16 - 19
            Some(V6(v6)) => {
                payload_bytes.extend_from_slice(&v6.p1.to_be_bytes()); // Bytes 16 - 23
                payload_bytes.extend_from_slice(&v6.p2.to_be_bytes()); // Bytes 24 - 31
            }
            None => panic!("Source address is None"),
        }
    }
    if let Some(destination_address) = payload.dst {
        match destination_address.value {
            Some(V4(v4)) => payload_bytes.extend_from_slice(&v4.to_be_bytes()), // Bytes 32 - 35
            Some(V6(v6)) => {
                payload_bytes.extend_from_slice(&v6.p1.to_be_bytes()); // Bytes 32 - 39
                payload_bytes.extend_from_slice(&v6.p2.to_be_bytes()); // Bytes 40 - 47
            }
            None => panic!("Destination address is None"),
        }
    }

    if src.is_v6() {
        ICMPPacket::echo_request_v6(origin.sport as u16, 2, payload_bytes, src.get_v6().into(), IP::from(dst.clone()).get_v6().into(), 255, info_url)
    } else {
        ICMPPacket::echo_request(origin.dport as u16, 2, payload_bytes, src.get_v4().into(), IP::from(dst.clone()).get_v4().into(), 255, info_url)
    }
}

/// Creates a UDP packet.
///
/// # Arguments
///
/// * 'origin' - the source address and port values we use for our probes
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'dst' - the destination address for the UDP packet
///
/// * 'measurement_type' - the type of measurement being performed (2 = UDP/DNS, 4 = UDP/CHAOS)
///
/// * 'is_ipv6' - whether we are using IPv6 or not
///
/// * 'dns_record' - the DNS record to request
///
/// # Returns
///
/// A UDP packet (including the IP header) as a byte vector.
///
/// # Panics
///
/// If the measurement type is not 2 or 4
pub fn create_udp(
    origin: Origin,
    dst: IP,
    client_id: u8,
    measurement_type: u8,
    is_ipv6: bool,
    dns_record: &str,
) -> Vec<u8> {
    let transmit_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let src = IP::from(origin.src.expect("None IP address"));
    let dport = origin.dport as u16;

    if is_ipv6 {
        if measurement_type == 2 {
            UDPPacket::dns_request_v6(src.get_v6().into(), dst.get_v6().into(), dport, dns_record, transmit_time, client_id, 255)
        } else if measurement_type == 4 {
            UDPPacket::chaos_request_v6(src.get_v6().into(), dst.get_v6().into(), dport, client_id, dns_record)
        } else {
            panic!("Invalid measurement type")
        }
    } else {
        if measurement_type == 2 {
            UDPPacket::dns_request(src.get_v4().into(), dst.get_v4().into(), dport, dns_record, transmit_time, client_id, 255)
        } else if measurement_type == 4 {
            UDPPacket::chaos_request(src.get_v4().into(), dst.get_v4().into(), dport, client_id, dns_record)
        } else {
            panic!("Invalid measurement type")
        }
    }
}

/// Creates a TCP packet.
///
/// # Arguments
///
/// * 'origin' - the source address and port values we use for our probes
///
/// * 'dst' - the destination address for the TCP packet
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'is_ipv6' - whether we are using IPv6 or not
///
/// * 'gcd' - whether we are performing anycast-based (false) or GCD probing (true)
///
/// # Returns
///
/// A TCP packet (including the IP header) as a byte vector.
pub fn create_tcp(
    origin: Origin,
    dst: IP,
    client_id: u8,
    is_ipv6: bool,
    gcd: bool,
    info_url: &str,
) -> Vec<u8> {
    let transmit_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32; // The least significant bits are kept
    let seq = 0; // information in seq gets lost
    // for MAnycast the ACK is the client ID, for GCD the ACK is the transmit time
    let ack = if !gcd {
        client_id as u32
    } else {
        transmit_time
    };

    if is_ipv6 {
        let src = IP::from(origin.src.expect("None IP address")).get_v6();
        let dest = IP::from(dst.clone()).get_v6();

        TCPPacket::tcp_syn_ack_v6(src.into(), dest.into(), origin.sport as u16, origin.dport as u16, seq, ack, 255, info_url)
    } else {
        let src = IP::from(origin.src.expect("None IP address")).get_v4();
        let dest = IP::from(dst.clone()).get_v4();

        TCPPacket::tcp_syn_ack(src.into(), dest.into(), origin.sport as u16, origin.dport as u16, seq, ack, 255, info_url)
    }
}
