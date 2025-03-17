use crate::custom_module::verfploeter::address::Value::{V4, V6};
use crate::custom_module::verfploeter::{Origin, PingPayload};
use crate::custom_module::IP;
use crate::net::{ICMPPacket, TCPPacket, UDPPacket};
use mac_address::{mac_address_by_name};
use std::io;
use std::io::BufRead;
use std::net::{IpAddr};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use pnet::ipnetwork::IpNetwork;

/// Returns the ethernet header to use for the outbound packets.
///
/// # Arguments
///
/// * 'is_ipv6' - whether we are using IPv6 or not
pub fn get_ethernet_header(
    is_ipv6: bool,
    if_name: String, // TODO different interfaces may be used for different addresses
) -> Vec<u8> {
    // Get the source MAC address for the used interface
    let mac_src = mac_address_by_name(&if_name)
        .expect(&format!{"No MAC address found for interface: {}", if_name}).unwrap().bytes().to_vec();

    // Run the sudo arp command (for the destination MAC addresses)
    let mut child = Command::new("cat")
        .arg("/proc/net/arp")
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to run command");
    let output = child.stdout.as_mut().expect("Failed to capture stdout");

    // Get the destination MAC addresses
    let mut mac_dst = vec![];
    let reader = io::BufReader::new(output);
    let mut lines = reader.lines();
    lines.next(); // Skip the first line (header)
    for line in lines {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 5 {
                // Skip 00:00:00:00:00:00
                if parts[3].split(':').all(|s| s == "00") {
                    continue;
                }
                // Match on the interface name
                if parts[5] == if_name {
                    mac_dst = parts[3]
                        .split(':')
                        .map(|s| u8::from_str_radix(s, 16).unwrap())
                        .collect();
                    break;
                }
            }
        }
    }
    child.wait().expect("Failed to wait on child");

    // Construct the ethernet header
    let ether_type = if is_ipv6 { 0x86DDu16 } else { 0x0800u16 };
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
/// * 'worker_id' - the unique worker ID of this worker
///
/// * 'measurement_id' - the unique ID of the current measurement
///
/// # Returns
///
/// A ping packet (including the IP header) as a byte vector.
pub fn create_ping(
    origin: Origin,
    dst: IP,
    worker_id: u16,
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
        src: Some(src.into()),
        dst: Some(dst.into()),
        tx_worker_id: worker_id as u32,
    };

    // Create the ping payload bytes
    let mut payload_bytes: Vec<u8> = Vec::new();
    payload_bytes.extend_from_slice(&measurement_id.to_be_bytes()); // Bytes 0 - 3
    payload_bytes.extend_from_slice(&payload.tx_time.to_be_bytes()); // Bytes 4 - 11 *
    payload_bytes.extend_from_slice(&payload.tx_worker_id.to_be_bytes()); // Bytes 12 - 15 *
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
        ICMPPacket::echo_request_v6(
            origin.sport as u16,
            2,
            payload_bytes,
            src.get_v6().into(),
            IP::from(dst).get_v6().into(),
            255,
            info_url,
        )
    } else {
        ICMPPacket::echo_request(
            origin.dport as u16,
            2,
            payload_bytes,
            src.get_v4().into(),
            IP::from(dst).get_v4().into(),
            255,
            info_url,
        )
    }
}

/// Creates a UDP packet.
///
/// # Arguments
///
/// * 'origin' - the source address and port values we use for our probes
///
/// * 'worker_id' - the unique worker ID of this worker
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
    worker_id: u16,
    measurement_type: u8,
    is_ipv6: bool,
    qname: &str,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let src = IP::from(origin.src.expect("None IP address"));
    let sport = origin.sport as u16;

    if is_ipv6 {
        if measurement_type == 2 {
            UDPPacket::dns_request_v6(
                src.get_v6().into(),
                dst.get_v6().into(),
                sport,
                qname,
                tx_time,
                worker_id,
                255,
            )
        } else if measurement_type == 4 {
            UDPPacket::chaos_request_v6(
                src.get_v6().into(),
                dst.get_v6().into(),
                sport,
                worker_id,
                qname,
            )
        } else {
            panic!("Invalid measurement type")
        }
    } else {
        if measurement_type == 2 {
            UDPPacket::dns_request(
                src.get_v4().into(),
                dst.get_v4().into(),
                sport,
                qname,
                tx_time,
                worker_id,
                255,
            )
        } else if measurement_type == 4 {
            UDPPacket::chaos_request(
                src.get_v4().into(),
                dst.get_v4().into(),
                sport,
                worker_id,
                qname,
            )
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
/// * 'worker_id' - the unique worker ID of this worker
///
/// * 'is_ipv6' - whether we are using IPv6 or not
///
/// * 'is_unicast' - whether we are performing anycast-based (false) or GCD probing (true)
///
/// # Returns
///
/// A TCP packet (including the IP header) as a byte vector.
pub fn create_tcp(
    origin: Origin,
    dst: IP,
    worker_id: u16,
    is_ipv6: bool,
    is_unicast: bool,
    info_url: &str,
) -> Vec<u8> {
    let transmit_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32; // The least significant bits are kept
    let seq = 0; // information in seq gets lost
                 // for MAnycast the ACK is the worker ID, for GCD the ACK is the transmit time
    let ack = if !is_unicast {
        worker_id as u32
    } else {
        transmit_time
    };

    if is_ipv6 {
        TCPPacket::tcp_syn_ack_v6(
            IP::from(origin.src.expect("None IP address")).get_v6().into(),
            IP::from(dst).get_v6().into(),
            origin.sport as u16,
            origin.dport as u16,
            seq,
            ack,
            255,
            info_url,
        )
    } else {
        TCPPacket::tcp_syn_ack(
            IP::from(origin.src.expect("None IP address")).get_v4().into(),
            IP::from(dst).get_v4().into(),
            origin.sport as u16,
            origin.dport as u16,
            seq,
            ack,
            255,
            info_url,
        )
    }
}

/// Checks if the given address is in the given prefix.
///
/// # Arguments
///
/// * 'address' - the address to check
///
/// * 'prefix' - the prefix to check against
///
/// # Returns
///
/// True if the address is in the prefix, false otherwise.
///
/// # Panics
///
/// If the address is not a valid IP address.
///
/// If the prefix is not a valid prefix.
///
/// # Example
///
/// ```
/// is_in_prefix("1.1.1.1", "1.1.1.0/24") // true
///
/// is_in_prefix("2001:db8::1", "2001:db8::/32") // true
/// ```
pub fn is_in_prefix(
    address: String,
    prefix: &IpNetwork
) -> bool {
    // Parse the address from String to IpAddr
    let ip_address = address.parse::<IpAddr>().expect("Invalid IP address format");

    match ip_address {
        IpAddr::V4(ipv4) => {
            // Check for IPv4 matching
            if let IpNetwork::V4(network_ip) = prefix {
                let network_ip_u32 = u32::from(network_ip.ip());
                let subnet_mask = u32::from(network_ip.mask());
                let ip_u32 = u32::from(ipv4) & subnet_mask;
                network_ip_u32 == ip_u32
            } else {
                false
            }
        }
        IpAddr::V6(ipv6) => {
            // Check for IPv6 matching
            if let IpNetwork::V6(network_ip) = prefix {
                let network_ip_u128 = u128::from(network_ip.ip());
                let subnet_mask = u128::from(network_ip.mask());
                let ip_u128 = u128::from(ipv6) & subnet_mask;
                network_ip_u128 == ip_u128
            } else {
                false
            }
        }
    }
}
