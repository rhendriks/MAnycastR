use crate::custom_module::manycastr::{Address, Origin};
use crate::net::{ICMPPacket, TCPPacket, UDPPacket};
use crate::{A_ID, CHAOS_ID};
use mac_address::mac_address_by_name;
use pnet::ipnetwork::IpNetwork;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn get_default_gateway_ip_linux() -> Result<String, String> {
    let file = File::open("/proc/net/route")
        .map_err(|e| format!("Failed to open /proc/net/route: {e}"))?;
    let reader = BufReader::new(file);

    for line in reader.lines().skip(1) {
        let line = line.map_err(|e| format!("Failed to read line: {e}"))?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == "00000000" {
            // Gateway is in hex, little-endian
            let hex = fields[2];
            if hex.len() != 8 {
                return Err(format!("Invalid gateway hex: {hex}"));
            }

            let bytes: Vec<u8> = (0..4)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
                .collect();

            // Return bytes in reverse order (little-endian format)
            return Ok(format!(
                "{}.{}.{}.{}",
                bytes[3], bytes[2], bytes[1], bytes[0]
            ));
        }
    }

    Err("Could not find default gateway in /proc/net/route".to_string())
}
fn get_default_gateway_ip_freebsd() -> Result<String, String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("Failed to execute 'route -n get default': {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to get default route (FreeBSD): {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.starts_with("gateway:") {
            let parts: Vec<&str> = trimmed_line.split_whitespace().collect();
            if parts.len() >= 2 {
                return Ok(parts[1].to_string());
            }
        }
    }
    Err("Could not parse default gateway IP from 'route -n get default' output".to_string())
}

/// Returns the ethernet header to use for the outbound packets.
///
/// # Arguments
///
/// * 'is_ipv6' - whether we are using IPv6 or not
///
/// * 'if_name' - the name of the interface to use
pub fn get_ethernet_header(is_ipv6: bool, if_name: &str) -> Vec<u8> {
    // Get the source MAC address for the used interface
    let mac_src = mac_address_by_name(if_name)
        .unwrap_or_else(|_| panic!("No MAC address found for interface: {if_name}"))
        .unwrap()
        .bytes()
        .to_vec();

    // Get the default gateway IP address (to get the destination MAC address)
    let gateway_ip = if cfg!(target_os = "freebsd") {
        get_default_gateway_ip_freebsd().expect("Could not get default gateway IP")
    } else if cfg!(target_os = "linux") {
        get_default_gateway_ip_linux().expect("Could not get default gateway IP")
    } else {
        panic!("Unsupported OS");
    };

    let lines: Vec<String> = if cfg!(target_os = "freebsd") {
        let output = std::process::Command::new("arp")
            .arg("-an")
            .output()
            .map_err(|e| format!("Failed to run arp command on FreeBSD: {e}"))
            .unwrap();

        if !output.status.success() {
            panic!("arp command failed on FreeBSD");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.lines().map(|s| s.to_string()).collect()
    } else {
        let file = File::open("/proc/net/arp")
            .map_err(|e| format!("Failed to open /proc/net/arp: {e}"))
            .unwrap();
        let reader = BufReader::new(file);

        reader
            .lines()
            .map(|line| line.expect("Failed to read line from /proc/net/arp"))
            .collect()
    };

    // Get the destination MAC addresses
    let mut mac_dst: Option<[u8; 6]> = None;

    for (i, line) in lines.iter().enumerate() {
        if cfg!(target_os = "linux") && i == 0 {
            // Skip the header on Linux
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() > 5 {
            let addr = parts[0]; // IP address

            if addr != gateway_ip {
                // Skip if not the default gateway
                continue;
            }

            let mac_address = if cfg!(target_os = "freebsd") {
                // For FreeBSD, MAC address is in the second column
                parts[1]
            } else {
                // For Linux, MAC address is in the fourth column
                parts[3]
            };

            // Skip local-loopback and broadcast
            if (mac_address == "00:00:00:00:00:00") || (mac_address == "ff:ff:ff:ff:ff:ff") {
                continue;
            }

            // If interface name matches, return the MAC address
            if parts[5] == if_name {
                let mac_bytes: [u8; 6] = mac_address
                    .split(':')
                    .map(|s| u8::from_str_radix(s, 16).unwrap())
                    .collect::<Vec<u8>>()
                    .try_into()
                    .expect("MAC address should have 6 bytes");

                mac_dst = Some(mac_bytes);
                break;
            }
        }
    }

    // panic if no MAC address was found
    if mac_dst.is_none() {
        panic!("No destination MAC address found for interface: {if_name}");
    }

    // Construct the ethernet header
    let ether_type = if is_ipv6 { 0x86DDu16 } else { 0x0800u16 };
    let mut ethernet_header: Vec<u8> = Vec::with_capacity(14);
    ethernet_header.extend_from_slice(&mac_dst.unwrap());
    ethernet_header.extend_from_slice(&mac_src);
    ethernet_header.extend_from_slice(&ether_type.to_be_bytes());

    ethernet_header
}

/// ICMP arguments to encode in the payload.
#[derive(Debug)]
pub struct ProbePayload<'a> {
    pub worker_id: u32,
    pub m_id: u32,
    pub info_url: &'a str,
}

/// Creates a ping packet to send.
///
/// # Arguments
///
/// * 'src' - the source address for the ping packet
/// * 'dst' - the destination address for the ping packet
/// * 'identifier' - the identifier to use in the ICMP header
/// * 'seq' - the sequence number to use in the ICMP header
/// * 'worker_id' - the unique worker ID of this worker (encoded in payload)
/// * 'm_id' - the unique ID of the current measurement (encoded in payload)
/// * 'info_url' - URL to encode in packet (e.g., opt-out URL) (encoded in payload)
/// * 'ttl' - the time-to-live (TTL) value to set in the IP header
///
/// # Returns
///
/// A ping packet (including the IP header) as a byte vector.
pub fn create_icmp(
    src: &Address,
    dst: &Address,
    identifier: u16,
    seq: u16,
    payload: ProbePayload,
    ttl: u8,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    // Create the ping payload bytes
    let mut payload_bytes: Vec<u8> = Vec::new();
    payload_bytes.extend_from_slice(&payload.m_id.to_be_bytes()); // Bytes 0 - 3
    payload_bytes.extend_from_slice(&tx_time.to_be_bytes()); // Bytes 4 - 11
    payload_bytes.extend_from_slice(&payload.worker_id.to_be_bytes()); // Bytes 12 - 15

    // Add addresses to payload (used for spoofing detection)
    payload_bytes.extend_from_slice(&src.to_be_bytes()); // Bytes 16 - 33 (v6) or 16 - 19 (v4)
    payload_bytes.extend_from_slice(&dst.to_be_bytes()); // Bytes 34 - 51 (v6) or 20 - 23 (v4)

    // Add info URL to payload
    payload_bytes.extend(payload.info_url.bytes());

    // add the source address
    if src.is_v6() {
        ICMPPacket::echo_request_v6(
            // TODO combine v6 and v4 functions into one
            identifier,
            seq,
            payload_bytes,
            src.get_v6(),
            dst.get_v6(),
            ttl,
        )
    } else {
        ICMPPacket::echo_request(
            identifier,
            seq,
            payload_bytes,
            src.get_v4(),
            dst.get_v4(),
            ttl,
        )
    }
}

/// Create a Record Route ICMP packet to send.
/// # Arguments
/// * 'src' - the source address for the ping packet
/// * 'dst' - the destination address for the ping packet
/// * 'identifier' - the identifier to use in the ICMP header
/// * 'seq' - the sequence number to use in the ICMP header
/// * 'worker_id' - the unique worker ID of this worker (encoded in payload)
/// * 'm_id' - the unique ID of the current measurement (encoded in payload)
/// * 'info_url' - URL to encode in packet (e.g., opt-out URL) (encoded in payload)
/// * 'ttl' - the time-to-live (TTL) value to set in the IP header
/// # Returns
/// A reverse traceroute ICMP packet (including the IP header) as a byte vector.
pub fn create_record_route_icmp(
    src: &Address,
    dst: &Address,
    identifier: u16,
    seq: u16,
    payload: ProbePayload,
    ttl: u8,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    // Create the ping payload bytes
    let mut payload_bytes: Vec<u8> = Vec::new();
    payload_bytes.extend_from_slice(&payload.m_id.to_be_bytes()); // Bytes 0 - 3
    payload_bytes.extend_from_slice(&tx_time.to_be_bytes()); // Bytes 4 - 11
    payload_bytes.extend_from_slice(&payload.worker_id.to_be_bytes()); // Bytes 12 - 15

    // Add addresses to payload (used for spoofing detection)
    payload_bytes.extend_from_slice(&src.to_be_bytes()); // Bytes 16 - 33 (v6) or 16 - 19 (v4)
    payload_bytes.extend_from_slice(&dst.to_be_bytes()); // Bytes 34 - 51 (v6) or 20 - 23 (v4)

    // Add info URL to payload
    payload_bytes.extend(payload.info_url.bytes());

    // add the source address
    if src.is_v6() {
        panic!("Reverse traceroute not supported for IPv6 yet"); // TODO
    } else {
        ICMPPacket::record_route_icmpv4(
            identifier,
            seq,
            payload_bytes,
            src.get_v4(),
            dst.get_v4(),
            ttl,
        )
    }
}

/// Creates a DNS packet.
///
/// # Arguments
///
/// * 'origin' - the source address and port values we use for our probes
///
/// * 'worker_id' - the unique worker ID of this worker
///
/// * 'dst' - the destination address for the DNS packet
///
/// * 'measurement_type' - the type of measurement being performed (2 = DNS/A, 4 = DNS/CHAOS)
///
/// * 'is_ipv6' - whether we are using IPv6 or not
///
/// * 'qname' - the DNS record to request
///
/// # Returns
///
/// A DNS packet (including the IP header) as a byte vector.
///
/// # Panics
///
/// If the measurement type is not 2 or 4
pub fn create_dns(
    origin: &Origin,
    dst: &Address,
    worker_id: u32,
    measurement_type: u8,
    qname: &str,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let src = &origin.src.expect("None IP address");
    let sport = origin.sport as u16;

    if measurement_type == A_ID {
        UDPPacket::dns_request(src, dst, sport, qname, tx_time, worker_id, 255)
    } else if measurement_type == CHAOS_ID {
        UDPPacket::chaos_request(src, dst, sport, worker_id, qname)
    } else {
        panic!("Invalid measurement type")
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
/// * 'is_symmetric' - whether we are measuring latency
///
/// * 'info_url' - URL to encode in packet payload (e.g., opt-out URL)
///
/// # Returns
///
/// A TCP packet (including the IP header) as a byte vector.
pub fn create_tcp(
    origin: &Origin,
    dst: &Address,
    worker_id: u32,
    is_discovery: bool,
    info_url: &str,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32;

    let timestamp_21b = tx_time & 0x1FFFFF;
    let worker_10b = worker_id & 0x3FF;

    let discovery_bit = if is_discovery { 1u32 << 31 } else { 0 };
    let ack = discovery_bit | (worker_10b << 21) | timestamp_21b;

    TCPPacket::tcp_syn_ack(
        &origin.src.unwrap(),
        dst,
        origin.sport as u16,
        origin.dport as u16,
        ack,
        255,
        info_url,
    )
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
pub fn is_in_prefix(address: &str, prefix: &IpNetwork) -> bool {
    // Convert the address string to an IpAddr
    let address = address
        .parse::<IpAddr>()
        .expect("Invalid IP address format");

    match address {
        IpAddr::V4(ipv4) => {
            if let IpNetwork::V4(network_ip) = prefix {
                // Use the contains method to check if the IP is in the network range
                network_ip.contains(ipv4)
            } else {
                false
            }
        }
        IpAddr::V6(ipv6) => {
            if let IpNetwork::V6(network_ip) = prefix {
                // Use the contains method to check if the IP is in the network range
                network_ip.contains(ipv6)
            } else {
                false
            }
        }
    }
}
