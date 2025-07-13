use crate::custom_module::manycastr::{Address, Origin};
use crate::net::{ICMPPacket, TCPPacket, UDPPacket};
use mac_address::mac_address_by_name;
use pnet::ipnetwork::IpNetwork;
use std::io;
use std::io::BufRead;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::{CHAOS_ID, A_ID};

fn get_default_gateway_ip_linux() -> Result<String, String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| format!("Failed to execute 'ip route': {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to get default route: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.starts_with("default via ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return Ok(parts[2].to_string());
            }
        }
    }
    Err("Could not parse default gateway IP from 'ip route' output".to_string())
}

fn get_default_gateway_ip_freebsd() -> Result<String, String> {
    // TODO test
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("Failed to execute 'route -n get default': {}", e))?;

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
pub fn get_ethernet_header(is_ipv6: bool, if_name: String) -> Vec<u8> {
    // Get the source MAC address for the used interface
    let mac_src = mac_address_by_name(&if_name)
        .expect(&format! {"No MAC address found for interface: {}", if_name})
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

    let mut child = if cfg!(target_os = "freebsd") {
        // `arp -an`
        Command::new("arp")
            .arg("-an")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to run arp command on FreeBSD")
    } else {
        // `/proc/net/arp`
        Command::new("cat")
            .arg("/proc/net/arp")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to run command on Linux")
    };
    let output = child.stdout.as_mut().expect("Failed to capture stdout");

    // Get the destination MAC addresses
    let mut mac_dst = Vec::with_capacity(6);
    let reader = io::BufReader::new(output);
    let mut lines = reader.lines();
    lines.next(); // Skip the first line (header)

    for line in lines {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() > 3 {
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
                if (mac_address == "00:00:00:00:00:00") | (mac_address == "ff:ff:ff:ff:ff:ff") {
                    continue;
                }

                // If interface name matches, return the MAC address
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

    // panic if no MAC address was found
    if mac_dst.is_empty() {
        panic!(
            "No destination MAC address found for interface: {}",
            if_name
        );
    }
    child.wait().expect("Failed to wait on child");

    // Construct the ethernet header
    let ether_type = if is_ipv6 { 0x86DDu16 } else { 0x0800u16 };
    let mut ethernet_header: Vec<u8> = Vec::with_capacity(14);
    ethernet_header.extend_from_slice(&mac_dst);
    ethernet_header.extend_from_slice(&mac_src);
    ethernet_header.extend_from_slice(&ether_type.to_be_bytes());

    ethernet_header
}

/// Creates a ping packet to send.
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
/// * 'info_url' - URL to encode in packet payload (e.g., opt-out URL)
///
/// # Returns
///
/// A ping packet (including the IP header) as a byte vector.
pub fn create_icmp(
    origin: &Origin,
    dst: &Address,
    worker_id: u32,
    measurement_id: u32,
    info_url: &str,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let src = origin.src.expect("None IP address");

    // Create the ping payload bytes
    let mut payload_bytes: Vec<u8> = Vec::new();
    payload_bytes.extend_from_slice(&measurement_id.to_be_bytes()); // Bytes 0 - 3
    payload_bytes.extend_from_slice(&tx_time.to_be_bytes()); // Bytes 4 - 11
    payload_bytes.extend_from_slice(&worker_id.to_be_bytes()); // Bytes 12 - 15

    // add the source address
    if src.is_v6() {
        payload_bytes.extend_from_slice(&src.get_v6().to_be_bytes()); // Bytes 16 - 33
        payload_bytes.extend_from_slice(&dst.get_v6().to_be_bytes()); // Bytes 34 - 51

        ICMPPacket::echo_request_v6(
            origin.dport as u16,
            2,
            payload_bytes,
            src.get_v6(),
            dst.get_v6(),
            255,
            info_url,
        )
    } else {
        payload_bytes.extend_from_slice(&src.get_v4().to_be_bytes()); // Bytes 16 - 19
        payload_bytes.extend_from_slice(&dst.get_v4().to_be_bytes()); // Bytes 20 - 23

        ICMPPacket::echo_request(
            origin.dport as u16,
            2,
            payload_bytes,
            src.get_v4(),
            dst.get_v4(),
            255,
            info_url,
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
    is_ipv6: bool,
    qname: &str,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let src = &origin.src.expect("None IP address");
    let sport = origin.sport as u16;

    if is_ipv6 {
        if measurement_type == A_ID {
            UDPPacket::dns_request_v6(
                src,
                dst,
                sport,
                qname,
                tx_time,
                worker_id,
                255,
            )
        } else if measurement_type == CHAOS_ID {
            UDPPacket::chaos_request_v6(src.get_v6(), dst.get_v6(), sport, worker_id, qname)
        } else {
            panic!("Invalid measurement type")
        }
    } else {
        if measurement_type == A_ID {
            UDPPacket::dns_request(
                src,
                dst,
                sport,
                qname,
                tx_time,
                worker_id,
                255,
            )
        } else if measurement_type == CHAOS_ID {
            UDPPacket::chaos_request(src.get_v4(), dst.get_v4(), sport, worker_id, qname)
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
/// * 'is_latency' - whether we are measuring latency
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
    is_ipv6: bool,
    is_latency: bool,
    info_url: &str,
) -> Vec<u8> {
    let seq = 0; // information in seq gets lost
    let ack = if !is_latency || worker_id > u16::MAX as u32 {
        // catchment mapping (or discovery probe for latency measurement)
        worker_id
    } else {
        // latency measurement
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u32
    };

    if is_ipv6 {
        TCPPacket::tcp_syn_ack_v6(
            origin.src.unwrap().get_v6(),
            dst.get_v6(),
            origin.sport as u16,
            origin.dport as u16,
            seq,
            ack,
            255,
            info_url,
        )
    } else {
        TCPPacket::tcp_syn_ack(
            origin.src.unwrap().get_v4(),
            dst.get_v4(),
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
pub fn is_in_prefix(address: &String, prefix: &IpNetwork) -> bool {
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
