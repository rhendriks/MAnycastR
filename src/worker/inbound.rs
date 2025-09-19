use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, Builder};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::UnboundedSender;

use crate::custom_module::manycastr::{Address, Origin, Reply, TaskResult};
use crate::custom_module::Separated;
use crate::net::{DNSAnswer, DNSRecord, IPPacket, IPv4Packet, IPv6Packet, PacketPayload, TXTRecord};
use crate::{A_ID, CHAOS_ID, ICMP_ID, TCP_ID};
use pnet::datalink::DataLinkReceiver;

/// Configuration for an inbound packet listening worker.
///
/// This struct holds all the parameters needed to initialize and run a worker
/// that listens for and processes incoming measurement packets.
pub struct InboundConfig {
    /// The unique ID of the measurement.
    pub m_id: u32,

    /// The unique ID of this specific worker.
    pub worker_id: u16,

    /// Specifies whether to listen for IPv6 packets (`true`) or IPv4 packets (`false`).
    pub is_ipv6: bool,

    /// The type of measurement being performed (e.g., ICMP, DNS, TCP).
    pub m_type: u8,

    /// A map of valid source addresses and port values (`Origin`) to verify incoming packets against.
    pub origin_map: Vec<Origin>,

    /// A shared signal that can be used to gracefully shut down the worker.
    pub abort_s: Arc<AtomicBool>,

    /// Indicates if the measurement involves traceroute.
    pub is_traceroute: bool,
}

/// Listen for incoming packets
/// Creates two threads, one that listens on the socket and another that forwards results to the orchestrator and shuts down the receiving socket when appropriate.
/// Makes sure that the received packets are valid and belong to the current measurement.
///
/// # Arguments
///
/// * 'config' - configuration for the inbound worker thread
///
/// * 'tx' - sender to put task results in
///
/// * 'socket_rx' - the socket to listen on
///
/// # Panics
///
/// Panics if the measurement type is invalid
pub fn inbound(
    config: InboundConfig,
    tx: UnboundedSender<TaskResult>,
    mut socket_rx: Box<dyn DataLinkReceiver>,
) {
    println!("[Worker inbound] Started listener");
    // Result queue to store incoming pings, and take them out when sending the TaskResults to the orchestrator
    let rq = Arc::new(Mutex::new(Vec::new()));
    let rq_c = rq.clone();
    let rx_f_c = config.abort_s.clone();
    Builder::new()
        .name("listener_thread".to_string())
        .spawn(move || {
            // Listen for incoming packets
            let mut received: u32 = 0;
            loop {
                // Check if we should exit
                if rx_f_c.load(Ordering::Relaxed) {
                    break;
                }
                let packet = match socket_rx.next() {
                    // TODO blocking call
                    Ok(packet) => packet,
                    Err(_) => {
                        sleep(Duration::from_millis(1)); // Sleep to free CPU, let buffer fill
                        continue;
                    }
                };

                if config.is_traceroute {
                    // Try to parse ICMP Time Exceeded first
                    let trace_reply = parse_icmp_trace(&packet[14..], config.m_id, &config.origin_map, config.is_ipv6);
                    // If we got a trace reply, add it to the queue and continue to the next packet
                    if trace_reply.is_some() {
                        received += 1;
                        let mut buffer = rq_c.lock().unwrap();
                        buffer.push(trace_reply.unwrap());
                        continue; // Continue to next packet
                    }
                }

                let result = if config.m_type == ICMP_ID {
                    // ICMP
                    // Convert the bytes into an ICMP packet (first 13 bytes are the eth header, which we skip)
                    if config.is_ipv6 {
                        parse_icmpv6(&packet[14..], config.m_id, &config.origin_map)
                    } else {
                        parse_icmpv4(&packet[14..], config.m_id, &config.origin_map)
                    }
                } else if config.m_type == A_ID || config.m_type == CHAOS_ID {
                    // DNS A
                    if config.is_ipv6 {
                        if packet[20] == 17 {
                            // 17 is the protocol number for UDP
                            parse_dnsv6(&packet[14..], config.m_type, &config.origin_map)
                        } else {
                            None
                        }
                    } else if packet[23] == 17 {
                        // 17 is the protocol number for UDP
                        parse_dnsv4(&packet[14..], config.m_type, &config.origin_map)
                    } else {
                        None
                    }
                } else if config.m_type == TCP_ID {
                    // TCP
                    if config.is_ipv6 {
                        parse_tcpv6(&packet[14..], &config.origin_map)
                    } else {
                        parse_tcpv4(&packet[14..], &config.origin_map)
                    }
                } else {
                    panic!("Invalid measurement type");
                };

                // Invalid packets have value None
                if result.is_none() {
                    continue;
                }

                // Put result in transmission queue
                {
                    received += 1;
                    let mut buffer = rq_c.lock().unwrap();
                    buffer.push(result.unwrap())
                }
            }

            println!(
                "[Worker inbound] Stopped pnet listener (received {} packets)",
                received.with_separator()
            );
        })
        .expect("Failed to spawn listener_thread");

    // Thread for sending the received replies to the orchestrator as TaskResult
    Builder::new()
        .name("result_sender_thread".to_string())
        .spawn(move || {
            handle_results(&tx, config.abort_s, config.worker_id, rq);
        })
        .expect("Failed to spawn result_sender_thread");
}

/// Thread for handling the received replies, wrapping them in a TaskResult, and streaming them back to the main worker class.
///
/// # Arguments
///
/// * `tx` - sender to put task results in
///
/// * `rx_f` - channel that is used to signal the end of the measurement
///
/// * `worker_id` - the unique worker ID of this worker
///
/// * `rq_sender` - contains a vector of all received replies as Reply results
fn handle_results(
    tx: &UnboundedSender<TaskResult>,
    rx_f: Arc<AtomicBool>,
    worker_id: u16,
    rq_sender: Arc<Mutex<Vec<(Reply, bool)>>>,
) {
    loop {
        // Every second, forward the ping results to the orchestrator
        sleep(Duration::from_secs(1));

        // Get the current result queue, and replace it with an empty one
        let rq = {
            let mut guard = rq_sender.lock().unwrap();
            mem::take(&mut *guard)
        };
        // Split on discovery and non-discovery replies
        let (discovery_rq, follow_rq): (Vec<_>, Vec<_>) = rq.into_iter().partition(|&(_, b)| b);
        let discovery_rq: Vec<Reply> = discovery_rq.into_iter().map(|(r, _)| r).collect();
        let follow_rq: Vec<Reply> = follow_rq.into_iter().map(|(r, _)| r).collect();

        // Send the result to the worker handler
        if !discovery_rq.is_empty() {
            tx.send(TaskResult {
                worker_id: worker_id as u32,
                result_list: discovery_rq,
                is_discovery: true,
            })
            .expect("Failed to send TaskResult to worker handler");
        }
        if !follow_rq.is_empty() {
            tx.send(TaskResult {
                worker_id: worker_id as u32,
                result_list: follow_rq,
                is_discovery: false,
            })
            .expect("Failed to send TaskResult to worker handler");
        }

        // Exit the thread if worker sends us the signal it's finished
        if rx_f.load(Ordering::SeqCst) {
            // Send default value to let the orchestrator know we are finished
            tx.send(TaskResult::default())
                .expect("Failed to send 'finished' signal to orchestrator");
            break;
        }
    }
}

/// Parse ICMP Time Exceeded packets (including v4/v6 headers) into a Reply result with trace information.
/// Filters out spoofed packets and only parses ICMP time exceeded valid for the current measurement.
///
/// From Wikipedia: IP header and first 64 bit of the original payload are used by the source host to match the time exceeded message to the discarded datagram.
/// For higher-level protocols such as UDP and TCP the 64-bit payload will include the source and destination ports of the discarded packet.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse (excluding the Ethernet header)
/// * `m_id` - the ID of the current measurement (to filter out packets not belonging to this measurement)
/// * `worker_map` - mapping of origin to origin ID
/// * `is_ipv6` - whether the packet is IPv6 (true) or IPv4 (false)
/// # Returns
/// * `Option<Reply>` - the received trace reply (None if it is not a valid ICMP Time Exceeded packet)
fn parse_icmp_trace(packet_bytes: &[u8], m_id: u32, worker_map: &Vec<Origin>, is_ipv6: bool)
-> Option<Reply>{
    // Check for ICMP Time Exceeded code TODO include length check
    if is_ipv6 {
        // ICMPv6 Time Exceeded 88 length (IPv6 header (40) + ICMP header (8) + original IPv6 header (40)) + check it is an ICMP Time Exceeded
        if (packet_bytes[40] != 3) || (packet_bytes.len() < 88) {
            return None;
        }
        // ICMPv4 Time Exceeded 48 length (IPv4 header (20) + ICMP header (8) + original IPv4 header (20)) + check it is an ICMP Time Exceeded
    } else if (packet_bytes[20] != 11) || (packet_bytes.len() < 48) {
        return None;
    }

    let ip_header = if is_ipv6 {
        IPPacket::V6(IPv6Packet::from(packet_bytes))
    } else {
        IPPacket::V4(IPv4Packet::from(packet_bytes))
    };
    // Parse ICMP TTL Exceeded header (first 8 bytes after the IPv4 header)
    let icmp_header = match &ip_header.payload() {
        PacketPayload::Icmp { value } => value,
        _ => return None,
    };

    // Parse IP header that caused the Time Exceeded (first 20 bytes of the ICMP body)
    let original_ip_header = if is_ipv6 {
        IPPacket::V6(IPv6Packet::from(&icmp_header.body[0..20]))
    } else {
        IPPacket::V4(IPv4Packet::from(&icmp_header.body[0..20]))
    };

    // Parse the ICMP header that caused the Time Exceeded (first 8 bytes of the ICMP body after the original IP header)
    let original_icmp_header = match &original_ip_header.payload() {
        PacketPayload::Icmp { value } => value,
        _ => return None,
    };

    // Get sender worker ID (ICMP identifier field)
    let tx_id = original_icmp_header.identifier as u32;

    // get TTL value of the probe that caused the Time Exceeded (i.e., hop count)
    let trace_ttl = original_ip_header.ttl() as u32;

    // get hop address
    let hop_addr = ip_header.source();

    // get origin ID
    let origin_id = if is_ipv6 {
        get_origin_id_v6(ip_header.dst(), 0, 0, worker_map)?
    } else {
        get_origin_id_v4(hop_addr.dst(), 0, 0, worker_map)?
    };


    todo!()
}

/// Parse ICMPv4 packets (including v4 headers) into a Reply result.
///
/// Filters out spoofed packets and only parses ICMP echo replies valid for the current measurement.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// * `measurement_id` - the ID of the current measurement
///
/// * `origin_map` - mapping of origin to origin ID
///
/// # Returns
///
/// * `Option<(Reply, bool)>` - the received ping reply and whether it is a discovery packet
///
/// # Remarks
///
/// The function returns None if the packet is not an ICMP echo reply or if the packet is too short to contain the necessary information.
///
/// The function also discards packets that do not belong to the current measurement.
fn parse_icmpv4(
    packet_bytes: &[u8],
    m_id: u32,
    origin_map: &Vec<Origin>,
) -> Option<Reply> {
    // ICMPv4 52 length (IPv4 header (20) + ICMP header (8) + ICMP body 24 bytes) + check it is an ICMP Echo reply TODO match with exact length (include -u URl length)
    if (packet_bytes.len() < 52) || (packet_bytes[20] != 0) {
        return None;
    }

    let ip_header = IPv4Packet::from(packet_bytes);

    let PacketPayload::Icmp { value: icmp_packet } = ip_header.payload else {
        return None;
    };

    if icmp_packet.icmp_type != 0 {
        return None;
    } // Only parse ICMP echo replies

    let pkt_measurement_id: [u8; 4] = icmp_packet.body[0..4].try_into().ok()?;
    // Make sure that this packet belongs to this measurement
    if u32::from_be_bytes(pkt_measurement_id) != m_id {
        // If not, we discard it and await the next packet
        return None;
    }

    let tx_time = u64::from_be_bytes(icmp_packet.body[4..12].try_into().unwrap());
    let mut tx_id = u32::from_be_bytes(icmp_packet.body[12..16].try_into().unwrap());
    let probe_src = u32::from_be_bytes(icmp_packet.body[16..20].try_into().unwrap());
    let probe_dst = u32::from_be_bytes(icmp_packet.body[20..24].try_into().unwrap());

    if (probe_src != ip_header.dst) | (probe_dst != ip_header.src) {
        return None; // spoofed reply
    }

    let origin_id = get_origin_id_v4(ip_header.dst, 0, 0, origin_map)?;

    let rx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    let is_discovery = if tx_id > u16::MAX as u32 {
        tx_id -= u16::MAX as u32;
        true
    } else {
        false
    };

    // Create a Reply for the received ping reply
    Some((
        Reply {
            tx_time,
            tx_id,
            src: Some(Address::from(ip_header.src)),
            ttl: ip_header.ttl as u32,
            rx_time,
            origin_id,
            chaos: None,
            trace_dst: None,
            trace_ttl: None,
        },
        is_discovery,
    ))
}

/// Parse ICMPv6 packets (including v6 headers) into a Reply result.
///
/// Filters out spoofed packets and only parses ICMP echo replies valid for the current measurement.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// * `measurement_id` - the ID of the current measurement
///
/// * `origin_map` - mapping of origin to origin ID
///
/// # Returns
///
/// * `Option<Reply>` - the received ping reply
///
/// # Remarks
///
/// The function returns None if the packet is not an ICMP echo reply or if the packet is too short to contain the necessary information.
///
/// The function also discards packets that do not belong to the current measurement.
fn parse_icmpv6(
    packet_bytes: &[u8],
    measurement_id: u32,
    origin_map: &Vec<Origin>,
) -> Option<Reply> {
    // ICMPv6 66 length (IPv6 header (40) + ICMP header (8) + ICMP body 48 bytes) + check it is an ICMP Echo reply TODO match with exact length (include -u URl length)
    if (packet_bytes.len() < 66) || (packet_bytes[40] != 129) {
        return None;
    }
    let ip_header = IPv6Packet::from(packet_bytes);

    // Parse the ICMP header
    let PacketPayload::Icmp { value: icmp_packet } = ip_header.payload else {
        return None;
    };

    // Obtain the payload
    if icmp_packet.icmp_type != 129 {
        return None;
    } // Only parse ICMP echo replies

    let pkt_measurement_id: [u8; 4] = icmp_packet.body[0..4].try_into().ok()?;
    // Make sure that this packet belongs to this measurement
    if u32::from_be_bytes(pkt_measurement_id) != measurement_id {
        return None;
    }

    let tx_time = u64::from_be_bytes(icmp_packet.body[4..12].try_into().unwrap());
    let mut tx_id = u32::from_be_bytes(icmp_packet.body[12..16].try_into().unwrap());
    let probe_src = u128::from_be_bytes(icmp_packet.body[16..32].try_into().unwrap());
    let probe_dst = u128::from_be_bytes(icmp_packet.body[32..48].try_into().unwrap());

    if (probe_src != ip_header.dst) | (probe_dst != ip_header.src) {
        return None; // spoofed reply
    }

    let origin_id = get_origin_id(Address::from(ip_header.dst), 0, 0, origin_map)?;

    let rx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    let is_discovery = if tx_id > u16::MAX as u32 {
        tx_id -= u16::MAX as u32;
        true
    } else {
        false
    };

    // Create a Reply for the received ping reply
    Some(
        Reply {
            tx_time,
            tx_id,
            src: Some(Address::from(ip_header.src)),
            ttl: ip_header.hop_limit as u32,
            rx_time,
            origin_id,
            chaos: None,
            trace_dst: None,
            trace_ttl: None,
        },
    )
}

/// Parse DNSv4 packets (including v4 headers) into a Reply result.
///
/// Filters out spoofed packets and only parses DNS replies valid for the current measurement.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// * 'measurement_type' - the type of measurement being performed
///
/// * 'origin_map' - mapping of origin to origin ID
///
/// # Returns
///
/// * `Option<Reply>` - the received DNS reply
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a UDP header.
fn parse_dnsv4(
    packet_bytes: &[u8],
    measurement_type: u8,
    origin_map: &Vec<Origin>,
) -> Option<Reply> {
    // DNSv4 28 minimum (IPv4 header (20) + UDP header (8)) + check next protocol is UDP TODO incorporate minimum payload size
    if (packet_bytes.len() < 28) || (packet_bytes[9] != 17) {
        return None;
    }

    let ip_header = IPv4Packet::from(packet_bytes);

    let PacketPayload::Udp { value: udp_packet } = ip_header.payload else {
        return None;
    };

    // The UDP responses will be from DNS services, with src port 53 and our possible src ports as dest port, furthermore the body length has to be large enough to contain a DNS A reply
    // TODO body packet length is variable based on the domain name used in the measurement
    if ((measurement_type == A_ID) & (udp_packet.body.len() < 66))
        | ((measurement_type == CHAOS_ID) & (udp_packet.body.len() < 10))
    {
        return None;
    }

    let reply_sport = udp_packet.sport;
    let reply_dport = udp_packet.dport;

    let rx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let (tx_time, tx_id, chaos, is_discovery) = if measurement_type == A_ID {
        let dns_result = parse_dns_a_record_v4(udp_packet.body.as_slice())?;

        if (dns_result.probe_sport != reply_dport)
            | (dns_result.probe_src != ip_header.dst)
            | (dns_result.probe_dst != ip_header.src)
        {
            return None; // spoofed reply
        }

        (
            dns_result.tx_time,
            dns_result.tx_id,
            None,
            dns_result.is_discovery,
        )
    } else if measurement_type == CHAOS_ID {
        // TODO is_discovery for chaos
        let (tx_time, tx_id, chaos) = parse_chaos(udp_packet.body.as_slice())?;

        (tx_time, tx_id, Some(chaos), false)
    } else {
        panic!("Invalid measurement type");
    };

    let origin_id = get_origin_id_v4(ip_header.dst, reply_sport, reply_dport, origin_map)?;

    // Create a Reply for the received DNS reply
    Some((
        Reply {
            tx_time,
            tx_id,
            src: Some(Address::from(ip_header.src)),
            ttl: ip_header.ttl as u32,
            rx_time,
            origin_id,
            chaos,
            trace_dst: None,
            trace_ttl: None,
        },
        is_discovery,
    ))
}

/// Parse DNSv6 packets (including v6 headers) into a Reply.
///
/// Filters out spoofed packets and only parses DNS replies valid for the current measurement.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// * `measurement_type` - the type of measurement being performed
///
/// * `origin_map` - mapping of origin to origin ID
///
/// # Returns
///
/// * `Option<Reply>` - the received DNS reply
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a UDP header.
fn parse_dnsv6(
    packet_bytes: &[u8],
    measurement_type: u8,
    origin_map: &Vec<Origin>,
) -> Option<Reply> {
    // DNSv6 48 length (IPv6 header (40) + UDP header (8)) + check next protocol is UDP TODO incorporate minimum payload size
    if (packet_bytes.len() < 48) || (packet_bytes[6] != 17) {
        return None;
    }
    let ip_header = IPv6Packet::from(packet_bytes);

    let PacketPayload::Udp { value: udp_packet } = ip_header.payload else {
        return None;
    };

    // The UDP responses will be from DNS services, with src port 53 and our possible src ports as dest port, furthermore the body length has to be large enough to contain a DNS A reply
    // TODO use 'get_domain_length'
    if ((measurement_type == A_ID) & (udp_packet.body.len() < 66))
        | ((measurement_type == CHAOS_ID) & (udp_packet.body.len() < 10))
    {
        return None;
    }

    let reply_sport = udp_packet.sport;
    let reply_dport = udp_packet.dport;

    let rx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let (tx_time, tx_id, chaos, is_discovery) = if measurement_type == A_ID {
        let dns_result = parse_dns_a_record_v6(udp_packet.body.as_slice())?;

        if (dns_result.probe_sport != reply_dport)
            | (dns_result.probe_dst != ip_header.src)
            | (dns_result.probe_src != ip_header.dst)
        {
            return None; // spoofed reply
        }

        (
            dns_result.tx_time,
            dns_result.tx_id,
            None,
            dns_result.is_discovery,
        )
    } else if measurement_type == CHAOS_ID {
        // TODO is_discovery for CHAOS
        let (tx_time, tx_worker_id, chaos) = parse_chaos(udp_packet.body.as_slice())?;
        (tx_time, tx_worker_id, Some(chaos), false)
    } else {
        panic!("Invalid measurement type");
    };

    let origin_id = get_origin_id_v6(ip_header.dst, reply_sport, reply_dport, origin_map)?;

    // Create a Reply for the received DNS reply
    Some((
        Reply {
            tx_time,
            tx_id,
            src: Some(Address::from(ip_header.src)),
            ttl: ip_header.hop_limit as u32,
            rx_time,
            origin_id,
            chaos,
            trace_dst: None,
            trace_ttl: None,
        },
        is_discovery,
    ))
}
enum Addr {
    V4(u32),
    V6(u128),
}

impl PartialEq<u32> for Addr {
    fn eq(&self, other_u32: &u32) -> bool {
        match self {
            Addr::V4(addr_val) => addr_val == other_u32,
            Addr::V6(_) => false,
        }
    }
}

impl PartialEq<u128> for Addr {
    fn eq(&self, other_u128: &u128) -> bool {
        match self {
            Addr::V6(addr_val) => addr_val == other_u128,
            Addr::V4(_) => false,
        }
    }
}

struct DnsResult {
    tx_time: u64,
    tx_id: u32,
    probe_sport: u16,
    probe_src: Addr,
    probe_dst: Addr,
    is_discovery: bool,
}

/// Attempts to parse the DNS A record from a DNS payload body.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// # Returns
///
/// * `Option<UdpResult, u16, u128, u128>` - the UDP result containing the DNS A record with the source port and source and destination addresses and whether it is a discovery packet
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a DNS A record.
fn parse_dns_a_record_v6(packet_bytes: &[u8]) -> Option<DnsResult> {
    // TODO v6 and v4 can be merged into one function
    let record = DNSRecord::from(packet_bytes);
    let domain = record.domain; // example: '1679305276037913215.3226971181.16843009.0.4000.any.dnsjedi.org'
                                // Get the information from the domain, continue to the next packet if it does not follow the format
    let parts: Vec<&str> = domain.split('.').collect();
    // Our domains have at least 5 parts
    if parts.len() < 5 {
        return None;
    }

    let tx_time = parts[0].parse::<u64>().ok()?;
    let probe_src = Addr::V6(parts[1].parse::<u128>().ok()?);
    let probe_dst = Addr::V6(parts[2].parse::<u128>().ok()?);
    let mut tx_id = parts[3].parse::<u32>().ok()?;
    let probe_sport = parts[4].parse::<u16>().ok()?;

    let is_discovery = if tx_id > u16::MAX as u32 {
        tx_id -= u16::MAX as u32;
        true
    } else {
        false
    };

    Some(DnsResult {
        tx_time,
        tx_id,
        probe_sport,
        probe_src,
        probe_dst,
        is_discovery,
    })
}

/// Attempts to parse the DNS A record from a UDP payload body.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// # Returns
///
/// * `Option<UdpResult, u16, u128, u128, bool>` - the UDP result containing the DNS A record with the source port and source and destination addresses and whether it is a discovery packet TODO rustdoc
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a DNS A record.
fn parse_dns_a_record_v4(packet_bytes: &[u8]) -> Option<DnsResult> {
    let record = DNSRecord::from(packet_bytes);
    let domain = record.domain; // example: '1679305276037913215.3226971181.16843009.0.4000.any.dnsjedi.org'
                                // Get the information from the domain, continue to the next packet if it does not follow the format

    let parts: Vec<&str> = domain.split('.').collect();
    // Our domains have at least 5 parts
    if parts.len() < 5 {
        return None;
    }

    let tx_time = parts[0].parse::<u64>().ok()?;
    let probe_src = Addr::V4(parts[1].parse::<u32>().ok()?);
    let probe_dst = Addr::V4(parts[2].parse::<u32>().ok()?);
    let mut tx_id = parts[3].parse::<u32>().ok()?;
    let probe_sport = parts[4].parse::<u16>().ok()?;

    let is_discovery = if tx_id > u16::MAX as u32 {
        tx_id -= u16::MAX as u32;
        true
    } else {
        false
    };

    Some(DnsResult {
        tx_time,
        tx_id,
        probe_sport,
        probe_src,
        probe_dst,
        is_discovery,
    })
}

/// Attempts to parse the DNS Chaos record from a UDP payload body.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// # Returns
///
/// * `Option<UdpPayload>` - the UDP payload containing the DNS Chaos record
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a DNS Chaos record.
fn parse_chaos(packet_bytes: &[u8]) -> Option<(u64, u32, String)> {
    let record = DNSRecord::from(packet_bytes);

    // 8 right most bits are the sender worker_id
    let tx_worker_id = ((record.transaction_id >> 8) & 0xFF) as u32;

    if record.answer == 0 {
        return Some((0u64, tx_worker_id, "Not implemented".to_string()));
    }

    let chaos_data = TXTRecord::from(DNSAnswer::from(record.body.as_slice()).data.as_slice()).txt;

    Some((0u64, tx_worker_id, chaos_data))
}

/// Parse TCPv4 packets (including v4 headers) into a Reply result.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// * `origin_map` - mapping of origin to origin ID
///
/// # Returns
///
/// * `Option<Reply>` - the received TCP reply
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a TCP header.
fn parse_tcpv4(packet_bytes: &[u8], origin_map: &Vec<Origin>) -> Option<Reply> {
    // TCPv4 40 bytes (IPv4 header (20) + TCP header (20)) + check for RST flag
    if (packet_bytes.len() < 40) || ((packet_bytes[33] & 0x04) == 0) {
        return None;
    }
    let ip_header = IPv4Packet::from(packet_bytes);
    // cannot filter out spoofed packets as the probe_dst is unknown

    let PacketPayload::Tcp { value: tcp_packet } = ip_header.payload else {
        return None;
    };

    let rx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    let origin_id = get_origin_id_v4(ip_header.dst, tcp_packet.sport, tcp_packet.dport, origin_map)?;

    // Discovery probes have bit 16 set and higher bits unset
    let bit_16_mask = 1 << 16;
    let higher_bits_mask = !0u32 << 17;

    let (tx_id, is_discovery) =
        if (tcp_packet.seq & bit_16_mask) != 0 && (tcp_packet.seq & higher_bits_mask) == 0 {
            (tcp_packet.seq - u16::MAX as u32, true)
        } else {
            (tcp_packet.seq, false)
        };

    Some((
        Reply {
            tx_time: tx_id as u64,
            tx_id,
            src: Some(Address::from(ip_header.src)),
            ttl: ip_header.ttl as u32,
            rx_time,
            origin_id,
            chaos: None,
            trace_dst: None,
            trace_ttl: None,
        },
        is_discovery,
    ))
}

/// Parse TCPv6 packets (including v6 headers) into a Reply result.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// * `origin_map` - mapping of origin to origin ID
///
/// # Returns
///
/// * `Option<(Reply, bool)>` - the received TCP reply and whether it is a discovery packet
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a TCP header.
fn parse_tcpv6(packet_bytes: &[u8], origin_map: &Vec<Origin>) -> Option<Reply> {
    // TCPv6 64 length (IPv6 header (40) + TCP header (20)) + check for RST flag
    if (packet_bytes.len() < 60) || ((packet_bytes[53] & 0x04) == 0) {
        return None;
    }
    let ip_header = IPv6Packet::from(packet_bytes);
    // cannot filter out spoofed packets as the probe_dst is unknown

    let PacketPayload::Tcp { value: tcp_packet } = ip_header.payload else {
        return None;
    };

    let rx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    let origin_id = get_origin_id_v6(ip_header.dst, tcp_packet.sport, tcp_packet.dport, origin_map)?;

    // Discovery probes have bit 16 set and higher bits unset
    let bit_16_mask = 1 << 16;
    let higher_bits_mask = !0u32 << 17;

    let (tx_id, is_discovery) =
        if (tcp_packet.seq & bit_16_mask) != 0 && (tcp_packet.seq & higher_bits_mask) == 0 {
            (tcp_packet.seq - u16::MAX as u32, true)
        } else {
            (tcp_packet.seq, false)
        };

    Some((
        Reply {
            tx_time: tx_id as u64,
            tx_id,
            src: Some(Address::from(ip_header.src)),
            ttl: ip_header.hop_limit as u32,
            rx_time,
            origin_id,
            chaos: None,
            trace_dst: None,
            trace_ttl: None,
        },
        is_discovery,
    ))
}

/// Get the origin ID from the origin map based on the reply destination address and ports.
///
/// # Arguments
///
/// * `reply_dst` - the destination address of the reply
/// * `reply_sport` - the source port of the reply
/// * `reply_dport` - the destination port of the reply
/// * `origin_map` - the origin map to search in
/// # Returns
/// * `Option<u32>` - the origin ID if found, None otherwise
pub fn get_origin_id(
    reply_dst: Address,
    reply_sport: u16,
    reply_dport: u16,
    origin_map: &Vec<Origin>,
) -> Option<u32> {
    for origin in origin_map {
        if origin.src == Some(reply_dst)
            && origin.sport as u16 == reply_dport
            && origin.dport as u16 == reply_sport
        {
            return Some(origin.origin_id);
        } else if origin.src == Some(reply_dst) && 0 == reply_sport && 0 == reply_dport {
            // ICMP replies have no port numbers
            return Some(origin.origin_id);
        }
    }
    None
}

// ICMP TTL Exceeded parser, used for traceroute.
//
// # Arguments
//
// * 'packet_bytes' - the bytes of the packet to parse
//
// * 'is_ipv6' - whether to parse the packet as IPv6 or IPv4
//
// # Returns
//
// * 'Option<VerfploeterResult>' - the VerfploeterResult for the received ping reply
//
// # Remarks
//
// The function returns None if the packet is not an ICMP time exceeded packet or if the packet is too short to contain the necessary information.
// fn parse_icmp_ttl_exceeded(packet_bytes: &[u8], is_ipv6: bool) -> Option<Reply> {
//     // Parse IP header
//     let (ip_result, payload) = if is_ipv6 {
//         match parse_ipv6(packet_bytes) {
//             //v6
//             None => return None, // Unable to parse IPv4 header
//             Some((ip_result, payload)) => (Some(ip_result), payload),
//         }
//     } else {
//         // v4
//         match parse_ipv4(packet_bytes) {
//             None => return None, // Unable to parse IPv4 header
//             Some((ip_result, payload)) => (Some(ip_result), payload),
//         }
//     };
//
//     // 2. ICMP time exceeded header
//     if let PacketPayload::ICMP { value: icmp_packet } = payload {
//         if (!is_ipv6 & (icmp_packet.icmp_type != 11)) | (is_ipv6 & (icmp_packet.icmp_type != 3)) {
//             // Code 11 (icmpv4), or code 3 (icmpv6) => time exceeded
//             return None;
//         }
//
//         // 3. IP header of the probe that caused the time exceeded
//         let (ip_result_probe, ip_payload_probe) = if is_ipv6 {
//             // Get the ipv6 header from the probe out of the ICMP body
//             let ipv6_header = parse_ipv6(icmp_packet.body.as_slice());
//
//             // If we are unable to retrieve an IP header out of the ICMP payload
//             if ipv6_header.is_none() {
//                 return None;
//             }
//
//             ipv6_header.unwrap()
//         } else {
//             // Get the ipv4 header from the probe out of the ICMP body
//             let ipv4_header = parse_ipv4(icmp_packet.body.as_slice());
//
//             // If we are unable to retrieve an IP header out of the ICMP payload
//             if ipv4_header.is_none() {
//                 return None;
//             }
//             ipv4_header.unwrap()
//         };
//
//         // 4. Parse the payload of the probe that caused the time exceeded
//         return match ip_payload_probe {
//             PacketPayload::UDP { value: udp_header } => {
//                 let inner_payload = udp_header.body.as_slice();
//                 if inner_payload.len() < 10 {
//                     return None;
//                 }
//
//                 let tx_time = u64::from_be_bytes(inner_payload[0..8].try_into().unwrap());
//                 let tx_worker_id = u32::from(inner_payload[8]);
//                 let probe_ttl = u32::from(inner_payload[9]);
//
//                 Some(VerfploeterResult {
//                     value: Some(Value::Trace(TraceResult {
//                         ip_result,
//                         ttl: probe_ttl,
//                         rx_time: SystemTime::now()
//                             .duration_since(UNIX_EPOCH)
//                             .unwrap()
//                             .as_nanos() as u64,
//                         tx_time,
//                         tx_worker_id,
//                         value: Some(trace_result::Value::Udp(UdpResult {
//                             rx_time: 0,
//                             sport: udp_header.source_port as u32,
//                             dport: udp_header.destination_port as u32,
//                             code: 16,
//                             ip_result: Some(ip_result_probe),
//                             payload: Some(UdpPayload { value: None }),
//                         })),
//                     })),
//                 })
//             }
//             PacketPayload::TCP { value: tcp_header } => {
//                 let inner_payload = tcp_header.body.as_slice();
//                 if inner_payload.len() < 10 {
//                     return None;
//                 }
//
//                 let tx_time = u64::from_be_bytes(inner_payload[0..8].try_into().unwrap());
//                 let tx_worker_id = u32::from(inner_payload[8]);
//                 let probe_ttl = u32::from(inner_payload[9]);
//
//                 Some(VerfploeterResult {
//                     value: Some(Value::Trace(TraceResult {
//                         ip_result,
//                         ttl: probe_ttl,
//                         rx_time: SystemTime::now()
//                             .duration_since(UNIX_EPOCH)
//                             .unwrap()
//                             .as_nanos() as u64,
//                         tx_time,
//                         tx_worker_id,
//                         value: Some(trace_result::Value::Tcp(TcpResult {
//                             rx_time: 0,
//                             sport: tcp_header.source_port as u32,
//                             dport: tcp_header.destination_port as u32,
//                             seq: tcp_header.seq,
//                             ip_result: Some(ip_result_probe),
//                             ack: tcp_header.ack,
//                         })),
//                     })),
//                 })
//             }
//             PacketPayload::ICMP { value: icmp_header } => {
//                 let inner_payload = icmp_header.body.as_slice();
//                 if inner_payload.len() < 10 {
//                     return None;
//                 }
//
//                 let tx_time = u64::from_be_bytes(inner_payload[0..8].try_into().unwrap());
//                 let tx_worker_id = u32::from(inner_payload[8]);
//                 let probe_ttl = u32::from(inner_payload[9]);
//
//                 Some(VerfploeterResult {
//                     value: Some(Value::Trace(TraceResult {
//                         ip_result,
//                         ttl: probe_ttl,
//                         rx_time: SystemTime::now()
//                             .duration_since(UNIX_EPOCH)
//                             .unwrap()
//                             .as_nanos() as u64,
//                         tx_time,
//                         tx_worker_id,
//                         value: Some(trace_result::Value::Ping(PingResult {
//                             rx_time: 0,
//                             ip_result: Some(ip_result_probe),
//                             payload: None,
//                         })),
//                     })),
//                 })
//             }
//             _ => None,
//         };
//     }
//
//     return None;
// }
