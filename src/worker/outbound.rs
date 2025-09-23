use std::num::NonZeroU32;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::thread::sleep;
use std::time::Duration;

use tokio::sync::mpsc::{error::TryRecvError, Receiver};

use crate::custom_module;
use custom_module::manycastr::task::Data::{End, Targets};
use custom_module::manycastr::{task::Data, Origin};

use pnet::datalink::DataLinkSender;

use crate::custom_module::Separated;
use crate::net::packet::{create_dns, create_icmp, create_tcp, get_ethernet_header};
use ratelimit_meter::{DirectRateLimiter, LeakyBucket};
use crate::custom_module::manycastr::task::Data::TraceTask;

const DISCOVERY_WORKER_ID_OFFSET: u32 = u16::MAX as u32;

/// Configuration for an outbound packet sending worker.
///
/// This struct holds all the parameters needed to initialize and run a worker
/// that generates and sends measurement probes (e.g., ICMP, DNS, TCP)
/// at a specified rate.
pub struct OutboundConfig {
    /// The unique ID of this specific worker.
    pub worker_id: u16,

    /// A list of source addresses and port values (`Origin`) to send probes from.
    pub tx_origins: Vec<Origin>,

    /// A shared signal that can be used to forcefully shut down the worker.
    ///
    /// E.g., when the CLI has abruptly disconnected.
    pub abort_s: Arc<AtomicBool>,

    /// Specifies whether to send IPv6 packets (`true`) or IPv4 packets (`false`).
    pub is_ipv6: bool,

    /// Indicates if this is a latency measurement.
    pub is_symmetric: bool,

    /// The unique ID of the measurement.
    pub m_id: u32,

    /// The type of probe to send (e.g., 1 for ICMP, 2 for DNS/A, 3 for TCP).
    pub m_type: u8,

    /// The domain name to query in DNS measurement probes.
    pub qname: String,

    /// An informational URL to be embedded in the probe's payload (e.g., an opt-out link).
    pub info_url: String,

    /// The name of the network interface to send packets from (e.g., "eth0").
    pub if_name: String,

    /// The target rate for sending probes, measured in packets per second (pps).
    pub probing_rate: u32,
}

/// Spawns thread that sends out ICMP, DNS, or TCP probes.
///
/// # Arguments
///
/// * 'config' - configuration for the outbound worker thread
///
/// * 'outbound_rx' - on this channel we receive future tasks that are part of the current measurement
///
/// * 'socket_tx' - the sender object to send packets
pub fn outbound(
    config: OutboundConfig,
    mut outbound_rx: Receiver<Data>,
    mut socket_tx: Box<dyn DataLinkSender>,
) {
    thread::Builder::new()
        .name("outbound".to_string())
        .spawn(move || {
            let mut sent: u32 = 0;
            let mut sent_discovery = 0;
            let mut failed : u32= 0;
            // Rate limit the number of packets sent per second, each origin has the same rate (i.e., sending with 2 origins will double the rate)
            let mut limiter = DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(config.probing_rate * config.tx_origins.len() as u32).unwrap());

            let ethernet_header = get_ethernet_header(config.is_ipv6, config.if_name);
            'outer: loop {
                if config.abort_s.load(std::sync::atomic::Ordering::SeqCst) {
                    // If the finish_rx is set to true, break the loop (abort)
                    println!("[Worker outbound] ABORTING");
                    break;
                }
                let task;
                // Receive tasks from the outbound channel
                loop {
                    match outbound_rx.try_recv() {
                        Ok(t) => {
                            task = t;
                            break;
                        }
                        Err(e) => {
                            if e == TryRecvError::Disconnected {
                                println!("[Worker outbound] Channel disconnected");
                                break 'outer;
                            }
                            // wait some time and try again
                            sleep(Duration::from_millis(100));
                        }
                    };
                }
                match task {
                    End(_) => {
                        // An End task means the measurement has finished
                        break;
                    }
                    Targets(targets) => {
                        let worker_id = if targets.is_discovery == Some(true) {
                            sent_discovery += targets.dst_list.len();
                            config.worker_id as u32 + DISCOVERY_WORKER_ID_OFFSET
                        } else {
                            config.worker_id as u32
                        };
                        for origin in &config.tx_origins {
                            match config.m_type {
                                1 => { // ICMP
                                    for dst in &targets.dst_list {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_icmp(
                                            &origin.src.unwrap(),
                                            dst,
                                            origin.dport as u16, // ICMP identifier
                                            2, // ICMP sequence number
                                            worker_id,
                                            config.m_id,
                                            &config.info_url,
                                            255,
                                        ));

                                        while limiter.check().is_err() { // Rate limit to avoid bursts
                                            sleep(Duration::from_millis(1));
                                        }

                                        match socket_tx.send_to(&packet, None) {
                                            Some(Ok(())) => sent += 1,
                                            Some(Err(e)) => {
                                                eprintln!("[Worker outbound] Failed to send ICMP packet: {e}");
                                                failed += 1;
                                            },
                                            None => eprintln!("[Worker outbound] Failed to send packet: No Tx interface"),
                                        }
                                    }
                                }
                                2 | 4 => { // DNS A record or CHAOS
                                    for dst in &targets.dst_list {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_dns(
                                            origin,
                                            dst,
                                            worker_id,
                                            config.m_type,
                                            &config.qname,
                                        ));
                                        while limiter.check().is_err() { // Rate limit to avoid bursts
                                            sleep(Duration::from_millis(1));
                                        }
                                        match socket_tx.send_to(&packet, None) {
                                            Some(Ok(())) => sent += 1,
                                            Some(Err(e)) => {
                                                eprintln!("[Worker outbound] Failed to send DNS packet: {e}");
                                                failed += 1;
                                            },
                                            None => eprintln!("[Worker outbound] Failed to send packet: No Tx interface"),
                                        }
                                    }
                                }
                                3 => { // TCP
                                    for dst in &targets.dst_list {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_tcp(
                                            origin,
                                            dst,
                                            worker_id,
                                            config.is_symmetric,
                                            &config.info_url,
                                        ));

                                        while limiter.check().is_err() { // Rate limit to avoid bursts
                                            sleep(Duration::from_millis(1));
                                        }

                                        match socket_tx.send_to(&packet, None) {
                                            Some(Ok(())) => sent += 1,
                                            Some(Err(e)) => {
                                                eprintln!("[Worker outbound] Failed to send TCP packet: {e}");
                                                failed += 1;
                                            },
                                            None => eprintln!("[Worker outbound] Failed to send packet: No Tx interface"),
                                        }
                                    }
                                }
                                255 => {
                                    panic!("Invalid measurement type)") // TODO all
                                }
                                _ => panic!("Invalid measurement type"), // Invalid measurement
                            }
                        }
                    }
                    _ => continue, // Invalid measurement
                };
            }
            println!("[Worker outbound] Outbound thread finished - packets sent : {} (including {} discovery probes), packets failed to send: {}", sent.with_separator(), sent_discovery.with_separator(), failed.with_separator());
        })
        .expect("Failed to spawn outbound thread");
}

pub struct TraceConfig {
    /// Unique worker ID
    pub worker_id: u16,

    /// A shared signal that can be used to forcefully shut down the outbound thread.
    ///
    /// E.g., when the CLI has abruptly disconnected.
    pub abort_s: Arc<AtomicBool>,

    /// Specifies whether to send IPv6 packets (`true`) or IPv4 packets (`false`).
    pub is_ipv6: bool,

    /// The name of the network interface to send packets from (e.g., "eth0").
    pub if_name: String,

    /// Whether to send unicast (true) or anycast (false) traceroute probes
    pub is_unicast: bool,

    /// The traceroute measurement ID
    pub trace_id: u32,

    /// The type of traceroute probe to send (1=ICMP, 2=DNS, 3=TCP)
    pub trace_type: u8,

    /// An informational URL to be embedded in the probe's payload (e.g., an opt-out link).
    pub info_url: String,
}

/// Spawns thread to send out traceroute probes
pub fn trace_outbound (
    config: TraceConfig,
    mut outbound_rx: Receiver<Data>,
    mut socket_tx: Box<dyn DataLinkSender>,
) {
    thread::Builder::new()
        .name("outbound".to_string())
        .spawn(move || {
            let mut sent: u32 = 0;
            let mut failed : u32= 0;
            // Traceroute tasks are scheduled by the Orchestrator, there are no rate limits in-place

            let ethernet_header = get_ethernet_header(config.is_ipv6, config.if_name);
            'outer: loop {
                if config.abort_s.load(std::sync::atomic::Ordering::SeqCst) {
                    // If the finish_rx is set to true, break the loop (abort)
                    println!("[Worker outbound] ABORTING");
                    break;
                }
                let task;
                // Receive tasks from the outbound channel
                loop {
                    match outbound_rx.try_recv() {
                        Ok(t) => {
                            task = t;
                            break;
                        }
                        Err(e) => {
                            if e == TryRecvError::Disconnected {
                                println!("[Worker outbound] Channel disconnected");
                                break 'outer;
                            }
                            // wait some time and try again
                            sleep(Duration::from_millis(100));
                        }
                    };
                }
                match task {
                    End(_) => {
                        // An End task means the measurement has finished
                        break;
                    }
                    TraceTask(trace_task) => {
                        let target = &trace_task.dst.unwrap(); // Single target for traceroute tasks
                        let worker_id = config.worker_id as u32;
                        let src = &trace_task.origin.unwrap().src.unwrap();
                        let mut packet = ethernet_header.clone();
                        // Create the appropriate traceroute packet based on the trace_type
                        match config.trace_type {
                            1 => { // ICMP
                                packet.extend_from_slice(&create_icmp(
                                    src,
                                    target,
                                    trace_task.ttl as u16, // encoding TTL in ICMP identifier
                                    worker_id as u16, // encoding worker ID in ICMP sequence number
                                    worker_id,
                                    config.trace_id,
                                    &config.info_url,
                                    trace_task.ttl as u8
                                ));
                            }
                            // TODO implement DNS and TCP traceroute packets
                            _ => panic!("Invalid measurement type"), // Invalid measurement
                        }
                        match socket_tx.send_to(&packet, None) {
                            Some(Ok(())) => sent += 1,
                            Some(Err(e)) => {
                                eprintln!("[Worker outbound] Failed to send traceroute packet: {e}");
                                failed += 1;
                            },
                            None => eprintln!("[Worker outbound] Failed to send packet: No Tx interface"),
                        }
                    }
                    _ => continue, // Invalid measurement
                };
            }
            println!("[Worker outbound] Outbound thread finished - packets sent : {}, packets failed to send: {}", sent.with_separator(), failed.with_separator());
        })
        .expect("Failed to spawn outbound thread");

}

// /// Performs a trace task by sending out ICMP, UDP, or TCP probes with increasing TTLs.
// ///
// /// # Arguments
// ///
// /// * 'origins' - the unique source address and port combinations we send traceroutes with
// ///
// /// * 'is_ipv6' - whether we are using IPv6 or not
// ///
// /// * 'ethernet_header' - the ethernet header to use for the traceroutes
// ///
// /// * 'cap' - the pcap capture to send the traceroutes with
// ///
// /// * 'dst' - the destination address for the traceroutes
// ///
// /// * 'worker_id' - the unique worker ID of this worker
// ///
// /// * 'max_ttl' - the maximum TTL to use for the traceroutes (the actual TTLs used are 5 to max_ttl + 10)
// ///
// /// * 'measurement_type' - the type of measurement being performed (1 = ICMP, 2 = UDP/DNS, 3 = TCP)
// fn perform_trace(
//     origins: Vec<Origin>,
//     is_ipv6: bool,
//     eth_header: Vec<u8>,
//     cap: &mut Capture<pcap::Active>,
//     dst: IP,
//     worker_id: u16,
//     max_ttl: u8,
//     measurement_type: u8,
//     info_url: &str,
// ) {
//     // TODO these are sent out in bursts, create a thread in here for the trace task to send them out 1 second after eachother
//     if measurement_type > 3 {
//         // Traceroute supported for ICMP, UDP, and TCP
//         panic!("Invalid measurement type")
//     }
//
//     println!("performing trace from {:?} to {}", origins, dst.to_string());
//     for origin in origins {
//         let src = IP::from(origin.src.expect("None IP address"));
//         let sport = origin.sport as u16;
//         let dport = origin.dport as u16;
//
//         // Send traceroutes to hops 5 to max_ttl + 10 (starting at 5 to avoid the first 4 vultr hops, and adding 10 to the max_ttl in case of false RTTs)
//         // TODO implement required feedback loop that stops sending traceroutes when the destination is reached (taking into consideration a different worker may receive the destination's response)
//         for i in 5..(max_ttl + 10) {
//             let mut packet: Vec<u8> = Vec::new();
//             packet.extend_from_slice(&eth_header);
//
//             let mut payload_bytes: Vec<u8> = Vec::new();
//             let tx_time = SystemTime::now()
//                 .duration_since(UNIX_EPOCH)
//                 .unwrap()
//                 .as_nanos() as u64;
//             payload_bytes.extend_from_slice(&tx_time.to_be_bytes()); // Bytes 0 - 7
//             payload_bytes.extend_from_slice(&worker_id.to_be_bytes()); // Byte 8 *
//             payload_bytes.extend_from_slice(&i.to_be_bytes()); // Byte 9 *
//
//             if measurement_type == 1 {
//                 // ICMP
//                 let icmp = if is_ipv6 {
//                     ICMPPacket::echo_request_v6(
//                         1,
//                         2,
//                         payload_bytes,
//                         src.get_v6().into(),
//                         dst.get_v6().into(),
//                         i,
//                         info_url,
//                     )
//                 } else {
//                     ICMPPacket::echo_request(
//                         1,
//                         2,
//                         payload_bytes,
//                         src.get_v4().into(),
//                         dst.get_v4().into(),
//                         i,
//                         info_url,
//                     )
//                 };
//                 packet.extend_from_slice(&icmp); // ip header included
//             } else if measurement_type == 2 {
//                 // UDP
//                 let udp = if is_ipv6 {
//                     // TODO encode TTL in the domain name
//                     UDPPacket::dns_request_v6(
//                         src.get_v6().into(),
//                         dst.get_v6().into(),
//                         sport,
//                         "any.dnsjedi.org",
//                         tx_time,
//                         worker_id,
//                         i,
//                     )
//                 } else {
//                     UDPPacket::dns_request(
//                         src.get_v4().into(),
//                         dst.get_v4().into(),
//                         sport,
//                         "any.dnsjedi.org",
//                         tx_time,
//                         worker_id,
//                         i,
//                     )
//                 };
//                 packet.extend_from_slice(&udp); // ip header included
//             } else if measurement_type == 3 {
//                 // TCP
//                 // ACK: first 16 is the TTL, last 16 is the worker ID
//                 let ack = (i as u32) << 16 | worker_id as u32; // TODO test this
//                 let tcp = if is_ipv6 {
//                     TCPPacket::tcp_syn_ack_v6(
//                         src.get_v6().into(),
//                         dst.get_v6().into(),
//                         sport,
//                         dport,
//                         0,
//                         ack,
//                         i,
//                         info_url,
//                     )
//                 } else {
//                     TCPPacket::tcp_syn_ack(
//                         src.get_v4().into(),
//                         dst.get_v4().into(),
//                         sport,
//                         dport,
//                         0,
//                         ack,
//                         i,
//                         info_url,
//                     )
//                 };
//                 packet.extend_from_slice(&tcp); // ip header included
//             }
//
//             cap.sendpacket(packet)
//                 .expect("Failed to send traceroute packet");
//         }
//     }
// }

