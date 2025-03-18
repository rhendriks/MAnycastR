use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, Builder};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{Receiver, UnboundedSender};

use pnet::datalink::DataLinkReceiver;

use crate::custom_module::manycastr::{
    address::Value::V4, address::Value::V6, ip_result, ip_result::Value::Ipv4 as ip_IPv4,
    ip_result::Value::Ipv6 as ip_IPv6, trace_result, udp_payload, verfploeter_result::Value,
    Address, DnsARecord, DnsChaos, IPv4Result, IPv6, IPv6Result, IpResult, PingPayload, PingResult,
    TaskResult, TcpResult, TraceResult, UdpPayload, UdpResult, VerfploeterResult,
};
use crate::net::{netv6::IPv6Packet, DNSAnswer, DNSRecord, IPv4Packet, PacketPayload, TXTRecord};

/// Listen for incoming packets
/// Creates two threads, one that listens on the socket and another that forwards results to the orchestrator and shuts down the receiving socket when appropriate.
/// Makes sure that the received packets are valid and belong to the current measurement.
///
/// # Arguments
///
/// * 'tx' - sender to put task results in
///
/// * 'rx_f' - channel that is used to signal the end of the measurement
///
/// * 'measurement_id' - the ID of the current measurement
///
/// * 'worker_id' - the unique worker ID of this worker
///
/// * 'is_ipv6' - whether to parse the packets as IPv6 or IPv4
///
/// * 'measurement_type' - the type of measurement being performed
///
/// * 'socket_rx' - the socket to listen on
///
/// # Panics
///
/// Panics if the measurement type is invalid
pub fn listen(
    tx: UnboundedSender<TaskResult>,
    rx_f: Receiver<()>,
    measurement_id: u32,
    worker_id: u16,
    is_ipv6: bool,
    measurement_type: u32,
    mut socket_rx: Box<dyn DataLinkReceiver>,
) {
    println!("[Worker inbound] Started listener");
    // Result queue to store incoming pings, and take them out when sending the TaskResults to the orchestrator
    let rq = Arc::new(Mutex::new(Some(Vec::new())));
    // Exit flag for pcap listener
    let exit_flag = Arc::new(AtomicBool::new(false));
    let exit_flag_r = Arc::clone(&exit_flag);
    let rq_r = rq.clone();
    Builder::new()
        .name("listener_thread".to_string())
        .spawn(move || {
            // Listen for incoming packets
            let mut received: u32 = 0;
            loop {
                // Check if we should exit
                if exit_flag_r.load(Ordering::Relaxed) {
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

                let result = if measurement_type == 1 {
                    // ICMP
                    // Convert the bytes into an ICMP packet (first 13 bytes are the eth header, which we skip)
                    let icmp_result = if is_ipv6 {
                        parse_icmpv6(&packet[14..], measurement_id)
                    } else {
                        parse_icmpv4(&packet[14..], measurement_id)
                    };

                    icmp_result
                } else if measurement_type == 2 || measurement_type == 4 {
                    // DNS A
                    let udp_result = if is_ipv6 {
                        if packet[20] == 17 {
                            // 17 is the protocol number for UDP
                            parse_udpv6(&packet[14..], measurement_type)
                        } else {
                            if measurement_type == 2 {
                                // We only parse icmp responses to DNS requests for A records
                                parse_icmp_dst_unreachable(&packet[14..], true)
                            } else {
                                None
                            }
                        }
                    } else {
                        if packet[23] == 17 {
                            // 17 is the protocol number for UDP
                            parse_udpv4(&packet[14..], measurement_type)
                        } else {
                            if measurement_type == 2 {
                                // We only parse icmp responses to DNS requests for A records
                                parse_icmp_dst_unreachable(&packet[14..], false)
                            } else {
                                None
                            }
                        }
                    };

                    udp_result
                } else if measurement_type == 3 {
                    // TCP
                    let tcp_result = if is_ipv6 {
                        parse_tcpv6(&packet[14..])
                    } else {
                        parse_tcpv4(&packet[14..])
                    };

                    tcp_result
                } else {
                    panic!("Invalid measurement type");
                };

                // Invalid packets have value None
                if result == None {
                    continue;
                }

                // Put result in transmission queue
                {
                    received += 1;
                    let mut rq_opt = rq_r.lock().unwrap();
                    if let Some(ref mut x) = *rq_opt {
                        x.push(result.unwrap())
                    }
                }
            }

            println!(
                "[Worker inbound] Stopped pnet listener (received {} packets)",
                received
            );
        })
        .expect("Failed to spawn listener_thread");

    // Thread for sending the received replies to the orchestrator as TaskResult
    Builder::new()
        .name("result_sender_thread".to_string())
        .spawn(move || {
            handle_results(&tx, rx_f, worker_id, rq);

            // Close the listener
            println!("[Worker inbound] Stopping listener");
            // Set the exit flag to true
            exit_flag.store(true, Ordering::SeqCst);

            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default())
                .expect("Failed to send 'finished' signal to orchestrator");
        })
        .expect("Failed to spawn result_sender_thread");
}

/// Thread for handling the received replies, wrapping them in a TaskResult, and streaming them back to the main worker class.
///
/// # Arguments
///
/// * 'tx' - sender to put task results in
///
/// * 'rx_f' - channel that is used to signal the end of the measurement
///
/// * 'worker_id' - the unique worker ID of this worker
///
/// * 'rq_sender' - contains a vector of all received replies as VerfploeterResult
fn handle_results(
    tx: &UnboundedSender<TaskResult>,
    mut rx_f: Receiver<()>,
    worker_id: u16,
    rq_sender: Arc<Mutex<Option<Vec<VerfploeterResult>>>>,
) {
    loop {
        // Every second, forward the ping results to the orchestrator
        sleep(Duration::from_secs(1));

        // Get the current result queue, and replace it with an empty one
        let rq = rq_sender.lock().unwrap().replace(Vec::new()).unwrap();

        // Do not send empty results
        if !rq.is_empty() {
            // Send the result to the worker handler
            tx.send(TaskResult {
                worker_id: worker_id as u32,
                result_list: rq,
            })
            .expect("Failed to send TaskResult to worker handler");
        }

        // Exit the thread if worker sends us the signal it's finished
        if let Ok(_) = rx_f.try_recv() {
            // We are finished
            break;
        }
    }
}

/// Parse packet bytes into an IPv4 header, returns the IP result for this header and the payload.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// # Returns
///
/// * 'Option<(IpResult, PacketPayload)>' - the IP result and the payload of the packet
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain an IPv4 header.
fn parse_ipv4(packet_bytes: &[u8]) -> Option<(IpResult, PacketPayload)> {
    // IPv4 20 minimum
    if packet_bytes.len() < 20 {
        return None;
    }

    // Create IPv4Packet from the bytes in the buffer
    let packet = IPv4Packet::from(packet_bytes);

    // Create a VerfploeterResult for the received ping reply
    return Some((
        IpResult {
            value: Some(ip_result::Value::Ipv4(IPv4Result {
                src: u32::from(packet.source_address),
                dst: u32::from(packet.destination_address),
            })),
            ttl: packet.ttl as u32,
        },
        packet.payload,
    ));
}

/// Parse packet bytes into an IPv6 header, returns the IP result for this header and the payload.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// # Returns
///
/// * 'Option<(IpResult, PacketPayload)>' - the IP result and the payload of the packet
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain an IPv6 header.
fn parse_ipv6(packet_bytes: &[u8]) -> Option<(IpResult, PacketPayload)> {
    // IPv6 40 minimum
    if packet_bytes.len() < 40 {
        return None;
    }

    // Create IPv6Packet from the bytes in the buffer
    let packet = IPv6Packet::from(packet_bytes);

    // Create a VerfploeterResult for the received ping reply
    return Some((
        IpResult {
            value: Some(ip_result::Value::Ipv6(IPv6Result {
                src: Some(IPv6 {
                    p1: (u128::from(packet.source_address) >> 64) as u64,
                    p2: u128::from(packet.source_address) as u64,
                }),
                dst: Some(IPv6 {
                    p1: (u128::from(packet.destination_address) >> 64) as u64,
                    p2: u128::from(packet.destination_address) as u64,
                }),
            })),
            ttl: packet.hop_limit as u32,
        },
        packet.payload,
    ));
}

/// Parse ICMPv4 packets (including v4 headers) into a VerfploeterResult.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// * 'measurement_id' - the ID of the current measurement
///
/// # Returns
///
/// * 'Option<VerfploeterResult>' - the VerfploeterResult for the received ping reply
///
/// # Remarks
///
/// The function returns None if the packet is not an ICMP echo reply or if the packet is too short to contain the necessary information.
///
/// The function also discards packets that do not belong to the current measurement.
fn parse_icmpv4(packet_bytes: &[u8], measurement_id: u32) -> Option<VerfploeterResult> {
    let (ip_result, payload) = match parse_ipv4(packet_bytes) {
        Some((ip_result, payload)) => (ip_result, payload),
        None => return None,
    };

    // Obtain the payload
    if let PacketPayload::ICMP { value: icmp_packet } = payload {
        if *&icmp_packet.icmp_type != 0 {
            return None;
        } // Only parse ICMP echo replies

        if *&icmp_packet.body.len() < 4 {
            return None;
        }
        let s = if let Ok(s) = *&icmp_packet.body[0..4].try_into() {
            s
        } else {
            return None;
        };
        let pkt_measurement_id = u32::from_be_bytes(s);
        // Make sure that this packet belongs to this measurement
        if (pkt_measurement_id != measurement_id) | (icmp_packet.body.len() < 24) {
            // If not, we discard it and await the next packet
            return None;
        }

        let tx_time = u64::from_be_bytes(*&icmp_packet.body[4..12].try_into().unwrap());
        let tx_worker_id = u32::from_be_bytes(*&icmp_packet.body[12..16].try_into().unwrap());
        let src = u32::from_be_bytes(*&icmp_packet.body[16..20].try_into().unwrap());
        let dst = u32::from_be_bytes(*&icmp_packet.body[20..24].try_into().unwrap());

        let rx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Create a VerfploeterResult for the received ping reply
        Some(VerfploeterResult {
            value: Some(Value::Ping(PingResult {
                rx_time,
                ip_result: Some(ip_result),
                payload: Some(PingPayload {
                    tx_time,
                    src: Some(Address {
                        value: Some(V4(src)),
                    }),
                    dst: Some(Address {
                        value: Some(V4(dst)),
                    }),
                    tx_worker_id,
                }),
            })),
        })
    } else {
        None
    }
}

/// Parse ICMPv6 packets (including v6 headers) into a VerfploeterResult.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// * 'measurement_id' - the ID of the current measurement
///
/// # Returns
///
/// * 'Option<VerfploeterResult>' - the VerfploeterResult for the received ping reply
///
/// # Remarks
///
/// The function returns None if the packet is not an ICMP echo reply or if the packet is too short to contain the necessary information.
///
/// The function also discards packets that do not belong to the current measurement.
fn parse_icmpv6(packet_bytes: &[u8], measurement_id: u32) -> Option<VerfploeterResult> {
    let (ip_result, payload) = match parse_ipv6(packet_bytes) {
        Some((ip_result, payload)) => (ip_result, payload),
        None => return None,
    };

    // Obtain the payload
    return if let PacketPayload::ICMP { value } = payload {
        if *&value.icmp_type != 129 {
            return None;
        } // Only parse ICMP echo replies

        if *&value.body.len() < 4 {
            return None;
        }
        let s = if let Ok(s) = *&value.body[0..4].try_into() {
            s
        } else {
            return None;
        };
        let pkt_measurement_id = u32::from_be_bytes(s);
        // Make sure that this packet belongs to this measurement
        if (pkt_measurement_id != measurement_id) | (value.body.len() < 48) {
            // If not, we discard it and await the next packet
            return None;
        }

        let tx_time = u64::from_be_bytes(*&value.body[4..12].try_into().unwrap());
        let tx_worker_id = u32::from_be_bytes(*&value.body[12..16].try_into().unwrap());
        let probe_src = u128::from_be_bytes(*&value.body[16..32].try_into().unwrap());
        let probe_dst = u128::from_be_bytes(*&value.body[32..48].try_into().unwrap());

        let rx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Create a VerfploeterResult for the received ping reply
        Some(VerfploeterResult {
            value: Some(Value::Ping(PingResult {
                rx_time,
                ip_result: Some(ip_result),
                payload: Some(PingPayload {
                    tx_time,
                    src: Some(Address {
                        value: Some(V6(IPv6 {
                            p1: (probe_src >> 64) as u64,
                            p2: probe_src as u64,
                        })),
                    }),
                    dst: Some(Address {
                        value: Some(V6(IPv6 {
                            p1: (probe_dst >> 64) as u64,
                            p2: probe_dst as u64,
                        })),
                    }),
                    tx_worker_id,
                }),
            })),
        })
    } else {
        None
    };
}

/// ICMP Time exceeded parser, used for traceroute.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// * 'is_ipv6' - whether to parse the packet as IPv6 or IPv4
///
/// # Returns
///
/// * 'Option<VerfploeterResult>' - the VerfploeterResult for the received ping reply
///
/// # Remarks
///
/// The function returns None if the packet is not an ICMP time exceeded packet or if the packet is too short to contain the necessary information.
#[allow(dead_code)]
fn parse_icmp_ttl_exceeded(packet_bytes: &[u8], is_ipv6: bool) -> Option<VerfploeterResult> {
    // 1. Parse IP header
    let (ip_result, payload) = if is_ipv6 {
        match parse_ipv6(packet_bytes) {
            //v6
            None => return None, // Unable to parse IPv4 header
            Some((ip_result, payload)) => (Some(ip_result), payload),
        }
    } else {
        // v4
        match parse_ipv4(packet_bytes) {
            None => return None, // Unable to parse IPv4 header
            Some((ip_result, payload)) => (Some(ip_result), payload),
        }
    };

    // 2. ICMP time exceeded header
    if let PacketPayload::ICMP { value: icmp_packet } = payload {
        if (!is_ipv6 & (icmp_packet.icmp_type != 11)) | (is_ipv6 & (icmp_packet.icmp_type != 3)) {
            // Code 11 (icmpv4), or code 3 (icmpv6) => time exceeded
            return None;
        }

        // 3. IP header of the probe that caused the time exceeded
        let (ip_result_probe, ip_payload_probe) = if is_ipv6 {
            // Get the ipv6 header from the probe out of the ICMP body
            let ipv6_header = parse_ipv6(icmp_packet.body.as_slice());

            // If we are unable to retrieve an IP header out of the ICMP payload
            if ipv6_header.is_none() {
                return None;
            }

            ipv6_header.unwrap()
        } else {
            // Get the ipv4 header from the probe out of the ICMP body
            let ipv4_header = parse_ipv4(icmp_packet.body.as_slice());

            // If we are unable to retrieve an IP header out of the ICMP payload
            if ipv4_header.is_none() {
                return None;
            }
            ipv4_header.unwrap()
        };

        // 4. Parse the payload of the probe that caused the time exceeded
        return match ip_payload_probe {
            PacketPayload::UDP { value: udp_header } => {
                let inner_payload = udp_header.body.as_slice();
                if inner_payload.len() < 10 {
                    return None;
                }

                let tx_time = u64::from_be_bytes(inner_payload[0..8].try_into().unwrap());
                let tx_worker_id = u32::from(inner_payload[8]);
                let probe_ttl = u32::from(inner_payload[9]);

                Some(VerfploeterResult {
                    value: Some(Value::Trace(TraceResult {
                        ip_result,
                        ttl: probe_ttl,
                        rx_time: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64,
                        tx_time,
                        tx_worker_id,
                        value: Some(trace_result::Value::Udp(UdpResult {
                            rx_time: 0,
                            sport: udp_header.source_port as u32,
                            dport: udp_header.destination_port as u32,
                            code: 16,
                            ip_result: Some(ip_result_probe),
                            payload: Some(UdpPayload { value: None }),
                        })),
                    })),
                })
            }
            PacketPayload::TCP { value: tcp_header } => {
                let inner_payload = tcp_header.body.as_slice();
                if inner_payload.len() < 10 {
                    return None;
                }

                let tx_time = u64::from_be_bytes(inner_payload[0..8].try_into().unwrap());
                let tx_worker_id = u32::from(inner_payload[8]);
                let probe_ttl = u32::from(inner_payload[9]);

                Some(VerfploeterResult {
                    value: Some(Value::Trace(TraceResult {
                        ip_result,
                        ttl: probe_ttl,
                        rx_time: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64,
                        tx_time,
                        tx_worker_id,
                        value: Some(trace_result::Value::Tcp(TcpResult {
                            rx_time: 0,
                            sport: tcp_header.source_port as u32,
                            dport: tcp_header.destination_port as u32,
                            seq: tcp_header.seq,
                            ip_result: Some(ip_result_probe),
                            ack: tcp_header.ack,
                        })),
                    })),
                })
            }
            PacketPayload::ICMP { value: icmp_header } => {
                let inner_payload = icmp_header.body.as_slice();
                if inner_payload.len() < 10 {
                    return None;
                }

                let tx_time = u64::from_be_bytes(inner_payload[0..8].try_into().unwrap());
                let tx_worker_id = u32::from(inner_payload[8]);
                let probe_ttl = u32::from(inner_payload[9]);

                Some(VerfploeterResult {
                    value: Some(Value::Trace(TraceResult {
                        ip_result,
                        ttl: probe_ttl,
                        rx_time: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64,
                        tx_time,
                        tx_worker_id,
                        value: Some(trace_result::Value::Ping(PingResult {
                            rx_time: 0,
                            ip_result: Some(ip_result_probe),
                            payload: None,
                        })),
                    })),
                })
            }
            _ => None,
        };
    }

    return None;
}

/// ICMP Destination unreachable parser, used for DNS A record probing.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// * 'is_ipv6' - whether to parse the packet as IPv6 or IPv4
///
/// # Returns
///
/// * 'Option<VerfploeterResult>' - the VerfploeterResult for the received ping reply
///
/// # Remarks
///
/// The function returns None if the packet is not an ICMP destination unreachable packet or if the packet is too short to contain the necessary information.
///
/// The function also discards packets that do not belong to the current measurement.
fn parse_icmp_dst_unreachable(packet_bytes: &[u8], is_ipv6: bool) -> Option<VerfploeterResult> {
    // 1. Parse IP header
    let (ip_result, payload) = if is_ipv6 {
        match parse_ipv6(packet_bytes) {
            None => return None, // Unable to parse IPv4 header
            Some((ip_result, payload)) => (Some(ip_result), payload),
        }
    } else {
        // v4
        match parse_ipv4(packet_bytes) {
            None => return None, // Unable to parse IPv4 header
            Some((ip_result, payload)) => (Some(ip_result), payload),
        }
    };

    // 2. Parse ICMP header
    return if let PacketPayload::ICMP { value: icmp_packet } = payload {
        // Make sure that this packet belongs to this measurement (if not we discard and continue)
        if !is_ipv6 & (icmp_packet.icmp_type != 3) {
            // Code 3 (v4) => destination unreachable
            return None;
        } else if is_ipv6 & (icmp_packet.icmp_type != 1) {
            // Code 1 (v6) => destination unreachable
            return None;
        }
        let reply_code = icmp_packet.code as u32;
        let reply_identifier = icmp_packet.identifier as u32;
        let mut probe_sport = 0u32;
        let mut udp_payload = None;
        let tx_worker_id = 0u32;
        let rx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // 3. Parse ICMP body
        // 3.1 IP header in ICMP body
        let icmp_body_result = if is_ipv6 {
            parse_ipv6(icmp_packet.body.as_slice())
        } else {
            parse_ipv4(icmp_packet.body.as_slice())
        };

        // If we are unable to retrieve an IP header out of the ICMP payload
        if icmp_body_result.is_none() {
            // Create a VerfploeterResult for the received ping reply
            return Some(VerfploeterResult {
                value: Some(Value::Udp(UdpResult {
                    rx_time,
                    sport: 0,
                    dport: 0,
                    code: reply_code,
                    ip_result,
                    payload: None,
                })),
            });
        }
        // Get the IP header from the ICMP body
        let (probe_ip_header, ip_payload_probe) = icmp_body_result.unwrap();

        // 3.2 UDP header in ICMP body
        if let PacketPayload::UDP { value: udp_header } = ip_payload_probe {
            probe_sport = udp_header.source_port as u32;

            // 3.3 DNS header
            if udp_header.body.len() >= 60 {
                // Rough minimum size for DNS A packet with our domain
                udp_payload = parse_dns_a_record(udp_header.body.as_slice(), is_ipv6);
            }
        }

        // If the ICMP payload does not contain the full DNS packet, we create a VerfploeterResult with the ICMP information
        if udp_payload.is_none() {
            // Get the source and destination addresses from the IP header in the ICMP body
            let (probe_src, probe_dst) = if is_ipv6 {
                let probe_src = Some(Address {
                    value: Some(V6(match probe_ip_header.value.clone().unwrap() {
                        ip_IPv4(_) => panic!("IPv4 header in ICMPv6 packet"),
                        ip_IPv6(ipv6) => ipv6.src.unwrap(),
                    })),
                });

                let probe_dst = Some(Address {
                    value: Some(V6(match probe_ip_header.value.clone().unwrap() {
                        ip_IPv4(_) => panic!("IPv4 header in ICMPv6 packet"),
                        ip_IPv6(ipv6) => ipv6.dst.unwrap(),
                    })),
                });

                (probe_src, probe_dst)
            } else {
                let probe_src = Some(Address {
                    value: Some(V4(match probe_ip_header.value.clone().unwrap() {
                        ip_IPv4(ipv4) => ipv4.src,
                        ip_IPv6(_) => panic!("IPv6 header in ICMPv4 packet"),
                    })),
                });

                let probe_dst = Some(Address {
                    value: Some(V4(match probe_ip_header.value.clone().unwrap() {
                        ip_IPv4(ipv4) => ipv4.dst,
                        ip_IPv6(_) => panic!("IPv6 header in ICMPv4 packet"),
                    })),
                });

                (probe_src, probe_dst)
            };

            udp_payload = Some(UdpPayload {
                value: Some(udp_payload::Value::DnsARecord(DnsARecord {
                    tx_time: 0,
                    src: probe_src,
                    dst: probe_dst,
                    tx_worker_id,
                    sport: probe_sport,
                })),
            })
        }

        // Create a VerfploeterResult for the received ping reply
        Some(VerfploeterResult {
            value: Some(Value::Udp(UdpResult {
                rx_time,
                sport: 0,                // ICMP replies have no port numbers
                dport: reply_identifier, // ICMP replies use the destination port value of a measurement as identifier
                code: reply_code,
                ip_result,
                payload: udp_payload,
            })),
        })
    } else {
        None
    };
}

/// Parse UDPv4 packets (including v4 headers) into a VerfploeterResult.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// * 'measurement_type' - the type of measurement being performed
///
/// # Returns
///
/// * 'Option<VerfploeterResult>' - the VerfploeterResult for the received UDP reply
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a UDP header.
fn parse_udpv4(packet_bytes: &[u8], measurement_type: u32) -> Option<VerfploeterResult> {
    let (ip_result, payload) = match parse_ipv4(packet_bytes) {
        Some((ip_result, payload)) => (ip_result, payload),
        None => return None,
    };

    // Obtain the payload
    if let PacketPayload::UDP { value: udp_packet } = payload {
        // The UDP responses will be from DNS services, with src port 53 and our possible src ports as dest port, furthermore the body length has to be large enough to contain a DNS A reply
        // TODO body packet length is variable based on the domain name used in the measurement
        if ((measurement_type == 2) & (udp_packet.body.len() < 66))
            | ((measurement_type == 4) & (udp_packet.body.len() < 10))
        {
            return None;
        }

        let rx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let payload = if measurement_type == 2 {
            parse_dns_a_record(udp_packet.body.as_slice(), false)
        } else if measurement_type == 4 {
            parse_chaos(udp_packet.body.as_slice())
        } else {
            None
        };

        // Create a VerfploeterResult for the received UDP reply
        Some(VerfploeterResult {
            value: Some(Value::Udp(UdpResult {
                rx_time,
                sport: udp_packet.source_port as u32,
                dport: udp_packet.destination_port as u32,
                code: 16,
                ip_result: Some(ip_result),
                payload,
            })),
        })
    } else {
        None
    }
}

/// Parse UDPv6 packets (including v6 headers) into a VerfploeterResult.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// * 'measurement_type' - the type of measurement being performed
///
/// # Returns
///
/// * 'Option<VerfploeterResult>' - the VerfploeterResult for the received UDP reply
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a UDP header.
fn parse_udpv6(packet_bytes: &[u8], measurement_type: u32) -> Option<VerfploeterResult> {
    let (ip_result, payload) = match parse_ipv6(packet_bytes) {
        Some((ip_result, payload)) => (ip_result, payload),
        None => return None,
    };

    // Obtain the payload
    if let PacketPayload::UDP { value } = payload {
        // The UDP responses will be from DNS services, with src port 53 and our possible src ports as dest port, furthermore the body length has to be large enough to contain a DNS A reply
        // TODO use 'get_domain_length'
        if ((measurement_type == 2) & (value.body.len() < 66))
            | ((measurement_type == 4) & (value.body.len() < 10))
        {
            return None;
        }

        let rx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let payload = if measurement_type == 2 {
            parse_dns_a_record(value.body.as_slice(), true)
        } else if measurement_type == 4 {
            parse_chaos(value.body.as_slice())
        } else {
            None
        };

        // Create a VerfploeterResult for the received UDP reply
        Some(VerfploeterResult {
            value: Some(Value::Udp(UdpResult {
                rx_time,
                sport: value.source_port as u32,
                dport: value.destination_port as u32,
                code: 16,
                ip_result: Some(ip_result),
                payload,
            })),
        })
    } else {
        None
    }
}

/// Attempts to parse the DNS A record from a UDP payload body.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// * 'is_ipv6' - whether to parse the packet as IPv6 or IPv4
///
/// # Returns
///
/// * 'Option<UdpPayload>' - the UDP payload containing the DNS A record
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a DNS A record.
fn parse_dns_a_record(packet_bytes: &[u8], is_ipv6: bool) -> Option<UdpPayload> {
    let record = DNSRecord::from(packet_bytes);
    let domain = record.domain; // example: '1679305276037913215.3226971181.16843009.0.4000.any.dnsjedi.org'
                                // Get the information from the domain, continue to the next packet if it does not follow the format
    if is_ipv6 {
        let parts: Vec<&str> = domain.split('.').collect();
        // Our domains have 8 'parts' separated by 7 dots
        if parts.len() != 8 {
            return None;
        }

        let tx_time = match parts[0].parse::<u64>() {
            Ok(t) => t,
            Err(_) => return None,
        };
        let probe_src = match parts[1].parse::<u128>() {
            Ok(s) => s,
            Err(_) => return None,
        };
        let probe_dst = match parts[2].parse::<u128>() {
            Ok(s) => s,
            Err(_) => return None,
        };
        let tx_worker_id = match parts[3].parse::<u8>() {
            Ok(s) => s,
            Err(_) => return None,
        };
        let probe_sport = match parts[4].parse::<u16>() {
            Ok(s) => s,
            Err(_) => return None,
        };

        Some(UdpPayload {
            value: Some(udp_payload::Value::DnsARecord(DnsARecord {
                tx_time,
                src: Some(Address {
                    value: Some(V6(IPv6 {
                        p1: (probe_src >> 64) as u64,
                        p2: probe_src as u64,
                    })),
                }),
                dst: Some(Address {
                    value: Some(V6(IPv6 {
                        p1: (probe_dst >> 64) as u64,
                        p2: probe_dst as u64,
                    })),
                }),
                tx_worker_id: tx_worker_id as u32,
                sport: probe_sport as u32,
            })),
        })
    } else {
        let parts: Vec<&str> = domain.split('.').next().unwrap().split('-').collect();
        // Our domains have 5 'parts' separated by 4 dashes
        if parts.len() != 5 {
            return None;
        }

        let tx_time = match parts[0].parse::<u64>() {
            Ok(t) => t,
            Err(_) => return None,
        };
        let probe_src = match parts[1].parse::<u32>() {
            Ok(s) => s,
            Err(_) => return None,
        };
        let probe_dst = match parts[2].parse::<u32>() {
            Ok(s) => s,
            Err(_) => return None,
        };
        let tx_worker_id = match parts[3].parse::<u8>() {
            Ok(s) => s,
            Err(_) => return None,
        };
        let probe_sport = match parts[4].parse::<u16>() {
            Ok(s) => s,
            Err(_) => return None,
        };

        Some(UdpPayload {
            value: Some(udp_payload::Value::DnsARecord(DnsARecord {
                tx_time,
                src: Some(Address {
                    value: Some(V4(probe_src)),
                }),
                dst: Some(Address {
                    value: Some(V4(probe_dst)),
                }),
                tx_worker_id: tx_worker_id as u32,
                sport: probe_sport as u32,
            })),
        })
    }
}

/// Attempts to parse the DNS Chaos record from a UDP payload body.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// # Returns
///
/// * 'Option<UdpPayload>' - the UDP payload containing the DNS Chaos record
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a DNS Chaos record.
fn parse_chaos(packet_bytes: &[u8]) -> Option<UdpPayload> {
    let record = DNSRecord::from(packet_bytes);

    // 8 right most bits are the sender worker_id
    let tx_worker_id = ((record.transaction_id >> 8) & 0xFF) as u32;

    if record.answer == 0 {
        return Some(UdpPayload {
            value: Some(udp_payload::Value::DnsChaos(DnsChaos {
                tx_worker_id,
                chaos_data: "Not implemented".to_string(),
            })),
        });
    }

    let dns_answer = DNSAnswer::from(record.body.as_slice());
    let txt = TXTRecord::from(dns_answer.data.as_slice());
    let chaos_data = txt.txt;

    return Some(UdpPayload {
        value: Some(udp_payload::Value::DnsChaos(DnsChaos {
            tx_worker_id,
            chaos_data,
        })),
    });
}

/// Parse TCP body into a VerfploeterResult.
///
/// # Arguments
///
/// * 'ip_payload' - the IP payload to parse
///
/// * 'ip_result' - the IP result for the IP header
///
/// # Returns
///
/// * 'Option<VerfploeterResult>' - the VerfploeterResult for the received TCP reply
///
/// # Remarks
///
/// The function returns None if the packet is not a TCP RST or RST+ACK packet.
fn parse_tcp(ip_payload: PacketPayload, ip_result: IpResult) -> Option<VerfploeterResult> {
    // Obtain the payload
    return if let PacketPayload::TCP { value: tcp_packet } = ip_payload {
        if !((tcp_packet.flags == 0b00000100) | (tcp_packet.flags == 0b00010100)) {
            // We assume all packets with RST or RST+ACK flags are replies
            return None;
        }

        let rx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        Some(VerfploeterResult {
            value: Some(Value::Tcp(TcpResult {
                sport: u32::from(tcp_packet.source_port),
                dport: tcp_packet.destination_port as u32,
                seq: tcp_packet.seq,
                ip_result: Some(ip_result),
                rx_time,
                ack: tcp_packet.ack,
            })),
        })
    } else {
        None
    };
}

/// Parse TCPv4 packets (including v4 headers) into a VerfploeterResult.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// # Returns
///
/// * 'Option<VerfploeterResult>' - the VerfploeterResult for the received TCP reply
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a TCP header.
fn parse_tcpv4(packet_bytes: &[u8]) -> Option<VerfploeterResult> {
    let (ip_result, payload) = match parse_ipv4(packet_bytes) {
        Some((ip_result, payload)) => (ip_result, payload),
        None => return None,
    };
    return parse_tcp(payload, ip_result);
}

/// Parse TCPv6 packets (including v6 headers) into a VerfploeterResult.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// # Returns
///
/// * 'Option<VerfploeterResult>' - the VerfploeterResult for the received TCP reply
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a TCP header.
fn parse_tcpv6(packet_bytes: &[u8]) -> Option<VerfploeterResult> {
    let (ip_result, payload) = match parse_ipv6(packet_bytes) {
        Some((ip_result, payload)) => (ip_result, payload),
        None => return None,
    };

    return parse_tcp(payload, ip_result);
}
