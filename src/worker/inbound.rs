use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, Builder};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{Receiver, UnboundedSender};

use pnet::datalink::DataLinkReceiver;

use crate::custom_module::manycastr::{
    ip_result, reply::Value, udp_payload, DnsARecord, DnsChaos, IPv4Result, IPv6, IPv6Result,
    IpResult, Origin, PingPayload, PingResult, Reply, TaskResult, TcpResult, UdpPayload, UdpResult,
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
/// * 'origin_map' - mapping of origin to origin ID
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
    measurement_type: u8,
    mut socket_rx: Box<dyn DataLinkReceiver>,
    origin_map: Vec<Origin>,
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
                        parse_icmpv6(&packet[14..], measurement_id, &origin_map)
                    } else {
                        parse_icmpv4(&packet[14..], measurement_id, &origin_map)
                    };

                    icmp_result
                } else if measurement_type == 2 || measurement_type == 4 {
                    // DNS A
                    let udp_result = if is_ipv6 {
                        if packet[20] == 17 {
                            // 17 is the protocol number for UDP
                            parse_udpv6(&packet[14..], measurement_type, &origin_map)
                        } else {
                            None
                        }
                    } else {
                        if packet[23] == 17 {
                            // 17 is the protocol number for UDP
                            parse_udpv4(&packet[14..], measurement_type, &origin_map)
                        } else {
                            None
                        }
                    };

                    udp_result
                } else if measurement_type == 3 {
                    // TCP
                    let tcp_result = if is_ipv6 {
                        parse_tcpv6(&packet[14..], &origin_map)
                    } else {
                        parse_tcpv4(&packet[14..], &origin_map)
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
/// * `tx` - sender to put task results in
///
/// * `rx_f` - channel that is used to signal the end of the measurement
///
/// * `worker_id` - the unique worker ID of this worker
///
/// * `rq_sender` - contains a vector of all received replies as Reply results
fn handle_results(
    tx: &UnboundedSender<TaskResult>,
    mut rx_f: Receiver<()>,
    worker_id: u16,
    rq_sender: Arc<Mutex<Option<Vec<Reply>>>>,
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
fn parse_ipv4(packet_bytes: &[u8]) -> Option<(IpResult, PacketPayload, u32, u32)> {
    // Create IPv4Packet from the bytes in the buffer
    let packet = IPv4Packet::from(packet_bytes);

    // Create a Reply for the received ping reply
    return Some((
        IpResult {
            value: Some(ip_result::Value::Ipv4(IPv4Result {
                src: u32::from(packet.source_address),
            })),
            ttl: packet.ttl as u32,
        },
        packet.payload,
        u32::from(packet.destination_address),
        u32::from(packet.source_address),
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
fn parse_ipv6(packet_bytes: &[u8]) -> Option<(IpResult, PacketPayload, u128, u128)> {
    // Create IPv6Packet from the bytes in the buffer
    let packet = IPv6Packet::from(packet_bytes);

    // Create a Reply for the received ping reply
    Some((
        IpResult {
            value: Some(ip_result::Value::Ipv6(IPv6Result {
                src: Some(IPv6 {
                    p1: (u128::from(packet.source_address) >> 64) as u64,
                    p2: u128::from(packet.source_address) as u64,
                }),
            })),
            ttl: packet.hop_limit as u32,
        },
        packet.payload,
        u128::from(packet.destination_address),
        u128::from(packet.source_address),
    ))
}

/// Parse ICMPv4 packets (including v4 headers) into a Reply result.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// * `measurement_id` - the ID of the current measurement
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
fn parse_icmpv4(
    packet_bytes: &[u8],
    measurement_id: u32,
    origin_map: &Vec<Origin>,
) -> Option<Reply> {
    // ICMPv4 50 length (IPv4 header (20) + ICMP header (8) + ICMP body 22 bytes) + check it is an ICMP Echo reply TODO match with exact length (include -u URl length)
    if (packet_bytes.len() < 50) || (packet_bytes[20] != 0) {
        return None;
    }

    let (ip_result, payload, reply_dst, reply_src) = parse_ipv4(packet_bytes)?;

    // Obtain the payload
    if let PacketPayload::ICMP { value: icmp_packet } = payload {
        if *&icmp_packet.icmp_type != 0 {
            return None;
        } // Only parse ICMP echo replies

        let pkt_measurement_id: [u8; 4] = icmp_packet.body[0..4].try_into().ok()?;
        // Make sure that this packet belongs to this measurement
        if u32::from_be_bytes(pkt_measurement_id) != measurement_id {
            // If not, we discard it and await the next packet
            return None;
        }

        let tx_time = u64::from_be_bytes(*&icmp_packet.body[4..12].try_into().unwrap());
        let tx_worker_id =
            u16::from_be_bytes(*&icmp_packet.body[12..14].try_into().unwrap()) as u32;
        let probe_src = u32::from_be_bytes(*&icmp_packet.body[14..18].try_into().unwrap());
        let probe_dst = u32::from_be_bytes(*&icmp_packet.body[18..22].try_into().unwrap());

        if (probe_src != reply_dst) | (probe_dst != reply_src) {
            return None; // spoofed reply
        }

        let origin_id = get_origin_id_v4(reply_dst, 0, 0, origin_map)?;

        let rx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Create a Reply for the received ping reply
        Some(Reply {
            value: Some(Value::Ping(PingResult {
                payload: Some(PingPayload {
                    tx_time,
                    tx_worker_id,
                }),
            })),
            ip_result: Some(ip_result),
            rx_time,
            origin_id,
        })
    } else {
        None
    }
}

/// Parse ICMPv6 packets (including v6 headers) into a Reply result.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// * `measurement_id` - the ID of the current measurement
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
    // ICMPv6 64 length (IPv6 header (40) + ICMP header (8) + ICMP body 46 bytes) + check it is an ICMP Echo reply TODO match with exact length (include -u URl length)
    if (packet_bytes.len() < 94) || (packet_bytes[40] != 129) {
        return None;
    }
    let (ip_result, payload, reply_dst, reply_src) = parse_ipv6(packet_bytes)?;

    // Parse the ICMP header
    let icmp_packet = if let PacketPayload::ICMP { value } = payload {
        value
    } else {
        return None;
    };
    // Obtain the payload
    if *&icmp_packet.icmp_type != 129 {
        return None;
    } // Only parse ICMP echo replies

    let pkt_measurement_id: [u8; 4] = icmp_packet.body[0..4].try_into().ok()?;
    // Make sure that this packet belongs to this measurement
    if u32::from_be_bytes(pkt_measurement_id) != measurement_id {
        return None;
    }

    let tx_time = u64::from_be_bytes(*&icmp_packet.body[4..12].try_into().unwrap());
    let tx_worker_id = u16::from_be_bytes(*&icmp_packet.body[12..14].try_into().unwrap()) as u32;
    let probe_src = u128::from_be_bytes(*&icmp_packet.body[14..30].try_into().unwrap());
    let probe_dst = u128::from_be_bytes(*&icmp_packet.body[30..46].try_into().unwrap());

    if (probe_src != reply_dst) | (probe_dst != reply_src) {
        return None; // spoofed reply
    }

    let origin_id = get_origin_id_v6(reply_dst, 0, 0, origin_map)?;

    let rx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Create a Reply for the received ping reply
    Some(Reply {
        value: Some(Value::Ping(PingResult {
            payload: Some(PingPayload {
                tx_time,
                tx_worker_id,
            }),
        })),
        ip_result: Some(ip_result),
        rx_time,
        origin_id,
    })
}

/// Parse UDPv4 packets (including v4 headers) into a Reply result.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// * 'measurement_type' - the type of measurement being performed
///
/// # Returns
///
/// * `Option<Reply>` - the received UDP reply
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a UDP header.
fn parse_udpv4(
    packet_bytes: &[u8],
    measurement_type: u8,
    origin_map: &Vec<Origin>,
) -> Option<Reply> {
    // UDPv4 28 minimum (IPv4 header (20) + UDP header (8)) + check next protocol is UDP TODO incorporate minimum payload size
    if (packet_bytes.len() < 28) || (packet_bytes[9] != 17) {
        return None;
    }
    let (ip_result, payload, reply_dst, reply_src) = parse_ipv4(packet_bytes)?;

    // Obtain the payload
    if let PacketPayload::UDP { value: udp_packet } = payload {
        // The UDP responses will be from DNS services, with src port 53 and our possible src ports as dest port, furthermore the body length has to be large enough to contain a DNS A reply
        // TODO body packet length is variable based on the domain name used in the measurement
        if ((measurement_type == 2) & (udp_packet.body.len() < 66))
            | ((measurement_type == 4) & (udp_packet.body.len() < 10))
        {
            return None;
        }

        let reply_sport = udp_packet.source_port;
        let reply_dport = udp_packet.destination_port;

        let rx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let payload = if measurement_type == 2 {
            let (udp_payload, probe_sport, probe_src, probe_dst) =
                parse_dns_a_record_v4(udp_packet.body.as_slice())?;

            if (probe_sport != reply_dport) | (probe_src != reply_dst) | (probe_dst != reply_src) {
                return None; // spoofed reply
            }

            Some(udp_payload)
        } else if measurement_type == 4 {
            parse_chaos(udp_packet.body.as_slice())
        } else {
            None
        };

        let origin_id = get_origin_id_v4(reply_dst, reply_sport, reply_dport, origin_map)?;

        // Create a Reply for the received UDP reply
        Some(Reply {
            value: Some(Value::Udp(UdpResult { code: 16, payload })),
            ip_result: Some(ip_result),
            rx_time,
            origin_id,
        })
    } else {
        None
    }
}

/// Parse UDPv6 packets (including v6 headers) into a Reply.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// * `measurement_type` - the type of measurement being performed
///
/// # Returns
///
/// * `Option<Reply>` - the received UDP reply
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a UDP header.
fn parse_udpv6(
    packet_bytes: &[u8],
    measurement_type: u8,
    origin_map: &Vec<Origin>,
) -> Option<Reply> {
    // UDPv6 64 length (IPv6 header (40) + UDP header (8)) + check next protocol is UDP TODO incorporate minimum payload size
    if (packet_bytes.len() < 48) || (packet_bytes[6] != 17) {
        return None;
    }
    let (ip_result, payload, reply_dst, reply_src) = parse_ipv6(packet_bytes)?;

    // Obtain the payload
    if let PacketPayload::UDP { value } = payload {
        // The UDP responses will be from DNS services, with src port 53 and our possible src ports as dest port, furthermore the body length has to be large enough to contain a DNS A reply
        // TODO use 'get_domain_length'
        if ((measurement_type == 2) & (value.body.len() < 66))
            | ((measurement_type == 4) & (value.body.len() < 10))
        {
            return None;
        }

        let reply_sport = value.source_port;
        let reply_dport = value.destination_port;

        let rx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let payload = if measurement_type == 2 {
            let (udp_payload, probe_sport, probe_src, probe_dst) =
                parse_dns_a_record_v6(value.body.as_slice())?;

            if (probe_sport != reply_dport) | (probe_dst != reply_src) | (probe_src != reply_dst) {
                return None; // spoofed reply
            }

            Some(udp_payload)
        } else if measurement_type == 4 {
            parse_chaos(value.body.as_slice())
        } else {
            None
        };

        let origin_id = get_origin_id_v6(reply_dst, reply_sport, reply_dport, origin_map)?;

        // Create a Reply for the received UDP reply
        Some(Reply {
            value: Some(Value::Udp(UdpResult { code: 16, payload })),
            ip_result: Some(ip_result),
            rx_time,
            origin_id,
        })
    } else {
        None
    }
}

/// Attempts to parse the DNS A record from a UDP payload body.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// * `is_ipv6` - whether to parse the packet as IPv6 or IPv4
///
/// # Returns
///
/// * `Option<UdpPayload>` - the UDP payload containing the DNS A record
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a DNS A record.
fn parse_dns_a_record_v6(packet_bytes: &[u8]) -> Option<(UdpPayload, u16, u128, u128)> {
    let record = DNSRecord::from(packet_bytes);
    let domain = record.domain; // example: '1679305276037913215.3226971181.16843009.0.4000.any.dnsjedi.org'
                                // Get the information from the domain, continue to the next packet if it does not follow the format
    let parts: Vec<&str> = domain.split('.').collect();
    // Our domains have 8 'parts' separated by 7 dots
    if parts.len() != 8 {
        return None;
    }

    let tx_time = parts[0].parse::<u64>().ok()?;
    let probe_src = parts[1].parse::<u128>().ok()?;
    let probe_dst = parts[2].parse::<u128>().ok()?;
    let tx_worker_id = parts[3].parse::<u16>().ok()? as u32;
    let probe_sport = parts[4].parse::<u16>().ok()?;

    Some((
        UdpPayload {
            value: Some(udp_payload::Value::DnsARecord(DnsARecord {
                tx_time,
                tx_worker_id,
            })),
        },
        probe_sport,
        probe_src,
        probe_dst,
    ))
}

fn parse_dns_a_record_v4(packet_bytes: &[u8]) -> Option<(UdpPayload, u16, u32, u32)> {
    let record = DNSRecord::from(packet_bytes);
    let domain = record.domain; // example: '1679305276037913215.3226971181.16843009.0.4000.any.dnsjedi.org'
                                // Get the information from the domain, continue to the next packet if it does not follow the format

    let parts: Vec<&str> = domain.split('.').next().unwrap().split('-').collect();
    // Our domains have 5 'parts' separated by 4 dashes
    if parts.len() != 5 {
        return None;
    }

    let tx_time = parts[0].parse::<u64>().ok()?;
    let probe_src = parts[1].parse::<u32>().ok()?;
    let probe_dst = parts[2].parse::<u32>().ok()?;
    let tx_worker_id = parts[3].parse::<u16>().ok()? as u32;
    let probe_sport = parts[4].parse::<u16>().ok()?;

    Some((
        UdpPayload {
            value: Some(udp_payload::Value::DnsARecord(DnsARecord {
                tx_time,
                tx_worker_id,
            })),
        },
        probe_sport,
        probe_src,
        probe_dst,
    ))
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

    let chaos_data = TXTRecord::from(DNSAnswer::from(record.body.as_slice()).data.as_slice()).txt;

    return Some(UdpPayload {
        value: Some(udp_payload::Value::DnsChaos(DnsChaos {
            tx_worker_id,
            chaos_data,
        })),
    });
}

/// Parse TCPv4 packets (including v4 headers) into a Reply result.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
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
    let (ip_result, payload, reply_dst, _reply_src) = parse_ipv4(packet_bytes)?;
    // cannot filter out spoofed packets as the probe_dst is unknown

    return if let PacketPayload::TCP { value: tcp_packet } = payload {
        if !((tcp_packet.flags == 0b00000100) | (tcp_packet.flags == 0b00010100)) {
            // We assume all packets with RST or RST+ACK flags are replies
            return None;
        }

        let rx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let origin_id = get_origin_id_v4(
            reply_dst,
            tcp_packet.source_port,
            tcp_packet.destination_port,
            origin_map,
        )?;

        Some(Reply {
            value: Some(Value::Tcp(TcpResult {
                seq: tcp_packet.seq,
                ack: tcp_packet.ack,
            })),
            ip_result: Some(ip_result),
            rx_time,
            origin_id,
        })
    } else {
        None
    };
}

/// Parse TCPv6 packets (including v6 headers) into a Reply result.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// # Returns
///
/// * `Option<Reply>` - the received TCP reply
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a TCP header.
fn parse_tcpv6(packet_bytes: &[u8], origin_map: &Vec<Origin>) -> Option<Reply> {
    // TCPv6 64 length (IPv6 header (40) + TCP header (20)) + check for RST flag
    if (packet_bytes.len() < 60) || ((packet_bytes[53] & 0x04) == 0) {
        return None;
    }
    let (ip_result, payload, reply_dst, _reply_src) = parse_ipv6(packet_bytes)?;
    // cannot filter out spoofed packets as the probe_dst is unknown

    return if let PacketPayload::TCP { value: tcp_packet } = payload {
        if !((tcp_packet.flags == 0b00000100) | (tcp_packet.flags == 0b00010100)) {
            // We assume all packets with RST or RST+ACK flags are replies
            return None;
        }

        let rx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let origin_id = get_origin_id_v6(
            reply_dst,
            tcp_packet.source_port,
            tcp_packet.destination_port,
            origin_map,
        )?;

        Some(Reply {
            value: Some(Value::Tcp(TcpResult {
                seq: tcp_packet.seq,
                ack: tcp_packet.ack,
            })),
            ip_result: Some(ip_result),
            rx_time,
            origin_id,
        })
    } else {
        None
    };
}

fn get_origin_id_v4(
    reply_dst: u32,
    reply_sport: u16,
    reply_dport: u16,
    origin_map: &Vec<Origin>,
) -> Option<u32> {
    for origin in origin_map {
        if origin.src.unwrap().get_v4() == reply_dst
            && origin.sport == reply_sport.into()
            && origin.dport == reply_dport.into()
        {
            return Some(origin.origin_id);
        } else if origin.src.unwrap().get_v4() == reply_dst
            && 0 == reply_sport.into()
            && 0 == reply_dport.into()
        {
            // ICMP replies have no port numbers
            return Some(origin.origin_id);
        }
    }
    return None;
}

fn get_origin_id_v6(
    reply_dst: u128,
    reply_sport: u16,
    reply_dport: u16,
    origin_map: &Vec<Origin>,
) -> Option<u32> {
    for origin in origin_map {
        if origin.src.unwrap().get_v6() == reply_dst
            && origin.sport == reply_sport.into()
            && origin.dport == reply_dport.into()
        {
            return Some(origin.origin_id);
        } else if origin.src.unwrap().get_v6() == reply_dst
            && 0 == reply_sport.into()
            && 0 == reply_dport.into()
        {
            // ICMP replies have no port numbers
            return Some(origin.origin_id);
        }
    }
    return None;
}
