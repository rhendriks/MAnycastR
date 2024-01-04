use std::net::{Shutdown};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use socket2::{Socket};
use tokio::sync::mpsc::{UnboundedSender, Receiver};
use crate::custom_module;
use custom_module::verfploeter::{
    Address, ip_result, IPv4Result, IPv6Result, IpResult, PingPayload, PingResult, TaskResult,
    TcpResult, UdpPayload, UdpResult, verfploeter_result::Value, VerfploeterResult,
    address::Value::V4, address::Value::V6, IPv6, DnsChaos, DnsARecord, ip_result::Value::Ipv4 as ip_IPv4, ip_result::Value::Ipv6 as ip_IPv6,
};
use crate::net::{DNSAnswer, DNSRecord, ICMPPacket, IPv4Packet, PacketPayload, TXTRecord};
use crate::net::netv6::IPv6Packet;
use pcap::{Active, Capture, Device};


/// Listen for incoming ping/ICMP packets, these packets must have our payload to be considered valid replies.
///
/// Creates two threads, one that listens on the socket and another that forwards results to the server and shuts down the receiving socket when appropriate.
///
/// For a received packet to be considered a reply, it must be an ICMP packet with the current task ID in the first 4 bytes of the ICMP payload.
/// From these replies it creates task results that are put in a result queue, which get sent to the server.
///
/// # Arguments
///
/// * 'metadata' - contains the metadata of this listening client (the hostname and client ID)
///
/// * 'socket' - the socket to listen on
///
/// * 'tx' - sender to put task results in
///
/// * 'rx_f' - channel that is used to signal the end of the measurement
///
/// * 'task_id' - the task_id of the current measurement
///
/// * 'client_id' - the unique client ID of this client
pub fn listen_ping(tx: UnboundedSender<TaskResult>, rx_f: Receiver<()>, task_id: u32, client_id: u8, v6: bool, filter: String) {
    println!("[Client inbound] Started ICMP listener with filter {}", filter);
    // Result queue to store incoming pings, and take them out when sending the TaskResults to the server
    let rq = Arc::new(Mutex::new(Some(Vec::new())));
    // Exit flag for pcap listener
    let exit_flag = Arc::new(Mutex::new(false));

    thread::spawn({
        let rq_receiver = rq.clone();
        let exit_flag = Arc::clone(&exit_flag);

        move || {
            println!("[Client inbound] Listening for ICMP packets for task - {}", task_id);
            let mut cap = get_pcap(filter);

            // Listen for incoming ICMP packets
            loop {
                let packet = match cap.next_packet() {
                    Ok(packet) => packet,
                    Err(e) => {
                        println!("Failed to get next packet: {}", e);
                        continue
                    },
                };
                // TODO next_packet will drop packets when the buffer is full
                // TODO figure out how to avoid receiving the ethernet header in the buffer
                // Convert the bytes into an ICMP packet (first 13 bytes are the eth header, which we skip)
                let result = if v6 {
                    parse_icmpv6(&packet.data[14..], task_id)
                } else {
                    parse_icmpv4(&packet.data[14..], task_id)
                };

                // Invalid ICMP packets have value None
                if result == None {
                    // Check the exit flag
                    if *exit_flag.lock().unwrap() { // TODO improve, currently we wait for a random packet to arrive before we check the exit flag
                        break
                    } else {
                        continue
                    }
                }

                // Put result in transmission queue
                {
                    let mut rq_opt = rq_receiver.lock().unwrap();
                    if let Some(ref mut x) = *rq_opt {
                        x.push(result.unwrap())
                    }
                }
            }

            let stats = cap.stats().expect("Failed to get pcap stats");
            println!("[Client inbound] Stopped ICMP pcap listener (received {} packets, dropped {} packets, if_dropped {} packets)", stats.received, stats.dropped, stats.if_dropped);
        }
    });

    // Thread for sending the received replies to the server as TaskResult
    thread::spawn({
        let result_queue_sender = rq.clone();
        move || {
            handle_results(&tx, rx_f, task_id, client_id, result_queue_sender);

            // Close the pcap listener
            *exit_flag.lock().unwrap() = true;

            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).expect("Failed to send 'finished' signal to server");
            println!("[Client inbound] Stopped listening for ICMP packets");
        }
    });
}

/// Listen for incoming UDP DNS packets,
/// these packets must have a DNS A record reply and use the correct port numbers to be considered a reply.
///
/// Additionally listens for ICMP port unreachable packets, and will parse the request if it is contained in the ICMP payload.
///
/// Creates three threads, two that listen on the sockets and another that forwards results to the server and shuts down the receiving socket when appropriate.
///
/// For a received UDP packet to be considered a reply, it must be an UDP DNS packet that contains an A record that follows a specific format.
/// From these replies it creates task results that are put in a result queue, which get sent to the server.
///
/// # Arguments
///
/// * 'metadata' - contains the metadata of this listening client (the hostname)
///
/// * 'socket' - the socket to listen on
///
/// * 'tx' - sender to put task results in
///
/// * 'rx_f' - channel that is used to signal the end of the measurement
///
/// * 'task_id' - the task_id of the current measurement
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'sender_src_port' - the source port used in the probes (destination port of received reply must match this value)
///
/// * 'socket_icmp' - an additional socket to listen for ICMP port unreachable responses
pub fn listen_udp(tx: UnboundedSender<TaskResult>, rx_f: Receiver<()>, task_id: u32, client_id: u8, socket_icmp: Arc<Socket>, v6: bool, task_type: u32, filter: String) {
    println!("[Client inbound] Started UDP listener with filter {}", filter);

    // Queue to store incoming UDP packets, and take them out when sending the TaskResults to the server
    let result_queue = Arc::new(Mutex::new(Some(Vec::new())));
    // Exit flag for pcap listener
    let exit_flag = Arc::new(Mutex::new(false));

    thread::spawn({
        let rq_receiver = result_queue.clone();
        let exit_flag = Arc::clone(&exit_flag);

        move || {
            println!("[Client inbound] Listening for UDP packets for task - {}", task_id);

            let mut cap = get_pcap(filter);

            loop {
                let packet = match cap.next_packet() {
                    Ok(packet) => packet,
                    Err(e) => {
                        println!("Failed to get next packet: {}", e);
                        continue
                    },
                };

                let result = if v6 {
                    parse_udpv6(&packet.data[14..], task_type)
                } else {
                    parse_udpv4(&packet.data[14..], task_type)
                };

                // Invalid UDP packets have value None
                if result == None {
                    // Check the exit flag
                    if *exit_flag.lock().unwrap() {
                        break
                    } else {
                        continue
                    }
                }

                // Put result in transmission queue
                {
                    let mut rq_opt = rq_receiver.lock().unwrap();
                    if let Some(ref mut x) = *rq_opt {
                        x.push(result.unwrap());
                    }
                }
            }

            let stats = cap.stats().expect("Failed to get pcap stats");
            println!("[Client inbound] Stopped UDP pcap listener (received {} packets, dropped {} packets, if_dropped {} packets)", stats.received, stats.dropped, stats.if_dropped);
        }
    });

    // ICMP port unreachable listening thread (only for A record DNS replies)
    if task_type == 2 { // TODO remove this socket and use the pcap listener instead
        thread::spawn({
            let rq_receiver = result_queue.clone();
            let socket_icmp = socket_icmp.clone();

            move || {
                let mut buffer: Vec<u8> = vec![0; 1500];
                println!("[Client inbound] Listening for ICMP packets for UDP task - {}", task_id);

                while let Ok(result) = socket_icmp.recv(&mut buffer) {
                    if result == 0 { break } // Received when the socket closes on some OS

                    // 1. Parse IP header
                    // Parse IP header
                    let (ip_result, payload) = if v6 { // TODO update to first parse the ipv6 header (when we fix the socket to receive full ipv6 packets)
                        let ip_result = None;
                        let payload = PacketPayload::ICMP {
                            value: ICMPPacket::from(&buffer[..result]),
                        };
                        (ip_result, payload)
                    } else { // v4
                        match parse_ipv4(&buffer[..result]) {
                            None => continue, // Unable to parse IPv4 header
                            Some((ip_result, payload)) => (Some(ip_result), payload),
                        }
                    };


                    // 2. Parse ICMP header
                    if let PacketPayload::ICMP { value: icmp_packet } = payload {
                        // Make sure that this packet belongs to this task (if not we discard and continue)
                        if !v6 & (icmp_packet.icmp_type != 3) { // Code 3 (v4) => destination unreachable
                            continue;
                        } else if v6 & (icmp_packet.icmp_type != 1) { // Code 1 (v6) => destination unreachable
                            continue;
                        }
                        let code = icmp_packet.code as u32;
                        // Initialize variables
                        let mut sender_src;
                        let mut sender_dest;
                        let mut sender_src_port: u32 = 0;
                        let result;
                        let mut sender_client_id = 0 as u32;
                        let mut transmit_time = 0;
                        let receive_time = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64;

                        // 3. Parse ICMP body
                        // 3.1 IP header
                        let (_, ip_payload_probe) = if v6 {
                            // Get the ipv6 header from the probe out of the ICMP body
                            let ipv6_header = parse_ipv6(icmp_packet.body.as_slice());

                            // If we are unable to retrieve an IP header out of the ICMP payload
                            if ipv6_header.is_none() {
                                // Create a VerfploeterResult for the received ping reply
                                result = Some(VerfploeterResult {
                                    value: Some(Value::Udp(UdpResult {
                                        receive_time,
                                        source_port: 0,
                                        destination_port: 0,
                                        code,
                                        ip_result,
                                        payload: None,
                                    })),
                                });

                                // Put result in transmission queue
                                {
                                    let mut rq_opt = rq_receiver.lock().unwrap();
                                    if let Some(ref mut x) = *rq_opt {
                                        x.push(result.unwrap());
                                    }
                                }
                                continue; // We are finished
                            }
                            let (ip_result_probe, ip_payload_probe) = ipv6_header.unwrap();

                            sender_src = match ip_result_probe.value.clone().unwrap() { // TODO save full u128 for ip_resultv6
                                ip_IPv4(_) => panic!("IPv4 header in ICMPv6 packet"),
                                ip_IPv6(ipv6) => (ipv6.source_address.unwrap().p2 & 0xFFFFFFFF) as u32,
                            };

                            sender_dest = match ip_result_probe.value.clone().unwrap() { // TODO save full u128 for ip_resultv6
                                ip_IPv4(_) => panic!("IPv4 header in ICMPv6 packet"),
                                ip_IPv6(ipv6) => (ipv6.destination_address.unwrap().p2 & 0xFFFFFFFF) as u32,
                            };


                            (ip_result_probe, ip_payload_probe)
                        } else {
                            // Get the ipv4 header from the probe out of the ICMP body
                            let ipv4_header = parse_ipv4(icmp_packet.body.as_slice());

                            // If we are unable to retrieve an IP header out of the ICMP payload
                            if ipv4_header.is_none() {
                                // Create a VerfploeterResult for the received ping reply
                                result = Some(VerfploeterResult {
                                    value: Some(Value::Udp(UdpResult {
                                        receive_time,
                                        source_port: 0,
                                        destination_port: 0,
                                        code,
                                        ip_result,
                                        payload: None,
                                    })),
                                });

                                // Put result in transmission queue
                                {
                                    let mut rq_opt = rq_receiver.lock().unwrap();
                                    if let Some(ref mut x) = *rq_opt {
                                        x.push(result.unwrap());
                                    }
                                }
                                continue; // We are finished
                            }
                            let (ip_result_probe, ip_payload_probe) = ipv4_header.unwrap();

                            sender_src = match ip_result_probe.value.clone().unwrap() {
                                ip_IPv4(ipv4) => ipv4.source_address,
                                ip_IPv6(_) => panic!("IPv6 header in ICMPv4 packet"),
                            };

                            sender_dest = match ip_result_probe.value.clone().unwrap() {
                                ip_IPv4(ipv4) => ipv4.destination_address,
                                ip_IPv6(_) => panic!("IPv6 header in ICMPv4 packet"),
                            };

                            (ip_result_probe, ip_payload_probe)
                        };

                        // 3.2 UDP header
                        if let PacketPayload::UDP { value: udp_header } = ip_payload_probe {
                            sender_src_port = udp_header.source_port as u32;

                            // 3.3 DNS header
                            if udp_header.body.len() >= 60 { // Rough minimum size for DNS A packet with our domain
                                let dns_record = DNSRecord::from(udp_header.body.as_slice()); // TODO failed to fill whole buffer
                                sender_client_id = ((dns_record.transaction_id >> 8) & 0xFF) as u32;
                                // 3.4 DNS body
                                let parts: Vec<&str> = dns_record.domain.split('.').next().expect("DNS answer did not contain dots").split('-').collect();
                                // Our domains have 5 'parts' separated by 4 dashes
                                if parts.len() == 5 {
                                    transmit_time = match parts[0].parse::<u64>() {
                                        Ok(t) => t,
                                        Err(_) => continue,
                                    };
                                    sender_src = match parts[1].parse::<u32>() {
                                        Ok(s) => s,
                                        Err(_) => continue,
                                    };
                                    sender_dest = match parts[2].parse::<u32>() {
                                        Ok(s) => s,
                                        Err(_) => continue,
                                    };
                                    sender_client_id = match parts[3].parse::<u8>() {
                                        Ok(s) => s,
                                        Err(_) => continue,
                                    } as u32;
                                    sender_src_port = match parts[4].parse::<u16>() {
                                        Ok(s) => s,
                                        Err(_) => continue,
                                    } as u32;
                                }
                            }
                        }

                        // Create a VerfploeterResult for the received ping reply
                        result = Some(VerfploeterResult {
                            value: Some(Value::Udp(UdpResult {
                                receive_time,
                                source_port: 0, // ICMP replies have no port numbers
                                destination_port: 0,
                                code,
                                ip_result,
                                payload: Some(UdpPayload {
                                    value: Some(custom_module::verfploeter::udp_payload::Value::DnsARecord(DnsARecord {
                                        transmit_time,
                                        source_address: Some(Address {
                                            value: Some(V4(sender_src)),
                                        }),
                                        destination_address: Some(Address {
                                            value: Some(V4(sender_dest)),
                                        }),
                                        sender_client_id,
                                        source_port: sender_src_port,
                                    })),
                                }),
                            })),
                        });

                        // Put result in transmission queue
                        {
                            let mut rq_opt = rq_receiver.lock().unwrap();
                            if let Some(ref mut x) = *rq_opt {
                                x.push(result.unwrap());
                            }
                        }
                    } else {
                        continue; // Not an ICMPv4 packet
                    };
                }
                println!("[Client inbound] Stopped listening on ICMP socket for the UDP task");
            }
        });
    }

    // Thread for sending the received replies to the server as TaskResult
    thread::spawn({
        let result_queue_sender = result_queue.clone();

        move || {
            handle_results(&tx, rx_f, task_id, client_id, result_queue_sender);

            // Close the pcap listener
            *exit_flag.lock().unwrap() = true;

            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).expect("Failed to send 'finished' signal to server");

            match socket_icmp.shutdown(Shutdown::Read) {
                Err(_) => println!("[Client inbound] Shut down ICMP socket erroneously"),
                _ => println!("[Client inbound] Shut down ICMP socket"),
            }
            println!("[Client inbound] Stopped listening for UDP packets");
        }
    });
}

/// Listen for incoming TCP/RST packets, these packets must have the correct destination port,
/// have the right flags set (RST), and have ACK == 0 for it to be considered a reply.
///
/// Creates two threads, one that listens on the socket and another that forwards results to the server and shuts down the receiving socket when appropriate.
///
/// For a received packet to be considered a reply, it must be a TCP packet with the RST flag set and using the correct port numbers.
/// From these replies it creates task results that are put in a result queue, which get sent to the server.
///
/// # Arguments
///
/// * 'metadata' - contains the metadata of this listening client (the hostname)
///
/// * 'socket' - the socket to listen on
///
/// * 'tx' - sender to put task results in
///
/// * 'rx_f' - channel that is used to signal the end of the measurement
///
/// * 'task_id' - the task_id of the current measurement
///
/// * 'client_id' - the unique client ID of this client
pub fn listen_tcp(tx: UnboundedSender<TaskResult>, rx_f: Receiver<()>, task_id: u32, client_id: u8, v6: bool, filter: String) {
    println!("[Client inbound] Started TCP listener with filter {}", filter);
    // Queue to store incoming TCP packets, and take them out when sending the TaskResults to the server
    let result_queue = Arc::new(Mutex::new(Some(Vec::new())));
    // Exit flag for pcap listener
    let exit_flag = Arc::new(Mutex::new(false));

    thread::spawn({
        let result_queue_receiver = result_queue.clone();
        let exit_flag = Arc::clone(&exit_flag);

        move || {
            println!("[Client inbound] Listening for TCP packets for task - {}", task_id);

            let mut cap = get_pcap(filter);

            loop {
                let packet = match cap.next_packet() {
                    Ok(packet) => packet,
                    Err(e) => {
                        println!("Failed to get next packet: {}", e);
                        continue
                    },
                };

                let result = if v6 {
                    parse_tcpv6(&packet.data[14..])
                } else {
                    parse_tcpv4(&packet.data[14..])
                };

                // Invalid TCP packets have value None
                if result == None {
                  // Check the exit flag
                  if *exit_flag.lock().unwrap() {
                      break
                  } else {
                      continue
                  }
                }

                // Put result in transmission queue
                {
                    let mut rq_opt = result_queue_receiver.lock().unwrap();
                    if let Some(ref mut x) = *rq_opt {
                        x.push(result.unwrap());
                    }
                }
            }
            let stats = cap.stats().expect("Failed to get pcap stats");
            println!("[Client inbound] Stopped TCP pcap listener (received {} packets, dropped {} packets, if_dropped {} packets)", stats.received, stats.dropped, stats.if_dropped);
        }
    });

    // Thread for sending the received replies to the server as TaskResult
    thread::spawn({
        let result_queue_sender = result_queue.clone();

        move || {
            handle_results(&tx, rx_f, task_id, client_id, result_queue_sender);

            // Close the pcap listener
            *exit_flag.lock().unwrap() = true;

            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).expect("Failed to send 'finished' signal to server");
            println!("[Client inbound] Stopped listening for TCP packets");
        }
    });
}

/// Thread for handling the received replies, wrapping them in a TaskResult, and streaming them back to the main client class.
///
/// # Arguments
///
/// * 'metadata' - contains the metadata of this listening client (the hostname)
///
/// * 'tx' - sender to put task results in
///
/// * 'rx_f' - channel that is used to signal the end of the measurement
///
/// * 'task_id' - the task_id of the current measurement
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'result_queue_sender' - contains a vector of all received replies as VerfploeterResult
fn handle_results(tx: &UnboundedSender<TaskResult>, mut rx_f: Receiver<()>, task_id: u32, client_id: u8, result_queue_sender: Arc<Mutex<Option<Vec<VerfploeterResult>>>>) {
    loop {
        // Every 5 seconds, forward the ping results to the server
        thread::sleep(Duration::from_secs(5));

        // Get the current result queue, and replace it with an empty one
        let rq;
        {
            let mut rq_mutex = result_queue_sender.lock().unwrap();
            rq = rq_mutex.replace(Vec::new()).unwrap();
        }

        // If we have an empty result queue
        if rq.len() == 0 {
            // Exit the thread if client sends us the signal it's finished
            if let Ok(_) = rx_f.try_recv()  {
                // We are finished
                break;
            }
            continue;
        }

        let tr = TaskResult {
            client_id: client_id as u32,
            result_list: rq,
        };

        // Send the result to the client handler
        tx.send(tr).expect("Failed to send TaskResult to client handler");
    }
}

fn get_pcap(filter: String) -> Capture<Active> {
    // Capture packets with pcap on the main interface TODO try PF_RING and evaluate performance gain (e.g., https://github.com/szymonwieloch/rust-rawsock)
    let main_interface = Device::lookup().expect("Failed to get main interface").unwrap(); // Get the main interface
    let mut cap = Capture::from_device(main_interface).expect("Failed to get capture device")
        .immediate_mode(true)
        // .buffer_size() // TODO set buffer size based on probing rate (default 1,000,000)
        // .snaplen() // TODO set snaplen
        .open().expect("Failed to open capture device");
    cap.direction(pcap::Direction::In).expect("Failed to set pcap direction"); // We only want to receive incoming packets
    cap.filter(&*filter, true).expect("Failed to set pcap filter"); // Set the appropriate filter
    cap
}

// TODO re-evaluate the parse functions -> BPF filter does most of the work already

/// Parse packet bytes into an IPv4 header, returns the IP result for this header and the payload.
fn parse_ipv4(packet_bytes: &[u8]) -> Option<(IpResult, PacketPayload)> {
    // IPv4 20 minimum
    if packet_bytes.len() < 20 { return None }

    // Create IPv4Packet from the bytes in the buffer
    let packet = IPv4Packet::from(packet_bytes);

    // Create a VerfploeterResult for the received ping reply
    return Some((IpResult {
        value: Some(ip_result::Value::Ipv4(IPv4Result {
            source_address: u32::from(packet.source_address),
            destination_address: u32::from(packet.destination_address),
        })),
        ttl: packet.ttl as u32,
    }, packet.payload));
}

/// Parse packet bytes into an IPv6 header, returns the IP result for this header and the payload.
fn parse_ipv6(packet_bytes: &[u8]) -> Option<(IpResult, PacketPayload)> {
    // IPv6 40 minimum
    if packet_bytes.len() < 40 { return None }

    // Create IPv6Packet from the bytes in the buffer
    let packet = IPv6Packet::from(packet_bytes);

    // Create a VerfploeterResult for the received ping reply
    return Some((IpResult {
        value: Some(ip_result::Value::Ipv6(IPv6Result {
            source_address: Some(IPv6 {
                p1: (u128::from(packet.source_address) >> 64) as u64,
                p2: u128::from(packet.source_address) as u64,
            }),
            destination_address: Some(IPv6 {
                p1: (u128::from(packet.destination_address) >> 64) as u64,
                p2: u128::from(packet.destination_address) as u64,
            }),
        })),
        ttl: packet.hop_limit as u32,
    }, packet.payload));
}

fn parse_icmpv4(packet_bytes: &[u8], task_id: u32) -> Option<VerfploeterResult> {
    let (ip_result, payload) = match parse_ipv4(packet_bytes) {
        Some((ip_result, payload)) => (ip_result, payload),
        None => return None,
    };
    // Obtain the payload
    if let PacketPayload::ICMP { value: icmp_packet } = payload {
        if *&icmp_packet.body.len() < 4 { return None }

        let s = if let Ok(s) = *&icmp_packet.body[0..4].try_into() { s } else { return None };
        let pkt_task_id = u32::from_be_bytes(s);

        // Make sure that this packet belongs to this task
        if (pkt_task_id != task_id) | (icmp_packet.body.len() < 24) {
            // If not, we discard it and await the next packet
            return None;
        }

        let transmit_time = u64::from_be_bytes(*&icmp_packet.body[4..12].try_into().unwrap());
        let sender_client_id = u32::from_be_bytes(*&icmp_packet.body[12..16].try_into().unwrap());
        let source_address = u32::from_be_bytes(*&icmp_packet.body[16..20].try_into().unwrap());
        let destination_address = u32::from_be_bytes(*&icmp_packet.body[20..24].try_into().unwrap());

        let receive_time = SystemTime::now() // TODO can get receive time from the pcap packet header
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Create a VerfploeterResult for the received ping reply
        return Some(VerfploeterResult {
            value: Some(Value::Ping(PingResult {
                receive_time,
                ip_result: Some(ip_result),
                payload: Some(PingPayload {
                    transmit_time,
                    source_address: Some(Address {
                        value: Some(V4(source_address)),
                    }),
                    destination_address: Some(Address {
                    value: Some(V4(destination_address)),
                }),
                    sender_client_id,
                }),
            })),
        });
    } else {
        return None
    }
}

fn parse_icmpv6(packet_bytes: &[u8], task_id: u32) -> Option<VerfploeterResult> {
    let (ip_result, payload) = match parse_ipv6(packet_bytes) {
        Some((ip_result, payload)) => (ip_result, payload),
        None => return None,
    };

    // Obtain the payload
    if let PacketPayload::ICMP { value } = payload {
        // let value = packet;
        if *&value.body.len() < 4 { return None }

        let s = if let Ok(s) = *&value.body[0..4].try_into() { s } else { return None };

        let pkt_task_id = u32::from_be_bytes(s);

        // Make sure that this packet belongs to this task
        if (pkt_task_id != task_id) | (value.body.len() < 48) {
            // If not, we discard it and await the next packet
            return None;
        }

        let transmit_time = u64::from_be_bytes(*&value.body[4..12].try_into().unwrap());
        let sender_client_id = u32::from_be_bytes(*&value.body[12..16].try_into().unwrap());
        let source_address = u128::from_be_bytes(*&value.body[16..32].try_into().unwrap());
        let destination_address = u128::from_be_bytes(*&value.body[32..48].try_into().unwrap());

        let receive_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Create a VerfploeterResult for the received ping reply
        return Some(VerfploeterResult {
            value: Some(Value::Ping(PingResult {
                receive_time,
                ip_result: Some(ip_result),
                payload: Some(PingPayload {
                    transmit_time,
                    source_address: Some(Address {
                        value: Some(V6(IPv6 {
                            p1: (source_address >> 64) as u64,
                            p2: source_address as u64,
                        })),
                    }),
                    destination_address: Some(Address {
                        value: Some(V6(IPv6 {
                            p1: (destination_address >> 64) as u64,
                            p2: destination_address as u64,
                        })),
                    }),
                    sender_client_id,
                }),
            })),
        });
    } else {
        return None
    }
}

fn parse_udpv4(packet_bytes: &[u8], task_type: u32) -> Option<VerfploeterResult> {
    let (ip_result, payload) = match parse_ipv4(packet_bytes) {
        Some((ip_result, payload)) => (ip_result, payload),
        None => return None,
    };

    // Obtain the payload
    if let PacketPayload::UDP { value: udp_packet } = payload {
        // The UDP responses will be from DNS services, with src port 53 and our possible src ports as dest port, furthermore the body length has to be large enough to contain a DNS A reply
        if (task_type == 2) & ((udp_packet.source_port != 53) | (udp_packet.destination_port < 61440) | (udp_packet.body.len() < 66)) {
            return None
        } else if (task_type == 4) & ((udp_packet.source_port != 53) | (udp_packet.destination_port < 61440) | (udp_packet.body.len() < 10)) {
            return None
        }

        let receive_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let payload = if task_type == 2 {
            parse_dns_a_record(udp_packet.body.as_slice(), false)
        } else if task_type == 4 {
            parse_chaos(udp_packet.body.as_slice())
        } else {
            None
        };

        // Create a VerfploeterResult for the received UDP reply
        return Some(VerfploeterResult {
            value: Some(Value::Udp(UdpResult {
                receive_time,
                source_port: udp_packet.source_port as u32,
                destination_port: udp_packet.destination_port as u32,
                code: 16,
                ip_result: Some(ip_result),
                payload,
            })),
        });
    } else {
        return None
    }
}

fn parse_udpv6(packet_bytes: &[u8], task_type: u32) -> Option<VerfploeterResult> {
    let (ip_result, payload) = match parse_ipv6(packet_bytes) {
        Some((ip_result, payload)) => (ip_result, payload),
        None => return None,
    };

    // Obtain the payload
    if let PacketPayload::UDP { value } = payload {
        // The UDP responses will be from DNS services, with src port 53 and our possible src ports as dest port, furthermore the body length has to be large enough to contain a DNS A reply
        if (task_type == 2) & ((value.source_port != 53) | (value.destination_port < 61440) | (value.body.len() < 66)) {
            return None
        } else if (task_type == 4) & ((value.source_port != 53) | (value.destination_port < 61440) | (value.body.len() < 10)) {
            return None
        }

        let receive_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let payload = if task_type == 2 {
            parse_dns_a_record(value.body.as_slice(), true)
        } else if task_type == 4 {
            parse_chaos(value.body.as_slice())
        } else {
            None
        };

        // Create a VerfploeterResult for the received UDP reply
        return Some(VerfploeterResult {
            value: Some(Value::Udp(UdpResult {
                receive_time,
                source_port: value.source_port as u32,
                destination_port: value.destination_port as u32,
                code: 16,
                ip_result: Some(ip_result),
                payload,
            })),
        });
    } else {
        return None
    }
}

/// Attempts to parse the DNS A record from a UDP payload body.
fn parse_dns_a_record(packet_bytes: &[u8], ipv6: bool) -> Option<UdpPayload> {
    let record = DNSRecord::from(packet_bytes);
    let domain = record.domain; // example: '1679305276037913215.3226971181.16843009.0.4000.any.dnsjedi.org' // TODO will requesting such domains cause issues?
    // Get the information from the domain, continue to the next packet if it does not follow the format
    if ipv6 {
        let parts: Vec<&str> = domain.split('.').collect();
        // Our domains have 8 'parts' separated by 7 dots
        if parts.len() != 8 { return None }

        let transmit_time = match parts[0].parse::<u64>() {
            Ok(t) => t,
            Err(_) => return None,
        };
        let sender_src = match parts[1].parse::<u128>() {
            Ok(s) => s,
            Err(_) => return None,
        };
        let sender_dest = match parts[2].parse::<u128>() {
            Ok(s) => s,
            Err(_) => return None,
        };
        let sender_client_id = match parts[3].parse::<u8>() {
            Ok(s) => s,
            Err(_) => return None,
        };
        let sender_src_port = match parts[4].parse::<u16>() {
            Ok(s) => s,
            Err(_) => return None,
        };

        return Some(UdpPayload {
            value: Some(custom_module::verfploeter::udp_payload::Value::DnsARecord(DnsARecord {
                transmit_time,
                source_address: Some(Address {
                    value: Some(V6(IPv6 {
                        p1: (sender_src >> 64) as u64,
                        p2: sender_src as u64,
                    })),
                }),
                destination_address: Some(Address {
                    value: Some(V6(IPv6 {
                        p1: (sender_dest >> 64) as u64,
                        p2: sender_dest as u64,
                    })),
                }),
                sender_client_id: sender_client_id as u32,
                source_port: sender_src_port as u32,
            })),
        });
    } else {
        let parts: Vec<&str> = domain.split('.').next().unwrap().split('-').collect();
        // Our domains have 5 'parts' separated by 4 dashes
        if parts.len() != 5 { return None }

        let transmit_time = match parts[0].parse::<u64>() {
            Ok(t) => t,
            Err(_) => return None,
        };
        let sender_src = match parts[1].parse::<u32>() {
            Ok(s) => s,
            Err(_) => return None,
        };
        let sender_dest = match parts[2].parse::<u32>() {
            Ok(s) => s,
            Err(_) => return None,
        };
        let sender_client_id = match parts[3].parse::<u8>() {
            Ok(s) => s,
            Err(_) => return None,
        };
        let sender_src_port = match parts[4].parse::<u16>() {
            Ok(s) => s,
            Err(_) => return None,
        };

        return Some(UdpPayload {
            value: Some(custom_module::verfploeter::udp_payload::Value::DnsARecord(DnsARecord {
                transmit_time,
                source_address: Some(Address {
                    value: Some(V4(sender_src)),
                }),
                destination_address: Some(Address {
                    value: Some(V4(sender_dest)),
                }),
                sender_client_id: sender_client_id as u32,
                source_port: sender_src_port as u32,
            })),
        });
    }
}

fn parse_chaos(packet_bytes: &[u8]) -> Option<UdpPayload> {
    let record = DNSRecord::from(packet_bytes);

    // 8 right most bits are the client_id
    let sender_client_id = ((record.transaction_id >> 8) & 0xFF) as u32;

    if record.answer == 0 {
        return Some(UdpPayload {
            value: Some(custom_module::verfploeter::udp_payload::Value::DnsChaos(DnsChaos {
                sender_client_id,
                chaos_data: "Not implemented".to_string(),
            })),
        });
    }

    let dns_answer = DNSAnswer::from(record.body.as_slice());
    let txt = TXTRecord::from(dns_answer.data.as_slice());
    let chaos_data = txt.txt;

    return Some(UdpPayload {
        value: Some(custom_module::verfploeter::udp_payload::Value::DnsChaos(DnsChaos {
            sender_client_id,
            chaos_data,
        })),
    });
}

fn parse_tcp(ip_payload: PacketPayload, ip_result: IpResult) -> Option<VerfploeterResult> {
    // Obtain the payload
    if let PacketPayload::TCP { value: tcp_packet } = ip_payload {
        // Responses to our probes have destination port > 4000 (as we use these as source)
        // Use the RST flag, and have ACK 0
        // TODO may want to ignore the ACK value due to: https://dl.acm.org/doi/pdf/10.1145/3517745.3561461
        if (tcp_packet.destination_port < 61440) | (tcp_packet.flags != 0b00000100) { // TODO make this statement more specific to filter out non-measurement related packets (maybe look at payload?)
            return None
        }

        let receive_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        return Some(VerfploeterResult {
            value: Some(Value::Tcp(TcpResult {
                source_port: u32::from(tcp_packet.source_port),
                destination_port: tcp_packet.destination_port as u32,
                seq: tcp_packet.seq,
                ip_result: Some(ip_result),
                receive_time,
                ack: tcp_packet.ack,
            })),
        })
    } else {
        return None
    }
}


fn parse_tcpv4(packet_bytes: &[u8]) -> Option<VerfploeterResult> {
    let (ip_result, payload) = match parse_ipv4(packet_bytes) {
        Some((ip_result, payload)) => (ip_result, payload),
        None => return None,
    };
    return parse_tcp(payload, ip_result);
}

fn parse_tcpv6(packet_bytes: &[u8]) -> Option<VerfploeterResult> {
    let (ip_result, payload) = match parse_ipv6(packet_bytes) {
        Some((ip_result, payload)) => (ip_result, payload),
        None => return None,
    };

    return parse_tcp(payload, ip_result);
}
