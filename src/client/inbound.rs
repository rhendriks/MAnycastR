use std::net::{Shutdown};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use socket2::{Socket};
use tokio::sync::mpsc::{UnboundedSender, Receiver};
use crate::custom_module;
use custom_module::verfploeter::{
    Address, ip_result, Client, IPv4Result, IPv6Result, IpResult, Metadata, PingPayload, PingResult, TaskResult,
    TcpResult, UdpPayload, UdpResult, verfploeter_result::Value, VerfploeterResult,
    address::Value::V4, address::Value::V6, IPv6
};
use crate::net::{DNSRequest, ICMPPacket, IPv4Packet, PacketPayload, TCPPacket, UDPPacket};


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
pub fn listen_ping(metadata: Metadata, socket: Arc<Socket>, tx: UnboundedSender<TaskResult>, rx_f: Receiver<()>, task_id: u32, client_id: u8, v6: bool) {
    println!("[Client inbound] Started ICMP listener");
    // Result queue to store incoming pings, and take them out when sending the TaskResults to the server
    let rq = Arc::new(Mutex::new(Some(Vec::new())));

    thread::spawn({
        let rq_receiver = rq.clone();

        let socket = socket.clone();
        move || {
            let mut buffer: Vec<u8> = vec![0; 1500];
            println!("[Client inbound] Listening for ICMP packets for task - {}", task_id);
            // https://web.stanford.edu/class/cs242/materials/assignments/rust_doc/libc/constant.IPV6_RECVRTHDR.html
            // https://docs.rs/socket2/latest/socket2/struct.Socket.html
            //https://www.ibm.com/docs/en/zos/2.3.0?topic=soadsiiil-options-that-provide-information-about-packets-that-have-been-received

            while let Ok(p_size) = socket.recv_with_flags(&mut buffer, 56) {
                // Received when the socket closes on some OS
                if p_size == 0 { break }

                let result = if v6 {
                    parse_icmpv6(&buffer[..p_size], task_id)
                } else {
                    parse_icmpv4(&buffer[..p_size], task_id)
                };

                // Invalid ICMP packets have value None
                if result == None { continue }

                // Put result in transmission queue
                {
                    println!("[Client inbound] Received ICMP packet");
                    let mut rq_opt = rq_receiver.lock().unwrap();
                    if let Some(ref mut x) = *rq_opt {
                        x.push(result.unwrap())
                    }
                }
            }
            println!("[Client inbound] Stopped listening on socket");
        }
    });

    // Thread for sending the received replies to the server as TaskResult
    thread::spawn({
        let result_queue_sender = rq.clone();
        move || {
            handle_results(metadata, &tx, rx_f, task_id, client_id, result_queue_sender);

            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).unwrap();
            match socket.shutdown(Shutdown::Read) {
                Err(_) => println!("[Client inbound] Shut down socket erroneously"),
                _ => println!("[Client inbound] Shut down socket"),
            }
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
pub fn listen_udp(metadata: Metadata, socket: Arc<Socket>, tx: UnboundedSender<TaskResult>, rx_f: Receiver<()>, task_id: u32, client_id: u8, socket_icmp: Arc<Socket>, v6: bool, task_type: u32) {
    println!("[Client inbound] Started UDP listener");

    // TODO task type

    // Queue to store incoming UDP packets, and take them out when sending the TaskResults to the server
    let result_queue = Arc::new(Mutex::new(Some(Vec::new())));

    thread::spawn({
        let rq_receiver = result_queue.clone();

        let socket = socket.clone();
        move || {
            let mut buffer: Vec<u8> = vec![0; 1500];
            println!("[Client inbound] Listening for UDP packets for task - {}", task_id);
            while let Ok(p_size) = socket.recv(&mut buffer) {
                println!("{:?}", p_size);
                // Received when the socket closes on some OS
                if p_size == 0 { break }

                let result = if v6 {
                    parse_udpv6(&buffer[..p_size])
                } else {
                    parse_udpv4(&buffer[..p_size])
                };

                // Invalid UDP packets have value None
                if result == None { continue }

                // Put result in transmission queue
                {
                    let mut rq_opt = rq_receiver.lock().unwrap();
                    if let Some(ref mut x) = *rq_opt {
                        x.push(result.unwrap());
                    }
                }
            }
            println!("[Client inbound] Stopped listening on socket");
        }
    });

    // ICMP port unreachable listening thread
    thread::spawn({
        let rq_receiver = result_queue.clone();
        let socket_icmp = socket_icmp.clone();

        move || {
            let mut buffer: Vec<u8> = vec![0; 1500];
            println!("[Client inbound] Listening for ICMP packets for UDP task - {}", task_id);
            // TODO ICMPv6 packets for udpv6
            while let Ok(result) = socket_icmp.recv(&mut buffer) {

                // Received when the socket closes on some OS
                if result == 0 { break }

                // IPv4 20 + ICMP ECHO 8 minimum
                if result < 28 { continue }

                // Create IPv4Packet from the bytes in the buffer
                let packet = IPv4Packet::from(&buffer[..result]);

                // Obtain the payload
                if let PacketPayload::ICMP { value } = packet.payload {
                    // Make sure that this packet belongs to this task
                    if value.icmp_type != 3 { // Code 3 => destination unreachable
                        // If not, we discard it and await the next packet
                        continue;
                    }

                    let mut transmit_time = 0;
                    let mut sender_src = 0;
                    let mut sender_dest = 0;
                    let mut sender_client_id = 0;
                    let mut sender_src_port = 0;
                    let code = value.code;

                    let receive_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64;

                    // Some hosts will ICMP reply with port unreachable that contain the original DNS request
                    if value.body.len() >= 20 { // IPv4 header is 20 bytes
                        let packet_icmp = IPv4Packet::from(&*value.body);

                        if value.body.len() >= 28 { // UDP is an additional 8 bytes
                            if let PacketPayload::UDP { value } = packet_icmp.payload {
                                // Obtain the DNS A record, including the domain name, from the UDP packet

                                // IP, UDP, DNS => 66 or more
                                if value.body.len() >= 66 {
                                    let record = DNSRequest::from(value.body.as_slice());
                                    let domain = record.domain; // example: '1679305276037913215-3226971181-16843009-0-4000.google.com'

                                    // Get the information from the domain, continue to the next packet if it does not follow the format
                                    let parts: Vec<&str> = domain.split('.').next().unwrap().split('-').collect();
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
                                    };
                                    sender_src_port = match parts[4].parse::<u16>() {
                                        Ok(s) => s,
                                        Err(_) => continue,
                                    };
                                } else {
                                    // We received the IP/UDP headers but not the DNS payload
                                    sender_src_port = value.destination_port;
                                    sender_src = u32::from(packet_icmp.source_address);
                                    sender_dest = u32::from(packet_icmp.destination_address);
                                }
                            }
                        } else {
                            // We just received the IP header
                            sender_src = u32::from(packet_icmp.source_address);
                            sender_dest = u32::from(packet_icmp.destination_address);
                        }
                    }

                    // Create a VerfploeterResult for the received ping reply
                    let result = VerfploeterResult {
                        value: Some(Value::Udp(UdpResult {
                            receive_time,
                            source_port: 0,
                            destination_port: 0,
                            code: code as u32,
                            ip_result: Some(IpResult {
                                value: Some(ip_result::Value::Ipv4(IPv4Result {
                                    source_address: u32::from(packet.source_address),
                                    destination_address: u32::from(packet.destination_address),
                                })),
                                ttl: packet.ttl as u32,
                            }),
                            payload: Some(UdpPayload {
                                transmit_time,
                                source_address: sender_src,
                                destination_address: sender_dest,
                                sender_client_id: sender_client_id as u32,
                                source_port: sender_src_port as u32,
                            }),
                        })),
                    };

                    // Put result in transmission queue
                    {
                        let mut rq_opt = rq_receiver.lock().unwrap();
                        if let Some(ref mut x) = *rq_opt {
                            x.push(result);
                        }
                    }
                }
            }
            println!("[Client inbound] Stopped listening on ICMP socket for the UDP task");
        }
    });

    // Thread for sending the received replies to the server as TaskResult
    thread::spawn({
        let result_queue_sender = result_queue.clone();

        move || {
            handle_results(metadata, &tx, rx_f, task_id, client_id, result_queue_sender);

            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).unwrap();
            match socket.shutdown(Shutdown::Read) {
                Err(_) => println!("[Client inbound] Shut down socket erroneously"),
                _ => println!("[Client inbound] Shut down socket"),
            }
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
pub fn listen_tcp(metadata: Metadata, socket: Arc<Socket>, tx: UnboundedSender<TaskResult>, rx_f: Receiver<()>, task_id: u32, client_id: u8, v6: bool) {
    println!("[Client inbound] Started TCP prober");
    // Queue to store incoming TCP packets, and take them out when sending the TaskResults to the server
    let result_queue = Arc::new(Mutex::new(Some(Vec::new())));

    thread::spawn({
        let result_queue_receiver = result_queue.clone();
        let socket = socket.clone();

        move || {
            let mut buffer: Vec<u8> = vec![0; 1500];

            println!("[Client inbound] Listening for TCP packets for task - {}", task_id);
            while let Ok(p_size) = socket.recv(&mut buffer) {
                // Received when the socket closes on some OS
                if p_size == 0 { break }

                let result = if v6 {
                    parse_tcpv6(&buffer[..p_size])
                } else {
                    parse_tcpv4(&buffer[..p_size])
                };

                // Invalid TCP packets have value None
                if result == None { continue }

                // Put result in transmission queue
                {
                    let mut rq_opt = result_queue_receiver.lock().unwrap();
                    if let Some(ref mut x) = *rq_opt {
                        x.push(result.unwrap());
                    }
                }
            }
            println!("[Client inbound] Stopped listening on socket");
        }
    });

    // Thread for sending the received replies to the server as TaskResult
    thread::spawn({
        let result_queue_sender = result_queue.clone();

        move || {
            handle_results(metadata, &tx, rx_f, task_id, client_id, result_queue_sender);
            // Send default value to let the rx know this is finished
            tx.send(TaskResult::default()).unwrap();
            match socket.shutdown(Shutdown::Read) {
                Err(_) => println!("[Client inbound] Shut down socket erroneously"),
                _ => println!("[Client inbound] Shut down socket"),
            }
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
fn handle_results(metadata: Metadata, tx: &UnboundedSender<TaskResult>, mut rx_f: Receiver<()>, task_id: u32, client_id: u8, result_queue_sender: Arc<Mutex<Option<Vec<VerfploeterResult>>>>) {
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
            task_id,
            client: Some(Client {
                client_id: client_id as u32,
                metadata: Some(metadata.clone()),
            }),
            result_list: rq,
        };

        // Send the result to the client handler
        tx.send(tr).unwrap();
    }
}

fn parse_icmpv4(packet_bytes: &[u8], task_id: u32) -> Option<VerfploeterResult> {
    // IPv4 20 + ICMP ECHO 8 minimum
    if packet_bytes.len() < 28 { return None }

    // Create IPv4Packet from the bytes in the buffer
    let packet = IPv4Packet::from(packet_bytes);

    // Obtain the payload
    if let PacketPayload::ICMP { value } = packet.payload {
        if *&value.body.len() < 4 { return None }

        let s = if let Ok(s) = *&value.body[0..4].try_into() { s } else { return None };

        let pkt_task_id = u32::from_be_bytes(s);

        // Make sure that this packet belongs to this task
        if (pkt_task_id != task_id) | (value.body.len() < 24) {
            // If not, we discard it and await the next packet
            return None;
        }

        let transmit_time = u64::from_be_bytes(*&value.body[4..12].try_into().unwrap());
        let sender_client_id = u32::from_be_bytes(*&value.body[12..16].try_into().unwrap());
        let source_address = u32::from_be_bytes(*&value.body[16..20].try_into().unwrap());
        let destination_address = u32::from_be_bytes(*&value.body[20..24].try_into().unwrap());

        let receive_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Create a VerfploeterResult for the received ping reply
        return Some(VerfploeterResult {
            value: Some(Value::Ping(PingResult {
                receive_time,
                ip_result: Some(IpResult {
                    value: Some(ip_result::Value::Ipv4(IPv4Result {
                        source_address: u32::from(packet.source_address),
                        destination_address: u32::from(packet.destination_address),
                    })),
                    ttl: packet.ttl as u32,
                }),
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
    // IPv6 40 + ICMP ECHO 8 minimum
    if packet_bytes.len() < 8 { return None }

    // TODO update for ipv6 header

    // Create IPv6Packet from the bytes in the buffer
    let packet = ICMPPacket::from(packet_bytes);

    // Obtain the payload
    // if let PacketPayload::ICMP { value } = packet.payload {
    let value = packet;
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
            ip_result: Some(IpResult {
                value: Some(ip_result::Value::Ipv6(IPv6Result {
                    source_address: Some(IPv6 {
                        p1: 0,
                        p2: 0,
                    }),
                    destination_address: Some(custom_module::verfploeter::IPv6 {
                        p1: 0,
                        p2: 0,
                    }),
                })),
                ttl: 0,
            }),
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
    // } else {
    //     return None
    // }
}

fn parse_udpv4(packet_bytes: &[u8]) -> Option<VerfploeterResult> {
    // IPv4 20 + UDP 8 minimum
    if packet_bytes.len() < 28 { return None }

    // Create IPv4Packet from the bytes in the buffer
    let packet = IPv4Packet::from(packet_bytes);

    // Obtain the payload
    if let PacketPayload::UDP { value } = packet.payload {
        // The UDP responses will be from DNS services, with src port 53 and our possible src ports as dest port, furthermore the body length has to be large enough to contain a DNS A reply
        if (value.source_port != 53) | (value.destination_port < 62321) | (value.body.len() < 66) {
            return None
        }

        let receive_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let record = DNSRequest::from(value.body.as_slice());
        let domain = record.domain; // example: '1679305276037913215-3226971181-16843009-0-4000.google.com'

        // Get the information from the domain, continue to the next packet if it does not follow the format
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

        // Create a VerfploeterResult for the received UDP reply
        return Some(VerfploeterResult {
            value: Some(Value::Udp(UdpResult {
                receive_time,
                source_port: value.source_port as u32,
                destination_port: value.destination_port as u32,
                code: 16,
                ip_result: Some(IpResult {
                    value: Some(ip_result::Value::Ipv4(IPv4Result {
                        source_address: u32::from(packet.source_address),
                        destination_address: u32::from(packet.destination_address),
                    })),
                    ttl: packet.ttl as u32,
                }),
                payload: Some(UdpPayload {
                    transmit_time,
                    source_address: sender_src,
                    destination_address: sender_dest,
                    sender_client_id: sender_client_id as u32,
                    source_port: sender_src_port as u32,
                }),
            })),
        });
    } else {
        return None
    }
}

fn parse_udpv6(packet_bytes: &[u8]) -> Option<VerfploeterResult> {
    // IPv6 40 + UDP 8 minimum
    if packet_bytes.len() < 8 { return None }

    // Create IPv4Packet from the bytes in the buffer
    // let packet = IPv6Packet::from(packet_bytes);
    // TODO update for ipv6 header

    let value = UDPPacket::from(packet_bytes);
    println!("UDP packet with IP {:?}", value);

    // Obtain the payload
    // if let PacketPayload::UDP { value } = packet.payload {
    // The UDP responses will be from DNS services, with src port 53 and our possible src ports as dest port, furthermore the body length has to be large enough to contain a DNS A reply
    if (value.source_port != 53) | (value.destination_port < 62321) | (value.body.len() < 66) {
        return None
    }

    let receive_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let record = DNSRequest::from(value.body.as_slice());
    let domain = record.domain; // example: '1679305276037913215-3226971181-16843009-0-4000.google.com'

    // Get the information from the domain, continue to the next packet if it does not follow the format
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

    // Create a VerfploeterResult for the received UDP reply
    return Some(VerfploeterResult {
        value: Some(Value::Udp(UdpResult {
            receive_time,
            source_port: value.source_port as u32,
            destination_port: value.destination_port as u32,
            code: 16,
            ip_result: Some(IpResult {
                value: Some(ip_result::Value::Ipv6(IPv6Result {
                    source_address: Some(IPv6 {
                        p1: 0,
                        p2: 0,
                    }),
                    destination_address: Some(custom_module::verfploeter::IPv6 {
                        p1: 0,
                        p2: 0,
                    }),
                })),
                ttl: 0,
            }),
            payload: Some(UdpPayload {
                transmit_time,
                source_address: sender_src,
                destination_address: sender_dest,
                sender_client_id: sender_client_id as u32,
                source_port: sender_src_port as u32,
            }),
        })),
    });
    // } else {
    //     return None
    // }
}

fn parse_tcpv4(packet_bytes: &[u8]) -> Option<VerfploeterResult> {
    // IPv4 20 + TCP 20 minimum
    if packet_bytes.len() < 40 { return None }

    // Create IPv4Packet from the bytes in the buffer
    let packet = IPv4Packet::from(packet_bytes);

    // Obtain the payload
    if let PacketPayload::TCP { value } = packet.payload {
        // Responses to our probes have destination port > 4000 (as we use these as source)
        // Use the RST flag, and have ACK 0
        // TODO may want to ignore the ACK value due to: https://dl.acm.org/doi/pdf/10.1145/3517745.3561461
        if (value.destination_port < 4000) | (value.flags != 0b00000100) | (value.ack != 0) {
            return None
        }

        let receive_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Create a VerfploeterResult for the received UDP reply
        return Some(VerfploeterResult {
            value: Some(Value::Tcp(TcpResult {
                source_port: u32::from(value.source_port),
                destination_port: value.destination_port as u32,
                seq: value.seq,
                ip_result: Some(IpResult {
                    value: Some(ip_result::Value::Ipv4(IPv4Result {
                        source_address: u32::from(packet.source_address),
                        destination_address: u32::from(packet.destination_address),
                    })),
                    ttl: packet.ttl as u32,
                }),
                receive_time,
                ack: value.ack,
            })),
        })
    } else {
        return None
    }
}

fn parse_tcpv6(packet_bytes: &[u8]) -> Option<VerfploeterResult> {
    // TCP 20 minimum
    if packet_bytes.len() < 20 { return None }

    // Create IPv4Packet from the bytes in the buffer
    // let packet = IPv6Packet::from(packet_bytes);
    // TODO update for ipv6 header

    let value = TCPPacket::from(packet_bytes);

    // let value = packet;
    // Obtain the payload
    // if let PacketPayload::TCP { value } = packet.payload {
        // Responses to our probes have destination port > 4000 (as we use these as source)
        // Use the RST flag, and have ACK 0
        // TODO may want to ignore the ACK value due to: https://dl.acm.org/doi/pdf/10.1145/3517745.3561461
    if (value.destination_port < 4000) | (value.flags != 0b00000100) | (value.ack != 0) {
        return None
    }

    let receive_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Create a VerfploeterResult for the received UDP reply
    return Some(VerfploeterResult {
        value: Some(Value::Tcp(TcpResult {
            source_port: u32::from(value.source_port),
            destination_port: value.destination_port as u32,
            seq: value.seq,
            ip_result: Some(IpResult {
                value: Some(ip_result::Value::Ipv6(IPv6Result {
                    source_address: Some(IPv6 {
                        p1: 0,
                        p2: 0,
                    }),
                    destination_address: Some(custom_module::verfploeter::IPv6 {
                        p1: 0,
                        p2: 0,
                    }),
                })),
                ttl: 0,
            }),
            receive_time,
            ack: value.ack,
        })),
    })
    // } else {
    //     return None
    // }
}
