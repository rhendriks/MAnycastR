use std::{io, thread};
use std::io::BufRead;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::net::{ICMPPacket, TCPPacket, UDPPacket};
use std::sync::{Arc, Mutex};
use futures::Future;
use pcap::{Capture, Device};
use crate::custom_module;
use custom_module::IP;
use tokio::sync::mpsc::Receiver;
use custom_module::verfploeter::{PingPayload, address::Value::V4, address::Value::V6, task::Data};
use custom_module::verfploeter::task::Data::{Ping, Tcp, Udp, End, Trace};
use std::process::{Command, Stdio};
use tokio::sync::mpsc::error::TryRecvError;

extern crate mac_address;
use mac_address::get_mac_address;
use crate::custom_module::verfploeter::{Address, Origin};

/// Creates a ping packet.
///
/// # Arguments
///
/// * 'source' - the source IP address of the ping packet
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'task_id' - the unique task ID of the current measurement
///
/// * 'origin' - the source address we use for our probes (dst port is used as the ICMP sequence number)
///
/// * 'dest_addr' - the destination address for the ping packet]
///
/// # Returns
///
/// A ping packet (including the IP header) as a byte vector.
///
/// # Panics
///
/// If the source address or destination address is None
pub fn create_ping(
    source: IP,
    client_id: u8,
    task_id: u32,
    origin: Origin,
    dest_addr: Address,
) -> Vec<u8> {
    let transmit_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Create ping payload
    let payload = PingPayload {
        transmit_time,
        source_address: Some(source.clone().into()),
        destination_address: Some(dest_addr.clone()),
        sender_client_id: client_id as u32,
    };

    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&task_id.to_be_bytes()); // Bytes 0 - 3
    bytes.extend_from_slice(&payload.transmit_time.to_be_bytes()); // Bytes 4 - 11 *
    bytes.extend_from_slice(&payload.sender_client_id.to_be_bytes()); // Bytes 12 - 15 *
    if let Some(source_address) = payload.source_address {
        match source_address.value {
            Some(V4(v4)) => bytes.extend_from_slice(&v4.to_be_bytes()), // Bytes 16 - 19
            Some(V6(v6)) => {
                bytes.extend_from_slice(&v6.p1.to_be_bytes()); // Bytes 16 - 23
                bytes.extend_from_slice(&v6.p2.to_be_bytes()); // Bytes 24 - 31
            },
            None => panic!("Source address is None"),
        }
    }
    if let Some(destination_address) = payload.destination_address {
        match destination_address.value {
            Some(V4(v4)) => bytes.extend_from_slice(&v4.to_be_bytes()), // Bytes 32 - 35
            Some(V6(v6)) => {
                bytes.extend_from_slice(&v6.p1.to_be_bytes()); // Bytes 32 - 39
                bytes.extend_from_slice(&v6.p2.to_be_bytes()); // Bytes 40 - 47
            },
            None => panic!("Destination address is None"),
        }
    }

    let ipv6 = source.is_v6();
    // TODO can we re-use the same v4/v6 headers like we do for the ethernet header (only requiring a recalculation of the checksum)?
    return if ipv6 {
        ICMPPacket::echo_request_v6(origin.destination_port as u16, 2, bytes, source.get_v6().into(), IP::from(dest_addr.clone()).get_v6().into(), 255)
    } else {
        ICMPPacket::echo_request(origin.destination_port as u16, 2, bytes, source.get_v4().into(), IP::from(dest_addr.clone()).get_v4().into(), 255)
    }
}

/// Creates a UDP packet.
///
/// # Arguments
///
/// * 'source_address' - the source IP address of the UDP packet
///
/// * 'source_port' - the source port of the UDP packet
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'dest_addr' - the destination address for the UDP packet
///
/// * 'ipv6' - whether we are using IPv6 or not
///
/// * 'task_type' - the type of task to perform (2 = UDP/DNS, 4 = UDP/CHAOS)
///
/// # Returns
///
/// A UDP packet (including the IP header) as a byte vector.
///
/// # Panics
///
/// If the task type is not 2 or 4
pub fn create_udp(
    source_address: IP,
    source_port: u16,
    client_id: u8,
    dest_addr: IP,
    ipv6: bool,
    task_type: u8,
) -> Vec<u8> {
    let transmit_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    return if ipv6 {
        let source = source_address.get_v6();
        let dest = IP::from(dest_addr.clone()).get_v6();

        if task_type == 2 {
            UDPPacket::dns_request_v6(source.into(), dest.into(), source_port, "any.dnsjedi.org", transmit_time, client_id, 255)
        } else if task_type == 4 {
            UDPPacket::chaos_request_v6(source.into(), dest.into(), source_port, client_id)
        } else {
            panic!("Invalid task type")
        }
    } else {
        let source = source_address.get_v4();
        let dest = IP::from(dest_addr.clone()).get_v4();

        if task_type == 2 {
            UDPPacket::dns_request(source.into(), dest.into(), source_port, "any.dnsjedi.org", transmit_time, client_id, 255)
        } else if task_type == 4 {
            UDPPacket::chaos_request(source.into(), dest.into(), source_port, client_id)
        } else {
            panic!("Invalid task type")
        }
    }
}

/// Creates a TCP packet.
///
/// # Arguments
///
/// * 'dest_addr' - the destination IP address of the TCP packet
///
/// * 'source_address' - the source IP address of the TCP packet
///
/// * 'source_port' - the source port of the TCP packet
///
/// * 'destination_port' - the destination port of the TCP packet
///
/// * 'is_ipv6' - whether we are using IPv6 or not
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'igreedy' - whether we are sending probes with unicast or anycast
///
/// # Returns
///
/// A TCP packet (including the IP header) as a byte vector.
///
/// # Panics
///
/// If the source address or destination address is None
///
/// If the task type is not 3
pub fn create_tcp(
    dest_addr: IP,
    source_address: IP,
    source_port: u16,
    destination_port: u16,
    is_ipv6: bool,
    client_id: u8,
    igreedy: bool,
) -> Vec<u8> {
    let transmit_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32; // The least significant bits are kept

    let seq = 0; // information in seq gets lost
    // for MAnycast the ACK is the client ID, for iGreedy the ACK is the transmit time
    let ack = if !igreedy {
        client_id as u32
    } else {
        transmit_time
    };

    return if is_ipv6 {
        let source = source_address.get_v6();
        let dest = IP::from(dest_addr.clone()).get_v6();

        TCPPacket::tcp_syn_ack_v6(source.into(), dest.into(), source_port, destination_port, seq, ack, 255)
    } else {
        let source = source_address.get_v4();
        let dest = IP::from(dest_addr.clone()).get_v4();

        TCPPacket::tcp_syn_ack(source.into(), dest.into(), source_port, destination_port, seq, ack, 255)
    }
}


/// Spawns thread that sends out ICMP, UDP, or TCP probes.
///
/// # Arguments
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'origins' - the unique source addresses and port combinations we use for our probes
///
/// * 'outbound_channel_rx' - on this channel we receive future tasks that are part of the current measurement
///
/// * 'finish_rx' - used to exit or abort the measurement
///
/// * 'ipv6' - whether we are using IPv6 or not
///
/// * 'igreedy' - whether we are sending probes with unicast or anycast
///
/// * 'task_id' - the unique task ID of the current measurement
///
/// * 'task_type' - the type of task to perform (1 = ICMP, 2 = UDP/DNS, 3 = TCP, 4 = UDP/CHAOS)
pub fn outbound(
    client_id: u8,
    origins: Vec<Origin>,
    mut outbound_channel_rx: Receiver<Data>,
    finish_rx: futures::sync::oneshot::Receiver<()>,
    ipv6: bool,
    igreedy: bool,
    task_id: u32,
    task_type: u8,
) {
    println!("[Client outbound] Started outbound probing thread");
    let abort = Arc::new(Mutex::new(false));
    abort_handler(abort.clone(), finish_rx);

    thread::Builder::new().name("outbound".to_string())
        .spawn(move || {
            let ethernet_header = get_ethernet_header(ipv6);
            let main_interface = Device::lookup().expect("Failed to get main interface").unwrap();
            let mut cap = Capture::from_device(main_interface).expect("Failed to create a capture").open().expect("Failed to open capture");
            'outer: loop {
                if *abort.lock().unwrap() == true {
                    println!("[Client outbound] ABORTING");
                    break
                }
                let task;
                // Receive tasks from the outbound channel
                loop {
                    match outbound_channel_rx.try_recv() {
                        Ok(t) => {
                            task = t;
                            break;
                        },
                        Err(e) => {
                            if e == TryRecvError::Disconnected {
                                println!("[Client outbound] Channel disconnected");
                                break 'outer
                            }
                            // wait some time and try again
                            thread::sleep(Duration::from_millis(100));
                        },
                    };
                }

                match task {
                    End(_) => {
                        break
                    }, // An End task means the measurement has finished
                    Ping(ping) => {
                        if task_type != 1 {
                            panic!("Non-matching task type")
                        }

                        for origin in &origins {
                            let source = IP::from(origin.source_address.clone().expect("None IP address"));
                            for dst_addr in &ping.destination_addresses {
                                let icmp = create_ping(
                                    source,
                                    client_id,
                                    task_id,
                                    origin.clone(),
                                    dst_addr.clone(),
                                );
                                let mut packet: Vec<u8> = Vec::new();
                                packet.extend_from_slice(&ethernet_header);
                                packet.extend_from_slice(&icmp); // ip header included
                                cap.sendpacket(packet).expect("Failed to send ICMP packet");
                            }
                        }
                    },
                    Udp(udp) => {
                        if task_type != 2 && task_type != 4 {
                            panic!("Non-matching task type")
                        }
                        for origin in &origins {
                            let source = IP::from(origin.source_address.clone().expect("None IP address"));
                            let source_port = origin.source_port as u16;
                            for dst_addr in &udp.destination_addresses {
                                let udp = create_udp(
                                    source,
                                    source_port,
                                    client_id,
                                    IP::from(dst_addr.clone()),
                                    ipv6,
                                    task_type
                                );

                                let mut packet: Vec<u8> = Vec::new();
                                packet.extend_from_slice(&ethernet_header);
                                packet.extend_from_slice(&udp); // ip header included
                                cap.sendpacket(packet).expect("Failed to send UDP packet");
                            }
                        }
                    },
                    Tcp(tcp) => {
                        if task_type != 3 {
                            panic!("Non-matching task type")
                        }
                        for origin in &origins {
                            let source = IP::from(origin.source_address.clone().expect("None IP address"));
                            let source_port = origin.source_port as u16;
                            let destination_port = origin.destination_port as u16;
                            for dst_addr in &tcp.destination_addresses {
                                let tcp = create_tcp(
                                    IP::from(dst_addr.clone()),
                                    source,
                                    source_port,
                                    destination_port,
                                    ipv6,
                                    client_id,
                                    igreedy,
                                );

                                let mut packet: Vec<u8> = Vec::new();
                                packet.extend_from_slice(&ethernet_header);
                                packet.extend_from_slice(&tcp); // ip header included
                                cap.sendpacket(packet).expect("Failed to send TCP packet");
                            }
                        }
                    },

                    Trace(trace) => {
                        perform_trace(
                            trace.origins,
                            ipv6,
                            ethernet_header.clone(),
                            &mut cap,
                            IP::from(trace.destination_address.expect("None IP address")),
                            client_id,
                            trace.max_ttl as u8,
                            task_type,
                            0 // TODO dst port
                        );
                        continue
                    },
                    _ => continue, // Invalid task
                };
            }
            println!("[Client outbound] Outbound thread finished");
        }).expect("Failed to spawn outbound thread");
}

/// Performs a trace task by sending out ICMP, UDP, or TCP probes with increasing TTLs.
///
/// # Arguments
///
/// * 'origins' - the unique source addresses and port combinations we send traceroutes with
///
/// * 'ipv6' - whether we are using IPv6 or not
///
/// * 'ethernet_header' - the ethernet header to use for the traceroutes
///
/// * 'cap' - the pcap capture to send the traceroutes with
///
/// * 'dest_addr' - the destination address for the traceroutes
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'max_ttl' - the maximum TTL to use for the traceroutes (the actual TTLs used are 5 to max_ttl + 10)
///
/// * 'task_type' - the type of task to perform (1 = ICMP, 2 = UDP/DNS, 3 = TCP)
///
/// * 'destination_port' - the destination port to use for the TCP traceroutes
fn perform_trace(
    origins: Vec<Origin>,
    ipv6: bool,
    ethernet_header: Vec<u8>,
    cap: &mut Capture<pcap::Active>,
    dest_addr: IP,
    client_id: u8,
    max_ttl: u8,
    task_type: u8,
    destination_port: u16,
) { // TODO these are sent out in bursts, create a thread in here for the trace task to send them out 1 second after eachother
    if task_type > 3 {
        panic!("Invalid task type")
    }

    println!("performing trace from {:?} to {}", origins, dest_addr.to_string());
    for origin in origins {
        let source_address = IP::from(origin.source_address.expect("None IP address"));
        let port = origin.source_port as u16;

        // Send traceroutes to hops 5 to max_ttl + 10 (starting at 5 to avoid the first 4 vultr hops, and adding 10 to the max_ttl in case of false RTTs)
        // TODO implement required feedback loop that stops sending traceroutes when the destination is reached (taking into consideration a different client may receive the destination's response)
        for i in 5..(max_ttl + 10) {
            let mut packet: Vec<u8> = Vec::new();
            packet.extend_from_slice(&ethernet_header);

            let mut payload_bytes: Vec<u8> = Vec::new();
            let transmit_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            payload_bytes.extend_from_slice(&transmit_time.to_be_bytes()); // Bytes 0 - 7
            payload_bytes.extend_from_slice(&client_id.to_be_bytes()); // Byte 8 *
            payload_bytes.extend_from_slice(&i.to_be_bytes()); // Byte 9 *

            if task_type == 1 { // ICMP
                let icmp = if ipv6 {
                    ICMPPacket::echo_request_v6(1, 2, payload_bytes, source_address.get_v6().into(), dest_addr.get_v6().into(), i)
                } else {
                    ICMPPacket::echo_request(1, 2, payload_bytes, source_address.get_v4().into(), dest_addr.get_v4().into(), i)
                };
                packet.extend_from_slice(&icmp); // ip header included
            } else if task_type == 2 { // UDP
                let udp = if ipv6 { // TODO encode TTL in the domain name
                    UDPPacket::dns_request_v6(source_address.get_v6().into(), dest_addr.get_v6().into(), port, "any.dnsjedi.org", transmit_time, client_id, i)
                } else {
                    UDPPacket::dns_request(source_address.get_v4().into(), dest_addr.get_v4().into(), port, "any.dnsjedi.org", transmit_time, client_id, i)
                };
                packet.extend_from_slice(&udp); // ip header included
            } else if task_type == 3 { // TCP
                // ACK: first 16 is the TTL, last 16 is the client ID
                let ack = (i as u32) << 16 | client_id as u32; // TODO test this
                let tcp = if ipv6 {
                    TCPPacket::tcp_syn_ack_v6(source_address.get_v6().into(), dest_addr.get_v6().into(), port, destination_port, 0, ack, i)
                } else {
                    TCPPacket::tcp_syn_ack(source_address.get_v4().into(), dest_addr.get_v4().into(), port, destination_port, 0, ack, i)
                };
                packet.extend_from_slice(&tcp); // ip header included
            }

            cap.sendpacket(packet).expect("Failed to send traceroute packet");
        }
    }
}





/// Spawns a thread that waits for a possible abort signal.
///
/// # Arguments
///
/// * 'abort' - the shared boolean that is set to true when the measurement is aborted (exiting the outbound thread)
///
/// * 'finish_rx' - main thread will send a message on this channel when the measurement must be aborted
fn abort_handler(
    abort: Arc<Mutex<bool>>,
    finish_rx: futures::sync::oneshot::Receiver<()>
) {
    thread::spawn({ // TODO does this thread get killed when the main thread finishes gracefully (i.e., no abort signal)?
        let abort = abort.clone();

        move || {
            finish_rx.wait().ok();
            *abort.lock().unwrap() = true;
        }
    });
}

/// Returns the ethernet header to use for the outbound packets.
///
/// # Arguments
///
/// * 'v6' - whether we are using IPv6 or not
fn get_ethernet_header(v6: bool) -> Vec<u8> {
    // Source MAC address
    let mac_src = match get_mac_address() {
        Ok(Some(ma)) => {
            ma.bytes()
        }
        Ok(None) => panic!("No MAC address found."),
        Err(e) => panic!("{:?}", e),
    };

    // Run the sudo arp command (for the destination MAC addresses)
    let output = Command::new("cat")
        .arg("/proc/net/arp")
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to run command")
        .stdout
        .expect("Failed to capture stdout");

    // Get the destination MAC addresses
    let mut mac_dest = vec![];
    let reader = io::BufReader::new(output);
    let mut lines = reader.lines();
    lines.next(); // Skip the first line (header)
    for line in lines {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 3 {
                mac_dest = parts[3].split(':').map(|s| u8::from_str_radix(s, 16).unwrap()).collect();
                break;
            }
        }
    }

    // TODO rotate the destination MAC address (when we have multiple next hops)

    // Construct the ethernet header
    let ether_type = if v6 {
        0x86DDu16
    } else {
        0x0800u16
    };
    let mut ethernet_header: Vec<u8> = Vec::new();
    ethernet_header.extend_from_slice(&mac_dest);
    ethernet_header.extend_from_slice(&mac_src);
    ethernet_header.extend_from_slice(&ether_type.to_be_bytes());

    ethernet_header
}
