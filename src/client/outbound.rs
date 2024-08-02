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
use custom_module::verfploeter::{PingPayload, address::Value::V4, address::Value::V6, task::Data, Origin};
use custom_module::verfploeter::task::Data::{Targets, End, Trace};
use std::process::{Command, Stdio};
use tokio::sync::mpsc::error::TryRecvError;

extern crate mac_address;
use mac_address::get_mac_address;

/// Creates a ping packet.
///
/// # Arguments
///
/// * 'origin' - the source address and ICMP identifier (dst port) we use for our probes
///
/// * 'dst' - the destination address for the ping packet
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'task_id' - the unique task ID of the current measurement
///
/// # Returns
///
/// A ping packet (including the IP header) as a byte vector.
///
/// # Panics
///
/// If the source address or destination address is None
pub fn create_ping(
    origin: Origin,
    dst: IP,
    client_id: u8,
    task_id: u32,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let src = IP::from(origin.src.expect("None IP address"));
    // Create ping payload
    let payload = PingPayload {
        tx_time,
        src: Some(src.clone().into()),
        dst: Some(dst.clone().into()),
        tx_client_id: client_id as u32,
    };

    // Create the ping payload bytes
    let mut payload_bytes: Vec<u8> = Vec::new();
    payload_bytes.extend_from_slice(&task_id.to_be_bytes()); // Bytes 0 - 3
    payload_bytes.extend_from_slice(&payload.tx_time.to_be_bytes()); // Bytes 4 - 11 *
    payload_bytes.extend_from_slice(&payload.tx_client_id.to_be_bytes()); // Bytes 12 - 15 *
    if let Some(source_address) = payload.src {
        match source_address.value {
            Some(V4(v4)) => payload_bytes.extend_from_slice(&v4.to_be_bytes()), // Bytes 16 - 19
            Some(V6(v6)) => {
                payload_bytes.extend_from_slice(&v6.p1.to_be_bytes()); // Bytes 16 - 23
                payload_bytes.extend_from_slice(&v6.p2.to_be_bytes()); // Bytes 24 - 31
            },
            None => panic!("Source address is None"),
        }
    }
    if let Some(destination_address) = payload.dst {
        match destination_address.value {
            Some(V4(v4)) => payload_bytes.extend_from_slice(&v4.to_be_bytes()), // Bytes 32 - 35
            Some(V6(v6)) => {
                payload_bytes.extend_from_slice(&v6.p1.to_be_bytes()); // Bytes 32 - 39
                payload_bytes.extend_from_slice(&v6.p2.to_be_bytes()); // Bytes 40 - 47
            },
            None => panic!("Destination address is None"),
        }
    }

   return if src.is_v6() {
        ICMPPacket::echo_request_v6(origin.sport as u16, 2, payload_bytes, src.get_v6().into(), IP::from(dst.clone()).get_v6().into(), 255)
    } else {
        ICMPPacket::echo_request(origin.dport as u16, 2, payload_bytes, src.get_v4().into(), IP::from(dst.clone()).get_v4().into(), 255)
    }
}

/// Creates a UDP packet.
///
/// # Arguments
///
/// * 'origin' - the source address and port values we use for our probes
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'dst' - the destination address for the UDP packet
///
/// * 'task_type' - the type of task to perform (2 = UDP/DNS, 4 = UDP/CHAOS)
///
/// * 'is_ipv6' - whether we are using IPv6 or not
///
/// # Returns
///
/// A UDP packet (including the IP header) as a byte vector.
///
/// # Panics
///
/// If the task type is not 2 or 4
pub fn create_udp(
    origin: Origin,
    dst: IP,
    client_id: u8,
    task_type: u8,
    is_ipv6: bool,
) -> Vec<u8> {
    let transmit_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let src = IP::from(origin.src.expect("None IP address"));
    let dport = origin.dport as u16;

    return if is_ipv6 {
        if task_type == 2 {
            UDPPacket::dns_request_v6(src.get_v6().into(), dst.get_v6().into(), dport, "any.dnsjedi.org", transmit_time, client_id, 255)
        } else if task_type == 4 {
            UDPPacket::chaos_request_v6(src.get_v6().into(), dst.get_v6().into(), dport, client_id)
        } else {
            panic!("Invalid task type")
        }
    } else {
        if task_type == 2 {
            UDPPacket::dns_request(src.get_v4().into(), dst.get_v4().into(), dport, "any.dnsjedi.org", transmit_time, client_id, 255)
        } else if task_type == 4 {
            UDPPacket::chaos_request(src.get_v4().into(), dst.get_v4().into(), dport, client_id)
        } else {
            panic!("Invalid task type")
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
/// * 'client_id' - the unique client ID of this client
///
/// * 'is_ipv6' - whether we are using IPv6 or not
///
/// * 'gcd' - whether we are performing anycast-based (false) or GCD probing (true)
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
    origin: Origin,
    dst: IP,
    client_id: u8,
    is_ipv6: bool,
    gcd: bool,
) -> Vec<u8> {
    let transmit_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32; // The least significant bits are kept
    let seq = 0; // information in seq gets lost
    // for MAnycast the ACK is the client ID, for GCD the ACK is the transmit time
    let ack = if !gcd {
        client_id as u32
    } else {
        transmit_time
    };

    return if is_ipv6 {
        let src = IP::from(origin.src.expect("None IP address")).get_v6();
        let dest = IP::from(dst.clone()).get_v6();

        TCPPacket::tcp_syn_ack_v6(src.into(), dest.into(), origin.sport as u16, origin.dport as u16, seq, ack, 255)
    } else {
        let src = IP::from(origin.src.expect("None IP address")).get_v4();
        let dest = IP::from(dst.clone()).get_v4();

        TCPPacket::tcp_syn_ack(src.into(), dest.into(), origin.sport as u16, origin.dport as u16, seq, ack, 255)
    }
}


/// Spawns thread that sends out ICMP, UDP, or TCP probes.
///
/// # Arguments
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'tx_origins' - the unique source addresses and port combinations we use for our probes
///
/// * 'outbound_channel_rx' - on this channel we receive future tasks that are part of the current measurement
///
/// * 'finish_rx' - used to exit or abort the measurement
///
/// * 'is_ipv6' - whether we are using IPv6 or not
///
/// * 'gcd' - whether we are sending probes with unicast or anycast
///
/// * 'task_id' - the unique task ID of the current measurement
///
/// * 'task_type' - the type of task to perform (1 = ICMP, 2 = UDP/DNS, 3 = TCP, 4 = UDP/CHAOS)
pub fn outbound(
    client_id: u8,
    tx_origins: Vec<Origin>,
    mut outbound_channel_rx: Receiver<Data>,
    finish_rx: futures::sync::oneshot::Receiver<()>,
    is_ipv6: bool,
    gcd: bool,
    task_id: u32,
    task_type: u8,
) {
    println!("[Client outbound] Started outbound probing thread");
    let abort = Arc::new(Mutex::new(false));
    abort_handler(abort.clone(), finish_rx);

    thread::Builder::new().name("outbound".to_string())
        .spawn(move || {
            let ethernet_header = get_ethernet_header(is_ipv6);
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
                    End(_) => { // An End task means the measurement has finished
                        break
                    },
                    Targets(targets) => {
                        for origin in &tx_origins {
                            match task_type {
                                1 => {
                                    for dst in &targets.dst_addresses {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_ping(
                                            origin.clone(),
                                            IP::from(dst.clone()),
                                            client_id,
                                            task_id,
                                        ));
                                        cap.sendpacket(packet).expect("Failed to send ICMP packet");
                                    }
                                },
                                2 | 4 => {
                                    for dst in &targets.dst_addresses {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_udp(
                                            origin.clone(),
                                            IP::from(dst.clone()),
                                            client_id,
                                            task_type,
                                            is_ipv6,
                                        ));
                                        cap.sendpacket(packet).expect("Failed to send UDP packet");
                                    }
                                },
                                3 => {
                                    for dst in &targets.dst_addresses {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_tcp(
                                            origin.clone(),
                                            IP::from(dst.clone()),
                                            client_id,
                                            is_ipv6,
                                            gcd,
                                        ));
                                        cap.sendpacket(packet).expect("Failed to send TCP packet");
                                    }
                                },
                                _ => panic!("Invalid task type"), // Invalid task
                            }
                        }
                    },
                    Trace(trace) => {
                        perform_trace(
                            trace.origins,
                            is_ipv6,
                            ethernet_header.clone(),
                            &mut cap,
                            IP::from(trace.dst.expect("None IP address")),
                            client_id,
                            trace.max_ttl as u8,
                            task_type,
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
/// * 'origins' - the unique source address and port combinations we send traceroutes with
///
/// * 'is_ipv6' - whether we are using IPv6 or not
///
/// * 'ethernet_header' - the ethernet header to use for the traceroutes
///
/// * 'cap' - the pcap capture to send the traceroutes with
///
/// * 'dst' - the destination address for the traceroutes
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'max_ttl' - the maximum TTL to use for the traceroutes (the actual TTLs used are 5 to max_ttl + 10)
///
/// * 'task_type' - the type of task to perform (1 = ICMP, 2 = UDP/DNS, 3 = TCP)
fn perform_trace(
    origins: Vec<Origin>,
    is_ipv6: bool,
    ethernet_header: Vec<u8>,
    cap: &mut Capture<pcap::Active>,
    dst: IP,
    client_id: u8,
    max_ttl: u8,
    task_type: u8,
) { // TODO these are sent out in bursts, create a thread in here for the trace task to send them out 1 second after eachother
    if task_type > 3 {
        // Traceroute supported for ICMP, UDP, and TCP
        panic!("Invalid task type")
    }

    println!("performing trace from {:?} to {}", origins, dst.to_string());
    for origin in origins {
        let src = IP::from(origin.src.expect("None IP address"));
        let sport = origin.sport as u16;
        let dport = origin.dport as u16;

        // Send traceroutes to hops 5 to max_ttl + 10 (starting at 5 to avoid the first 4 vultr hops, and adding 10 to the max_ttl in case of false RTTs)
        // TODO implement required feedback loop that stops sending traceroutes when the destination is reached (taking into consideration a different client may receive the destination's response)
        for i in 5..(max_ttl + 10) {
            let mut packet: Vec<u8> = Vec::new();
            packet.extend_from_slice(&ethernet_header);

            let mut payload_bytes: Vec<u8> = Vec::new();
            let tx_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            payload_bytes.extend_from_slice(&tx_time.to_be_bytes()); // Bytes 0 - 7
            payload_bytes.extend_from_slice(&client_id.to_be_bytes()); // Byte 8 *
            payload_bytes.extend_from_slice(&i.to_be_bytes()); // Byte 9 *

            if task_type == 1 { // ICMP
                let icmp = if is_ipv6 {
                    ICMPPacket::echo_request_v6(1, 2, payload_bytes, src.get_v6().into(), dst.get_v6().into(), i)
                } else {
                    ICMPPacket::echo_request(1, 2, payload_bytes, src.get_v4().into(), dst.get_v4().into(), i)
                };
                packet.extend_from_slice(&icmp); // ip header included
            } else if task_type == 2 { // UDP
                let udp = if is_ipv6 { // TODO encode TTL in the domain name
                    UDPPacket::dns_request_v6(src.get_v6().into(), dst.get_v6().into(), sport, "any.dnsjedi.org", tx_time, client_id, i)
                } else {
                    UDPPacket::dns_request(src.get_v4().into(), dst.get_v4().into(), sport, "any.dnsjedi.org", tx_time, client_id, i)
                };
                packet.extend_from_slice(&udp); // ip header included
            } else if task_type == 3 { // TCP
                // ACK: first 16 is the TTL, last 16 is the client ID
                let ack = (i as u32) << 16 | client_id as u32; // TODO test this
                let tcp = if is_ipv6 {
                    TCPPacket::tcp_syn_ack_v6(src.get_v6().into(), dst.get_v6().into(), sport, dport, 0, ack, i)
                } else {
                    TCPPacket::tcp_syn_ack(src.get_v4().into(), dst.get_v4().into(), sport, dport, 0, ack, i)
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
    thread::Builder::new()
        .name("abort_thread".to_string())
        .spawn(move || {
            finish_rx.wait().ok();
            *abort.lock().unwrap() = true;
        }).expect("Failed to spawn abort thread");
}

/// Returns the ethernet header to use for the outbound packets.
///
/// # Arguments
///
/// * 'is_ipv6' - whether we are using IPv6 or not
fn get_ethernet_header(is_ipv6: bool) -> Vec<u8> {
    // Source MAC address
    let mac_src = match get_mac_address() {
        Ok(Some(ma)) => {
            ma.bytes()
        }
        Ok(None) => panic!("No MAC address found."),
        Err(e) => panic!("{:?}", e),
    };

    // Run the sudo arp command (for the destination MAC addresses)
    let mut child = Command::new("cat")
        .arg("/proc/net/arp")
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to run command");
        // .stdout
        // .expect("Failed to capture stdout");

    let output = child.stdout.as_mut().expect("Failed to capture stdout");

    // Get the destination MAC addresses
    let mut mac_dst = vec![];
    let reader = io::BufReader::new(output);
    let mut lines = reader.lines();
    lines.next(); // Skip the first line (header)
    for line in lines {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 3 {
                mac_dst = parts[3].split(':').map(|s| u8::from_str_radix(s, 16).unwrap()).collect();
                break;
            }
        }
    }
    child.wait().expect("Failed to wait on child");

    // Construct the ethernet header
    let ether_type = if is_ipv6 {
        0x86DDu16
    } else {
        0x0800u16
    };
    let mut ethernet_header: Vec<u8> = Vec::new();
    ethernet_header.extend_from_slice(&mac_dst);
    ethernet_header.extend_from_slice(&mac_src);
    ethernet_header.extend_from_slice(&ether_type.to_be_bytes());

    ethernet_header
}
