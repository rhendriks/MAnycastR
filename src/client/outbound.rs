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
use crate::custom_module::verfploeter::Origin;

/// Performs a ping/ICMP task by sending out ICMP ECHO Requests with a custom payload.
///
/// This payload contains the client ID of this prober, transmission time, source and destination address, and the task ID of the current measurement.
///
/// # Arguments
///
/// * 'socket' - the socket to send the probes from
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'source_addr' - the source address we use in our probes
///
/// * 'outbound_channel_rx' - on this channel we receive future tasks that are part of the current measurement
///
/// * 'finish_rx' - used to exit or abort the measurement
///
/// * 'rate' - the number of probes to send out each second
pub fn perform_ping(client_id: u8, sources: Vec<IP>, mut outbound_channel_rx: Receiver<Data>, finish_rx: futures::sync::oneshot::Receiver<()>, _rate: u32, ipv6: bool, task_id: u32) {
    println!("[Client outbound] Started pinging thread");
    let abort = Arc::new(Mutex::new(false));
    abort_handler(abort.clone(), finish_rx);

    thread::spawn({
        move || {
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

                let ping_task = match task {
                    End(_) => {
                        break
                    }, // An End task means the measurement has finished
                    Ping(ping) => ping,
                    Trace(trace) => { // TODO trace task for udp/tcp
                        perform_trace(trace.origins, ipv6, ethernet_header.clone(), &mut cap, IP::from(trace.destination_address.expect("None IP address")), client_id, trace.max_ttl as u8, 1, 0);
                        continue
                    },
                    _ => continue, // Invalid task
                };

                let dest_addresses = ping_task.destination_addresses;

                // Loop over the source addresses
                for source in &sources {
                    // Loop over the destination addresses
                    for dest_addr in &dest_addresses {
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

                        // TODO can we re-use the same v4/v6 headers like we do for the ethernet header (only requiring a recalculation of the checksum)?
                        let icmp = if ipv6 {
                            ICMPPacket::echo_request_v6(1, 2, bytes, source.get_v6().into(), IP::from(dest_addr.clone()).get_v6().into(), 255)
                        } else {
                            ICMPPacket::echo_request(1, 2, bytes, source.get_v4().into(), IP::from(dest_addr.clone()).get_v4().into(), 255)
                        };

                        let mut packet: Vec<u8> = Vec::new();
                        packet.extend_from_slice(&ethernet_header);
                        packet.extend_from_slice(&icmp); // ip header included

                        // Send out packet
                        cap.sendpacket(packet).expect("Failed to send ICMP packet");
                    }
                }
            }
            debug!("finished ping");
            println!("[Client outbound] Outbound thread finished");
        }
    });
}

/// Performs a UDP DNS task by sending out DNS A Record requests with a custom domain name.
///
/// This domain name contains the transmission time, the client ID of the prober, the task ID of the current task, and the source and destination address of the probe.
///
/// # Arguments
///
/// * 'socket' - the socket to send the probes from
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'source_addr' - the source address we use in our probes
///
/// * 'source_port' - the source port we use in our probes
///
/// * 'outbound_channel_rx' - on this channel we receive future tasks that are part of the current measurement
///
/// * 'finish_rx' - used to exit or abort the measurement
///
/// * 'rate' - the number of probes to send out each second
pub fn perform_udp(client_id: u8, source_address: IP, source_port: u16, mut outbound_channel_rx: Receiver<Data>, finish_rx: futures::sync::oneshot::Receiver<()>, _rate: u32, ipv6: bool, task_type: u32) {
    println!("[Client outbound] Started UDP probing thread");

    let abort = Arc::new(Mutex::new(false));
    abort_handler(abort.clone(), finish_rx);

    thread::spawn({
        move || {
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

                let udp_task = match task {
                    End(_) => {
                        break
                    }, // An End task means the measurement has finished
                    Udp(udp) => udp,
                    Trace(trace) => {
                        // perform_trace(source_address, ipv6, ethernet_header.clone(), &mut cap, IP::from(trace.destination_address.expect("None IP address")), client_id, trace.max_ttl as u8, task_type as u8); TODO
                        continue
                    },
                    _ => continue, // Invalid task
                };

                let dest_addresses = udp_task.destination_addresses;

                // Loop over the destination addresses
                for dest_addr in dest_addresses {
                    let transmit_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64;

                    let udp = if ipv6 {
                        let source = source_address.get_v6();
                        let dest = IP::from(dest_addr.clone()).get_v6();

                        if task_type == 2 {
                            UDPPacket::dns_request_v6(source.into(), dest.into(), source_port, "any.dnsjedi.org", transmit_time, client_id, 255)
                        } else if task_type == 4 {
                            UDPPacket::chaos_request(source_address, IP::from(dest_addr), source_port, client_id)
                        } else {
                            panic!("Invalid task type")
                        }
                    } else {
                        let source =source_address.get_v4();
                        let dest = IP::from(dest_addr.clone()).get_v4();

                        if task_type == 2 {
                            UDPPacket::dns_request(source.into(), dest.into(), source_port, "any.dnsjedi.org", transmit_time, client_id, 255)
                        } else if task_type == 4 {
                            UDPPacket::chaos_request(source_address, IP::from(dest_addr), source_port, client_id)
                        } else {
                            panic!("Invalid task type")
                        }
                    };

                    let mut packet: Vec<u8> = Vec::new();
                    packet.extend_from_slice(&ethernet_header);
                    packet.extend_from_slice(&udp); // ip header included

                    // Send out packet
                    cap.sendpacket(packet).expect("Failed to send UDP packet");
                }
            }
            debug!("finished udp probing");

            println!("[Client outbound] UDP Outbound thread finished");
        }
    });
}

/// Performs a TCP task by sending out TCP SYN/ACK probes with a custom port and ACK value.
///
/// The destination port uses a constant value with the client ID added, the ACK value has the current millis encoded into it.
///
/// # Arguments
///
/// * 'socket' - the socket to send the probes from
///
/// * 'source_addr' - the source address we use in our probes
///
/// * 'destination_port' - the destination port we use in our probes
///
/// * 'source_port' - the source port we use in our probes
///
/// * 'outbound_channel_rx' - on this channel we receive future tasks that are part of the current measurement
///
/// * 'finish_rx' - used to exit or abort the measurement
///
/// * 'rate' - the number of probes to send out each second
pub fn perform_tcp(source_address: IP, destination_port: u16, source_port: u16, mut outbound_channel_rx: Receiver<Data>, finish_rx: futures::sync::oneshot::Receiver<()>, _rate: u32, ipv6: bool, client_id: u8) {
    println!("[Client outbound] Started TCP probing thread using source address {:?}", source_address.to_string());

    let abort = Arc::new(Mutex::new(false));
    abort_handler(abort.clone(), finish_rx);

    thread::spawn({
        move || {
            let ethernet_header = get_ethernet_header(ipv6);
            let main_interface = Device::lookup().expect("Failed to get main interface").unwrap();
            let mut cap = Capture::from_device(main_interface).expect("Failed to create a capture").buffer_size(1_000_000).open().expect("Failed to open capture");
            'outer: loop {
                if *abort.lock().unwrap() == true {
                    println!("ABORTING");
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

                let tcp_task = match task {
                    End(_) => {
                        break
                    }, // An End task means the measurement has finished
                    Tcp(tcp) => tcp,
                    Trace(trace) => {
                        // perform_trace(origins, ipv6, ethernet_header.clone(), &mut cap, IP::from(trace.destination_address.expect("None IP address")), client_id, trace.max_ttl as u8, 3);
                        continue
                    },
                    _ => continue, // Invalid task
                };

                let dest_addresses = tcp_task.destination_addresses;

                // Loop over the destination addresses
                for dest_addr in dest_addresses {
                    // let transmit_time = SystemTime::now()
                    //     .duration_since(UNIX_EPOCH)
                    //     .unwrap()
                    //     .as_millis() as u32; // The least significant bits are kept

                    let seq = 0; // information in seq gets lost
                    // let ack = transmit_time; // ack information gets returned as seq
                    let ack = client_id as u32; // Does not trigger ECMP

                    let tcp = if ipv6 {
                        let source = source_address.get_v6();
                        let dest = IP::from(dest_addr).get_v6();

                        TCPPacket::tcp_syn_ack_v6(source.into(), dest.into(), source_port, destination_port, seq, ack, 255)
                    } else {
                        let source = source_address.get_v4();
                        let dest = IP::from(dest_addr).get_v4();

                        TCPPacket::tcp_syn_ack(source.into(), dest.into(), source_port, destination_port, seq, ack, 255)
                    };

                    let mut packet: Vec<u8> = Vec::new();
                    packet.extend_from_slice(&ethernet_header);
                    packet.extend_from_slice(&tcp); // ip header included

                    // Send out packet
                    cap.sendpacket(packet).expect("Failed to send TCP packet"); // TODO encountered PcapError "send: no buffer space available"
                }
            }
            debug!("finished TCP probing");

            println!("[Client outbound] TCP Outbound thread finished");
        }
    });
}

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
    println!("Performing trace to {}", dest_addr.to_string());
    println!("Origins: {:?}", origins);

    for origin in origins {
        let source_address = IP::from(origin.source_address.expect("None IP address"));
        let port = origin.source_port as u16;

        // Send traceroutes to hops 5 to max_ttl + 5 (starting at 5 to avoid the first 4 vultr hops, and adding 5 to the max_ttl in case of false RTTs)
        for i in 5..(max_ttl + 15) {
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
fn abort_handler(abort: Arc<Mutex<bool>>, finish_rx: futures::sync::oneshot::Receiver<()>) {
    thread::spawn({
        let abort = abort.clone();

        move || {
            finish_rx.wait().ok();
            *abort.lock().unwrap() = true;
        }
    });
}

fn get_ethernet_header(v6: bool) -> Vec<u8> {
    // Source MAC address
    let mac_src = match get_mac_address() {
        Ok(Some(ma)) => {
            ma.bytes()
        }
        Ok(None) => panic!("No MAC address found."),
        Err(e) => panic!("{:?}", e),
    };

    // Run the sudo arp command (for the destination MAC address)
    let output = Command::new("cat")
        .arg("/proc/net/arp")
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to run command")
        .stdout
        .expect("Failed to capture stdout");

    let mut mac_dest = vec![];
    // Read the output line by line
    let reader = io::BufReader::new(output);
    let mut lines = reader.lines();
    lines.next(); // Skip the first line (header)
    for line in lines {
        // Skip the first line
        if let Ok(line) = line {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 3 {
                mac_dest = parts[3].split(':').map(|s| u8::from_str_radix(s, 16).unwrap()).collect();
                break;
            }
        }
    }

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
