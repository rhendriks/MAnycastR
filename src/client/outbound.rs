extern crate mac_address;
use std::thread;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::Future;
use pcap::{Capture, Device};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::Receiver;

use custom_module::IP;
use custom_module::verfploeter::{Origin, task::Data};
use custom_module::verfploeter::task::Data::{End, Targets, Trace};

use crate::custom_module;
use crate::net::packet::{create_ping, create_tcp, create_udp, get_ethernet_header};
use crate::net::{ICMPPacket, TCPPacket, UDPPacket};


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
/// * 'measurement_id' - the unique ID of the current measurement
///
/// * 'measurement_type' - the type of measurement being performed (1 = ICMP, 2 = UDP/DNS, 3 = TCP, 4 = UDP/CHAOS)
///
/// * 'chaos' - the domain name to use for CHAOS measurements
pub fn outbound(
    client_id: u8,
    tx_origins: Vec<Origin>,
    mut outbound_channel_rx: Receiver<Data>,
    finish_rx: futures::sync::oneshot::Receiver<()>,
    is_ipv6: bool,
    gcd: bool,
    measurement_id: u32,
    measurement_type: u8,
    chaos: String,
    info_url: String,
) {
    let abort = Arc::new(Mutex::new(false));
    abort_handler(abort.clone(), finish_rx);

    thread::Builder::new().name("outbound".to_string())
        .spawn(move || {
            let ethernet_header = get_ethernet_header(is_ipv6);
            let main_interface = Device::lookup().expect("Failed to get main interface").unwrap();
            let mut cap = Capture::from_device(main_interface).expect("Failed to create a capture").buffer_size(100_000_000).open().expect("Failed to open capture");
            'outer: loop {
                if *abort.lock().unwrap() {
                    println!("[Client outbound] ABORTING");
                    break;
                }
                let task;
                // Receive tasks from the outbound channel
                loop {
                    match outbound_channel_rx.try_recv() {
                        Ok(t) => {
                            task = t;
                            break;
                        }
                        Err(e) => {
                            if e == TryRecvError::Disconnected {
                                println!("[Client outbound] Channel disconnected");
                                break 'outer;
                            }
                            // wait some time and try again
                            thread::sleep(Duration::from_millis(100));
                        }
                    };
                }

                match task {
                    End(_) => { // An End task means the measurement has finished
                        break
                    }
                    Targets(targets) => {
                        for origin in &tx_origins {
                            match measurement_type {
                                1 => {
                                    for dst in &targets.dst_addresses {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_ping(
                                            origin.clone(),
                                            IP::from(dst.clone()),
                                            client_id,
                                            measurement_id,
                                            &info_url,
                                        ));
                                        cap.sendpacket(packet).unwrap_or_else(|e| {
                                            println!("Failed to send ICMP packet: {}", e)
                                        });
                                    }
                                }
                                2 | 4 => {
                                    for dst in &targets.dst_addresses {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_udp(
                                            origin.clone(),
                                            IP::from(dst.clone()),
                                            client_id,
                                            measurement_type,
                                            is_ipv6,
                                            chaos.clone(),
                                        ));
                                        cap.sendpacket(packet).unwrap_or_else(|e| {
                                            println!("Failed to send ICMP packet: {}", e)
                                        });                                    }
                                }
                                3 => {
                                    for dst in &targets.dst_addresses {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_tcp(
                                            origin.clone(),
                                            IP::from(dst.clone()),
                                            client_id,
                                            is_ipv6,
                                            gcd,
                                            &info_url,
                                        ));
                                        cap.sendpacket(packet).unwrap_or_else(|e| {
                                            println!("Failed to send ICMP packet: {}", e)
                                        });
                                    }
                                }
                                _ => panic!("Invalid measurement type"), // Invalid measurement
                            }
                        }
                    }
                    Trace(trace) => {
                        perform_trace(
                            trace.origins,
                            is_ipv6,
                            ethernet_header.clone(),
                            &mut cap,
                            IP::from(trace.dst.expect("None IP address")),
                            client_id,
                            trace.max_ttl as u8,
                            measurement_type,
                            &info_url,
                        );
                        continue;
                    }
                    _ => continue, // Invalid measurement
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
/// * 'measurement_type' - the type of measurement being performed (1 = ICMP, 2 = UDP/DNS, 3 = TCP)
fn perform_trace(
    origins: Vec<Origin>,
    is_ipv6: bool,
    ethernet_header: Vec<u8>,
    cap: &mut Capture<pcap::Active>,
    dst: IP,
    client_id: u8,
    max_ttl: u8,
    measurement_type: u8,
    info_url: &str,
) { // TODO these are sent out in bursts, create a thread in here for the trace task to send them out 1 second after eachother
    if measurement_type > 3 {
        // Traceroute supported for ICMP, UDP, and TCP
        panic!("Invalid measurement type")
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

            if measurement_type == 1 { // ICMP
                let icmp = if is_ipv6 {
                    ICMPPacket::echo_request_v6(1, 2, payload_bytes, src.get_v6().into(), dst.get_v6().into(), i, info_url)
                } else {
                    ICMPPacket::echo_request(1, 2, payload_bytes, src.get_v4().into(), dst.get_v4().into(), i, info_url)
                };
                packet.extend_from_slice(&icmp); // ip header included
            } else if measurement_type == 2 { // UDP
                let udp = if is_ipv6 { // TODO encode TTL in the domain name
                    UDPPacket::dns_request_v6(src.get_v6().into(), dst.get_v6().into(), sport, "any.dnsjedi.org", tx_time, client_id, i)
                } else {
                    UDPPacket::dns_request(src.get_v4().into(), dst.get_v4().into(), sport, "any.dnsjedi.org", tx_time, client_id, i)
                };
                packet.extend_from_slice(&udp); // ip header included
            } else if measurement_type == 3 { // TCP
                // ACK: first 16 is the TTL, last 16 is the client ID
                let ack = (i as u32) << 16 | client_id as u32; // TODO test this
                let tcp = if is_ipv6 {
                    TCPPacket::tcp_syn_ack_v6(src.get_v6().into(), dst.get_v6().into(), sport, dport, 0, ack, i, info_url)
                } else {
                    TCPPacket::tcp_syn_ack(src.get_v4().into(), dst.get_v4().into(), sport, dport, 0, ack, i, info_url)
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
    finish_rx: futures::sync::oneshot::Receiver<()>,
) {
    thread::Builder::new()
        .name("abort_thread".to_string())
        .spawn(move || {
            finish_rx.wait().ok();
            *abort.lock().unwrap() = true;
        }).expect("Failed to spawn abort thread");
}
