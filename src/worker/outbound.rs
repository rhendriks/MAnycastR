use std::thread;
use std::time::Duration;

use tokio::sync::mpsc::{error::TryRecvError, Receiver};

use crate::custom_module;
use custom_module::manycastr::task::Data::{End, Targets};
use custom_module::manycastr::{task::Data, Origin};
use custom_module::IP;

use pnet::datalink::DataLinkSender;

use crate::net::packet::{create_ping, create_tcp, create_udp, get_ethernet_header};

/// Spawns thread that sends out ICMP, UDP, or TCP probes.
///
/// # Arguments
///
/// * 'worker_id' - the unique worker ID of this worker
///
/// * 'tx_origins' - the unique source addresses and port combinations we use for our probes
///
/// * 'outbound_channel_rx' - on this channel we receive future tasks that are part of the current measurement
///
/// * 'finish_rx' - used to exit or abort the measurement upon receiving the signal from the Orchestrator
///
/// * 'is_ipv6' - whether we are using IPv6 or not
///
/// * 'is_unicast' - whether we are sending probes with unicast or anycast
///
/// * 'measurement_id' - the unique ID of the current measurement
///
/// * 'measurement_type' - the type of measurement being performed (1 = ICMP, 2 = UDP/DNS, 3 = TCP, 4 = UDP/CHAOS)
///
/// * 'qname' - the domain name to use for DNS measurements
///
/// * 'info_url' - URL to encode in payload (e.g., opt-out URL)
///
/// * 'if_name' - the name of the network interface to use
///
/// * 'socket_tx' - the sender object to send packets
pub fn outbound(
    worker_id: u16,
    tx_origins: Vec<Origin>,
    mut outbound_channel_rx: Receiver<Data>,
    mut finish_rx: futures::channel::oneshot::Receiver<()>,
    is_ipv6: bool,
    is_unicast: bool,
    measurement_id: u32,
    measurement_type: u8,
    qname: String,
    info_url: String,
    if_name: String,
    mut socket_tx: Box<dyn DataLinkSender>,
) {
    thread::Builder::new()
        .name("outbound".to_string())
        .spawn(move || {
            let mut sent = 0;
            let mut failed = 0;
            let ethernet_header = get_ethernet_header(is_ipv6, if_name.clone());
            'outer: loop {
                if let Ok(Some(())) = finish_rx.try_recv() {
                    // If the finish_rx received a signal, break the loop (abort)
                    println!("[Worker outbound] ABORTING");
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
                                println!("[Worker outbound] Channel disconnected");
                                break 'outer;
                            }
                            // wait some time and try again
                            thread::sleep(Duration::from_millis(100));
                        }
                    };
                }

                match task {
                    End(_) => {
                        // An End task means the measurement has finished
                        break;
                    }
                    Targets(targets) => {
                        for origin in &tx_origins {
                            match measurement_type {
                                1 => { // ICMP
                                    for dst in &targets.dst_addresses {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_ping(
                                            origin.clone(),
                                            IP::from(dst.clone()),
                                            worker_id,
                                            measurement_id,
                                            &info_url,
                                        ));

                                        match socket_tx.send_to(&packet, None) {
                                            Some(Ok(())) => sent += 1,
                                            Some(Err(e)) => {
                                                eprintln!("[Worker outbound] Failed to send ICMP packet: {}", e);
                                                failed += 1;
                                            },
                                            None => eprintln!("[Worker outbound] Failed to send packet: No Tx interface"),
                                        }
                                    }
                                }
                                2 | 4 => { // UDP or UDP/CHAOS
                                    for dst in &targets.dst_addresses {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_udp(
                                            origin.clone(),
                                            IP::from(dst.clone()),
                                            worker_id,
                                            measurement_type,
                                            is_ipv6,
                                            &qname.clone(),
                                        ));

                                        match socket_tx.send_to(&packet, None) {
                                            Some(Ok(())) => sent += 1,
                                            Some(Err(e)) => {
                                                eprintln!("[Worker outbound] Failed to send UDP packet: {}", e);
                                                failed += 1;
                                            },
                                            None => eprintln!("[Worker outbound] Failed to send packet: No Tx interface"),
                                        }
                                    }
                                }
                                3 => { // TCP
                                    for dst in &targets.dst_addresses {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_tcp(
                                            origin.clone(),
                                            IP::from(dst.clone()),
                                            worker_id,
                                            is_ipv6,
                                            is_unicast,
                                            &info_url,
                                        ));

                                        match socket_tx.send_to(&packet, None) {
                                            Some(Ok(())) => sent += 1,
                                            Some(Err(e)) => {
                                                eprintln!("[Worker outbound] Failed to send TCP packet: {}", e);
                                                failed += 1;
                                            },
                                            None => eprintln!("[Worker outbound] Failed to send packet: No Tx interface"),
                                        }
                                    }
                                }
                                255 => {
                                    // TODO all
                                }
                                _ => panic!("Invalid measurement type"), // Invalid measurement
                            }
                        }
                    }
                    _ => continue, // Invalid measurement
                };
            }
            println!("[Worker outbound] Outbound thread finished - packets sent: {}, packets failed to send: {}", sent, failed);
        })
        .expect("Failed to spawn outbound thread");
}
