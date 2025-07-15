use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::thread::sleep;
use std::time::Duration;

use tokio::sync::mpsc::{error::TryRecvError, Receiver};

use crate::custom_module;
use custom_module::manycastr::task::Data::{End, Targets};
use custom_module::manycastr::{task::Data, Origin};

use pnet::datalink::DataLinkSender;

use ratelimit_meter::{DirectRateLimiter, LeakyBucket};

use crate::net::packet::{create_icmp, create_tcp, create_dns, get_ethernet_header};

/// Spawns thread that sends out ICMP, DNS, or TCP probes.
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
/// * 'is_latency' - whether we are measuring latency
///
/// * 'measurement_id' - the unique ID of the current measurement
///
/// * 'measurement_type' - the type of measurement being performed (1 = ICMP, 2 = DNS/A, 3 = TCP, 4 = DNS/CHAOS)
///
/// * 'qname' - the domain name to use for DNS measurements
///
/// * 'info_url' - URL to encode in payload (e.g., opt-out URL)
///
/// * 'if_name' - the name of the network interface to use
///
/// * 'socket_tx' - the sender object to send packets
///
/// * 'probing_rate' - the rate at which to send packets (in packets per second)
pub fn outbound(
    worker_id: u16,
    tx_origins: Vec<Origin>,
    mut outbound_channel_rx: Receiver<Data>,
    finish_rx: Arc<AtomicBool>,
    is_ipv6: bool,
    is_latency: bool,
    measurement_id: u32,
    measurement_type: u8,
    qname: String,
    info_url: String,
    if_name: String,
    mut socket_tx: Box<dyn DataLinkSender>,
    probing_rate: u32,
) {
    thread::Builder::new()
        .name("outbound".to_string())
        .spawn(move || {
            let mut sent = 0;
            let mut sent_discovery = 0;
            let mut failed = 0;
            // Rate limit the number of packets sent per second, each origin has the same rate (i.e., sending with 2 origins will double the rate)
            let mut limiter = DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(probing_rate * tx_origins.len() as u32).unwrap());

            let ethernet_header = get_ethernet_header(is_ipv6, if_name);
            'outer: loop {
                if finish_rx.load(std::sync::atomic::Ordering::SeqCst) {
                    // If the finish_rx is set to true, break the loop (abort)
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
                            worker_id as u32 + u16::MAX as u32
                        } else {
                            worker_id as u32
                        };
                        for origin in &tx_origins {
                            match measurement_type {
                                1 => { // ICMP
                                    for dst in &targets.dst_list {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_icmp(
                                            origin,
                                            dst,
                                            worker_id,
                                            measurement_id,
                                            &info_url,
                                        ));

                                        // TODO re-implement rate limiting that works with non-deterministic packet sending (due to discovery probing)
                                        // while let Err(_) = limiter.check() { // Rate limit to avoid bursts
                                        //     sleep(Duration::from_millis(1));
                                        // }

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
                                2 | 4 => { // DNS A record or CHAOS
                                    for dst in &targets.dst_list {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_dns(
                                            origin,
                                            dst,
                                            worker_id,
                                            measurement_type,
                                            &qname,
                                        ));
                                        
                                        while let Err(_) = limiter.check() { // Rate limit to avoid bursts
                                            sleep(Duration::from_millis(1));
                                        }

                                        match socket_tx.send_to(&packet, None) {
                                            Some(Ok(())) => sent += 1,
                                            Some(Err(e)) => {
                                                eprintln!("[Worker outbound] Failed to send DNS packet: {}", e);
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
                                            is_latency,
                                            &info_url,
                                        ));

                                        while let Err(_) = limiter.check() { // Rate limit to avoid bursts
                                            sleep(Duration::from_millis(1));
                                        }

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
            println!("[Worker outbound] Outbound thread finished - packets sent : {} (including {} discovery probes)), packets failed to send: {}", sent + sent_discovery, sent_discovery, failed);
        })
        .expect("Failed to spawn outbound thread");
}
