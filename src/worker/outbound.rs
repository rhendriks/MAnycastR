use std::num::NonZeroU32;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::thread::sleep;
use std::time::Duration;

use tokio::sync::mpsc::{error::TryRecvError, Receiver};

use crate::custom_module;
use custom_module::manycastr::task::Data::{End, Targets};
use custom_module::manycastr::{task::Data, Origin};

use pnet::datalink::DataLinkSender;

use crate::custom_module::Separated;
use crate::net::packet::{create_dns, create_icmp, create_tcp, get_ethernet_header};
use ratelimit_meter::{DirectRateLimiter, LeakyBucket};

const DISCOVERY_WORKER_ID_OFFSET: u32 = u16::MAX as u32;

/// Configuration for the outbound worker thread.
///
/// This struct contains all the necessary parameters to configure the outbound worker thread.
/// It includes the worker ID, the origins for sending probes, the abort signal, whether to
/// use IPv6, whether to measure latency, the measurement ID, the measurement type,
/// the query name for DNS measurements, the info URL to encode in the payload,
/// the network interface name, and the probing rate.
pub struct OutboundConfig {
    pub worker_id: u16,
    pub tx_origins: Vec<Origin>,
    pub abort_s: Arc<AtomicBool>,
    pub is_ipv6: bool,
    pub is_latency: bool,
    pub m_id: u32,
    pub m_type: u8,
    pub qname: String,
    pub info_url: String,
    pub if_name: String,
    pub probing_rate: u32,
}

/// Spawns thread that sends out ICMP, DNS, or TCP probes.
///
/// # Arguments
///
/// * 'config' - configuration for the outbound worker thread
///
/// * 'outbound_rx' - on this channel we receive future tasks that are part of the current measurement
///
/// * 'socket_tx' - the sender object to send packets
pub fn outbound(
    config: OutboundConfig,
    mut outbound_rx: Receiver<Data>,
    mut socket_tx: Box<dyn DataLinkSender>,
) {
    thread::Builder::new()
        .name("outbound".to_string())
        .spawn(move || {
            let mut sent: u32 = 0;
            let mut sent_discovery = 0;
            let mut failed : u32= 0;
            // Rate limit the number of packets sent per second, each origin has the same rate (i.e., sending with 2 origins will double the rate)
            let mut limiter = DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(config.probing_rate * config.tx_origins.len() as u32).unwrap());

            let ethernet_header = get_ethernet_header(config.is_ipv6, config.if_name);
            'outer: loop {
                if config.abort_s.load(std::sync::atomic::Ordering::SeqCst) {
                    // If the finish_rx is set to true, break the loop (abort)
                    println!("[Worker outbound] ABORTING");
                    break;
                }
                let task;
                // Receive tasks from the outbound channel
                loop {
                    match outbound_rx.try_recv() {
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
                            config.worker_id as u32 + DISCOVERY_WORKER_ID_OFFSET
                        } else {
                            config.worker_id as u32
                        };
                        for origin in &config.tx_origins {
                            match config.m_type {
                                1 => { // ICMP
                                    for dst in &targets.dst_list {
                                        let mut packet = ethernet_header.clone();
                                        packet.extend_from_slice(&create_icmp(
                                            origin,
                                            dst,
                                            worker_id,
                                            config.m_id,
                                            &config.info_url,
                                        ));

                                        while limiter.check().is_err() { // Rate limit to avoid bursts
                                            sleep(Duration::from_millis(1));
                                        }

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
                                            config.m_type,
                                            &config.qname,
                                        ));
                                        while limiter.check().is_err() { // Rate limit to avoid bursts
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
                                            config.is_latency,
                                            &config.info_url,
                                        ));

                                        while limiter.check().is_err() { // Rate limit to avoid bursts
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
                                    panic!("Invalid measurement type)") // TODO all
                                }
                                _ => panic!("Invalid measurement type"), // Invalid measurement
                            }
                        }
                    }
                    _ => continue, // Invalid measurement
                };
            }
            println!("[Worker outbound] Outbound thread finished - packets sent : {} (including {} discovery probes), packets failed to send: {}", sent.with_separator(), sent_discovery.with_separator(), failed.with_separator());
        })
        .expect("Failed to spawn outbound thread");
}
