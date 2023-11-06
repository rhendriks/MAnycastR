use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::net::{ICMPPacket, TCPPacket, UDPPacket};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use futures::Future;
use socket2::Socket;
use crate::custom_module;
use custom_module::IP;
use custom_module::verfploeter::{PingPayload, Task, address::Value::V4, address::Value::V6};
use custom_module::verfploeter::task::Data::{Ping, Tcp, Udp};

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
pub fn perform_ping(socket: Arc<Socket>, client_id: u8, source_addr: IP, mut outbound_channel_rx: tokio::sync::mpsc::Receiver<Task>, finish_rx: futures::sync::oneshot::Receiver<()>, _rate: u32, ipv6: bool) {
    println!("[Client outbound] Started pinging thread");
    let abort = Arc::new(Mutex::new(false));

    thread::spawn({
        let abort = abort.clone();

        // Waits for a possible abort
        move || {
            finish_rx.wait().ok();
            *abort.lock().unwrap() = true;
        }
    });

    thread::spawn({
        move || {
            loop {
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
                        Err(_e) => {
                            // wait some time and try again
                            thread::sleep(Duration::from_millis(100));
                        },
                    };
                }

                let task_data = match task.data {
                    None => {
                        break
                    }, // A None task data means the measurement has finished
                    Some(t) => t,
                };

                let ping = if let Ping(ping) = task_data { ping } else { continue };
                let dest_addresses = ping.destination_addresses;

                // Loop over the destination addresses
                for dest_addr in dest_addresses {
                    let transmit_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64;

                    // Create ping payload
                    let payload = PingPayload {
                        transmit_time,
                        source_address: Some(source_addr.clone().into()),
                        destination_address: Some(dest_addr.clone()),
                        sender_client_id: client_id as u32,
                    };

                    let mut bytes: Vec<u8> = Vec::new();
                    bytes.extend_from_slice(&task.task_id.to_be_bytes()); // Bytes 0 - 3
                    bytes.extend_from_slice(&payload.transmit_time.to_be_bytes()); // Bytes 4 - 11
                    bytes.extend_from_slice(&payload.sender_client_id.to_be_bytes()); // Bytes 12 - 15
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

                    let bind_addr_dest = if ipv6 {
                        format!("[{}]:0", IP::from(dest_addr.clone()).to_string())
                    } else {
                        format!("{}:0", IP::from(dest_addr.clone()).to_string())
                    };

                    let icmp = if ipv6 {
                        ICMPPacket::echo_request_v6(1, 2, bytes)
                    } else {
                        ICMPPacket::echo_request(1, 2, bytes)
                    };

                    println!("[Client outbound] Sending ICMP packet with source {} to socket", bind_addr_dest);

                    // Send out packet
                    if let Err(e) = socket.send_to(
                        &icmp,
                        &bind_addr_dest
                            .to_string()
                            .parse::<SocketAddr>()
                            .unwrap()
                            .into(),
                    ) {
                        error!("Failed to send ICMP packet with source {} to socket: {:?}", bind_addr_dest, e);
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
pub fn perform_udp(socket: Arc<Socket>, client_id: u8, source_address: IP, source_port: u16, mut outbound_channel_rx: tokio::sync::mpsc::Receiver<Task>, finish_rx: futures::sync::oneshot::Receiver<()>, _rate: u32, ipv6: bool, task_type: u32) {
    println!("[Client outbound] Started UDP probing thread");

    let abort = Arc::new(Mutex::new(false));

    thread::spawn({
        let abort = abort.clone();

        move || {
            finish_rx.wait().ok();
            *abort.lock().unwrap() = true;
        }
    });

    thread::spawn({
        move || {
            loop {
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
                        Err(_e) => {
                            // wait some time and try again
                            thread::sleep(Duration::from_millis(100));
                        },
                    };
                }

                let task_data = match task.data {
                    None => break, // A None task data means the measurement has finished
                    Some(t) => t,
                };

                let udp = if let Udp(udp) = task_data { udp } else { continue };
                let dest_addresses = udp.destination_addresses;

                // Loop over the destination addresses
                for dest_addr in dest_addresses {
                    let transmit_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64;

                    let bind_addr_dest = if ipv6 {
                        format!("[{}]:0", IP::from(dest_addr.clone()).to_string())
                    } else {
                        format!("{}:0", IP::from(dest_addr.clone()).to_string())
                    };

                    let udp = if ipv6 {
                        let source = source_address.get_v6();
                        let dest = IP::from(dest_addr.clone()).get_v6();

                        if task_type == 2 {
                            UDPPacket::dns_request_v6(source.into(), dest.into(), source_port, Vec::new(), "any.dnsjedi.org", transmit_time, client_id)
                        } else if task_type == 4 {
                            UDPPacket::chaos_request(source_address, IP::from(dest_addr), source_port, Vec::new(), client_id)
                        } else {
                            panic!("Invalid task type")
                        }
                    } else {
                        let source =source_address.get_v4();
                        let dest = IP::from(dest_addr.clone()).get_v4();

                        if task_type == 2 {
                            UDPPacket::dns_request(source.into(), dest.into(), source_port, Vec::new(), "any.dnsjedi.org", transmit_time, client_id)
                        } else if task_type == 4 {
                            UDPPacket::chaos_request(source_address, IP::from(dest_addr), source_port, Vec::new(), client_id)
                        } else {
                            panic!("Invalid task type")
                        }
                    };

                    // Send out packet
                    if let Err(e) = socket.send_to(
                        &udp,
                        &bind_addr_dest
                            .to_string()
                            .parse::<SocketAddr>()
                            .unwrap()
                            .into(),
                    ) {
                        error!("Failed to send UDP packet with source {} to socket: {:?}", bind_addr_dest, e);
                    }
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
pub fn perform_tcp(socket: Arc<Socket>, source_address: IP, destination_port: u16, source_port: u16, mut outbound_channel_rx: tokio::sync::mpsc::Receiver<Task>, finish_rx: futures::sync::oneshot::Receiver<()>, _rate: u32, ipv6: bool) {
    println!("[Client outbound] Started TCP probing thread using source address {:?}", source_address.to_string());

    let abort = Arc::new(Mutex::new(false));

    thread::spawn({
        let abort = abort.clone();

        move || {
            finish_rx.wait().ok();
            *abort.lock().unwrap() = true;
        }
    });

    thread::spawn({
        move || {
            loop {
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
                        Err(_e) => {
                            // wait some time and try again
                            thread::sleep(Duration::from_millis(100));
                        },
                    };
                }

                let task_data = match task.data {
                    None => break, // A None task data means the measurement has finished
                    Some(t) => t,
                };

                let tcp = if let Tcp(tcp) = task_data { tcp } else { continue };
                let dest_addresses = tcp.destination_addresses;

                // Loop over the destination addresses
                for dest_addr in dest_addresses {
                    let transmit_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u32; // The least significant bits are kept

                    let bind_addr_dest = if ipv6 {
                        format!("[{}]:0", IP::from(dest_addr.clone()).to_string())
                    } else {
                        format!("{}:0", IP::from(dest_addr.clone()).to_string())
                    };

                    let seq = task.task_id; // information in seq gets lost
                    let ack = transmit_time; // ack information gets returned as seq

                    let tcp = if ipv6 {
                        let source = match IP::from(source_address) {
                            IP::V6(v6) => v6,
                            _ => panic!("Destination address is not IPv6")
                        };
                        let dest = match IP::from(dest_addr) {
                            IP::V6(v6) => v6,
                            _ => panic!("Source address is not IPv6")
                        };

                        TCPPacket::tcp_syn_ack_v6(source.into(), dest.into(), source_port, destination_port, seq, ack, Vec::new())
                    } else {
                        let source = match IP::from(source_address) {
                            IP::V4(v4) => v4,
                            _ => panic!("Destination address is not IPv4")
                        };
                        let dest = match IP::from(dest_addr) {
                            IP::V4(v4) => v4,
                            _ => panic!("Source address is not IPv4")
                        };

                        TCPPacket::tcp_syn_ack(source.into(), dest.into(), source_port, destination_port, seq, ack, Vec::new())
                    };

                    // Send out packet
                    if let Err(e) = socket.send_to(
                        &tcp,
                        &bind_addr_dest
                            .to_string()
                            .parse::<SocketAddr>()
                            .unwrap()
                            .into(),
                    ) {
                        error!("Failed to send TCP packet with source {} to socket: {:?}", bind_addr_dest, e);
                    }
                }
            }
            debug!("finished TCP probing");

            println!("[Client outbound] TCP Outbound thread finished");
        }
    });
}
