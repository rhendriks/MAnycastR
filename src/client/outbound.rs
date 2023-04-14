use ratelimit_meter::{DirectRateLimiter, LeakyBucket};
use std::num::NonZeroU32;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::net::{ICMP4Packet, TCPPacket, UDPPacket};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use futures::Future;
use tokio::sync::oneshot::Receiver;
use socket2::Socket;
use crate::client::verfploeter::{PingPayload, Task};
use crate::client::verfploeter::task::Data::{Ping, Tcp, Udp};

/// Performs a ping/ICMP task by sending out ICMP ECHO Requests with a custom payload.
///
/// This payload contains the client ID of this prober, transmission time, source and destination address, and the task ID of the current measurement.
///
/// We notify the receiver that it is finished 10 seconds after the last packet is sent.
///
/// # Arguments
///
/// * 'socket' - the socket to send the probes from
///
/// * 'rx_f' - channel that we close when we are done probing, to notify the inbound listener that we are finished
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'source_addr' - the source address we use in our probes
///
/// * 'outbound_channel_rx' - on this channel we receive future tasks that are part of the current measurement
///
/// * 'finish_rx' - used to abort the measurement
///
/// * 'rate' - the number of probes to send out each second
pub fn perform_ping(socket: Arc<Socket>, mut rx_f: Receiver<()>, client_id: u8, source_addr: u32, mut outbound_channel_rx: tokio::sync::mpsc::Receiver<Task>, finish_rx: futures::sync::oneshot::Receiver<()>, rate: u32) {
    println!("[Client outbound] Started pinging thread");
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
            // Rate limiter, to avoid server tasks being sent out in bursts (amount of packets per second)
            let mut lb = DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(rate).unwrap());

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
                        source_address: source_addr,
                        destination_address: dest_addr,
                        sender_client_id: client_id as u32,
                    };

                    let mut bytes: Vec<u8> = Vec::new();
                    bytes.extend_from_slice(&task.task_id.to_be_bytes()); // Bytes 0 - 3
                    bytes.extend_from_slice(&payload.transmit_time.to_be_bytes()); // Bytes 4 - 11
                    bytes.extend_from_slice(&payload.source_address.to_be_bytes()); // Bytes 12 - 15
                    bytes.extend_from_slice(&payload.destination_address.to_be_bytes()); // Bytes 16 - 19
                    bytes.extend_from_slice(&payload.sender_client_id.to_be_bytes()); // Bytes 20 - 23

                    let bind_addr_dest = format!("{}:0", Ipv4Addr::from(dest_addr).to_string());

                    let icmp = ICMP4Packet::echo_request(1, 2, bytes);

                    // Rate limiting
                    while let Err(_) = lb.check() {
                        thread::sleep(Duration::from_millis(1));
                    }

                    // println!("Sending packet to {} at time {}", bind_addr_dest, transmit_time);

                    // Send out packet
                    if let Err(e) = socket.send_to(
                        &icmp,
                        &bind_addr_dest
                            .to_string()
                            .parse::<SocketAddr>()
                            .unwrap()
                            .into(),
                    ) {
                        error!("Failed to send packet to socket: {:?}", e);
                    } else {
                        // println!("[Client outbound] Packet sent!");
                    }
                }
            }
            debug!("finished ping");

            // All packets have been sent for this task, give the listener 10 seconds for the replies
            if *abort.lock().unwrap() == false { // Unless if we aborted, then we don't wait
                thread::sleep(Duration::from_secs(10));
            }
            // Now close down the listener
            rx_f.close();
            println!("[Client outbound] Outbound thread finished");
        }
    });
}

/// Performs a UDP DNS task by sending out DNS A Record requests with a custom domain name.
///
/// This domain name contains the transmission time, the client ID of the prober, the task ID of the current task, and the source and destination address of the probe.
///
/// We notify the receiver that it is finished 10 seconds after the last packet is sent.
///
/// # Arguments
///
/// * 'socket' - the socket to send the probes from
///
/// * 'rx_f' - channel that we close when we are done probing, to notify the inbound listener that we are finished
///
/// * 'client_id' - the unique client ID of this client
///
/// * 'source_addr' - the source address we use in our probes
///
/// * 'source_port' - the source port we use in our probes
///
/// * 'outbound_channel_rx' - on this channel we receive future tasks that are part of the current measurement
///
/// * 'finish_rx' - used to abort the measurement
///
/// * 'rate' - the number of probes to send out each second
pub fn perform_udp(socket: Arc<Socket>, mut rx_f: Receiver<()>, client_id: u8, source_address: u32, source_port: u16, mut outbound_channel_rx: tokio::sync::mpsc::Receiver<Task>, finish_rx: futures::sync::oneshot::Receiver<()>, rate: u32) {
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
            // Rate limiter
            let mut lb = DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(rate).unwrap());

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

                    let bind_addr_dest = format!("{}:{}", Ipv4Addr::from(dest_addr).to_string(), source_port.to_string());

                    let udp = UDPPacket::dns_request(source_address, dest_addr, source_port, Vec::new(), "google.com", transmit_time, client_id);

                    // Rate limiting
                    while let Err(_) = lb.check() {
                        println!("Checking");
                        thread::sleep(Duration::from_millis(1));
                    }

                    // Send out packet
                    if let Err(e) = socket.send_to(
                        &udp,
                        &bind_addr_dest
                            .to_string()
                            .parse::<SocketAddr>()
                            .unwrap()
                            .into(),
                    ) {
                        error!("Failed to send UDP packet to socket: {:?}", e);
                    } else {
                        // println!("[Client outbound] Packet sent!");
                    }
                }
            }
            debug!("finished udp probing");

            // All packets have been sent for this task, give the listener 10 seconds for the replies
            thread::sleep(Duration::from_secs(10));
            // Now close down the listener
            rx_f.close();
            println!("[Client outbound] UDP Outbound thread finished");
        }
    });
}

/// Performs a TCP task by sending out TCP SYN/ACK probes with a custom port and ACK value.
///
/// The destination port uses a constant value with the client ID added, the ACK value has the current millis encoded into it.
///
/// We notify the receiver that it is finished 10 seconds after the last packet is sent.
///
/// # Arguments
///
/// * 'socket' - the socket to send the probes from
///
/// * 'rx_f' - channel that we close when we are done probing, to notify the inbound listener that we are finished
///
/// * 'source_addr' - the source address we use in our probes
///
/// * 'destination_port' - the destination port we use in our probes
///
/// * 'source_port' - the source port we use in our probes
///
/// * 'outbound_channel_rx' - on this channel we receive future tasks that are part of the current measurement
///
/// * 'finish_rx' - used to abort the measurement
///
/// * 'rate' - the number of probes to send out each second
pub fn perform_tcp(socket: Arc<Socket>, mut rx_f: Receiver<()>, source_addr: u32, destination_port: u16, source_port: u16, mut outbound_channel_rx: tokio::sync::mpsc::Receiver<Task>, finish_rx: futures::sync::oneshot::Receiver<()>, rate: u32) {
    println!("[Client outbound] Started TCP probing thread using source address {:?}", source_addr);

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
            // Rate limiter
            let mut lb = DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(rate).unwrap());

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

                    let bind_addr_dest = format!("{}:{}", Ipv4Addr::from(dest_addr).to_string(), destination_port.to_string());

                    let seq = task.task_id; // information in seq gets lost
                    let ack = transmit_time; // ack information gets returned as seq

                    let tcp = TCPPacket::tcp_syn_ack(source_addr, dest_addr, source_port, destination_port, seq, ack, Vec::new());

                    // Rate limiting
                    while let Err(_) = lb.check() {
                        thread::sleep(Duration::from_millis(1));
                    }

                    // Send out packet
                    if let Err(e) = socket.send_to(
                        &tcp,
                        &bind_addr_dest
                            .to_string()
                            .parse::<SocketAddr>()
                            .unwrap()
                            .into(),
                    ) {
                        error!("Failed to send TCP packet to socket: {:?}", e);
                    } else {
                        // println!("[Client outbound] Packet sent!");
                    }
                }
            }
            debug!("finished TCP probing");

            // All packets have been sent for this task, give the listener 10 seconds for the replies
            thread::sleep(Duration::from_secs(10));
            // Now close down the listener
            rx_f.close();
            println!("[Client outbound] TCP Outbound thread finished");
        }
    });
}