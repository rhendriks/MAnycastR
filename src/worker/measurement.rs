use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::{
    Finished, Instruction, MeasurementType, Origin, ProtocolType, ReplyBatch,
};
use crate::worker::config::{set_unicast_origins, Worker};
use crate::worker::inbound::{inbound, InboundConfig};
use crate::worker::outbound::{outbound, OutboundConfig};
use log::{error, info, warn};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

impl Worker {
    /// Initialize a new measurement by creating outbound and inbound threads, and ensures task results are sent back to the orchestrator.
    ///
    /// Extracts the protocol type from the measurement definition, and determines which source address to use.
    /// Creates a socket to send out probes and receive replies with, calls the appropriate inbound & outbound functions.
    /// Creates an additional thread that forwards task results to the orchestrator.
    ///
    /// # Arguments
    /// * `instruction` - Instruction containing a definition for a new measurement
    /// * `worker_id` - the unique ID of this worker
    /// * `abort_outbound` - Forcefully signal the outbound thread to stop sending probes
    pub(crate) fn init(
        &mut self,
        instruction: Instruction,
        worker_id: u16,
        abort_outbound: Arc<AtomicBool>,
    ) -> Result<(), Box<dyn Error>> {
        let start = match instruction.instruction_type {
            Some(InstructionType::Start(s)) => s,
            _ => return Err("Received non-start packet for init".into()),
        };

        let m_id = start.m_id;
        let is_ipv6 = start.is_ipv6;
        let m_type = start.m_type();

        // Channel for sending from inbound to the orchestrator forwarder thread
        let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::unbounded_channel();

        // Replace unspecified unicast addresses in rx_origins, tx_origins with local addresses
        let rx_origins = set_unicast_origins(start.rx_origins, is_ipv6);
        let tx_origins = set_unicast_origins(start.tx_origins, is_ipv6);
        let tx_origin_ids: std::collections::HashSet<_> =
            tx_origins.iter().map(|o| o.origin_id).collect();

        let is_traceroute = m_type == MeasurementType::AnycastTraceroute;
        let needs_raw = is_traceroute || start.is_record;

        // Start inbound/outbound threads for each origin
        for rx_origin in rx_origins {
            let (socket, is_dgram) =
                Self::get_socket(is_ipv6, rx_origin.p_type(), rx_origin, needs_raw);

            inbound(
                InboundConfig {
                    m_id,
                    worker_id,
                    p_type: rx_origin.p_type(),
                    abort_s: self.abort_inbound.clone(),
                    is_traceroute,
                    is_record: start.is_record,
                    is_dgram,
                    origin_id: rx_origin.origin_id,
                    sport: rx_origin.sport as u16,
                    src: rx_origin.src.expect("no src").to_string(),
                },
                inbound_tx.clone(),
                socket.clone(),
            );

            // See if this origin_id is in tx_origins
            if tx_origin_ids.contains(&rx_origin.origin_id) {
                self.log_probe_details(&rx_origin);

                // Channel for forwarding tasks to outbound
                let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(1000);
                self.outbound_txs.push(outbound_tx);

                outbound(
                    OutboundConfig {
                        worker_id,
                        abort_outbound: abort_outbound.clone(),
                        m_id,
                        p_type: rx_origin.p_type(),
                        qname: start.record.clone(),
                        info_url: start.url.clone(),
                        probing_rate: start.rate / tx_origins.len() as u32, // Adjust probing rate for multiple origins
                        is_record: start.is_record,
                        is_dgram,
                        src: rx_origin.src.unwrap(),
                        sport: rx_origin.sport as u16,
                        dport: rx_origin.dport as u16,
                        origin_id: rx_origin.origin_id,
                    },
                    outbound_rx,
                    socket,
                );
            }
        }

        // Spawn thread to forward reply batches to the CLI
        let m_id_handle = self.current_m_id.clone();
        let mut grpc_client_clone = self.grpc_client.clone();
        tokio::spawn(async move {
            while let Some(batch) = inbound_rx.recv().await {
                if batch == ReplyBatch::default() {
                    // Set the current measurement ID to None (no active measurement)
                    if let Ok(mut guard) = m_id_handle.lock() {
                        *guard = None;
                    }
                    info!("[Worker] Letting the orchestrator know that this worker finished the measurement");
                    let _ = grpc_client_clone
                        .measurement_finished(Finished {
                            m_id,
                            worker_id: worker_id.into(),
                        })
                        .await;
                    break;
                }

                if let Err(e) = grpc_client_clone.send_result(batch).await {
                    error!("[Worker] Failed to forward batch: {e}");
                    break;
                }
            }
            inbound_rx.close();
        });

        Ok(())
    }

    /// Print the Origins (i.e., source address and port values) used for this measurement
    ///
    /// # Arguments
    /// * `p_type` - Protocol used
    /// * `origins` - Sending origins used by this Worker
    fn log_probe_details(&self, origin: &Origin) {
        match origin.p_type() {
            ProtocolType::Icmp => info!(
                "[Worker] Sending {} on: {} using ICMP ID {}",
                origin.p_type(),
                origin.src.unwrap(),
                origin.dport
            ),
            _ => info!(
                "[Worker] Sending {} on: {}, {}:{}",
                origin.p_type(),
                origin.src.unwrap(),
                origin.sport,
                origin.dport
            ),
        }
    }

    /// Obtain a socket.
    /// Type of socket depends on the IP version (IPv4 or IPv6)
    /// And the protocol type (ICMP, UDP, TCP)
    ///
    /// For ICMP measurements that don't need raw socket features (traceroute TTL,
    /// Record Route IP options, TCP SYN/ACK), tries a SOCK_DGRAM ICMP socket first.
    /// This allows ICMP probing without sudo on Linux (when ping_group_range is set).
    /// Falls back to SOCK_RAW if DGRAM creation fails.
    ///
    /// # Arguments
    /// * `is_ipv6` - IP version used (true: IPv6)
    /// * `p_type` - Protocol type used (ICMP, UDP, or TCP)
    /// * `origin` - Origin used in this measurement (anycast or local unicast address)
    /// * `needs_raw` - Whether the measurement requires raw socket features
    ///
    /// # Returns
    /// (Arc<Socket>, bool) containing a Socket and whether it is a DGRAM socket
    fn get_socket(
        is_ipv6: bool,
        p_type: ProtocolType,
        origin: Origin,
        needs_raw: bool,
    ) -> (Arc<Socket>, bool) {
        let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };

        let protocol = match p_type {
            ProtocolType::Icmp => {
                if is_ipv6 {
                    Protocol::ICMPV6
                } else {
                    Protocol::ICMPV4
                }
            }
            ProtocolType::Tcp => Protocol::TCP,
            ProtocolType::ADns | ProtocolType::ChaosDns => Protocol::UDP,
        };

        let addr: IpAddr = (origin.src.as_ref().expect("no src")).into();

        // Prefer dgram sockets for ICMP for performance (ICMP identifier filtering in kernel)
        // TODO prefer raw sockets (for custom IP identifiers) after implementing eBPF filter
        // TODO UDP/DNS can use dgram? (TCP SYNACK requires raw?)
        let (socket, is_dgram) = if p_type == ProtocolType::Icmp && !needs_raw {
            let bind_addr = SockAddr::from(SocketAddr::new(addr, origin.dport as u16));
            match Self::try_dgram_socket(domain, protocol, &bind_addr, is_ipv6) {
                Some(s) => {
                    info!("[Worker] Using unprivileged ICMP socket (no sudo required)");
                    (s, true)
                }
                None => {
                    warn!(
                        "[Worker] Unprivileged ICMP socket unavailable, falling back to raw socket"
                    );
                    (Self::raw_socket(domain, protocol, is_ipv6), false)
                }
            }
        } else {
            (Self::raw_socket(domain, protocol, is_ipv6), false)
        };

        if !is_dgram {
            let sock_addr = SockAddr::from(SocketAddr::new(addr, origin.sport as u16));
            socket
                .bind(&sock_addr)
                .expect("Failed to bind socket to address.");
        }

        // TODO Attach BPF filter (filter on TCP RST, port values for TCP/UDP, and m_ids encoded in packets)

        socket.set_send_buffer_size(4 * 1024 * 1024).ok(); // 4 MB buffer for sending
        socket.set_recv_buffer_size(16 * 1024 * 1024).ok(); // 16 MB for receiving

        unsafe { // TODO no API for SO_TIMESTAMP in socket2
            let val: libc::c_int = 1;
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMP,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(1)))
            .expect("Failed to set read timeout");

        (Arc::new(socket), is_dgram)
    }

    /// Try to create a DGRAM ICMP socket (unprivileged).
    /// Returns None if creation or setup fails.
    fn try_dgram_socket(
        domain: Domain,
        protocol: Protocol,
        bind_addr: &SockAddr,
        is_ipv6: bool,
    ) -> Option<Socket> {
        let socket = Socket::new(domain, Type::DGRAM, Some(protocol)).ok()?;
        socket.bind(bind_addr).ok()?;

        if is_ipv6 {
            socket.set_recv_hoplimit_v6(true).ok()?;
        } else {
            Self::set_recv_ttl_v4(&socket).ok()?;
        }

        Some(socket)
    }

    /// Create a RAW socket with IP_HDRINCL and appropriate options.
    fn raw_socket(domain: Domain, protocol: Protocol, is_ipv6: bool) -> Socket {
        let socket = Socket::new(domain, Type::RAW, Some(protocol))
            .expect("Failed to create raw socket. sudo or raw socket permissions required");

        if is_ipv6 {
            socket
                .set_recv_hoplimit_v6(true)
                .expect("Failed to set recv_hop_limit");
            socket
                .set_header_included_v6(true)
                .expect("Failed to set header_included_v6");
        } else {
            socket
                .set_header_included_v4(true)
                .expect("Failed to set header_included");
        }

        socket
    }

    /// Enable IP_RECVTTL on an IPv4 socket so TTL arrives as ancillary data.
    #[cfg(unix)]
    fn set_recv_ttl_v4(socket: &Socket) -> std::io::Result<()> {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let val: libc::c_int = 1;
        let ret = unsafe { // TODO unsafe
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVTTL,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}
