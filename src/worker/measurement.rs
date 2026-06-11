use crate::custom_module::manycastr::{
    Finished, MeasurementType, Origin, ProtocolType, ReplyBatch, Start,
};
use crate::dns_identifier;
use crate::worker::bpf::{
    attach_dns_filter, attach_icmp_filter, attach_tcp_filter, attach_traceroute_filter,
};
use crate::worker::config::{Worker, set_unicast_origins};
use crate::worker::inbound::{InboundConfig, inbound};
use crate::worker::outbound::{OutboundConfig, outbound};
use log::{error, info, warn};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

impl Worker {
    /// Initialize a new measurement by creating outbound and inbound threads, and ensures task results are sent back to the orchestrator.
    ///
    /// Extracts the protocol type from the measurement definition, and determines which source address to use.
    /// Creates a socket to send out probes and receive replies with, calls the appropriate inbound & outbound functions.
    /// Creates an additional thread that forwards task results to the orchestrator.
    ///
    /// # Arguments
    /// * `start` - Definition of the new measurement
    /// * `worker_id` - the unique ID of this worker
    /// * `abort_outbound` - Forcefully signal the outbound thread to stop sending probes
    pub(crate) fn init(
        &mut self,
        start: Start,
        worker_id: u16,
        abort_outbound: Arc<AtomicBool>,
    ) -> Result<(), Box<dyn Error>> {
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

        // Start inbound/outbound threads for each origin
        for rx_origin in rx_origins {
            let is_transport_traceroute =
                is_traceroute && !matches!(rx_origin.p_type(), ProtocolType::Icmp);

            // UDP/TCP (Paris) traceroute uses two sockets (ICMP and UDP/TCP)
            let (rx_socket, tx_socket, is_dgram) = if is_transport_traceroute {
                let (rx, _) = Self::get_socket(
                    is_ipv6,
                    ProtocolType::Icmp,
                    rx_origin,
                    true, // Attaches Time Exceeded + Dest Unreachable BPF filter
                    false,
                    m_id,
                );
                let (tx, _) = Self::get_socket(
                    is_ipv6,
                    rx_origin.p_type(),
                    rx_origin,
                    true, // forces a raw socket (TTL + checksum control)
                    false,
                    m_id,
                );
                (rx, tx, false)
            } else {
                let (socket, is_dgram) = Self::get_socket(
                    is_ipv6,
                    rx_origin.p_type(),
                    rx_origin,
                    is_traceroute,
                    start.is_record,
                    m_id,
                );
                (socket.clone(), socket, is_dgram)
            };

            let inbound_config = InboundConfig {
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
                is_transport_trace: false,
            };

            // For transport traceroute, listen on the raw transport socket for discovery replies
            if is_transport_traceroute {
                inbound(
                    InboundConfig {
                        is_traceroute: false, // parse as normal DNS/TCP discovery replies
                        is_record: false,
                        is_dgram: false, // raw transport socket
                        is_transport_trace: true,
                        ..inbound_config.clone()
                    },
                    inbound_tx.clone(),
                    tx_socket.clone(),
                );
            }

            // Primary listener (ICMP trace replies for transport traceroute)
            inbound(inbound_config, inbound_tx.clone(), rx_socket);

            // See if this origin_id is in tx_origins
            if tx_origin_ids.contains(&rx_origin.origin_id) {
                self.log_probe_details(&rx_origin);

                // Channel for forwarding tasks to outbound
                let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(1000);
                self.outbound_txs.push((rx_origin.origin_id, outbound_tx));

                let outbound_handle = outbound(
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
                    tx_socket,
                );
                self.outbound_handles.push(outbound_handle);
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
                    info!(
                        "[Worker] Letting the orchestrator know that this worker finished the measurement"
                    );
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
    /// ICMP and TCP prefer SOCK_RAW (plain ICMP echo falls back to an unprivileged
    /// SOCK_DGRAM ICMP socket if no raw socket is available). DNS instead *prefers*
    /// SOCK_DGRAM UDP even when a raw socket is available: a raw socket registers no
    /// UDP listener, so the kernel answers every DNS reply with an ICMP/ICMPv6 port
    /// unreachable to the resolver — a bound UDP socket avoids that.
    ///
    /// # Arguments
    /// * `is_ipv6` - IP version used (true: IPv6)
    /// * `p_type` - Protocol type used (ICMP, UDP, or TCP)
    /// * `origin` - Origin used in this measurement (anycast or local unicast address)
    /// * `is_traceroute` - Whether this is a traceroute measurement (raw-only)
    /// * `is_record` - Whether this is a Record Route measurement (raw-only)
    ///
    /// # Returns
    /// (Arc<Socket>, bool) containing a Socket and whether it is a DGRAM socket
    fn get_socket(
        is_ipv6: bool,
        p_type: ProtocolType,
        origin: Origin,
        is_traceroute: bool,
        is_record: bool,
        m_id: u32,
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
        let is_ping = p_type == ProtocolType::Icmp && !is_traceroute && !is_record;
        let is_dns = matches!(p_type, ProtocolType::ADns | ProtocolType::ChaosDns);

        // Prefer SOCK_DGRAM for DNS (avoid ICMP port unreachable replies), except for traceroute
        let (socket, is_dgram) = if is_dns && !is_traceroute {
            let bind_addr = SockAddr::from(SocketAddr::new(addr, origin.sport as u16));
            match Self::try_dgram_socket(domain, protocol, &bind_addr, is_ipv6) {
                Some(s) => {
                    info!("[Worker] Using UDP datagram socket for DNS");
                    (s, true)
                }
                None => match Self::try_raw_socket(domain, protocol, is_ipv6) {
                    Some(s) => {
                        warn!(
                            "[Worker] UDP datagram socket unavailable, falling back to raw socket (may emit ICMP port-unreachable replies)"
                        );
                        (s, false)
                    }
                    None => panic!(
                        "Failed to create UDP socket for DNS. Check the source address is local."
                    ),
                },
            }
        } else {
            // ICMP and TCP prefer a raw socket for better performance and timestamp accuracy
            match Self::try_raw_socket(domain, protocol, is_ipv6) {
                Some(s) => {
                    info!("[Worker] Using raw socket");
                    (s, false)
                }
                None if is_ping => {
                    // Fall back to an unprivileged SOCK_DGRAM ICMP socket bound to the ICMP identifier.
                    let bind_addr = SockAddr::from(SocketAddr::new(addr, origin.dport as u16));
                    match Self::try_dgram_socket(domain, protocol, &bind_addr, is_ipv6) {
                        Some(s) => {
                            info!(
                                "[Worker] Raw socket unavailable, using unprivileged ICMP socket (no sudo required)"
                            );
                            (s, true)
                        }
                        None => panic!(
                            "Failed to create raw or unprivileged ICMP socket. Grant CAP_NET_RAW or set net.ipv4.ping_group_range."
                        ),
                    }
                }
                None => panic!("Failed to create raw socket. sudo or CAP_NET_RAW required."),
            }
        };

        if !is_dgram {
            let sock_addr = SockAddr::from(SocketAddr::new(addr, origin.sport as u16));
            socket
                .bind(&sock_addr)
                .expect("Failed to bind socket to address.");

            // Attach a cBPF filter so the kernel drops non-matching packets
            let filter = match p_type {
                ProtocolType::Icmp if is_traceroute => (
                    // Time-Exceeded + Echo-Reply by type (identifier is per-probe dynamic)
                    attach_traceroute_filter(&socket, is_ipv6),
                    "ICMP traceroute".to_string(),
                ),
                ProtocolType::Icmp => (
                    // Plain echo and Record Route: both are echo replies with id == dport
                    attach_icmp_filter(&socket, origin.dport as u16, is_ipv6),
                    format!("ICMP (id {})", origin.dport),
                ),
                ProtocolType::Tcp => (
                    // RST flag + sport filtering
                    attach_tcp_filter(&socket, origin.sport as u16, is_ipv6),
                    format!("TCP RST (sport {})", origin.sport),
                ),
                // DNS Identifier + sport filtering
                ProtocolType::ADns | ProtocolType::ChaosDns => (
                    attach_dns_filter(&socket, origin.sport as u16, dns_identifier(m_id), is_ipv6),
                    format!("DNS (sport {})", origin.sport),
                ),
            };
            match filter {
                (Ok(()), desc) => info!("[Worker] Attached {desc} BPF filter"),
                (Err(e), desc) => warn!("[Worker] Failed to attach {desc} BPF filter: {e}"),
            }
        }

        socket.set_send_buffer_size(4 * 1024 * 1024).ok(); // 4 MB buffer for sending
        socket.set_recv_buffer_size(16 * 1024 * 1024).ok(); // 16 MB for receiving

        // enable SO_TIMESTAMP (get kernel timestamp when packet is received)
        let ts_ret = unsafe {
            let val: libc::c_int = 1;
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMP,
                &val as *const _ as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ts_ret != 0 {
            warn!(
                "[Worker] Failed to enable SO_TIMESTAMP: {}",
                std::io::Error::last_os_error()
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
        let socket = match Socket::new(domain, Type::DGRAM, Some(protocol)) {
            Ok(s) => s,
            Err(e) => {
                warn!("[Worker] DGRAM socket creation failed: {e}");
                return None;
            }
        };
        if let Err(e) = socket.bind(bind_addr) {
            warn!("[Worker] DGRAM socket bind to {bind_addr:?} failed: {e}");
            return None;
        }

        let ttl_res = if is_ipv6 {
            socket.set_recv_hoplimit_v6(true)
        } else {
            Self::set_recv_ttl_v4(&socket)
        };
        if let Err(e) = ttl_res {
            warn!("[Worker] DGRAM socket TTL/hoplimit option failed: {e}");
            return None;
        }

        Some(socket)
    }

    /// Try to create a RAW socket with IP_HDRINCL and appropriate options.
    /// Returns None if creation or setup fails (e.g. missing CAP_NET_RAW).
    fn try_raw_socket(domain: Domain, protocol: Protocol, is_ipv6: bool) -> Option<Socket> {
        let socket = match Socket::new(domain, Type::RAW, Some(protocol)) {
            Ok(s) => s,
            Err(e) => {
                warn!("[Worker] RAW socket creation failed: {e}");
                return None;
            }
        };

        let res = if is_ipv6 {
            // Always request the received hop limit as ancillary data.
            let r = socket.set_recv_hoplimit_v6(true);

            // TODO header_included_v6 not supported currently in socket2
            if protocol == Protocol::ICMPV6 {
                r
            } else {
                r.and_then(|_| socket.set_header_included_v6(true))
            }
        } else {
            socket.set_header_included_v4(true)
        };
        if let Err(e) = res {
            warn!("[Worker] RAW socket option failed: {e}");
            return None;
        }

        Some(socket)
    }

    /// Enable IP_RECVTTL on an IPv4 socket so TTL arrives as ancillary data.
    #[cfg(unix)]
    fn set_recv_ttl_v4(socket: &Socket) -> std::io::Result<()> {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let val: libc::c_int = 1;
        let ret = unsafe {
            // TODO unsafe
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVTTL,
                &val as *const _ as *const libc::c_void,
                size_of_val(&val) as libc::socklen_t,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}
