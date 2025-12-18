use bimap::BiHashMap;
use crate::cli::writer::{calculate_rtt, MetadataArgs};
use crate::custom_module::manycastr::Reply;
use crate::{ALL_WORKERS, TCP_ID};

/// Get the result (csv row) from a Reply message
///
/// # Arguments
/// * `result` - The Reply that is being written to this row
/// * `rx_worker_id` - The worker ID of the receiver
/// * `m_type` - The type of measurement being performed
/// * `is_symmetric` - A boolean that determines whether the measurement is symmetric (i.e., sender == receiver is always true)
/// * `worker_map` - A map of worker IDs to hostnames, used to convert worker IDs to hostnames in the results
/// * `is_record` - A boolean that determines whether Record Route is included
///
/// # Returns
///
/// A vector of strings representing the row in the CSV file
pub fn get_row( // TODO split into multiple 'get_row' functions based on result/measurement type
            result: Reply,
            rx_worker_id: &u32,
            m_type: u8,
            is_symmetric: bool,
            worker_map: &BiHashMap<u32, String>,
            is_record: bool,
) -> Vec<String> {
    let origin_id = result.origin_id.to_string();
    let is_multi_origin = result.origin_id != 0 && result.origin_id != u32::MAX;
    // convert the worker ID to hostname
    let rx_hostname = worker_map
        .get_by_left(rx_worker_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();
    let rx_time = result.rx_time.to_string();
    let tx_time = result.tx_time.to_string();
    let tx_id = result.tx_id;
    let ttl = result.ttl.to_string();
    let reply_src = result.src.unwrap().to_string();

    let mut row = if is_symmetric {
        let rtt = format!(
            "{:.2}",
            calculate_rtt(result.rx_time, result.tx_time, m_type == TCP_ID)
        );
        vec![rx_hostname, reply_src, ttl, rtt]
    } else {
        let tx_hostname = worker_map
            .get_by_left(&tx_id)
            .unwrap_or(&String::from("Unknown"))
            .to_string();

        // TCP anycast does not have tx_time
        if m_type == TCP_ID {
            vec![rx_hostname, rx_time, reply_src, ttl, tx_hostname]
        } else {
            vec![rx_hostname, rx_time, reply_src, ttl, tx_time, tx_hostname]
        }
    };

    // Optional fields
    if let Some(chaos) = result.chaos {
        row.push(chaos);
    }
    if is_multi_origin {
        row.push(origin_id);
    }
    if is_record {
        let hops_str = result
            .recorded_hops
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>()
            .join(" | ");

        row.push(hops_str);
    }

    row
}

/// Get traceroute row
/// format: rx, hop_addr, ttl, tx, trace_dst, trace_ttl, rtt
pub fn get_trace_row(
    trace_result: Reply,
    rx_worker_id: &u32,
    _m_type: u8, // TODO ICMP only for now
    worker_map: &BiHashMap<u32, String>,
) -> Vec<String> {
    // convert the worker ID to hostname
    let rx_hostname = worker_map
        .get_by_left(rx_worker_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();
    let hop_addr = trace_result.src.unwrap().to_string();
    let ttl = trace_result.ttl.to_string();
    let tx_id = trace_result.tx_id;
    let tx_hostname = worker_map
        .get_by_left(&tx_id)
        .unwrap_or(&String::from("Unknown"))
        .to_string();

    // Calculate RTT if tx_time is available
    let rtt = if trace_result.tx_time != 0 {
        format!(
            "{:.2}",
            calculate_rtt(trace_result.rx_time, trace_result.tx_time, false)
        )
    } else {
        String::from("")
    };
    if let Some(trace_ttl) = trace_result.trace_ttl {
        let trace_dst = trace_result.trace_dst.unwrap().to_string();
        // Intermediate hop
        vec![
            rx_hostname,
            hop_addr,
            ttl,
            tx_hostname,
            trace_dst,
            trace_ttl.to_string(),
            rtt,
        ]
    } else {
        // Reply from the destination
        vec![
            rx_hostname,
            hop_addr,
            ttl,
            tx_hostname,
            String::from(""),
            String::from(""),
            rtt,
        ]
    }
}

/// Returns a vector of lines containing the metadata of the measurement
///
/// # Arguments
///
/// Variables describing the measurement
pub fn get_csv_metadata(
    args: MetadataArgs<'_>,
    worker_map: &BiHashMap<u32, String>,
) -> Vec<String> {
    let mut md_file = Vec::new();
    if args.is_divide {
        md_file.push("# Measurement style: Divide-and-conquer".to_string());
    } else if args.is_latency {
        md_file.push("# Measurement style: Anycast latency".to_string());
    } else if args.is_responsive {
        md_file.push("# Measurement style: Responsive-mode".to_string());
    }

    // Print configurations used
    for configuration in args.configurations {
        let origin = configuration.origin.unwrap();
        let src = origin.src.expect("Invalid source address");
        let hostname = if configuration.worker_id == ALL_WORKERS {
            "ALL".to_string()
        } else {
            worker_map
                .get_by_left(&configuration.worker_id)
                .unwrap_or(&String::from("Unknown"))
                .to_string()
        };
        md_file.push(format!(
            "# Configuration - Worker: {:<2}, source IP: {}, source port: {}, destination port: {}",
            hostname, src, origin.sport, origin.dport
        ));
    }
    md_file.push(format!(
        "# Hitlist{}: {}",
        if args.is_shuffle { " (shuffled)" } else { "" },
        args.hitlist
    ));
    md_file.push(format!("# Measurement type: {}", args.m_type_str));
    md_file.push(format!(
        "# Probing rate: {}",
        args.probing_rate.with_separator()
    ));
    md_file.push(format!("# Worker interval: {}", args.interval));
    md_file.push(format!("# {} connected workers:", args.all_workers.len()));
    for (_, hostname) in args.all_workers {
        md_file.push(format!("# * {hostname}"))
    }

    // Write configurations used for the measurement
    if args.is_config {
        md_file.push("# Configurations:".to_string());
        for configuration in args.configurations {
            let origin = configuration.origin.unwrap();
            let src = origin.src.expect("Invalid source address");
            let hostname = if configuration.worker_id == u32::MAX {
                "ALL".to_string()
            } else {
                worker_map
                    .get_by_left(&configuration.worker_id)
                    .unwrap_or(&String::from("Unknown"))
                    .to_string()
            };
            md_file.push(format!(
                "# * {:<2}, source IP: {}, source port: {}, destination port: {}",
                hostname, src, origin.sport, origin.dport
            ));
        }
    }

    md_file
}