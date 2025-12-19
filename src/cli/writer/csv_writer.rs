use bimap::BiHashMap;
use crate::cli::writer::{calculate_rtt, MetadataArgs};
use crate::custom_module::manycastr::Result;
use crate::{ALL_WORKERS, TCP_ID};
use crate::custom_module::Separated;

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