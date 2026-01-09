use crate::cli::writer::MetadataArgs;
use crate::custom_module::Separated;
use crate::ALL_WORKERS;
use bimap::BiHashMap;

/// Returns a vector of lines containing the metadata of the measurement
///
/// # Arguments
/// * `args` - Contains measurement arguments to be written into the metadata
/// * `worker_map` - Convert IDs to hostnames
pub fn get_csv_metadata(
    args: MetadataArgs<'_>,
    worker_map: &BiHashMap<u32, String>,
) -> Vec<String> {
    let mut md_file = Vec::new();
    md_file.push(format!("# Measurement type: {}", args.m_type));
    md_file.push(format!("# Protocol used: {}", args.p_type));
    if args.is_responsive {
        md_file.push("# Responsiveness mode enabled".to_string());
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
            "# Configuration - Worker: {hostname:<2}, src IP: {src}, src port: {}, dst port: {}",
            origin.sport, origin.dport
        ));
    }
    md_file.push(format!(
        "# Hitlist{}: {}",
        if args.is_shuffle { " (shuffled)" } else { "" },
        args.hitlist
    ));
    md_file.push(format!(
        "# Probing rate: {}",
        args.probing_rate.with_separator()
    ));
    md_file.push(format!("# Worker interval: {}", args.interval));
    let hostnames: Vec<_> = args.all_workers.iter().map(|(_, h)| h.as_str()).collect();
    md_file.push(format!(
        "# Connected workers ({}): {}",
        hostnames.len(),
        hostnames.join(", ")
    ));

    md_file
}
