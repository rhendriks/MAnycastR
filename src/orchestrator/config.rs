use crate::ALL_WORKERS;
use crate::custom_module::manycastr::{Address, ProtocolType};
use crate::custom_module::parse_src_address;
use log::info;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Display;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// An origin allow-list rule: a source address and the protocols permitted for it.
#[derive(Debug, Clone)]
pub struct AllowedOrigin {
    /// Anycast source address, or a `unicastv4`/`unicastv6` marker
    pub src: Address,
    /// Permitted protocols (`None` = any protocol)
    pub protocols: Option<Vec<ProtocolType>>,
}

impl AllowedOrigin {
    /// Whether this rule permits the given protocol.
    pub fn allows(&self, p_type: ProtocolType) -> bool {
        self.protocols
            .as_ref()
            .is_none_or(|protocols| protocols.contains(&p_type))
    }
}

/// Print an allow-list rule, e.g. "10.0.0.1 (all)" or "unicastv4 (icmp|tcp)"
impl Display for AllowedOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.protocols {
            None => write!(f, "{} (all)", self.src),
            Some(protocols) => {
                let protocols: Vec<&str> = protocols.iter().map(|p| p.as_str()).collect();
                write!(f, "{} ({})", self.src, protocols.join("|"))
            }
        }
    }
}

/// Load the origin allow-list from a file (`--origins`).
/// Each line defines one rule:
/// src_addr, protocol[, protocol...]
///
/// `src_addr` is an anycast IP address or `unicastv4`/`unicastv6`;
/// the protocol list may be `all` to allow all protocols.
///
/// # Arguments
/// * `origins_path` - the path to the origins file
///
/// # Returns
/// * The list of allowed origins
///
/// # Panics
/// If the file does not exist, contains malformed entries, or defines no rules.
pub fn load_allowed_origins(origins_path: &String) -> Vec<AllowedOrigin> {
    if !Path::new(origins_path).exists() {
        panic!("[Orchestrator] Origins file {origins_path} not found!");
    }

    let content =
        fs::read_to_string(origins_path).expect("[Orchestrator] Could not read the origins file.");

    let mut allowed_origins = Vec::new();

    for (i, line) in content.lines().enumerate() {
        let line_number = i + 1;

        let trimmed_line = line.trim();

        // Skip empty lines and comments
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }

        // Format: "src_addr, protocol[, protocol...]"
        let mut parts = trimmed_line.split(',').map(str::trim);
        let src = parse_src_address(parts.next().unwrap());

        let protocol_tokens: Vec<&str> = parts.collect();
        if protocol_tokens.is_empty() {
            panic!(
                "[Orchestrator] Error on line {line_number}: Malformed entry. Expected 'src_addr, protocol[, protocol...]' ('all' allows all protocols), found '{line}'"
            );
        }

        // 'all' allows all protocols
        let protocols = if protocol_tokens
            .iter()
            .any(|p| p.eq_ignore_ascii_case("all"))
        {
            None
        } else {
            Some(
                protocol_tokens
                    .iter()
                    .map(|p| {
                        ProtocolType::from_str(p).unwrap_or_else(|| {
                            panic!(
                                "[Orchestrator] Error on line {line_number}: Unknown protocol '{p}'. Expected icmp, dns, tcp, chaos, or all."
                            )
                        })
                    })
                    .collect(),
            )
        };

        allowed_origins.push(AllowedOrigin { src, protocols });
    }

    if allowed_origins.is_empty() {
        panic!("[Orchestrator] No origin rules found in {origins_path}");
    }

    info!(
        "[Orchestrator] {} allowed origins loaded.",
        allowed_origins.len()
    );

    allowed_origins
}

/// Load the worker configuration from a file.
/// This provides a static mapping of hostnames to worker IDs.
/// Formats the file as follows:
/// hostname,id
///
/// # Arguments
/// * `config_path` - the path to the configuration file
///
/// # Returns
/// * The worker ID for any new hostname, which is the maximum ID + 1 in the configuration file
/// * A mapping of hostnames to worker IDs
///
/// # Panics
/// If the configuration file does not exist, or if there are malformed entries, duplicate hostnames, or duplicate IDs.
pub fn load_worker_config(config_path: &String) -> (Arc<Mutex<u32>>, Option<HashMap<String, u32>>) {
    if !Path::new(config_path).exists() {
        panic!("[Orchestrator] Configuration file {config_path} not found!");
    }

    let config_content = fs::read_to_string(config_path)
        .expect("[Orchestrator] Could not read the configuration file.");

    let mut hosts = HashMap::new();
    let mut used_ids = HashSet::new();

    for (i, line) in config_content.lines().enumerate() {
        let line_number = i + 1;

        let trimmed_line = line.trim();

        // Skip empty lines and comments
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }

        // Format: "hostname,id"
        let parts: Vec<&str> = trimmed_line.split(',').collect();
        if parts.len() != 2 {
            panic!(
                "[Orchestrator] Error on line {line_number}: Malformed entry. Expected 'hostname,id', found '{line}'"
            );
        }

        let hostname = parts[0].trim().to_string();
        let id = match parts[1].trim().parse::<u32>() {
            Ok(val) => val,
            Err(_) => {
                panic!(
                    "[Orchestrator] Error on line {line_number}: Invalid ID '{}'. ID must be an integer.",
                    parts[1].trim()
                );
            }
        };

        // Check for duplicate hostname before inserting.
        if hosts.contains_key(&hostname) {
            panic!(
                "[Orchestrator] Error on line {line_number}: Duplicate hostname '{hostname}' found. Hostnames must be unique."
            );
        }

        // Insert the ID (if it is not already used)
        if !used_ids.insert(id) {
            panic!(
                "[Orchestrator] Error on line {line_number}: Duplicate ID '{id}' found. IDs must be unique."
            );
        }

        // Avoid special worker IDs
        if id == ALL_WORKERS {
            panic!(
                "[Orchestrator] Error on line {line_number}: ID '{id}' is reserved for special purposes. Please use a different ID."
            );
        }

        hosts.insert(hostname, id);
    }

    info!("[Orchestrator] {} hosts loaded.", hosts.len());

    // Current worker ID is the maximum ID + 1 in the configuration file
    let current_worker_id = hosts.values().max().map_or(1, |&max_id| max_id + 1);

    (Arc::new(Mutex::new(current_worker_id)), Some(hosts))
}
