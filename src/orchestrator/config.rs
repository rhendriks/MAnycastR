use crate::orchestrator::{ALL_WORKERS_DIRECT, ALL_WORKERS_INTERVAL, BREAK_SIGNAL};
use log::info;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tonic::transport::Identity;

/// Load the worker configuration from a file.
/// This provides a static mapping of hostnames to worker IDs.
/// Formats the file as follows:
/// hostname,id
///
/// # Arguments
/// * 'config_path' - the path to the configuration file
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
        if id == ALL_WORKERS_INTERVAL || id == ALL_WORKERS_DIRECT || id == BREAK_SIGNAL {
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

// 1. Generate private key:
// openssl genpkey -algorithm RSA -out orchestrator.key -pkeyopt rsa_keygen_bits:2048
// 2. Generate certificate signing request:
// openssl req -new -key orchestrator.key -out orchestrator.csr
// 3. Generate self-signed certificate:
// openssl x509 -req -in orchestrator.csr -signkey orchestrator.key -out orchestrator.crt -days 3650
// 4. Distribute orchestrator.crt to clients
pub fn load_tls() -> Identity {
    // Load TLS certificate
    let cert = fs::read("tls/orchestrator.crt")
        .expect("Unable to read certificate file at ./tls/orchestrator.crt");
    // Load TLS private key
    let key = fs::read("tls/orchestrator.key")
        .expect("Unable to read key file at ./tls/orchestrator.key");

    // Create TLS configuration
    Identity::from_pem(cert, key)
}
