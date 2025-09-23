use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;
use bimap::BiHashMap;
use flate2::read::GzDecoder;
use rand::prelude::SliceRandom;
use crate::custom_module::manycastr::{Address, Configuration, Origin};

/// Get the hitlist from a file.
///
/// # Arguments
///
/// * 'hitlist_path' - path to the hitlist file
///
/// * 'configurations' - list of configurations to check the source address type
///
/// * 'is_unicast' - boolean whether the measurement is unicast or anycast
///
/// * 'is_shuffle' - boolean whether the hitlist should be shuffled or not
///
/// # Returns
///
/// * A tuple containing a vector of addresses and a boolean indicating whether the addresses are IPv6 or IPv4.
///
/// # Panics
///
/// * If the hitlist file cannot be opened.
///
/// * If the anycast source address type (v4 or v6) does not match the hitlist addresses.
///
/// * If the hitlist addresses are of mixed types (v4 and v6).
pub fn get_hitlist(
    hitlist_path: &String,
    configurations: &[Configuration],
    is_unicast: bool,
    is_shuffle: bool,
) -> (Vec<Address>, bool) {
    let file =
        File::open(hitlist_path).unwrap_or_else(|_| panic!("Unable to open file {hitlist_path}"));

    // Create reader based on file extension
    let reader: Box<dyn BufRead> = if hitlist_path.ends_with(".gz") {
        let decoder = GzDecoder::new(file);
        Box::new(BufReader::new(decoder))
    } else {
        Box::new(BufReader::new(file))
    };

    let mut ips: Vec<Address> = reader // Create a vector of addresses from the file
        .lines()
        .map_while(Result::ok) // Handle potential errors
        .filter(|l| !l.trim().is_empty()) // Skip empty lines
        .map(Address::from)
        .collect();
    let is_ipv6 = ips.first().unwrap().is_v6();

    // Panic if the source IP is not the same type as the addresses
    if !is_unicast
        && configurations
        .first()
        .expect("Empty configuration list")
        .origin
        .expect("No origin found")
        .src
        .expect("No source address")
        .is_v6()
        != is_ipv6
    {
        panic!(
            "Hitlist addresses are not the same type as the source addresses used! (IPv4 & IPv6)"
        );
    }
    // Panic if the ips in the hitlist are not all the same type
    if ips.iter().any(|ip| ip.is_v6() != is_ipv6) {
        panic!("Hitlist addresses are not all of the same type! (mixed IPv4 & IPv6)");
    }

    // Shuffle the hitlist, if desired
    if is_shuffle {
        ips.as_mut_slice().shuffle(&mut rand::rng());
    }
    (ips, is_ipv6)
}

// TODO implement feed of addresses instead of a hitlist file
// format: address,tx -> tx optional to specify from which site to probe
// protocol and ports used are pre-configured when starting a live measurement at the CLI

pub fn parse_configurations(conf_file: &str, worker_map: &BiHashMap<u32, String>) -> Vec<Configuration> {
    println!("[CLI] Using configuration file: {conf_file}");
    let file = File::open(conf_file)
        .unwrap_or_else(|_| panic!("Unable to open configuration file {conf_file}"));
    let buf_reader = BufReader::new(file);
    let mut origin_id = 0;
    let mut is_ipv6: Option<bool> = None;

    let configurations: Vec<Configuration> = buf_reader // Create a vector of addresses from the file
        .lines()
        .filter_map(|line| {
            let line = line.expect("Unable to read configuration line");
            let line = line.trim();
            if line.is_empty() || line.starts_with("#") {
                return None;
            } // Skip comments and empty lines

            let parts: Vec<&str> = line.splitn(2, " - ").map(|s| s.trim()).collect();
            if parts.len() != 2 {
                panic!("Invalid configuration format: {line}");
            }

            // Parse the worker ID
            let worker_id = if parts[0] == "ALL" {
                u32::MAX
            } else if let Ok(id_val) = parts[0].parse::<u32>() {
                if !worker_map.contains_left(&id_val) {
                    panic!("Worker ID {id_val} is not a known worker.");
                }
                id_val
            } else if let Some(&found_id) = worker_map.get_by_right(parts[0]) {
                // Try to find the hostname in the map
                found_id
            } else {
                panic!("'{}' is not a valid worker ID or known hostname.", parts[0]);
            };

            let addr_ports: Vec<&str> = parts[1].split(',').map(|s| s.trim()).collect();
            if addr_ports.len() != 3 {
                panic!("Invalid configuration format: {line}");
            }
            let src = Address::from(addr_ports[0]);

            if let Some(v6) = is_ipv6 {
                if v6 != src.is_v6() {
                    panic!("Configuration file contains mixed IPv4 and IPv6 addresses!");
                }
            } else {
                is_ipv6 = Some(src.is_v6());
            }

            // Parse to u16 first, must fit in header
            let sport =
                u16::from_str(addr_ports[1]).expect("Unable to parse source port") as u32;
            let dport = u16::from_str(addr_ports[2])
                .expect("Unable to parse destination port")
                as u32;
            origin_id += 1;

            Some(Configuration {
                worker_id,
                origin: Some(Origin {
                    src: Some(src),
                    sport,
                    dport,
                    origin_id,
                }),
            })
        })
        .collect();
    if configurations.is_empty() {
        panic!("No valid configurations found in file {conf_file}");
    }

    configurations
}
