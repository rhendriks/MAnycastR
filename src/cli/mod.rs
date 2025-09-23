mod writer;
mod client;
mod commands;
mod config;
mod utils;

use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use flate2::read::GzDecoder;
use rand::seq::SliceRandom;

use custom_module::manycastr::{Address, Configuration};

use crate::{custom_module};
pub use commands::execute;

/// Validate the provided path for writing permissions.
/// # Arguments
/// * 'path' - Optional path to validate
/// # Returns
/// * 'Option<Result<(), Box<dyn Error>>>' - None if path is valid, Some(Ok(())) if path is valid, Some(Err) if path is invalid
/// # Panics
/// * If unable to get path metadata
/// * If unable to create or remove file/directory
fn validate_path_perms(path: Option<&String>) -> Option<Result<(), Box<dyn Error>>> {
    if let Some(path_str) = path {
        let path = Path::new(path_str);

        if !path_str.ends_with('/') {
            // User provided a file
            if path.exists() {
                if path.is_dir() {
                    println!("[CLI] Path is already a directory, exiting");
                    return Some(Err("Path is already a directory".into()));
                } else if fs::metadata(path)
                    .expect("Unable to get path metadata")
                    .permissions()
                    .readonly()
                {
                    println!("[CLI] Lacking write permissions for file {path_str}");
                    return Some(Err("Lacking write permissions".into()));
                } else {
                    println!("[CLI] Overwriting existing file {path_str} when measurement is done");
                }
            } else {
                println!("[CLI] Writing results to new file {path_str}");

                // File does not yet exist, create it to verify permissions
                File::create(path)
                    .expect("Unable to create output file")
                    .sync_all()
                    .expect("Unable to sync file");
                fs::remove_file(path).expect("Unable to remove file");
            }
        } else {
            // User provided a directory
            if path.exists() {
                if !path.is_dir() {
                    println!("[CLI] Path is already a file, exiting");
                    return Some(Err("Cannot make dir, file with name already exists.".into()));
                } else if fs::metadata(path)
                    .expect("Unable to get path metadata")
                    .permissions()
                    .readonly()
                {
                    println!("[CLI] Lacking write permissions for directory {path_str}");
                    return Some(Err("Path is not writable".into()));
                } else {
                    println!("[CLI] Writing results to existing directory {path_str}");
                }
            } else {
                println!("[CLI] Writing results to new directory {path_str}");

                // Attempt creating path to verify permissions
                fs::create_dir_all(path).expect("Unable to create output directory");
            }
        }
    }
    None
}

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
fn get_hitlist(
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
