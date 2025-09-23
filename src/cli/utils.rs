use std::error::Error;
use std::fs;
use std::fs::File;
use std::path::Path;

/// Validate the provided path for writing permissions.
/// # Arguments
/// * 'path' - Optional path to validate
/// # Returns
/// * 'Option<Result<(), Box<dyn Error>>>' - None if path is valid, Some(Ok(())) if path is valid, Some(Err) if path is invalid
/// # Panics
/// * If unable to get path metadata
/// * If unable to create or remove file/directory
pub fn validate_path_perms(path: Option<&String>) -> Option<Result<(), Box<dyn Error>>> {
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