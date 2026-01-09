use log::{error, warn};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::path::Path;

/// Validate the provided path for writing permissions.
/// # Arguments
/// * `path_str` - Path to validate
///
/// # Returns
/// * Ok(()) if the path is valid and writable, Err with a message otherwise
///
/// # Panics
/// * If unable to get path metadata
/// * If unable to create or remove file/directory
pub fn validate_path_perms(path_str: &String) -> Result<(), Box<dyn Error>> {
    let path = Path::new(path_str);

    // If user provided a file
    if !path_str.ends_with('/') {
        if path.exists() {
            if path.is_dir() {
                error!("[CLI] Path is already a directory, exiting");
                return Err("Path is already a directory".into());
            } else if fs::metadata(path)
                .expect("Unable to get path metadata")
                .permissions()
                .readonly()
            {
                error!("[CLI] Lacking write permissions for file {path_str}");
                return Err("Lacking write permissions".into());
            } else {
                warn!("[CLI] Overwriting existing file {path_str} when measurement is done");
            }
        } else {
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
                error!("[CLI] Path is already a file, exiting");
                return Err("Cannot make dir, file with name already exists.".into());
            } else if fs::metadata(path)
                .expect("Unable to get path metadata")
                .permissions()
                .readonly()
            {
                error!("[CLI] Lacking write permissions for directory {path_str}");
                return Err("Path is not writable".into());
            }
        } else {
            // Attempt creating path to verify permissions
            fs::create_dir_all(path).expect("Unable to create output directory");
        }
    }
    Ok(())
}
