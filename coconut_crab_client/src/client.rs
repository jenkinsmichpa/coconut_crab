use log::{debug, error, warn};
use std::{path::Path, thread::available_parallelism};

use crate::comm::register;
use crate::status::{create_status, export_status_csv, import_status_csv, Status};

pub fn initialize_client(
    exe_path_dir: &Path,
    server_fqdn: &str,
    server_port: &u16,
    preshared_secret: &str,
    https: &bool,
    verify_server: &bool,
) -> Status {
    match import_status_csv(exe_path_dir) {
        Some(csv_result) => {
            debug!("Successully imported status: {:?}", csv_result);
            csv_result
        }
        None => {
            warn!("Existing status not imported");
            let new_status = create_status();
            register(
                server_fqdn,
                server_port,
                &new_status,
                preshared_secret,
                https,
                verify_server,
            );
            export_status_csv(exe_path_dir, &new_status);
            debug!("Created new status: {:?}", new_status);
            new_status
        }
    }
}

#[derive(Clone, Debug)]
pub struct ThreadNums {
    pub walk_threads: usize,
    pub shred_threads: usize,
    pub encrypt_threads: usize,
    pub decrypt_threads: usize,
    pub canary_threads: usize,
    pub encrypt_threads_canary: usize,
}

pub fn get_thread_nums() -> ThreadNums {
    let num_threads = match available_parallelism() {
        Ok(suggested_threads_result) => {
            debug!(
                "Successfully got suggested number of threads: {}",
                suggested_threads_result
            );
            suggested_threads_result.get()
        }
        Err(suggested_threads_result) => {
            error!(
                "Failed to get suggested number of threads: {}",
                suggested_threads_result
            );
            1
        }
    };

    let num_walk_threads = (num_threads / 6).max(1);
    debug!("Using {} walk threads", num_walk_threads);
    let num_shred_threads = (num_threads / 6).max(1);
    debug!("Using {} shred threads", num_shred_threads);
    let num_canary_threads = (num_threads / 6).max(1);
    debug!("Using {} canary threads", num_canary_threads);
    let num_encrypt_threads = (num_threads - num_walk_threads - num_shred_threads).max(1);
    debug!("Using {} encrypt threads", num_encrypt_threads);
    let num_encrypt_threads_canary = (num_encrypt_threads - num_canary_threads).max(1);
    debug!(
        "Using {} encrypt threads if using canary filter",
        num_encrypt_threads_canary
    );
    let num_decrypt_threads = (num_threads - num_walk_threads).max(1);
    debug!("Using {} decrypt threads", num_decrypt_threads);

    ThreadNums {
        walk_threads: num_walk_threads,
        shred_threads: num_shred_threads,
        encrypt_threads: num_encrypt_threads,
        decrypt_threads: num_decrypt_threads,
        canary_threads: num_canary_threads,
        encrypt_threads_canary: num_encrypt_threads_canary,
    }
}
