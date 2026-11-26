use std::time::SystemTime;

use tracing::{debug, error};

use crate::config;

pub(crate) fn epoch_time() -> Option<i64> {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(time) => {
            debug!(?time, "Reported time");
            Some(time.as_secs().cast_signed())
        }
        Err(error) => {
            error!(error = ?error, "Reported time before UNIX Epoch");
            None
        }
    }
}

pub(crate) fn is_recovery_valid(upload_time: Option<i64>, complete: bool) -> bool {
    if complete {
        return false;
    }
    let Some(upload_time) = upload_time else {
        return false;
    };
    let Some(current_time) = epoch_time() else {
        return false;
    };
    let elapsed = current_time.saturating_sub(upload_time);
    if elapsed < 0 {
        return false;
    }
    let Ok(window) = i64::try_from(config::RECOVERY_WINDOW_SECONDS) else {
        return false;
    };
    elapsed <= window
}
