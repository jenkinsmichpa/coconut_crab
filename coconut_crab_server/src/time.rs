use log::{debug, error};
use std::time::SystemTime;

use crate::config;

pub fn get_epoch_time() -> Option<i64> {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(time) => {
            debug!("Reported Time: {time:?}");
            Some(time.as_secs().cast_signed())
        }
        Err(error) => {
            error!("Reported time before UNIX Epoch: {error}");
            None
        }
    }
}

pub fn is_recovery_valid(upload_time: Option<i64>, complete: bool) -> bool {
    if complete {
        return false;
    }
    let Some(upload_time) = upload_time else {
        return false;
    };
    let Some(current_time) = get_epoch_time() else {
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
