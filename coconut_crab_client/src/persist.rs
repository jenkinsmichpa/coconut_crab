use auto_launch::{AutoLaunch, AutoLaunchBuilder};
use log::{debug, error, info, log_enabled, Level};
use std::{env, io};

fn get_autolaunch() -> Result<AutoLaunch, io::Error> {
    let exe_path = match env::current_exe() {
        Ok(exe_path_result) => {
            debug!("Successfully got current exe path: {:?}", exe_path_result);
            exe_path_result.to_string_lossy().into_owned()
        }
        Err(exe_path_result) => {
            error!("Failed to get current exe path: {}", exe_path_result);
            return Err(exe_path_result);
        }
    };
    let app_name = "Coconut Crab";
    let autolaunch = match AutoLaunchBuilder::new()
        .set_app_name(app_name)
        .set_app_path(&exe_path)
        .set_args(&[] as &[&str])
        .build()
    {
        Ok(autolaunch_result) => {
            debug!("Successfully created AutoLaunch: {:?}", autolaunch_result);
            autolaunch_result
        }
        Err(autolaunch_result) => {
            error!("Failed to create AutoLaunch: {}", autolaunch_result);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                autolaunch_result.to_string(),
            ));
        }
    };
    Ok(autolaunch)
}

pub fn start_persist() {
    let autolaunch = match get_autolaunch() {
        Ok(autolaunch_result) => {
            debug!("Successfully got AutoLaunch: {:?}", autolaunch_result);
            autolaunch_result
        }
        Err(autolaunch_result) => {
            error!("Failed to get AutoLaunch: {}", autolaunch_result);
            return;
        }
    };

    if let Err(enable_result) = autolaunch.enable() {
        error!("Error enabling AutoLaunch: {}", enable_result);
    }

    if log_enabled!(Level::Info) {
        match autolaunch.is_enabled() {
            Ok(enable_status_result) => {
                if enable_status_result {
                    info!(
                        "AutoLaunch successfully enabled. Status: {}",
                        enable_status_result
                    );
                } else {
                    error!(
                        "Unable to enable AutoLaunch. Status: {}",
                        enable_status_result
                    );
                }
            }
            Err(enable_status_result) => {
                error!("Error getting AutoLaunch. status: {}", enable_status_result);
            }
        };
    }
}

pub fn stop_persist() {
    let autolaunch = match get_autolaunch() {
        Ok(autolaunch_result) => {
            debug!("Successfully got AutoLaunch: {:?}", autolaunch_result);
            autolaunch_result
        }
        Err(autolaunch_result) => {
            error!("Failed to get AutoLaunch: {}", autolaunch_result);
            return;
        }
    };

    if let Err(enable_result) = autolaunch.disable() {
        error!("Error disabling AutoLaunch: {}", enable_result);
    }
    if log_enabled!(Level::Info) {
        match autolaunch.is_enabled() {
            Ok(enable_status_result) => {
                if enable_status_result {
                    error!(
                        "Unable to disable AutoLaunch. Status: {}",
                        enable_status_result
                    );
                } else {
                    info!(
                        "AutoLaunch successfully disabled. Status: {}",
                        enable_status_result
                    );
                }
            }
            Err(enable_status_result) => {
                error!("Error getting AutoLaunch status: {}", enable_status_result);
            }
        };
    }
}
