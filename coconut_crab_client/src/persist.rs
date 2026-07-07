use auto_launch::{AutoLaunch, AutoLaunchBuilder};
use log::{Level, debug, error, info, log_enabled};
use std::{env, io};

fn get_autolaunch() -> Result<AutoLaunch, io::Error> {
    let exe_path = match env::current_exe() {
        Ok(path) => {
            debug!("Successfully got current exe path: {}", path.display());
            path.to_string_lossy().into_owned()
        }
        Err(error) => {
            error!("Failed to get current exe path: {error}");
            return Err(error);
        }
    };
    let app_name = "Coconut Crab";
    let autolaunch = match AutoLaunchBuilder::new()
        .set_app_name(app_name)
        .set_app_path(&exe_path)
        .set_args(&[] as &[&str])
        .build()
    {
        Ok(autolaunch) => {
            debug!("Successfully created AutoLaunch: {autolaunch:?}");
            autolaunch
        }
        Err(error) => {
            error!("Failed to create AutoLaunch: {error}");
            return Err(io::Error::other(error.to_string()));
        }
    };
    Ok(autolaunch)
}

pub fn start_persist() {
    let autolaunch = match get_autolaunch() {
        Ok(autolaunch) => {
            debug!("Successfully got AutoLaunch: {autolaunch:?}");
            autolaunch
        }
        Err(error) => {
            error!("Failed to get AutoLaunch: {error}");
            return;
        }
    };

    if let Err(error) = autolaunch.enable() {
        error!("Error enabling AutoLaunch: {error}");
    }

    if log_enabled!(Level::Info) {
        match autolaunch.is_enabled() {
            Ok(status) => {
                if status {
                    info!("AutoLaunch successfully enabled. Status: {status}");
                } else {
                    error!("Unable to enable AutoLaunch. Status: {status}");
                }
            }
            Err(error) => {
                error!("Error getting AutoLaunch. status: {error}");
            }
        }
    }
}

pub fn stop_persist() {
    let autolaunch = match get_autolaunch() {
        Ok(autolaunch) => {
            debug!("Successfully got AutoLaunch: {autolaunch:?}");
            autolaunch
        }
        Err(error) => {
            error!("Failed to get AutoLaunch: {error}");
            return;
        }
    };

    if let Err(error) = autolaunch.disable() {
        error!("Error disabling AutoLaunch: {error}");
    }
    if log_enabled!(Level::Info) {
        match autolaunch.is_enabled() {
            Ok(status) => {
                if status {
                    error!("Unable to disable AutoLaunch. Status: {status}");
                } else {
                    info!("AutoLaunch successfully disabled. Status: {status}");
                }
            }
            Err(error) => {
                error!("Error getting AutoLaunch status: {error}");
            }
        }
    }
}
