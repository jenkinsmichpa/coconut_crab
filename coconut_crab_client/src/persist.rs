use auto_launch::{AutoLaunch, AutoLaunchBuilder};
use log::{debug, error, info};
use std::{env, io};

const APP_NAME: &str = "Coconut Crab";

fn get_autolaunch() -> Result<AutoLaunch, io::Error> {
    let exe_path = env::current_exe()
        .map(|path| {
            debug!("Successfully got current exe path: {}", path.display());
            path.to_string_lossy().into_owned()
        })
        .map_err(|error| {
            error!("Failed to get current exe path: {error}");
            error
        })?;
    AutoLaunchBuilder::new()
        .set_app_name(APP_NAME)
        .set_app_path(&exe_path)
        .build()
        .map_err(|error| {
            error!("Failed to create AutoLaunch: {error}");
            io::Error::other(error.to_string())
        })
}

fn check_enabled(
    autolaunch: &AutoLaunch,
    want_enabled: bool,
    present: &str,
    past: &str,
) -> Result<(), io::Error> {
    match autolaunch.is_enabled() {
        Ok(enabled) if enabled == want_enabled => {
            info!("AutoLaunch successfully {past}");
            Ok(())
        }
        Ok(_) => {
            error!("Unable to {present} AutoLaunch");
            Err(io::Error::other(format!(
                "AutoLaunch state unexpected after {present}"
            )))
        }
        Err(error) => {
            error!("Error getting AutoLaunch status: {error}");
            Err(io::Error::other(error.to_string()))
        }
    }
}

pub fn start_persist() -> Result<(), io::Error> {
    let autolaunch = get_autolaunch()?;
    debug!("Successfully got AutoLaunch");

    autolaunch.enable().map_err(|error| {
        error!("Error enabling AutoLaunch: {error}");
        io::Error::other(error.to_string())
    })?;
    check_enabled(&autolaunch, true, "enable", "enabled")
}

pub fn stop_persist() -> Result<(), io::Error> {
    let autolaunch = get_autolaunch()?;
    debug!("Successfully got AutoLaunch");

    autolaunch.disable().map_err(|error| {
        error!("Error disabling AutoLaunch: {error}");
        io::Error::other(error.to_string())
    })?;
    check_enabled(&autolaunch, false, "disable", "disabled")
}
