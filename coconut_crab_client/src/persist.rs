use std::env;

use anyhow::{Context, anyhow};
use auto_launch::{AutoLaunch, AutoLaunchBuilder};
use tracing::{debug, info};

const APP_NAME: &str = "Coconut Crab";

fn build_autolaunch() -> anyhow::Result<AutoLaunch> {
    let exe_path = env::current_exe()
        .map(|path| {
            debug!(path = %path.display(), "Successfully got current exe path");
            path.to_string_lossy().into_owned()
        })
        .context("failed to get current exe path")?;
    AutoLaunchBuilder::new()
        .set_app_name(APP_NAME)
        .set_app_path(&exe_path)
        .build()
        .context("failed to create AutoLaunch")
}

fn check_enabled(
    autolaunch: &AutoLaunch,
    want_enabled: bool,
    present: &str,
    past: &str,
) -> anyhow::Result<()> {
    match autolaunch.is_enabled() {
        Ok(enabled) if enabled == want_enabled => {
            info!(past, "AutoLaunch operation succeeded");
            Ok(())
        }
        Ok(_) => Err(anyhow!(
            "auto-launch state unexpected after {present} attempt"
        )),
        Err(error) => Err(error).context("failed to get AutoLaunch status"),
    }
}

pub(crate) fn start_persist() -> anyhow::Result<()> {
    let autolaunch = build_autolaunch()?;
    debug!("Successfully got AutoLaunch");

    autolaunch.enable().context("failed to enable AutoLaunch")?;
    check_enabled(&autolaunch, true, "enable", "enabled")
}

pub(crate) fn stop_persist() -> anyhow::Result<()> {
    let autolaunch = build_autolaunch()?;
    debug!("Successfully got AutoLaunch");

    autolaunch
        .disable()
        .context("failed to disable AutoLaunch")?;
    check_enabled(&autolaunch, false, "disable", "disabled")
}
