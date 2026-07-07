/// Port used by web server [required]
pub const PORT: u16 = 3000;

/// Whether HTTPS or HTTP should be used [required]
pub const HTTPS: bool = true;

/// Time window in seconds where a failed encryption can recover a symmetric key [required]
pub const RECOVERY_WINDOW_SECONDS: u64 = 3600;

/// Secret used to validate web requests [required]
pub static PRESHARED_SECRET: &str =
    "gEFPsWMHEjdbBccgFKAFwdYwD98mH6cn7mmVwVgS8Vq4EUNocCwh3wLHrEVA7RzS";

/// Code valid for any victim [required]
pub static BYPASS_CODE: &str = "2NSd-NRF3-qkB3-v6qP";
