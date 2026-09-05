use flume::Receiver;
use log::{debug, error, info};
use rand::{Rng, SeedableRng, rngs::SmallRng};
use std::{
    cmp::min,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    sync::Arc,
    thread,
};

use crate::client::recv_path;

const SHRED_BUFFER_SIZE: usize = 64 * 1024;

pub fn shred(receiver: Receiver<Arc<PathBuf>>) -> thread::JoinHandle<()> {
    debug!("Starting shredder thread");
    thread::spawn(move || {
        let mut rng_cheap = SmallRng::from_rng(&mut rand::rng());
        debug!("Created cheap random number generator");
        let mut buffer = vec![0u8; SHRED_BUFFER_SIZE];

        loop {
            let Some(file_path) = recv_path(&receiver) else {
                return;
            };

            info!("Shredding file: {}", file_path.display());

            let mut file = match File::options().write(true).open(file_path.as_ref()) {
                Ok(file) => {
                    debug!("Successfully opened file for writing: {file_path:?}");
                    file
                }
                Err(error) => {
                    error!("Error opening file for writing: {error}");
                    continue;
                }
            };

            let file_size = match file.metadata() {
                Ok(metadata) => {
                    debug!("Successfully extracted file metadata: {metadata:?}");
                    metadata.len()
                }
                Err(error) => {
                    error!("Error extracting file metadata: {error}");
                    continue;
                }
            };
            debug!("Existing data length: {file_size}");

            let mut remaining = file_size;
            let mut write_ok = true;
            while remaining > 0 {
                let chunk_len = usize::try_from(min(remaining, SHRED_BUFFER_SIZE as u64))
                    .unwrap_or(SHRED_BUFFER_SIZE);
                let data = &mut buffer[..chunk_len];
                rng_cheap.fill_bytes(data);
                if let Err(error) = file.write_all(data) {
                    error!("Error writing random data to file: {error}");
                    write_ok = false;
                    break;
                }
                remaining -= chunk_len as u64;
            }
            if !write_ok {
                continue;
            }

            if let Err(error) = file.sync_all() {
                error!("Error completing file io operations: {error}");
                continue;
            }
            debug!("Successfully completed file io operations: {file:?}");
            drop(file);

            if let Err(error) = fs::remove_file(file_path.as_ref()) {
                error!("Error removing file: {error}");
            } else {
                debug!("Successfully removed file: {file_path:?}");
            }
        }
    })
}
