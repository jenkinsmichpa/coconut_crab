use std::{
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    thread::{self, JoinHandle},
};

use flume::Receiver;
use rand::{Rng, SeedableRng, rngs::SmallRng};
use tracing::{debug, error, info};

use crate::client::recv_path;

const SHRED_BUFFER_SIZE: usize = 1024 * 1024;

pub fn shred(receiver: Receiver<Arc<PathBuf>>) -> io::Result<JoinHandle<()>> {
    debug!("Starting shredder thread");
    thread::Builder::new().spawn(move || {
        let mut rng_cheap = SmallRng::from_rng(&mut rand::rng());
        debug!("Created cheap random number generator");
        let mut buffer = vec![0u8; SHRED_BUFFER_SIZE];
        let max_chunk = u64::try_from(SHRED_BUFFER_SIZE).unwrap_or(u64::MAX);

        loop {
            let Some(file_path) = recv_path(&receiver) else {
                return;
            };

            info!(path = %file_path.display(), "Shredding file");

            let mut file = match File::options().write(true).open(file_path.as_ref()) {
                Ok(file) => {
                    debug!(path = %file_path.display(), "Successfully opened file for writing");
                    file
                }
                Err(error) => {
                    error!(error = ?error, "Error opening file for writing");
                    continue;
                }
            };

            let file_size = match file.metadata() {
                Ok(metadata) => {
                    debug!(?metadata, "Successfully extracted file metadata");
                    metadata.len()
                }
                Err(error) => {
                    error!(error = ?error, "Error extracting file metadata");
                    continue;
                }
            };
            debug!(?file_size, "Existing data length");

            let mut remaining = file_size;
            let mut write_ok = true;
            while remaining > 0 {
                let chunk_len =
                    usize::try_from(remaining.min(max_chunk)).unwrap_or(SHRED_BUFFER_SIZE);
                let data = &mut buffer[..chunk_len];
                rng_cheap.fill_bytes(data);
                if let Err(error) = file.write_all(data) {
                    error!(error = ?error, "Error writing random data to file");
                    write_ok = false;
                    break;
                }
                remaining = remaining.saturating_sub(u64::try_from(chunk_len).unwrap_or(max_chunk));
            }
            if !write_ok {
                continue;
            }

            if let Err(error) = file.sync_all() {
                error!(error = ?error, "Error completing file io operations");
                continue;
            }
            debug!(?file, "Successfully completed file io operations");
            drop(file);

            if let Err(error) = fs::remove_file(file_path.as_ref()) {
                error!(error = ?error, "Error removing file");
            } else {
                debug!(path = %file_path.display(), "Successfully removed file");
            }
        }
    })
}
