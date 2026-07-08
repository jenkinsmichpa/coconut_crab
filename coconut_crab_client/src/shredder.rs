use crossbeam_channel::Receiver;
use log::{debug, error, info, warn};
use rand::{Rng, SeedableRng, rngs::SmallRng};
use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    sync::Arc,
    thread,
};

const SHRED_BUFFER_SIZE: usize = 64 * 1024;

pub fn shred(receiver: Receiver<Arc<PathBuf>>) -> thread::JoinHandle<()> {
    debug!("Starting shredder thread");
    thread::spawn(move || {
        let mut rng_cheap = SmallRng::from_rng(&mut rand::rng());
        debug!("Created cheap random number generator");

        loop {
            let file_path = match receiver.recv() {
                Ok(path) => {
                    debug!("Received file path over channel: {path:?}");
                    path
                }
                Err(error) => {
                    warn!("Error receiving file path over channel: {error}");
                    return;
                }
            };

            info!("Shredding file: {}", file_path.display());

            let file_metadata = match fs::metadata(file_path.as_ref()) {
                Ok(metadata) => {
                    debug!("Successfully extracted file metadata: {metadata:?}");
                    metadata
                }
                Err(metadata) => {
                    debug!("Error extracting file metadata: {metadata:?}");
                    continue;
                }
            };

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

            let file_size = file_metadata.len();
            debug!("Existing data length: {file_size}");

            let Ok(_) = file.seek(SeekFrom::Start(0)) else {
                error!("Error seeking to start of file: {}", file_path.display());
                continue;
            };

            let mut buffer = vec![0u8; SHRED_BUFFER_SIZE];
            let mut remaining = file_size;
            while remaining > 0 {
                let chunk_size = std::cmp::min(remaining, SHRED_BUFFER_SIZE as u64);
                let data = &mut buffer[..usize::try_from(chunk_size).unwrap()]; // chunk_size <= SHRED_BUFFER_SIZE = 65536 = well within max usize
                rng_cheap.fill_bytes(data);
                if let Err(error) = file.write_all(data) {
                    error!("Error writing random data to file: {error}");
                    break;
                }
                remaining -= chunk_size;
            }

            match file.sync_all() {
                Ok(()) => {
                    debug!("Successfully completed file io operations: {file:?}");
                }
                Err(error) => {
                    error!("Error completing file io operations: {error}");
                    continue;
                }
            }

            match fs::remove_file(file_path.as_ref()) {
                Ok(()) => {
                    debug!("Successfully removed file: {file_path:?}");
                }
                Err(error) => {
                    error!("Error removing file: {error}");
                }
            }
        }
    })
}
