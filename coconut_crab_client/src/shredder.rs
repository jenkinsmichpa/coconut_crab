use crossbeam_channel::Receiver;
use log::{debug, error, info, warn};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    sync::Arc,
    thread,
};

pub fn shred(r: Receiver<Arc<PathBuf>>) -> thread::JoinHandle<()> {
    debug!("Starting shredder thread");
    thread::spawn(move || {
        let mut rng_cheap = SmallRng::from_rng(&mut rand::rng());
        debug!("Created cheap random number generator");

        loop {
            let file_path = match r.recv() {
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
                    debug!("Successfuly extracted file metadata: {metadata:?}");
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
                    eprintln!("Error opening file for writing: {error}");
                    continue;
                }
            };

            let Ok(file_size) = usize::try_from(file_metadata.len()) else {
                warn!(
                    "File too large to shred on this platform, skipping: {}",
                    file_path.display()
                );
                continue;
            };
            let mut data = vec![0u8; file_size];
            debug!("Existing data length: {}", file_metadata.len());

            rng_cheap.fill_bytes(&mut data);

            match file.seek(SeekFrom::Start(0)) {
                Ok(position) => {
                    debug!("Successfuly seeked to start of file: {position}");
                }
                Err(error) => {
                    error!("Error seeking to start of file: {error}");
                    continue;
                }
            }

            match file.write_all(&data) {
                Ok(()) => {
                    debug!("Successfuly wrote to file: {file:?}");
                }
                Err(error) => {
                    error!("Error writing to file: {error}");
                    continue;
                }
            }

            match file.sync_all() {
                Ok(()) => {
                    debug!("Successfuly completed file io operations: {file:?}");
                }
                Err(error) => {
                    error!("Error completing file io operations: {error}");
                    continue;
                }
            }

            match fs::remove_file(file_path.as_ref()) {
                Ok(()) => {
                    debug!("Successfuly removed file: {file_path:?}");
                }
                Err(error) => {
                    error!("Error removing file: {error}");
                }
            }
        }
    })
}
