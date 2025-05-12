use crossbeam_channel::Receiver;
use log::{debug, error, info, warn};
use rand::{rngs::SmallRng, RngCore, SeedableRng};
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
        let mut rng_cheap = SmallRng::from_entropy();
        debug!("Created cheap random number generator");

        loop {
            let file_path = match r.recv() {
                Ok(file_path_result) => {
                    debug!("Received file path over channel: {:?}", file_path_result);
                    file_path_result
                }
                Err(file_path_result) => {
                    warn!(
                        "Error receiving file path over channel: {}",
                        file_path_result
                    );
                    return;
                }
            };

            info!("Shredding file: {}", file_path.display());

            let file_metadata = match fs::metadata(file_path.as_ref()) {
                Ok(file_metadata_result) => {
                    debug!(
                        "Successfuly extracted file metadata: {:?}",
                        file_metadata_result
                    );
                    file_metadata_result
                }
                Err(file_metadata_result) => {
                    debug!("Error extracting file metadata: {:?}", file_metadata_result);
                    continue;
                }
            };

            let mut file = match File::options().write(true).open(file_path.as_ref()) {
                Ok(file_result) => {
                    debug!("Successfully opened file for writing: {:?}", file_path);
                    file_result
                }
                Err(file_result) => {
                    eprintln!("Error opening file for writing: {}", file_result);
                    continue;
                }
            };

            let mut data = vec![0u8; file_metadata.len() as usize];
            debug!("Existing data length: {}", file_metadata.len());

            rng_cheap.fill_bytes(&mut data);

            match file.seek(SeekFrom::Start(0)) {
                Ok(seek_result) => {
                    debug!("Successfuly seeked to start of file: {}", seek_result);
                }
                Err(seek_result) => {
                    error!("Error seeking to start of file: {}", seek_result);
                    continue;
                }
            }

            match file.write_all(&data) {
                Ok(_) => {
                    debug!("Successfuly wrote to file: {:?}", file);
                }
                Err(write_result) => {
                    error!("Error writing to file: {}", write_result);
                    continue;
                }
            }

            match file.sync_all() {
                Ok(_) => {
                    debug!("Successfuly completed file io operations: {:?}", file);
                }
                Err(flush_result) => {
                    error!("Error completing file io operations: {}", flush_result);
                    continue;
                }
            }

            match fs::remove_file(file_path.as_ref()) {
                Ok(_) => {
                    debug!("Successfuly removed file: {:?}", file_path);
                }
                Err(remove_result) => {
                    error!("Error removing file: {}", remove_result);
                    continue;
                }
            }
        }
    })
}
