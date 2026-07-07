use crossbeam_channel::Sender;
use log::{debug, error};
use rand::{rngs::SmallRng, seq::SliceRandom, SeedableRng};
use std::{path::PathBuf, sync::Arc, thread};
use zlob::walk::{WalkBuilder, WalkFlags, WalkState};

use crate::status::STATUS_FILENAME;
use coconut_crab_lib::file::get_lowercase_extension;

pub fn walk(
    sender: Sender<Arc<PathBuf>>,
    allowlist_paths_arc: Arc<Vec<PathBuf>>,
    blocklist_paths_arc: Arc<Option<Vec<PathBuf>>>,
    allowlist_extensions_arc: Arc<Option<Vec<String>>>,
    blocklist_extensions_arc: Arc<Option<Vec<String>>>,
    avoid_hidden_arc: Arc<bool>,
) -> thread::JoinHandle<()> {
    debug!("Starting walk thread");
    thread::spawn(move || {
        for starting_path in allowlist_paths_arc.iter() {
            let mut builder = match WalkBuilder::new(starting_path) {
                Ok(b) => {
                    debug!("Created WalkBuilder for: {:?}", starting_path);
                    b
                }
                Err(e) => {
                    error!(
                        "Failed to create WalkBuilder for {:?}: {}",
                        starting_path, e
                    );
                    continue;
                }
            };

            // Build walk flags
            let mut flags = WalkFlags::FOLLOW_SYMLINKS;
            if *avoid_hidden_arc {
                flags |= WalkFlags::SKIP_HIDDEN;
                debug!("Hidden files/dirs will be skipped");
            }
            debug!("Walk flags set: {:?}", flags);
            builder.options(flags);

            // Single-threaded walk: we manage parallelism at the Rust thread level
            // (zlob's own thread pool would oversubscribe with our existing multi-threaded design)
            builder.threads(1);

            // Capture references for the callback
            let blocklist = blocklist_paths_arc.as_ref();
            let allow_exts = allowlist_extensions_arc.as_ref();
            let block_exts = blocklist_extensions_arc.as_ref();

            debug!("Starting zlob walk for: {:?}", starting_path);
            if let Err(e) = builder.run_serial(|entry| {
                if entry.is_file() {
                    let entry_path = entry.path().to_path_buf();

                    // Check blocklist paths
                    if let Some(blocklist_paths) = blocklist {
                        if blocklist_paths.contains(&entry_path) {
                            debug!("Blocklist contains entry: {:?}", entry_path);
                            return WalkState::Continue;
                        }
                    }

                    // Check file filters (extension allowlist/blocklist, status file)
                    if file_filter(&entry_path, allow_exts, block_exts, &entry_path) {
                        debug!("Entry matched filter: {:?}", entry_path);
                        match sender.send(Arc::new(entry_path)) {
                            Ok(_) => {
                                debug!("Successfully sent path to crypto/analysis/canary thread");
                            }
                            Err(send_result) => {
                                error!(
                                    "Failed to send path to crypto/analysis/canary thread: {}",
                                    send_result
                                );
                            }
                        }
                    } else {
                        debug!("Entry did not match filter: {:?}", entry_path);
                    }
                }
                WalkState::Continue
            }) {
                error!("Walk error for {:?}: {}", starting_path, e);
            }
        }
    })
}

pub fn random_walk(
    sender: Sender<Arc<PathBuf>>,
    allowlist_paths_arc: Arc<Vec<PathBuf>>,
    blocklist_paths_arc: Arc<Option<Vec<PathBuf>>>,
    allowlist_extensions_arc: Arc<Option<Vec<String>>>,
    blocklist_extensions_arc: Arc<Option<Vec<String>>>,
    avoid_hidden_arc: Arc<bool>,
) -> thread::JoinHandle<()> {
    debug!("Starting random walk thread");
    thread::spawn(move || {
        let mut found_paths: Vec<PathBuf> = vec![];

        for starting_path in allowlist_paths_arc.iter() {
            let mut builder = match WalkBuilder::new(starting_path) {
                Ok(b) => {
                    debug!("Created WalkBuilder for: {:?}", starting_path);
                    b
                }
                Err(e) => {
                    error!(
                        "Failed to create WalkBuilder for {:?}: {}",
                        starting_path, e
                    );
                    continue;
                }
            };

            // Build walk flags
            let mut flags = WalkFlags::FOLLOW_SYMLINKS;
            if *avoid_hidden_arc {
                flags |= WalkFlags::SKIP_HIDDEN;
                debug!("Hidden files/dirs will be skipped");
            }
            builder.options(flags);
            builder.threads(1);

            debug!("Starting zlob collect for: {:?}", starting_path);
            let results = match builder.collect() {
                Ok(r) => r,
                Err(e) => {
                    error!("Walk error for {:?}: {}", starting_path, e);
                    continue;
                }
            };

            debug!("Walked {} entries in {:?}", results.len(), starting_path);

            for entry in results.iter() {
                if entry.is_file() {
                    let entry_path = entry.path().to_path_buf();

                    // Check blocklist paths
                    if let Some(blocklist_paths) = blocklist_paths_arc.as_ref() {
                        if blocklist_paths.contains(&entry_path) {
                            debug!("Blocklist contains entry: {:?}", entry_path);
                            continue;
                        }
                    }

                    // Check file filters
                    if file_filter(
                        &entry_path,
                        allowlist_extensions_arc.as_ref(),
                        blocklist_extensions_arc.as_ref(),
                        &entry_path,
                    ) {
                        debug!("Entry matched filter: {:?}", entry_path);
                        found_paths.push(entry_path);
                    } else {
                        debug!("Entry did not match filter: {:?}", entry_path);
                    }
                }
            }
        }

        let mut rng_cheap = SmallRng::from_entropy();
        debug!("Created cheap random number generator");

        found_paths.shuffle(&mut rng_cheap);

        for path in found_paths {
            debug!("Sending path to crypto/analysis/canary thread: {:?}", path);
            match sender.send(Arc::new(path)) {
                Ok(_) => {
                    debug!("Successfully sent path to crypto/analysis/canary thread");
                }
                Err(send_result) => {
                    error!(
                        "Failed to send path to crypto/analysis/canary thread: {}",
                        send_result
                    );
                }
            }
        }
    })
}

/// Checks if a file should be included based on extension allowlist/blocklist and status file exclusion.
///
/// Note: The `_entry_path` parameter is unused here but kept for signature compatibility
/// with future extensions. Extension matching is done on `file_path`.
fn file_filter(
    file_path: &PathBuf,
    allowlist_extensions: &Option<Vec<String>>,
    blocklist_extensions: &Option<Vec<String>>,
    _entry_path: &PathBuf,
) -> bool {
    let mut file_match = true;

    if let Some(allowlist_extensions) = allowlist_extensions {
        debug!("Applying allowlist to file: {:?}", file_path);
        if allowlist_extensions.contains(&get_lowercase_extension(file_path)) {
            debug!("Allowlist contains extension: {:?}", file_path);
            file_match = true;
        } else {
            debug!("Allowlist does not contain extension: {:?}", file_path);
            file_match = false;
        }
    } else {
        debug!("Not applying allowlist to file: {:?}", file_path);
    }

    if let Some(blocklist_extensions) = blocklist_extensions {
        debug!("Applying blocklist to file: {:?}", file_path);
        if blocklist_extensions.contains(&get_lowercase_extension(file_path)) {
            debug!("Blocklist contains file extension: {:?}", file_path);
            file_match = false;
        } else {
            debug!("Blocklist does not contain file extension: {:?}", file_path);
        }
    } else {
        debug!("Not applying blocklist to file: {:?}", file_path);
    }

    match file_path.file_name() {
        Some(file_name_result) => {
            debug!("Successfully got filename: {:?}", file_name_result);
            if file_name_result.to_string_lossy() == STATUS_FILENAME {
                debug!("File is {} Avoiding ouroboros.", STATUS_FILENAME);
                file_match = false;
            }
        }
        None => {
            error!("Failed to get filename: {:?}", file_path);
        }
    }

    debug!("{:?} matches: {}", file_path, file_match);
    file_match
}
