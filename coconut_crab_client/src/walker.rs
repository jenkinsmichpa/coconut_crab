use crossbeam_channel::Sender;
use log::{debug, error};
use rand::{SeedableRng, rngs::SmallRng, seq::SliceRandom};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};
use zlob::walk::{WalkBuilder, WalkFlags, WalkState};

use crate::{config, status::STATUS_FILENAME};
use coconut_crab_lib::file::get_lowercase_extension;

pub fn walk(sender: Sender<Arc<PathBuf>>) -> thread::JoinHandle<()> {
    walk_with_exts(sender, None, None)
}

pub fn walk_with_exts(
    sender: Sender<Arc<PathBuf>>,
    allow_exts: Option<Vec<String>>,
    block_exts: Option<Vec<String>>,
) -> thread::JoinHandle<()> {
    debug!("Starting walk thread");
    thread::spawn(move || {
        let allow_exts = allow_exts
            .as_deref()
            .or(Some(config::ALLOWLIST_EXTENSIONS.as_slice()));
        let block_exts = block_exts.as_deref();

        for starting_path in config::ALLOWLIST_PATHS.iter() {
            let mut builder = match WalkBuilder::new(starting_path) {
                Ok(builder) => {
                    debug!("Created WalkBuilder for: {}", starting_path.display());
                    builder
                }
                Err(error) => {
                    error!(
                        "Failed to create WalkBuilder for {}: {error}",
                        starting_path.display()
                    );
                    continue;
                }
            };

            let mut flags = WalkFlags::FOLLOW_SYMLINKS;
            if config::AVOID_HIDDEN {
                flags |= WalkFlags::SKIP_HIDDEN;
                debug!("Hidden files/dirs will be skipped");
            }
            debug!("Walk flags set: {flags:?}");
            builder.options(flags);
            builder.threads(1);

            debug!("Starting zlob walk for: {}", starting_path.display());
            if let Err(error) = builder.run_serial(|entry| {
                if entry.is_file() {
                    let entry_path = entry.path().to_path_buf();

                    if let Some(blocklist_paths) = config::BLOCKLIST_PATHS.as_ref()
                        && blocklist_paths.contains(&entry_path)
                    {
                        debug!("Blocklist contains entry: {}", entry_path.display());
                        return WalkState::Continue;
                    }

                    if file_filter(&entry_path, allow_exts, block_exts, &entry_path) {
                        debug!("Entry matched filter: {}", entry_path.display());
                        if let Err(error) = sender.send(Arc::new(entry_path)) {
                            error!("Failed to send path to crypto/analysis/canary thread: {error}");
                        }
                    } else {
                        debug!("Entry did not match filter: {}", entry_path.display());
                    }
                }
                WalkState::Continue
            }) {
                error!("Walk error for {}: {error}", starting_path.display());
            }
        }
    })
}

pub fn random_walk(sender: Sender<Arc<PathBuf>>) -> thread::JoinHandle<()> {
    random_walk_with_exts(sender, None, None)
}

pub fn random_walk_with_exts(
    sender: Sender<Arc<PathBuf>>,
    allow_exts: Option<Vec<String>>,
    block_exts: Option<Vec<String>>,
) -> thread::JoinHandle<()> {
    debug!("Starting random walk thread");
    thread::spawn(move || {
        let allow_exts = allow_exts
            .as_deref()
            .or(Some(config::ALLOWLIST_EXTENSIONS.as_slice()));
        let block_exts = block_exts.as_deref();
        let mut found_paths: Vec<PathBuf> = vec![];

        for starting_path in config::ALLOWLIST_PATHS.iter() {
            let mut builder = match WalkBuilder::new(starting_path) {
                Ok(builder) => {
                    debug!("Created WalkBuilder for: {}", starting_path.display());
                    builder
                }
                Err(error) => {
                    error!(
                        "Failed to create WalkBuilder for {}: {error}",
                        starting_path.display()
                    );
                    continue;
                }
            };

            let mut flags = WalkFlags::FOLLOW_SYMLINKS;
            if config::AVOID_HIDDEN {
                flags |= WalkFlags::SKIP_HIDDEN;
                debug!("Hidden files/dirs will be skipped");
            }
            builder.options(flags);
            builder.threads(1);

            debug!("Starting zlob collect for: {}", starting_path.display());
            let results = match builder.collect() {
                Ok(results) => results,
                Err(error) => {
                    error!("Walk error for {}: {error}", starting_path.display());
                    continue;
                }
            };

            debug!(
                "Walked {} entries in {}",
                results.len(),
                starting_path.display()
            );

            for entry in results.iter() {
                if entry.is_file() {
                    let entry_path = entry.path().to_path_buf();

                    if let Some(blocklist_paths) = config::BLOCKLIST_PATHS.as_ref()
                        && blocklist_paths.contains(&entry_path)
                    {
                        debug!("Blocklist contains entry: {}", entry_path.display());
                        continue;
                    }

                    if file_filter(&entry_path, allow_exts, block_exts, &entry_path) {
                        debug!("Entry matched filter: {}", entry_path.display());
                        found_paths.push(entry_path);
                    } else {
                        debug!("Entry did not match filter: {}", entry_path.display());
                    }
                }
            }
        }

        let mut rng_cheap = SmallRng::from_rng(&mut rand::rng());
        debug!("Created cheap random number generator");

        found_paths.shuffle(&mut rng_cheap);

        for path in found_paths {
            debug!(
                "Sending path to crypto/analysis/canary thread: {}",
                path.display()
            );
            if let Err(error) = sender.send(Arc::new(path)) {
                error!("Failed to send path to crypto/analysis/canary thread: {error}");
            }
        }
    })
}

fn file_filter(
    file_path: &Path,
    allowlist_extensions: Option<&[String]>,
    blocklist_extensions: Option<&[String]>,
    _entry_path: &Path,
) -> bool {
    let mut file_match = true;

    if let Some(allowlist_extensions) = allowlist_extensions {
        debug!("Applying allowlist to file: {}", file_path.display());
        if allowlist_extensions.contains(&get_lowercase_extension(file_path)) {
            debug!("Allowlist contains extension: {}", file_path.display());
            file_match = true;
        } else {
            debug!(
                "Allowlist does not contain extension: {}",
                file_path.display()
            );
            file_match = false;
        }
    } else {
        debug!("Not applying allowlist to file: {}", file_path.display());
    }

    if let Some(blocklist_extensions) = blocklist_extensions {
        debug!("Applying blocklist to file: {}", file_path.display());
        if blocklist_extensions.contains(&get_lowercase_extension(file_path)) {
            debug!("Blocklist contains file extension: {}", file_path.display());
            file_match = false;
        } else {
            debug!(
                "Blocklist does not contain file extension: {}",
                file_path.display()
            );
        }
    } else {
        debug!("Not applying blocklist to file: {}", file_path.display());
    }

    match file_path.file_name() {
        Some(name) => {
            debug!("Successfully got filename: {}", name.to_string_lossy());
            if name.to_string_lossy() == *STATUS_FILENAME {
                debug!("File is {}. Avoiding ouroboros.", *STATUS_FILENAME);
                file_match = false;
            }
        }
        None => {
            error!("Failed to get filename: {}", file_path.display());
        }
    }

    debug!("{} matches: {file_match}", file_path.display());
    file_match
}
