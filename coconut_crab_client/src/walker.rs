use crossbeam_channel::Sender;
use log::{debug, error};
use rand::{SeedableRng, rngs::SmallRng, seq::SliceRandom};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};
use zlob::walk::{WalkBuilder, WalkEntry, WalkFlags, WalkState};

use crate::{config, status::STATUS_FILENAME};
use coconut_crab_lib::file::get_lowercase_extension;

const WALK_COORDINATOR_STACK_SIZE: usize = 8 << 20;

pub fn walk_with_exts(
    sender: Sender<Arc<PathBuf>>,
    allow_exts: Option<Vec<String>>,
    block_exts: Option<Vec<String>>,
    threads: usize,
) -> thread::JoinHandle<()> {
    debug!("Starting walk thread with {threads} zlob workers");

    thread::Builder::new()
        .stack_size(WALK_COORDINATOR_STACK_SIZE)
        .spawn(move || {
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

                let mut flags = WalkFlags::empty();
                if config::AVOID_HIDDEN {
                    flags |= WalkFlags::SKIP_HIDDEN;
                    debug!("Hidden files/dirs will be skipped");
                }
                debug!("Walk flags set: {flags:?}");
                builder.options(flags);
                builder.threads(threads);

                debug!(
                    "Starting zlob walk for: {} with {threads} worker threads",
                    starting_path.display()
                );
                if let Err(error) = builder.run(|entry| {
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        process_walk_entry(entry, &sender, allow_exts, block_exts)
                    }));
                    match result {
                        Ok(state) => state,
                        Err(payload) => {
                            error!(
                                "Walk visitor recovered from panic on {}: {payload:?}",
                                entry.path().display()
                            );
                            WalkState::Continue
                        }
                    }
                }) {
                    error!("Walk error for {}: {error}", starting_path.display());
                }
            }
        })
        .expect("Failed to spawn walk coordinator thread")
}

pub fn random_walk_with_exts(
    sender: Sender<Arc<PathBuf>>,
    allow_exts: Option<Vec<String>>,
    block_exts: Option<Vec<String>>,
    threads: usize,
) -> thread::JoinHandle<()> {
    debug!("Starting random walk thread with {threads} zlob workers");

    thread::Builder::new()
        .stack_size(WALK_COORDINATOR_STACK_SIZE)
        .spawn(move || {
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

                let mut flags = WalkFlags::empty();
                if config::AVOID_HIDDEN {
                    flags |= WalkFlags::SKIP_HIDDEN;
                    debug!("Hidden files/dirs will be skipped");
                }
                builder.options(flags);
                builder.threads(threads);

                debug!(
                    "Starting zlob collect for: {} with {threads} worker threads",
                    starting_path.display()
                );
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

                        if file_filter(&entry_path, allow_exts, block_exts) {
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
        .expect("Failed to spawn random walk coordinator thread")
}

fn process_walk_entry(
    entry: WalkEntry<'_>,
    sender: &Sender<Arc<PathBuf>>,
    allow_exts: Option<&[String]>,
    block_exts: Option<&[String]>,
) -> WalkState {
    if entry.is_file() {
        let entry_path = entry.path().to_path_buf();

        if let Some(blocklist_paths) = config::BLOCKLIST_PATHS.as_ref()
            && blocklist_paths.contains(&entry_path)
        {
            debug!("Blocklist contains entry: {}", entry_path.display());
            return WalkState::Continue;
        }

        if file_filter(&entry_path, allow_exts, block_exts) {
            debug!("Entry matched filter: {}", entry_path.display());
            if let Err(error) = sender.send(Arc::new(entry_path)) {
                error!("Failed to send path to crypto/analysis/canary thread: {error}");
            }
        } else {
            debug!("Entry did not match filter: {}", entry_path.display());
        }
    }

    WalkState::Continue
}

fn file_filter(
    file_path: &Path,
    allowlist_extensions: Option<&[String]>,
    blocklist_extensions: Option<&[String]>,
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
