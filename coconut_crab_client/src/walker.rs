use flume::Sender;
use log::{debug, error, trace};
use rand::{SeedableRng, rngs::SmallRng, seq::SliceRandom};
use std::{
    ffi::OsStr,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};
use zlob::walk::{WalkBuilder, WalkEntry, WalkFlags, WalkState};

use crate::{
    config,
    status::{ANALYSIS_FILENAME, STATUS_FILENAME},
};

const WALK_COORDINATOR_STACK_SIZE: usize = 8 << 20;

fn new_builder(starting_path: &Path, threads: usize) -> Option<WalkBuilder> {
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
            return None;
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
    Some(builder)
}

fn resolve_filters<'a>(
    allow_exts: Option<&'a [String]>,
    block_exts: Option<&'a [String]>,
) -> (Option<&'a [String]>, Option<&'a [String]>) {
    let allow = allow_exts.or(Some(config::ALLOWLIST_EXTENSIONS.as_slice()));
    let block = block_exts.or(config::BLOCKLIST_EXTENSIONS.as_deref());
    (allow, block)
}

fn file_should_include(
    path: &Path,
    allow_exts: Option<&[String]>,
    block_exts: Option<&[String]>,
) -> bool {
    if is_blocked(path) {
        return false;
    }
    file_filter(path, allow_exts, block_exts)
}

fn send_path(sender: &Sender<Arc<PathBuf>>, path: PathBuf) {
    debug!(
        "Sending path to crypto/analysis/canary thread: {}",
        path.display()
    );
    if let Err(error) = sender.send(Arc::new(path)) {
        error!("Failed to send path to crypto/analysis/canary thread: {error}");
    }
}

fn with_each_builder(threads: usize, mut visit: impl FnMut(&Path, WalkBuilder)) {
    for starting_path in config::ALLOWLIST_PATHS.iter() {
        let Some(builder) = new_builder(starting_path, threads) else {
            continue;
        };
        visit(starting_path, builder);
    }
}

fn spawn_coordinator(
    label: &'static str,
    allow_exts: Option<&[String]>,
    block_exts: Option<&[String]>,
    body: impl FnOnce(Option<Vec<String>>, Option<Vec<String>>) + Send + 'static,
) -> thread::JoinHandle<()> {
    debug!("Starting {label} coordinator thread");
    let allow_owned = allow_exts.map(<[String]>::to_vec);
    let block_owned = block_exts.map(<[String]>::to_vec);
    thread::Builder::new()
        .stack_size(WALK_COORDINATOR_STACK_SIZE)
        .spawn(move || body(allow_owned, block_owned))
        .expect("Failed to spawn walk coordinator thread")
}

fn shuffle_and_send_path(sender: &Sender<Arc<PathBuf>>, mut paths: Vec<PathBuf>) {
    let mut rng_cheap = SmallRng::from_rng(&mut rand::rng());
    debug!("Created cheap random number generator");
    paths.shuffle(&mut rng_cheap);
    for path in paths {
        send_path(sender, path);
    }
}

pub fn walk_with_exts(
    sender: Sender<Arc<PathBuf>>,
    allow_exts: Option<&[String]>,
    block_exts: Option<&[String]>,
    threads: usize,
) -> thread::JoinHandle<()> {
    spawn_coordinator(
        "walk",
        allow_exts,
        block_exts,
        move |allow_owned, block_owned| {
            let (allow_exts, block_exts) =
                resolve_filters(allow_owned.as_deref(), block_owned.as_deref());

            with_each_builder(threads, |starting_path, builder| {
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
            });
        },
    )
}

pub fn random_walk_with_exts(
    sender: Sender<Arc<PathBuf>>,
    allow_exts: Option<&[String]>,
    block_exts: Option<&[String]>,
    threads: usize,
) -> thread::JoinHandle<()> {
    spawn_coordinator(
        "random walk",
        allow_exts,
        block_exts,
        move |allow_owned, block_owned| {
            let (allow_exts, block_exts) =
                resolve_filters(allow_owned.as_deref(), block_owned.as_deref());
            let mut found_paths: Vec<PathBuf> = Vec::new();

            with_each_builder(threads, |starting_path, builder| {
                debug!(
                    "Starting zlob collect for: {} with {threads} worker threads",
                    starting_path.display()
                );
                let results = match builder.collect() {
                    Ok(results) => results,
                    Err(error) => {
                        error!("Walk error for {}: {error}", starting_path.display());
                        return;
                    }
                };

                debug!(
                    "Walked {} entries in {}",
                    results.len(),
                    starting_path.display()
                );

                for entry in results.iter() {
                    if !entry.is_file() {
                        continue;
                    }
                    if file_should_include(entry.path(), allow_exts, block_exts) {
                        debug!("Entry matched filter: {}", entry.path().display());
                        found_paths.push(entry.path().to_path_buf());
                    } else {
                        debug!("Entry did not match filter: {}", entry.path().display());
                    }
                }
            });

            shuffle_and_send_path(&sender, found_paths);
        },
    )
}

fn process_walk_entry(
    entry: WalkEntry<'_>,
    sender: &Sender<Arc<PathBuf>>,
    allow_exts: Option<&[String]>,
    block_exts: Option<&[String]>,
) -> WalkState {
    if entry.is_dir() {
        return if is_blocked(entry.path()) {
            WalkState::SkipDir
        } else {
            WalkState::Continue
        };
    }

    if entry.is_file() {
        if file_should_include(entry.path(), allow_exts, block_exts) {
            debug!("Entry matched filter: {}", entry.path().display());
            send_path(sender, entry.path().to_path_buf());
        } else {
            debug!("Entry did not match filter: {}", entry.path().display());
        }
    }

    WalkState::Continue
}

fn is_blocked(entry_path: &Path) -> bool {
    config::BLOCKLIST_PATHS.as_deref().is_some_and(|paths| {
        paths.iter().any(|blocked| {
            let hit = entry_path.starts_with(blocked);
            if hit {
                debug!("Blocklist contains entry: {}", entry_path.display());
            }
            hit
        })
    })
}

fn extension_matches(list: &[String], file_path: &Path) -> bool {
    let Some(ext) = file_path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    list.iter()
        .any(|allowed| allowed.as_str().eq_ignore_ascii_case(ext))
}

fn file_filter(
    file_path: &Path,
    allowlist_extensions: Option<&[String]>,
    blocklist_extensions: Option<&[String]>,
) -> bool {
    if let Some(allowlist_extensions) = allowlist_extensions {
        trace!("Applying allowlist to file: {}", file_path.display());
        if !extension_matches(allowlist_extensions, file_path) {
            trace!(
                "Allowlist does not contain extension: {}",
                file_path.display()
            );
            return false;
        }
        trace!("Allowlist contains extension: {}", file_path.display());
    } else {
        trace!("Not applying allowlist to file: {}", file_path.display());
    }

    if let Some(blocklist_extensions) = blocklist_extensions {
        trace!("Applying blocklist to file: {}", file_path.display());
        if extension_matches(blocklist_extensions, file_path) {
            trace!("Blocklist contains file extension: {}", file_path.display());
            return false;
        }
        trace!(
            "Blocklist does not contain file extension: {}",
            file_path.display()
        );
    } else {
        trace!("Not applying blocklist to file: {}", file_path.display());
    }

    if let Some(name) = file_path.file_name() {
        trace!("Successfully got filename: {}", name.to_string_lossy());
        if name == OsStr::new(STATUS_FILENAME.as_str())
            || name == OsStr::new(ANALYSIS_FILENAME.as_str())
        {
            trace!("File is own output. Avoiding ouroboros.");
            return false;
        }
    } else {
        error!("Failed to get filename: {}", file_path.display());
        return false;
    }

    trace!("{} matches: true", file_path.display());
    true
}
