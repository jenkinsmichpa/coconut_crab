use flume::Sender;
use log::{debug, error, trace};
use rand::{SeedableRng, rngs::SmallRng, seq::SliceRandom};
use std::{
    collections::HashSet,
    ffi::OsStr,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};
use zlob::{
    ZlobFlags,
    walk::{WalkBuilder, WalkEntry, WalkFlags, WalkMetadata, WalkState},
};

use crate::{
    canary::{SUSPICIOUS_KEYWORDS, canary_active},
    config,
    status::{ANALYSIS_FILENAME, STATUS_FILENAME},
};

const WALK_COORDINATOR_STACK_SIZE: usize = 8 << 20;
const WALK_ROOT_STACK_SIZE: usize = 8 << 20;

const COARSE_GATE: &str = "**/*.*";

const COARSE_GATE_FLAGS: ZlobFlags = ZlobFlags::DOUBLESTAR_RECURSIVE.union(ZlobFlags::PERIOD);

const MAX_FOLDED_EXT_LEN: usize = 32;

#[derive(Debug)]
enum AllowPlan {
    WalkAll,
    MatchNone,
    CoarseGate,
}

const fn allow_plan(allow_exts: Option<&[String]>) -> AllowPlan {
    match allow_exts {
        None => AllowPlan::WalkAll,
        Some([]) => AllowPlan::MatchNone,
        Some(_) => AllowPlan::CoarseGate,
    }
}

fn escape_ignore(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (index, character) in text.chars().enumerate() {
        if matches!(character, '*' | '?' | '[' | ']' | '\\')
            || ((character == '!' || character == '#') && index == 0)
        {
            out.push('\\');
        }
        out.push(character);
    }
    out
}

fn fold_case_ignore(text: &str) -> Option<String> {
    if text.contains(['\0', '\n', '\r']) {
        return None;
    }
    let mut out = String::with_capacity(text.len() * 4);
    for character in text.chars() {
        if character.is_ascii_alphabetic() {
            out.push('[');
            out.push(character.to_ascii_lowercase());
            out.push(character.to_ascii_uppercase());
            out.push(']');
        } else {
            if matches!(character, '*' | '?' | '[' | ']' | '\\' | '!') {
                out.push('\\');
            }
            out.push(character);
        }
    }
    Some(out)
}

fn keyword_ignore_pattern(keyword: &str) -> Option<String> {
    if keyword.is_empty()
        || keyword.contains(['/', '\\', '\0', '\n', '\r'])
        || keyword.starts_with(' ')
        || keyword.ends_with(' ')
    {
        return None;
    }
    Some(format!("*{}*", fold_case_ignore(keyword)?))
}

const fn oversize(size: Option<u64>, max_file_bytes: Option<u64>) -> bool {
    matches!((size, max_file_bytes), (Some(known), Some(limit)) if known > limit)
}

fn native_ignore_rules(root: &Path, block_exts: Option<&[String]>) -> Vec<String> {
    let mut rules = Vec::new();
    if let Some(blocked_roots) = config::BLOCKLIST_PATHS.as_deref() {
        for blocked in blocked_roots {
            let Ok(rel) = blocked.strip_prefix(root) else {
                continue;
            };
            if rel.as_os_str().is_empty() {
                continue;
            }
            let Some(rel_str) = rel.to_str() else {
                continue;
            };
            if rel_str.contains('\0') {
                continue;
            }
            let pat = escape_ignore(&rel_str.replace('\\', "/"));
            rules.push(format!("/{pat}"));
        }
    }
    for name in [STATUS_FILENAME.as_str(), ANALYSIS_FILENAME.as_str()] {
        if name.contains(['/', '\\', '\0']) {
            continue;
        }
        rules.push(escape_ignore(name));
    }
    if let Some(exts) = block_exts {
        for ext in exts {
            if ext.is_empty() || ext.contains(['/', '\0']) {
                continue;
            }
            match fold_case_ignore(ext) {
                Some(folded) => rules.push(format!("*.{folded}")),
                None => debug!("Extension {ext:?} cannot be expressed natively, skipping"),
            }
        }
    }
    if config::AVOID_KEYWORDS && canary_active() {
        for keyword in SUSPICIOUS_KEYWORDS.iter() {
            if let Some(pattern) = keyword_ignore_pattern(keyword) {
                rules.push(pattern);
            } else {
                debug!("Keyword {keyword:?} cannot be expressed natively, skipping");
            }
        }
    }
    rules
}

fn native_ignore_coverage(block_exts: Option<&[String]>) -> NativeIgnores {
    let paths = config::BLOCKLIST_PATHS.as_deref().is_none_or(|blocked| {
        blocked
            .iter()
            .all(|path| path.to_str().is_some_and(|text| !text.contains('\0')))
    });
    let exts = block_exts.is_none_or(|exts| {
        exts.iter()
            .all(|ext| !ext.is_empty() && !ext.contains(['/', '\0', '\n', '\r']))
    });
    let ouroboros = [STATUS_FILENAME.as_str(), ANALYSIS_FILENAME.as_str()]
        .iter()
        .all(|name| !name.contains(['/', '\\', '\0']));
    NativeIgnores {
        paths,
        exts,
        ouroboros,
    }
}

fn configure_builder(
    starting_path: &Path,
    threads: usize,
    plan: &AllowPlan,
    block_exts: Option<&[String]>,
    max_file_bytes: Option<u64>,
) -> Option<WalkBuilder> {
    if config::BLOCKLIST_PATHS.as_deref().is_some_and(|paths| {
        paths
            .iter()
            .any(|blocked| starting_path.starts_with(blocked))
    }) {
        debug!(
            "Walk root {} is blocklisted, skipping",
            starting_path.display()
        );
        return None;
    }

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

    let mut flags = WalkFlags::NO_REPORT_DIRS;
    if config::AVOID_HIDDEN {
        flags |= WalkFlags::SKIP_HIDDEN;
        debug!("Hidden files/dirs will be skipped");
    }
    debug!("Walk flags set: {flags:?}");
    builder.options(flags);
    builder.threads(threads);

    if max_file_bytes.is_some() {
        builder.metadata(WalkMetadata::SIZE);
    }

    if matches!(plan, AllowPlan::CoarseGate) {
        match builder.include(COARSE_GATE) {
            Ok(builder) => {
                builder.include_flags(COARSE_GATE_FLAGS);
            }
            Err(error) => {
                error!("Invalid native include pattern, using Rust filter: {error}");
            }
        }
    }

    let rules = native_ignore_rules(starting_path, block_exts);
    if !rules.is_empty()
        && let Err(error) = builder.extra_ignore(&rules)
    {
        error!("Failed to install native ignore rules: {error}");
    }
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

#[derive(Debug, Clone, Copy, Default)]
struct NativeIgnores {
    paths: bool,
    exts: bool,
    ouroboros: bool,
}

struct WalkFilters<'a> {
    allow: Option<HashSet<String>>,
    block: Option<HashSet<String>>,
    block_exts: Option<&'a [String]>,
    native: NativeIgnores,
}

impl<'a> WalkFilters<'a> {
    fn new(allow: Option<&[String]>, block: Option<&'a [String]>, native: NativeIgnores) -> Self {
        Self {
            allow: allow.map(lowercase_exts),
            block: block.map(lowercase_exts),
            block_exts: block,
            native,
        }
    }

    fn should_include(&self, path: &Path) -> bool {
        if !self.native.paths && is_blocked(path) {
            return false;
        }
        self.file_filter(path)
    }

    fn file_filter(&self, file_path: &Path) -> bool {
        if let Some(allow) = &self.allow {
            trace!("Applying allowlist to file: {}", file_path.display());
            if !extension_matches(allow, file_path) {
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

        if self.native.exts {
            trace!("Native ignores cover the blocklist, skipping Rust check");
        } else if let Some(block) = &self.block {
            trace!("Applying blocklist to file: {}", file_path.display());
            if extension_matches(block, file_path) {
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

        if !self.native.ouroboros {
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
        }

        trace!("{} matches: true", file_path.display());
        true
    }
}

fn lowercase_exts(exts: &[String]) -> HashSet<String> {
    exts.iter().map(|ext| ext.to_ascii_lowercase()).collect()
}

fn extension_matches(set: &HashSet<String>, file_path: &Path) -> bool {
    let Some(ext) = file_path.extension().and_then(OsStr::to_str) else {
        return false;
    };
    if ext.len() <= MAX_FOLDED_EXT_LEN {
        let mut buf = [0_u8; MAX_FOLDED_EXT_LEN];
        for (slot, byte) in buf.iter_mut().zip(ext.bytes()) {
            *slot = byte.to_ascii_lowercase();
        }
        if let Ok(folded) = std::str::from_utf8(&buf[..ext.len()]) {
            return set.contains(folded);
        }
    }
    set.contains(&ext.to_ascii_lowercase())
}

fn per_root_threads(threads: usize, roots: usize) -> usize {
    if threads == 0 || roots == 0 {
        return threads;
    }
    (threads / roots).max(1)
}

fn send_path(sender: &Sender<Arc<PathBuf>>, path: PathBuf) {
    trace!(
        "Sending path to crypto/analysis/canary thread: {}",
        path.display()
    );
    if let Err(error) = sender.send(Arc::new(path)) {
        error!("Failed to send path to crypto/analysis/canary thread: {error}");
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

#[allow(clippy::too_many_arguments)]
fn run_root(
    starting_path: &Path,
    threads: usize,
    plan: &AllowPlan,
    filters: &WalkFilters<'_>,
    max_file_bytes: Option<u64>,
    sender: &Sender<Arc<PathBuf>>,
    matched: &AtomicUsize,
    filtered: &AtomicUsize,
) {
    let Some(builder) = configure_builder(
        starting_path,
        threads,
        plan,
        filters.block_exts,
        max_file_bytes,
    ) else {
        return;
    };
    debug!(
        "Starting zlob walk for: {} with {threads} worker threads",
        starting_path.display()
    );
    let result = builder.run(|entry| {
        let result = catch_unwind(AssertUnwindSafe(|| {
            process_walk_entry(entry, sender, filters, max_file_bytes, matched, filtered)
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
    });
    match result {
        Ok(_) => {
            debug!(
                "Walk finished for {}: matched={} filtered={}",
                starting_path.display(),
                matched.load(Ordering::Relaxed),
                filtered.load(Ordering::Relaxed)
            );
        }
        Err(error) => {
            error!("Walk error for {}: {error}", starting_path.display());
        }
    }
}

fn collect_root(
    starting_path: &Path,
    threads: usize,
    plan: &AllowPlan,
    filters: &WalkFilters<'_>,
    max_file_bytes: Option<u64>,
) -> Vec<PathBuf> {
    let Some(builder) = configure_builder(
        starting_path,
        threads,
        plan,
        filters.block_exts,
        max_file_bytes,
    ) else {
        return Vec::new();
    };
    debug!(
        "Starting zlob collect for: {} with {threads} worker threads",
        starting_path.display()
    );
    let results = match builder.collect() {
        Ok(results) => results,
        Err(error) => {
            error!("Walk error for {}: {error}", starting_path.display());
            return Vec::new();
        }
    };

    debug!(
        "Walked {} entries in {}",
        results.len(),
        starting_path.display()
    );

    let mut found = Vec::new();
    for entry in results.iter() {
        if !entry.is_file() {
            continue;
        }
        if oversize(entry.size(), max_file_bytes) {
            trace!(
                "Entry exceeds size limit, skipping: {}",
                entry.path().display()
            );
            continue;
        }
        if filters.should_include(entry.path()) {
            trace!("Entry matched filter: {}", entry.path().display());
            found.push(entry.path().to_path_buf());
        } else {
            trace!("Entry did not match filter: {}", entry.path().display());
        }
    }
    found
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
    max_file_bytes: Option<u64>,
) -> thread::JoinHandle<()> {
    spawn_coordinator(
        "walk",
        allow_exts,
        block_exts,
        move |allow_owned, block_owned| {
            let (allow_exts, block_exts) =
                resolve_filters(allow_owned.as_deref(), block_owned.as_deref());
            let plan = allow_plan(allow_exts);
            if matches!(plan, AllowPlan::MatchNone) {
                debug!("Extension allowlist is empty, nothing to walk");
                return;
            }
            debug!("Native allow plan: {plan:?}");
            let native = native_ignore_coverage(block_exts);
            let filters = WalkFilters::new(allow_exts, block_exts, native);
            let per_root = per_root_threads(threads, config::ALLOWLIST_PATHS.len());

            let matched = AtomicUsize::new(0);
            let filtered = AtomicUsize::new(0);
            thread::scope(|scope| {
                for starting_path in config::ALLOWLIST_PATHS.iter() {
                    let spawned = thread::Builder::new()
                        .name(format!("zlob-walk-{}", starting_path.display()))
                        .stack_size(WALK_ROOT_STACK_SIZE)
                        .spawn_scoped(scope, || {
                            run_root(
                                starting_path,
                                per_root,
                                &plan,
                                &filters,
                                max_file_bytes,
                                &sender,
                                &matched,
                                &filtered,
                            );
                        });
                    if let Err(error) = spawned {
                        error!(
                            "Failed to spawn walk thread for {}: {error}",
                            starting_path.display()
                        );
                    }
                }
            });
            debug!(
                "Walk complete: matched={} filtered={}",
                matched.load(Ordering::Relaxed),
                filtered.load(Ordering::Relaxed)
            );
        },
    )
}

pub fn random_walk_with_exts(
    sender: Sender<Arc<PathBuf>>,
    allow_exts: Option<&[String]>,
    block_exts: Option<&[String]>,
    threads: usize,
    max_file_bytes: Option<u64>,
) -> thread::JoinHandle<()> {
    spawn_coordinator(
        "random walk",
        allow_exts,
        block_exts,
        move |allow_owned, block_owned| {
            let (allow_exts, block_exts) =
                resolve_filters(allow_owned.as_deref(), block_owned.as_deref());
            let plan = allow_plan(allow_exts);
            if matches!(plan, AllowPlan::MatchNone) {
                debug!("Extension allowlist is empty, nothing to walk");
                return;
            }
            debug!("Native allow plan: {plan:?}");
            let native = native_ignore_coverage(block_exts);
            let filters = WalkFilters::new(allow_exts, block_exts, native);
            let per_root = per_root_threads(threads, config::ALLOWLIST_PATHS.len());

            let mut found_paths: Vec<PathBuf> = Vec::new();
            thread::scope(|scope| {
                let mut handles = Vec::new();
                for starting_path in config::ALLOWLIST_PATHS.iter() {
                    match thread::Builder::new()
                        .name(format!("zlob-collect-{}", starting_path.display()))
                        .stack_size(WALK_ROOT_STACK_SIZE)
                        .spawn_scoped(scope, || {
                            collect_root(starting_path, per_root, &plan, &filters, max_file_bytes)
                        }) {
                        Ok(handle) => handles.push((starting_path, handle)),
                        Err(error) => {
                            error!(
                                "Failed to spawn collect thread for {}: {error}",
                                starting_path.display()
                            );
                        }
                    }
                }
                for (starting_path, handle) in handles {
                    match handle.join() {
                        Ok(mut paths) => found_paths.append(&mut paths),
                        Err(_) => {
                            error!("Collect thread panicked for {}", starting_path.display());
                        }
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
    filters: &WalkFilters<'_>,
    max_file_bytes: Option<u64>,
    matched: &AtomicUsize,
    filtered: &AtomicUsize,
) -> WalkState {
    if entry.is_file() {
        if oversize(entry.size(), max_file_bytes) {
            trace!(
                "Entry exceeds size limit, skipping: {}",
                entry.path().display()
            );
            filtered.fetch_add(1, Ordering::Relaxed);
        } else if filters.should_include(entry.path()) {
            trace!("Entry matched filter: {}", entry.path().display());
            matched.fetch_add(1, Ordering::Relaxed);
            send_path(sender, entry.path().to_path_buf());
        } else {
            trace!("Entry did not match filter: {}", entry.path().display());
            filtered.fetch_add(1, Ordering::Relaxed);
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
