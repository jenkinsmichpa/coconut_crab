use std::{
    ffi::OsStr,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    str::from_utf8,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
};

use ahash::AHashSet;
use flume::Sender;
use rand::{SeedableRng, rngs::SmallRng, seq::SliceRandom};
use tracing::{debug, error, trace};
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
    let keyword_count = if config::AVOID_KEYWORDS && canary_active() {
        SUSPICIOUS_KEYWORDS.len()
    } else {
        0
    };
    let mut rules = Vec::with_capacity(
        2 + config::BLOCKLIST_PATHS
            .as_deref()
            .map_or_default(<[PathBuf]>::len)
            + block_exts.map_or_default(<[String]>::len)
            + keyword_count,
    );
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
            if let Some(folded) = fold_case_ignore(ext) {
                rules.push(format!("*.{folded}"));
            } else {
                debug!(?ext, "Extension cannot be expressed natively, skipping");
            }
        }
    }
    if config::AVOID_KEYWORDS && canary_active() {
        for keyword in SUSPICIOUS_KEYWORDS.iter() {
            if let Some(pattern) = keyword_ignore_pattern(keyword) {
                rules.push(pattern);
            } else {
                debug!(?keyword, "Keyword cannot be expressed natively, skipping");
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
        debug!(path = %starting_path.display(), "Walk root is blocklisted, skipping");
        return None;
    }

    let mut builder = match WalkBuilder::new(starting_path) {
        Ok(builder) => {
            debug!(path = %starting_path.display(), "Created WalkBuilder");
            builder
        }
        Err(error) => {
            error!(
                error = ?error,
                path = %starting_path.display(),
                "Failed to create WalkBuilder"
            );
            return None;
        }
    };

    let mut flags = WalkFlags::NO_REPORT_DIRS;
    if config::AVOID_HIDDEN {
        flags |= WalkFlags::SKIP_HIDDEN;
        debug!("Hidden files/dirs will be skipped");
    }
    debug!(?flags, "Walk flags set");
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
                error!(error = ?error, "Invalid native include pattern, using Rust filter");
            }
        }
    }

    let rules = native_ignore_rules(starting_path, block_exts);
    if !rules.is_empty()
        && let Err(error) = builder.extra_ignore(&rules)
    {
        error!(error = ?error, "Failed to install native ignore rules");
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
    allow: Option<AHashSet<String>>,
    block: Option<AHashSet<String>>,
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
            trace!(path = %file_path.display(), "Applying allowlist to file");
            if !extension_matches(allow, file_path) {
                trace!(path = %file_path.display(), "Allowlist does not contain extension");
                return false;
            }
            trace!(path = %file_path.display(), "Allowlist contains extension");
        } else {
            trace!(path = %file_path.display(), "Not applying allowlist to file");
        }

        if self.native.exts {
            trace!("Native ignores cover the blocklist, skipping Rust check");
        } else if let Some(block) = &self.block {
            trace!(path = %file_path.display(), "Applying blocklist to file");
            if extension_matches(block, file_path) {
                trace!(path = %file_path.display(), "Blocklist contains file extension");
                return false;
            }
            trace!(path = %file_path.display(), "Blocklist does not contain file extension");
        } else {
            trace!(path = %file_path.display(), "Not applying blocklist to file");
        }

        if !self.native.ouroboros {
            if let Some(name) = file_path.file_name() {
                trace!(name = %name.to_string_lossy(), "Successfully got filename");
                if name == OsStr::new(STATUS_FILENAME.as_str())
                    || name == OsStr::new(ANALYSIS_FILENAME.as_str())
                {
                    trace!("File is own output. Avoiding ouroboros.");
                    return false;
                }
            } else {
                error!(path = %file_path.display(), "Failed to get filename");
                return false;
            }
        }

        trace!(path = %file_path.display(), "File matches: true");
        true
    }
}

fn lowercase_exts(exts: &[String]) -> AHashSet<String> {
    exts.iter().map(|ext| ext.to_ascii_lowercase()).collect()
}

fn extension_matches(set: &AHashSet<String>, file_path: &Path) -> bool {
    let Some(ext) = file_path.extension().and_then(OsStr::to_str) else {
        return false;
    };
    if ext.len() <= MAX_FOLDED_EXT_LEN {
        let mut buf = [0_u8; MAX_FOLDED_EXT_LEN];
        for (slot, byte) in buf.iter_mut().zip(ext.bytes()) {
            *slot = byte.to_ascii_lowercase();
        }
        if let Ok(folded) = from_utf8(&buf[..ext.len()]) {
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
    trace!(path = %path.display(), "Sending path to crypto/analysis/canary thread");
    if let Err(error) = sender.send(Arc::new(path)) {
        error!(error = ?error, "Failed to send path to crypto/analysis/canary thread");
    }
}

fn spawn_coordinator(
    label: &'static str,
    allow_exts: Option<&[String]>,
    block_exts: Option<&[String]>,
    body: impl FnOnce(Option<Vec<String>>, Option<Vec<String>>) + Send + 'static,
) -> io::Result<JoinHandle<()>> {
    debug!(label, "Starting coordinator thread");
    let allow_owned = allow_exts.map(<[String]>::to_vec);
    let block_owned = block_exts.map(<[String]>::to_vec);
    thread::Builder::new()
        .stack_size(WALK_COORDINATOR_STACK_SIZE)
        .spawn(move || body(allow_owned, block_owned))
}

#[allow(
    clippy::too_many_arguments,
    reason = "walk coordinator threads pass their shared walk state explicitly"
)]
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
    debug!(path = %starting_path.display(), ?threads, "Starting zlob walk");
    let result = builder.visit(|entry| {
        let result = catch_unwind(AssertUnwindSafe(|| {
            process_walk_entry(entry, sender, filters, max_file_bytes, matched, filtered)
        }));
        match result {
            Ok(state) => state,
            Err(payload) => {
                error!(
                    path = %entry.path().display(),
                    ?payload,
                    "Walk visitor recovered from panic"
                );
                WalkState::Continue
            }
        }
    });
    match result {
        Ok(()) => {
            debug!(
                path = %starting_path.display(),
                matched = matched.load(Ordering::Relaxed),
                filtered = filtered.load(Ordering::Relaxed),
                "Walk finished"
            );
        }
        Err(error) => {
            error!(error = ?error, path = %starting_path.display(), "Walk error");
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
    debug!(path = %starting_path.display(), ?threads, "Starting zlob collect");
    let found = Mutex::new(Vec::new());
    let result = builder.visit(|entry| {
        let result = catch_unwind(AssertUnwindSafe(|| {
            process_collect_entry(entry, filters, max_file_bytes, &found)
        }));
        match result {
            Ok(state) => state,
            Err(payload) => {
                error!(
                    path = %entry.path().display(),
                    ?payload,
                    "Collect visitor recovered from panic"
                );
                WalkState::Continue
            }
        }
    });
    let found = found.into_inner().unwrap_or_else(PoisonError::into_inner);
    match result {
        Ok(()) => {
            debug!(
                path = %starting_path.display(),
                found = found.len(),
                "Collect finished"
            );
        }
        Err(error) => {
            error!(error = ?error, path = %starting_path.display(), "Walk error");
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

pub(crate) fn walk_with_exts(
    sender: Sender<Arc<PathBuf>>,
    allow_exts: Option<&[String]>,
    block_exts: Option<&[String]>,
    threads: usize,
    max_file_bytes: Option<u64>,
) -> io::Result<JoinHandle<()>> {
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
            debug!(?plan, "Native allow plan");
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
                            error = ?error,
                            path = %starting_path.display(),
                            "Failed to spawn walk thread"
                        );
                    }
                }
            });
            debug!(
                matched = matched.load(Ordering::Relaxed),
                filtered = filtered.load(Ordering::Relaxed),
                "Walk complete"
            );
        },
    )
}

pub(crate) fn random_walk_with_exts(
    sender: Sender<Arc<PathBuf>>,
    allow_exts: Option<&[String]>,
    block_exts: Option<&[String]>,
    threads: usize,
    max_file_bytes: Option<u64>,
) -> io::Result<JoinHandle<()>> {
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
            debug!(?plan, "Native allow plan");
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
                                error = ?error,
                                path = %starting_path.display(),
                                "Failed to spawn collect thread"
                            );
                        }
                    }
                }
                for (starting_path, handle) in handles {
                    match handle.join() {
                        Ok(mut paths) => found_paths.append(&mut paths),
                        Err(_) => {
                            error!(path = %starting_path.display(), "Collect thread panicked");
                        }
                    }
                }
            });

            shuffle_and_send_path(&sender, found_paths);
        },
    )
}

fn process_collect_entry(
    entry: WalkEntry<'_>,
    filters: &WalkFilters<'_>,
    max_file_bytes: Option<u64>,
    found: &Mutex<Vec<PathBuf>>,
) -> WalkState {
    if entry.is_file() {
        if oversize(entry.size(), max_file_bytes) {
            trace!(path = %entry.path().display(), "Entry exceeds size limit, skipping");
        } else if filters.should_include(entry.path()) {
            trace!(path = %entry.path().display(), "Entry matched filter");
            found
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(entry.path().to_path_buf());
        } else {
            trace!(path = %entry.path().display(), "Entry did not match filter");
        }
    }

    WalkState::Continue
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
            trace!(path = %entry.path().display(), "Entry exceeds size limit, skipping");
            filtered.fetch_add(1, Ordering::Relaxed);
        } else if filters.should_include(entry.path()) {
            trace!(path = %entry.path().display(), "Entry matched filter");
            matched.fetch_add(1, Ordering::Relaxed);
            send_path(sender, entry.path().to_path_buf());
        } else {
            trace!(path = %entry.path().display(), "Entry did not match filter");
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
                debug!(path = %entry_path.display(), "Blocklist contains entry");
            }
            hit
        })
    })
}
