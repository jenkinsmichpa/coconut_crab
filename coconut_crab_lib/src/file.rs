#![allow(clippy::missing_errors_doc)]

use log::{debug, error, info, warn};
use std::{
    env::current_exe,
    fs::{self, File},
    io::{Error, Read, Write},
    path::{Path, PathBuf},
};

pub fn get_file_data(file_path: impl AsRef<Path>, max_size: u64) -> Result<Option<Vec<u8>>, Error> {
    let file_path = file_path.as_ref();
    let file = File::open(file_path).map_err(|error| {
        error!("Failed to open file: {error}");
        error
    })?;
    let mut limited = file.take(max_size + 1);
    let cap = usize::try_from(max_size.min(8 * 1024 * 1024)).unwrap_or(usize::MAX);
    let mut data = Vec::with_capacity(cap);
    limited.read_to_end(&mut data).map_err(|error| {
        error!("Error reading file: {error:?}");
        error
    })?;
    if u64::try_from(data.len()).is_ok_and(|len| len > max_size) {
        warn!(
            "File size exceeds max read size ({max_size}): {}",
            file_path.display()
        );
        return Ok(None);
    }
    debug!("Successfully read file: {}", file_path.display());
    Ok(Some(data))
}

pub fn get_exe_path_dir() -> Result<PathBuf, Error> {
    let exe_path = current_exe().map_err(|error| {
        error!("Failed to get executable path: {error}");
        error
    })?;
    debug!("Got EXE path: {}", exe_path.display());
    let Some(parent) = exe_path.parent() else {
        error!("Failed to get executable parent path");
        return Err(Error::other("Failed to get executable parent path"));
    };
    debug!("Got EXE parent path: {}", parent.display());
    Ok(parent.to_path_buf())
}

pub fn write_to_file(data: &[u8], file_path: impl AsRef<Path>) -> Result<(), Error> {
    let file_path = file_path.as_ref();
    let mut tmp_path = file_path.as_os_str().to_os_string();
    tmp_path.push(".tmp");
    let tmp_path = PathBuf::from(tmp_path);
    let result = (|| -> Result<(), Error> {
        let mut file = File::create(&tmp_path).map_err(|error| {
            error!("Unable to open file: {error}");
            error
        })?;
        debug!("Successfully opened file: {}", tmp_path.display());
        file.write_all(data).map_err(|error| {
            error!("Failed to write data to file: {error}");
            error
        })?;
        file.sync_all().map_err(|error| {
            error!("Failed to sync data to file: {error}");
            error
        })?;
        drop(file);
        fs::rename(&tmp_path, file_path).map_err(|error| {
            error!("Failed to replace file: {error}");
            error
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    } else {
        info!("Successfully wrote data to file: {}", file_path.display());
    }
    result
}
