#![allow(clippy::missing_errors_doc)]

use std::{
    env::current_exe,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use tracing::{debug, info, warn};

use crate::error::Error;

pub fn read_file_data(
    file_path: impl AsRef<Path>,
    max_size: u64,
) -> Result<Option<Vec<u8>>, Error> {
    let file_path = file_path.as_ref();
    let file = File::open(file_path).map_err(|source| Error::OpenFile {
        path: file_path.to_path_buf(),
        source,
    })?;
    let mut limited = file.take(max_size.saturating_add(1));
    let cap = usize::try_from(max_size.min(8 * 1024 * 1024)).unwrap_or(usize::MAX);
    let mut data = Vec::with_capacity(cap);
    limited
        .read_to_end(&mut data)
        .map_err(|source| Error::ReadFile {
            path: file_path.to_path_buf(),
            source,
        })?;
    if u64::try_from(data.len()).is_ok_and(|len| len > max_size) {
        warn!(
            max_size,
            path = %file_path.display(),
            "File size exceeds max read size"
        );
        return Ok(None);
    }
    debug!(path = %file_path.display(), "Successfully read file");
    Ok(Some(data))
}

pub fn current_exe_dir() -> Result<PathBuf, Error> {
    let exe_path = current_exe()?;
    debug!(path = %exe_path.display(), "Got EXE path");
    let Some(parent) = exe_path.parent() else {
        return Err(Error::NoExeParent);
    };
    debug!(path = %parent.display(), "Got EXE parent path");
    Ok(parent.to_path_buf())
}

pub fn write_to_file(data: &[u8], file_path: impl AsRef<Path>) -> Result<(), Error> {
    let file_path = file_path.as_ref();
    let mut tmp_path = file_path.as_os_str().to_os_string();
    tmp_path.push(".tmp");
    let tmp_path = PathBuf::from(tmp_path);
    let result = (|| -> Result<(), Error> {
        let mut file = File::create(&tmp_path).map_err(|source| Error::WriteFile {
            path: tmp_path.clone(),
            source,
        })?;
        debug!(path = %tmp_path.display(), "Successfully opened file");
        file.write_all(data).map_err(|source| Error::WriteFile {
            path: tmp_path.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| Error::WriteFile {
            path: tmp_path.clone(),
            source,
        })?;
        drop(file);
        fs::rename(&tmp_path, file_path).map_err(|source| Error::ReplaceFile {
            path: file_path.to_path_buf(),
            source,
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    } else {
        info!(path = %file_path.display(), "Successfully wrote data to file");
    }
    result
}
