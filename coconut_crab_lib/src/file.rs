use log::{debug, error, info, warn};
use std::{
    env::current_exe,
    ffi::OsStr,
    fs::{self, File},
    io::{Error, Write},
    path::{Path, PathBuf},
};

pub fn get_lowercase_extension(path: &Path) -> String {
    let file_extension = path.extension().map_or_else(
        || {
            debug!("File has no extension: {}", path.display());
            OsStr::new("")
        },
        |ext| {
            debug!("File has extension: {}", ext.display());
            ext
        },
    );
    file_extension.to_string_lossy().to_lowercase()
}

pub fn get_file_size(path: &PathBuf) -> Result<u64, Error> {
    match fs::metadata(path) {
        Ok(metadata) => {
            debug!("Successfuly extracted file metadata: {metadata:?}");
            Ok(metadata.len())
        }
        Err(error) => {
            error!("Cannot extract file metadata: {error:?}");
            Err(error)
        }
    }
}

pub fn get_file_data(file_path: &PathBuf, max_size: &u64) -> Result<Option<Vec<u8>>, Error> {
    match get_file_size(file_path) {
        Ok(size) => {
            if size > *max_size {
                warn!("File size ({size}) exceeds max read size ({max_size})");
                return Ok(None);
            }
        }
        Err(error) => {
            error!("Failed to get file size: {error}");
            return Err(error);
        }
    }

    match fs::read(file_path) {
        Ok(data) => {
            debug!("Successfully read file: {}", file_path.display());
            Ok(Some(data))
        }
        Err(error) => {
            error!("Error reading file: {error:?}");
            Err(error)
        }
    }
}

pub fn get_exe_path_dir() -> PathBuf {
    let exe_path = match current_exe() {
        Ok(path) => {
            debug!("Got EXE path: {}", path.display());
            path
        }
        Err(error) => {
            error!("Failed to get executable path: {error}");
            PathBuf::new()
        }
    };
    let exe_path_dir = exe_path.parent().map_or_else(
        || {
            error!("Failed to get executable parent path");
            Path::new("")
        },
        |parent| {
            debug!("Got EXE parent path: {}", parent.display());
            parent
        },
    );
    exe_path_dir.to_path_buf()
}

pub fn write_to_file(data: &[u8], file_path: &PathBuf) -> Result<(), Error> {
    let mut file = match File::create(file_path) {
        Ok(file) => {
            debug!("Successfully opened file: {file:?}");
            file
        }
        Err(error) => {
            error!("Unable to open file: {error}");
            return Err(error);
        }
    };
    match file.write_all(data) {
        Ok(()) => {
            info!("Successfully wrote data to file: {}", file_path.display());
            Ok(())
        }
        Err(error) => {
            error!("Failed to write data to file: {error}");
            Err(error)
        }
    }
}
