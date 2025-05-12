use log::{debug, error, info, warn};
use std::{
    env::current_exe,
    ffi::OsStr,
    fs::{self, File},
    io::{Error, Write},
    path::{Path, PathBuf},
};

pub fn get_lowercase_extension(path: &PathBuf) -> String {
    let file_extension = match path.extension() {
        Some(file_extension_result) => {
            debug!("File has extension: {:?}", file_extension_result);
            file_extension_result
        }
        None => {
            debug!("File has no extension: {:?}", path);
            OsStr::new("")
        }
    };
    file_extension.to_string_lossy().to_lowercase()
}

pub fn get_file_size(path: &PathBuf) -> Result<u64, Error> {
    match fs::metadata(path) {
        Ok(file_metadata_result) => {
            debug!(
                "Successfuly extracted file metadata: {:?}",
                file_metadata_result
            );
            Ok(file_metadata_result.len())
        }
        Err(file_metadata_result) => {
            error!("Cannot extract file metadata: {:?}", file_metadata_result);
            Err(file_metadata_result)
        }
    }
}

pub fn get_file_data(file_path: &PathBuf, max_size: &u64) -> Result<Option<Vec<u8>>, Error> {
    match get_file_size(file_path) {
        Ok(file_size_result) => {
            if file_size_result > *max_size {
                warn!(
                    "File size ({}) exceeds max read size ({})",
                    file_size_result, max_size
                );
                return Ok(None);
            }
        }
        Err(file_size_result) => {
            error!("Failed to get file size: {}", file_size_result);
            return Err(file_size_result);
        }
    }

    match fs::read(file_path) {
        Ok(file_data_result) => {
            debug!("Successfully read file: {:?}", file_path);
            Ok(Some(file_data_result))
        }
        Err(file_data_result) => {
            error!("Error reading file: {:?}", file_data_result);
            Err(file_data_result)
        }
    }
}

pub fn get_exe_path_dir() -> PathBuf {
    let exe_path = match current_exe() {
        Ok(exe_pathbuf_result) => {
            debug!("Got EXE path: {:?}", exe_pathbuf_result);
            exe_pathbuf_result
        }
        Err(exe_pathbuf_result) => {
            error!("Failed to get executable path: {}", exe_pathbuf_result);
            PathBuf::new()
        }
    };
    let exe_path_dir = match exe_path.parent() {
        Some(exe_path_result) => {
            debug!("Got EXE parent path: {:?}", exe_path_result);
            exe_path_result
        }
        None => {
            error!("Failed to get executable parent path");
            Path::new("")
        }
    };
    exe_path_dir.to_path_buf()
}

pub fn write_to_file(data: &[u8], file_path: &PathBuf) -> Result<(), Error> {
    let mut file = match File::create(file_path) {
        Ok(file_creation_result) => {
            debug!("Successfully opened file: {:?}", file_creation_result);
            file_creation_result
        }
        Err(file_creation_result) => {
            error!("Unable to open file: {}", file_creation_result);
            return Err(file_creation_result);
        }
    };
    match file.write_all(data) {
        Ok(_) => {
            info!("Successfully wrote data to file: {:?}", file_path);
            Ok(())
        }
        Err(file_write_result) => {
            error!("Failed to write data to file: {}", file_write_result);
            Err(file_write_result)
        }
    }
}
