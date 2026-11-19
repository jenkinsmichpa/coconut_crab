use std::{io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("failed to open file {path}: {source}")]
    OpenFile { path: PathBuf, source: io::Error },

    #[error("failed to read file {path}: {source}")]
    ReadFile { path: PathBuf, source: io::Error },

    #[error("failed to write file {path}: {source}")]
    WriteFile { path: PathBuf, source: io::Error },

    #[error("failed to replace file {path}: {source}")]
    ReplaceFile { path: PathBuf, source: io::Error },

    #[error("executable path has no parent directory")]
    NoExeParent,

    #[error("embedded asset {name} is missing or invalid")]
    EmbeddedAsset { name: &'static str },

    #[error("server rejected {label} request with status {status}")]
    ServerRejected { label: &'static str, status: u16 },

    #[error("invalid {label} request")]
    InvalidRequest {
        label: &'static str,
        #[source]
        source: ureq::Error,
    },

    #[error("no response from server for {label} request after {retries} retries")]
    NoResponse {
        label: &'static str,
        retries: u8,
        #[source]
        source: ureq::Error,
    },
}
