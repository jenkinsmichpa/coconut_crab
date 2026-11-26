use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, anyhow, bail};
use coconut_crab_lib::web::validate::decode_hex;
use hex::encode;
use purecrypto::{
    cipher::ChaCha20Poly1305,
    rng::{OsRng, RngCore},
    rsa::BoxedRsaPublicKey,
};
use tracing::{debug, error};

pub(crate) fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub(crate) fn generate_sym_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    debug!("Generated symmetric key");
    key
}

pub(crate) fn encrypted_file_path(source: &Path, nonce: &[u8; 12], extension: &str) -> PathBuf {
    let nonce_ext = format!("{}.{extension}", encode(nonce));
    let mut path = source.to_path_buf();
    let name = path
        .file_name()
        .map_or_default(|file_name| file_name.to_string_lossy().into_owned());
    path.set_file_name(format!("{name}.{nonce_ext}"));
    path
}

pub(crate) fn parse_encrypted_file_name(
    file_name: &str,
    expected_ext: &str,
) -> Option<(String, [u8; 12])> {
    let mut parts = file_name.rsplitn(3, '.');
    let extension = parts.next()?;
    let nonce_str = parts.next()?;
    let original = parts.next()?;
    if extension != expected_ext {
        return None;
    }
    let nonce: [u8; 12] = decode_hex(nonce_str)?;
    Some((original.to_string(), nonce))
}

pub(crate) fn aead_encrypt_file(
    source_file_path: &Path,
    destination_file_path: &Path,
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
    aad: &[u8],
    max_file_bytes: u64,
) -> anyhow::Result<()> {
    let result = (|| -> anyhow::Result<()> {
        let cipher = ChaCha20Poly1305::new(key);
        let mut source = File::open(source_file_path)
            .with_context(|| format!("failed to open file {}", source_file_path.display()))?;
        let source_len = source
            .metadata()
            .with_context(|| format!("failed to read metadata of {}", source_file_path.display()))?
            .len();
        if source_len > max_file_bytes {
            bail!(
                "file size {source_len} exceeds in-memory encryption limit {max_file_bytes}; skipping"
            );
        }
        let mut dest = File::create(destination_file_path).with_context(|| {
            format!("failed to create file {}", destination_file_path.display())
        })?;
        let mut data = Vec::with_capacity(usize::try_from(source_len).unwrap_or(0));
        source
            .read_to_end(&mut data)
            .with_context(|| format!("failed to read file {}", source_file_path.display()))?;
        let tag = cipher.encrypt(full_nonce_bytes, aad, &mut data);
        dest.write_all(&data)
            .with_context(|| format!("failed to write file {}", destination_file_path.display()))?;
        dest.write_all(&tag)
            .with_context(|| format!("failed to write file {}", destination_file_path.display()))?;
        dest.sync_all()
            .with_context(|| format!("failed to sync file {}", destination_file_path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination_file_path);
    }
    result
}

pub(crate) fn aead_decrypt_file(
    source_file_path: &Path,
    destination_file_path: &Path,
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
    aad: &[u8],
    max_file_bytes: u64,
) -> anyhow::Result<()> {
    let cipher = ChaCha20Poly1305::new(key);
    let mut source = File::open(source_file_path)
        .with_context(|| format!("failed to open file {}", source_file_path.display()))?;

    let mut tmp_path = destination_file_path.as_os_str().to_os_string();
    tmp_path.push(".tmp");
    let tmp_path = PathBuf::from(tmp_path);
    let result = (|| -> anyhow::Result<()> {
        let source_len = source
            .metadata()
            .with_context(|| format!("failed to read metadata of {}", source_file_path.display()))?
            .len();
        if source_len > max_file_bytes.saturating_add(16) {
            bail!("encrypted file size {source_len} exceeds in-memory decryption limit; skipping");
        }
        let mut dest = File::create(&tmp_path)
            .with_context(|| format!("failed to create file {}", tmp_path.display()))?;
        let mut data = Vec::with_capacity(usize::try_from(source_len).unwrap_or(0));
        source
            .read_to_end(&mut data)
            .with_context(|| format!("failed to read file {}", source_file_path.display()))?;
        if data.len() < 16 {
            bail!("encrypted file shorter than Poly1305 tag");
        }
        let cipher_len = data.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[cipher_len..]);
        data.truncate(cipher_len);
        cipher
            .decrypt(full_nonce_bytes, aad, &mut data, &tag)
            .map_err(|_| anyhow!("ChaCha20-Poly1305 authentication failed"))?;
        dest.write_all(&data)
            .with_context(|| format!("failed to write file {}", tmp_path.display()))?;
        dest.sync_all()
            .with_context(|| format!("failed to sync file {}", tmp_path.display()))?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            fs::rename(&tmp_path, destination_file_path).with_context(|| {
                format!("failed to replace file {}", destination_file_path.display())
            })?;
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(&tmp_path);
            Err(error)
        }
    }
}

pub(crate) fn encrypt_string(
    source: &str,
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
    aad: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let mut source_data = source.as_bytes().to_vec();
    let tag = ChaCha20Poly1305::new(key).encrypt(full_nonce_bytes, aad, &mut source_data);
    debug!(bytes = source_data.len(), "String encrypted");
    (source_data, tag)
}

pub(crate) fn decrypt_string(
    ciphertext: &[u8],
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
    tag: &[u8; 16],
    aad: &[u8],
) -> Option<String> {
    let mut source_data = ciphertext.to_vec();
    ChaCha20Poly1305::new(key)
        .decrypt(full_nonce_bytes, aad, &mut source_data, tag)
        .ok()?;
    match String::from_utf8(source_data) {
        Ok(string) => {
            debug!(chars = string.len(), "Successfully decoded bytes to string");
            Some(string)
        }
        Err(error) => {
            error!(error = ?error, "Failed to decode bytes to string");
            None
        }
    }
}

pub(crate) fn encrypt_sym_key(
    asym_pub_key: &BoxedRsaPublicKey,
    sym_key: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    let mut rng = OsRng;
    asym_pub_key
        .encrypt_pkcs1v15(sym_key, &mut rng)
        .context("failed to encrypt symmetric key")
}
