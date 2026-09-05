use hex::encode;
use log::{debug, error};
use purecrypto::{cipher::ChaCha20Poly1305, rng::OsRng, rsa::BoxedRsaPublicKey};
use rand::RngExt;
use std::{
    fs::{self, File},
    io::{Error, Read, Write},
    path::{Path, PathBuf},
};

use coconut_crab_lib::web::validate::decode_hex;

pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::rng().fill(&mut nonce);
    nonce
}

pub fn generate_sym_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rng().fill(&mut key);
    debug!("Generated symmetric key");
    key
}

pub fn encrypted_file_path(source: &Path, nonce: &[u8; 12], extension: &str) -> PathBuf {
    let nonce_ext = format!("{}.{extension}", encode(nonce));
    let mut path = source.to_path_buf();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.set_file_name(format!("{name}.{nonce_ext}"));
    path
}

pub fn parse_encrypted_file_name(
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

pub fn aead_encrypt_file(
    source_file_path: &Path,
    destination_file_path: &Path,
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
    aad: &[u8],
    max_file_bytes: u64,
) -> Result<(), Error> {
    let result = (|| -> Result<(), Error> {
        let cipher = ChaCha20Poly1305::new(key);
        let mut source = File::open(source_file_path)?;
        let source_len = source.metadata()?.len();
        if source_len > max_file_bytes {
            return Err(Error::other(format!(
                "File size {source_len} exceeds in-memory encryption limit {max_file_bytes}; skipping"
            )));
        }
        let mut dest = File::create(destination_file_path)?;
        let len = source_len.min(8 * 1024 * 1024);
        let mut data = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        source.read_to_end(&mut data)?;
        let tag = cipher.encrypt(full_nonce_bytes, aad, &mut data);
        dest.write_all(&data)?;
        dest.write_all(&tag)?;
        dest.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination_file_path);
    }
    result
}

pub fn aead_decrypt_file(
    source_file_path: &Path,
    destination_file_path: &Path,
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
    aad: &[u8],
    max_file_bytes: u64,
) -> Result<(), Error> {
    let cipher = ChaCha20Poly1305::new(key);
    let mut source = File::open(source_file_path)?;

    let mut tmp_path = destination_file_path.as_os_str().to_os_string();
    tmp_path.push(".tmp");
    let tmp_path = PathBuf::from(tmp_path);
    let result = (|| -> Result<(), Error> {
        let source_len = source.metadata()?.len();
        if source_len > max_file_bytes.saturating_add(16) {
            return Err(Error::other(format!(
                "Encrypted file size {source_len} exceeds in-memory decryption limit; skipping"
            )));
        }
        let mut dest = File::create(&tmp_path)?;
        let len = source_len.min(8 * 1024 * 1024);
        let mut data = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        source.read_to_end(&mut data)?;
        if data.len() < 16 {
            return Err(Error::other("Encrypted file shorter than Poly1305 tag"));
        }
        let cipher_len = data.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[cipher_len..]);
        data.truncate(cipher_len);
        cipher
            .decrypt(full_nonce_bytes, aad, &mut data, &tag)
            .map_err(|_| Error::other("ChaCha20-Poly1305 authentication failed"))?;
        dest.write_all(&data)?;
        dest.sync_all()?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            fs::rename(&tmp_path, destination_file_path)?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

pub fn encrypt_string(
    source: &str,
    key: &[u8; 32],
    full_nonce_bytes: &[u8; 12],
    aad: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let mut source_data = source.as_bytes().to_vec();
    let tag = ChaCha20Poly1305::new(key).encrypt(full_nonce_bytes, aad, &mut source_data);
    debug!("String encrypted ({} bytes)", source_data.len());
    (source_data, tag)
}

pub fn decrypt_string(
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
            debug!(
                "Successfully decoded bytes to string ({} chars)",
                string.len()
            );
            Some(string)
        }
        Err(error) => {
            error!("Failed to decode bytes to string: {error}");
            None
        }
    }
}

pub fn encrypt_sym_key(
    asym_pub_key: &BoxedRsaPublicKey,
    sym_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut rng = OsRng;
    asym_pub_key
        .encrypt_pkcs1v15(sym_key, &mut rng)
        .map_err(|e| format!("Failed to encrypt symmetric key: {e}"))
}
