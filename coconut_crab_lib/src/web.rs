pub mod structs {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct Registration {
        pub id: String,
        pub hostname: String,
        pub proof: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct UploadSymKey {
        pub id: String,
        pub key: String,
        pub proof: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct AnnounceCompletion {
        pub id: String,
        pub proof: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct DownloadSymKey {
        pub id: String,
        pub code: String,
        pub proof: String,
    }
}

pub mod codes {
    pub const RECOVERY_REQUEST_CODE: &str = "0000-0000-0000-0000";
}

pub mod client {
    use crate::web::ureq_client::{web_get_recv_bytes_ureq, web_post_send_json_recv_text_ureq};

    const RETRIES: u8 = 5;
    const INITIAL_RETRY_WAIT: u64 = 10;

    pub fn web_get_recv_bytes(url: &str, verify_server: bool) -> Option<Vec<u8>> {
        web_get_recv_bytes_ureq(url, verify_server, INITIAL_RETRY_WAIT, RETRIES)
    }

    pub fn web_post_send_json_recv_text<T: serde::Serialize>(
        url: &str,
        json: &T,
        verify_server: bool,
    ) -> Option<String> {
        web_post_send_json_recv_text_ureq(url, json, verify_server, INITIAL_RETRY_WAIT, RETRIES)
    }
}

pub mod server_tls {
    use rust_embed::RustEmbed;
    #[derive(RustEmbed)]
    #[folder = "assets/cert"]
    #[exclude = "ca-cert.pem"]
    #[exclude = "ca-key.pem"]
    #[include = "cert.pem"]
    #[include = "key.pem"]
    #[exclude = "server.pem"]
    struct AssetCertPriv;

    pub fn get_tls_public_key() -> Vec<u8> {
        AssetCertPriv::get("cert.pem")
            .expect("Failed to get public key file")
            .data
            .to_vec()
    }
    pub fn get_tls_private_key() -> Vec<u8> {
        AssetCertPriv::get("key.pem")
            .expect("Failed to get private key file")
            .data
            .to_vec()
    }
}

pub mod client_tls {
    use rust_embed::RustEmbed;
    use std::borrow::Cow;
    #[derive(RustEmbed)]
    #[folder = "assets/cert"]
    #[include = "ca-cert.pem"]
    #[exclude = "ca-key.pem"]
    #[exclude = "cert.pem"]
    #[exclude = "key.pem"]
    #[exclude = "server.pem"]
    struct AssetCertPub;

    pub fn get_ca_public_key() -> Cow<'static, [u8]> {
        AssetCertPub::get("ca-cert.pem")
            .expect("Failed to get public key file")
            .data
    }
}

pub mod validate {
    use hex::{decode, encode};
    use log::debug;
    use purecrypto::hash::HmacSha256;
    use regex::Regex;
    use std::sync::LazyLock;

    static ID_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[[:alnum:]]{16}$").expect("Invalid Regex"));
    static HOSTNAME_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[0-9A-Za-z.\-]{1,32}$").expect("Invalid Regex"));
    static SHA256_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[a-fA-F0-9]{64}$").expect("Invalid Regex"));
    static CODE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{4}$")
            .expect("Invalid Regex")
    });
    static CODE_SEGMENT_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[[:alnum:]]{4}$").expect("Invalid Regex"));

    pub fn validate_id(id: &str) -> bool {
        ID_REGEX.is_match(id)
    }

    pub fn validate_hostname(hostname: &str) -> bool {
        HOSTNAME_REGEX.is_match(hostname)
    }

    pub fn validate_proof(proof: &str) -> bool {
        SHA256_REGEX.is_match(proof)
    }

    pub fn validate_key(key: &str) -> bool {
        let len = key.len();
        (128..=1024).contains(&len) // depends on key size (256-1024 chars for 512-4096 bit keys)
            && len.is_multiple_of(2)
            && key.chars().all(|c| c.is_ascii_hexdigit())
    }

    pub fn validate_code_segment(code_segment: &str) -> bool {
        CODE_SEGMENT_REGEX.is_match(code_segment)
    }

    pub fn validate_code(code: &str) -> bool {
        CODE_REGEX.is_match(code)
    }

    pub fn create_proof(proof_source: &[u8], secret: &str) -> String {
        let tag = HmacSha256::mac(secret.as_bytes(), proof_source);
        debug!("Created HMAC-SHA256 proof: {}", encode(tag.as_ref()));
        encode(tag.as_ref())
    }

    pub fn check_proof(proof_source: &[u8], secret: &str, proof: &str) -> bool {
        let Ok(expected) = decode(proof) else {
            return false;
        };
        bool::from(
            HmacSha256::new(secret.as_bytes())
                .chain(proof_source)
                .verify(&expected),
        )
    }
}

mod ureq_client {
    use log::{debug, error, warn};
    use std::{io::Read, thread::sleep, time::Duration};

    use ureq::{
        Agent,
        tls::{Certificate, RootCerts, TlsConfig},
    };

    use crate::web::client_tls::get_ca_public_key;

    fn create_client_ureq(verify_server: bool) -> Agent {
        let tls_config = if verify_server {
            debug!("Creating web client with server certificate verification");
            let ca_cert = Certificate::from_pem(&get_ca_public_key()).unwrap();
            TlsConfig::builder()
                .root_certs(RootCerts::new_with_certs(&[ca_cert]))
                .build()
        } else {
            debug!("Creating web client without server certificate verification");
            TlsConfig::builder().disable_verification(true).build()
        };

        Agent::config_builder()
            .tls_config(tls_config)
            .timeout_global(Some(Duration::from_secs(30)))
            .timeout_connect(Some(Duration::from_secs(10)))
            .build()
            .into()
    }

    pub fn web_get_recv_bytes_ureq(
        url: &str,
        verify_server: bool,
        initial_retry_wait: u64,
        retries: u8,
    ) -> Option<Vec<u8>> {
        let mut retry_wait = initial_retry_wait;
        let client = create_client_ureq(verify_server);
        for attempt in 0..retries {
            let response = match client.get(url).call() {
                Ok(response) => {
                    debug!("Received sever response to GET: {response:?}");
                    response
                }
                Err(error) => {
                    if let ureq::Error::StatusCode(_) = &error {
                        error!("Server rejected GET: {error:?} - not retrying");
                        return None;
                    }
                    error!("Failed to receive server response to GET: {error:?}");
                    if attempt + 1 >= retries {
                        return None;
                    }
                    warn!("Sleeping for {retry_wait} seconds before retrying");
                    sleep(Duration::from_secs(retry_wait));
                    retry_wait *= 2;
                    continue;
                }
            };

            let content_length;
            if let Some(header) = response.headers().get("Content-Length") {
                match header.to_str() {
                    Ok(header_str) => {
                        debug!(
                            "Successfully retrieved string of Content-Length header: {header_str}"
                        );
                        match header_str.parse() {
                            Ok(length) => {
                                debug!("Successfully parsed Content-Length header: {length}");
                                content_length = length;
                            }
                            Err(error) => {
                                error!("Failed to parse Content-Length header: {error}");
                                content_length = 1;
                            }
                        }
                    }
                    Err(error) => {
                        error!("Failed to retrieve string of Content-Length header: {error}");
                        content_length = 1;
                    }
                }
            } else {
                error!("Failed to get Content-Length header");
                content_length = 1;
            }

            let mut content = Vec::with_capacity(content_length);
            match response
                .into_body()
                .into_reader()
                .take(10_000_000)
                .read_to_end(&mut content)
            {
                Ok(bytes_read) => {
                    debug!("Successfully read {bytes_read} content bytes from response");
                }
                Err(error) => {
                    debug!("Failed to read content bytes from response: {error}");
                    if attempt + 1 >= retries {
                        return None;
                    }
                    warn!("Sleeping for {retry_wait} seconds before retrying");
                    sleep(Duration::from_secs(retry_wait));
                    retry_wait *= 2;
                    continue;
                }
            }

            return Some(content);
        }
        None
    }

    pub fn web_post_send_json_recv_text_ureq<T: serde::Serialize>(
        url: &str,
        json: &T,
        verify_server: bool,
        initial_retry_wait: u64,
        retries: u8,
    ) -> Option<String> {
        let mut retry_wait = initial_retry_wait;
        let client = create_client_ureq(verify_server);
        for attempt in 0..retries {
            let mut response = match client.post(url).send_json(json) {
                Ok(response) => {
                    debug!("Received sever response to POST: {response:?}");
                    response
                }
                Err(error) => {
                    if let ureq::Error::StatusCode(_) = &error {
                        error!("Server rejected POST: {error:?} - not retrying");
                        return None;
                    }
                    error!("Failed to receive server response to POST: {error:?}");
                    if attempt + 1 >= retries {
                        return None;
                    }
                    warn!("Sleeping for {retry_wait} seconds before retrying");
                    sleep(Duration::from_secs(retry_wait));
                    retry_wait *= 2;
                    continue;
                }
            };

            let content = match response.body_mut().read_to_string() {
                Ok(text) => {
                    debug!("Successfully read content text from response: {text}");
                    text
                }
                Err(error) => {
                    debug!("Failed to read content text from response: {error}");
                    if attempt + 1 >= retries {
                        return None;
                    }
                    warn!("Sleeping for {retry_wait} seconds before retrying");
                    sleep(Duration::from_secs(retry_wait));
                    retry_wait *= 2;
                    continue;
                }
            };

            return Some(content);
        }
        None
    }
}
