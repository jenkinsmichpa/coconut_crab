use axum::http::StatusCode;
use hex::{decode, encode};
use log::{debug, error};
use purecrypto::rsa::BoxedRsaPrivateKey;
use rand::{RngExt, distr::Alphanumeric};

use coconut_crab_lib::web::codes::RECOVERY_REQUEST_CODE;

const CODE_LEN: usize = 19;

pub fn generate_code() -> String {
    let code = loop {
        let raw: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        let mut code = String::with_capacity(CODE_LEN);
        for (i, c) in raw.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                code.push('-');
            }
            code.push(c);
        }
        if code != RECOVERY_REQUEST_CODE {
            break code;
        }
        debug!("Generated the reserved recovery sentinel by miracle... regenerating");
    };
    debug!("Generated new code");
    code
}

pub fn decrypt_key(
    private_key: &BoxedRsaPrivateKey,
    key: &str,
) -> Result<String, (StatusCode, &'static str)> {
    let key_vec = decode(key).map_err(|error| {
        error!("Failed To Decode Key: {error}");
        (StatusCode::BAD_REQUEST, "Invalid Key")
    })?;
    let key = private_key.decrypt_pkcs1v15(&key_vec).map_err(|error| {
        error!("Failed To Decrypt Key: {error}");
        (StatusCode::BAD_REQUEST, "Invalid Key")
    })?;
    Ok(encode(key))
}
