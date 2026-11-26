use coconut_crab_lib::web::codes::RECOVERY_REQUEST_CODE;
use hex::{decode, encode};
use purecrypto::rsa::BoxedRsaPrivateKey;
use rand::{RngExt, distr::Alphanumeric};
use tracing::{debug, error};

use crate::extract::ApiError;

const CODE_LEN: usize = 19;

pub(crate) fn generate_code() -> String {
    let code = loop {
        let raw: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        let mut code = String::with_capacity(CODE_LEN);
        for (index, character) in raw.chars().enumerate() {
            if index > 0 && index % 4 == 0 {
                code.push('-');
            }
            code.push(character);
        }
        if code != RECOVERY_REQUEST_CODE {
            break code;
        }
        debug!("Generated the reserved recovery sentinel by miracle... regenerating");
    };
    debug!("Generated new code");
    code
}

pub(crate) fn decrypt_key(private_key: &BoxedRsaPrivateKey, key: &str) -> Result<String, ApiError> {
    let key_vec = decode(key).map_err(|error| {
        error!(error = ?error, "Failed to decode key");
        ApiError::InvalidKey
    })?;
    let key = private_key.decrypt_pkcs1v15(&key_vec).map_err(|error| {
        error!(error = ?error, "Failed to decrypt key");
        ApiError::InvalidKey
    })?;
    Ok(encode(key))
}
