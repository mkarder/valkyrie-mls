use ed25519_dalek::{SigningKey, VerifyingKey};
use std::fs;
use std::path::Path;

use crate::authentication::error::CredentialError;

const AUTHENTICATION_DIR: &str = "authentication";

pub fn load_verifying_key_from_issuer(
    issuer_bytes: Vec<u8>,
) -> Result<VerifyingKey, CredentialError> {
    let issuer_string =
        String::from_utf8(issuer_bytes).map_err(|_| CredentialError::IssuerEncodingError)?;
    let path = format!("{}/keys/{}.pub", AUTHENTICATION_DIR, issuer_string);

    if Path::new(&path).exists() {
        let data = fs::read(&path).unwrap();
        let pub_key_bytes = extract_raw_ed25519_key_from_der(data)?;
        VerifyingKey::from_bytes(&pub_key_bytes).map_err(|_| CredentialError::VerifyingError)
    } else {
        Err(CredentialError::UnknownIssuer)
    }
}

pub fn load_signing_key_from_issuer(issuer_bytes: Vec<u8>) -> Result<SigningKey, CredentialError> {
    let issuer_string =
        String::from_utf8(issuer_bytes).map_err(|_| CredentialError::IssuerEncodingError)?;
    let path = format!("{}/keys/{}.priv", AUTHENTICATION_DIR, issuer_string);

    if Path::new(&path).exists() {
        let data = fs::read(&path).unwrap();
        let priv_key_bytes = extract_raw_ed25519_key_from_der(data)?;
        Ok(SigningKey::from_bytes(&priv_key_bytes))
    } else {
        Err(CredentialError::UnknownIssuer)
    }
}

fn extract_raw_ed25519_key_from_der(data: Vec<u8>) -> Result<[u8; 32], CredentialError> {
    let key_bytes = &data[data.len() - 32..];
    key_bytes
        .try_into()
        .map_err(|_| CredentialError::VerifyingError)
}
