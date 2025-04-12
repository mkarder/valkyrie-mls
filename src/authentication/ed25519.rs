use crate::authentication::error::CredentialError;
use crate::authentication::issuer::{load_signing_key_from_issuer, load_verifying_key_from_issuer};
use ed25519_dalek::{Signature, Signer, Verifier};
use openmls::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

const AUTHENTICATION_DIR: &str = "authentication";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519CredentialData {
    pub identity: Vec<u8>,
    pub credential_key_bytes: Vec<u8>,
    pub not_after: u64,
    pub signature_bytes: Vec<u8>,
    pub issuer: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519credential {
    pub credential_data: Ed25519CredentialData,
}

impl Ed25519credential {
    pub fn new(credential_data: Ed25519CredentialData) -> Self {
        Self { credential_data }
    }

    pub fn serialized_contents(&self) -> Vec<u8> {
        bincode::serialize(&self.credential_data).expect("Serialization failed")
    }

    pub fn validate(
        &self,
        expected_signature_key: &SignaturePublicKey,
    ) -> Result<(), CredentialError> {
        if self.credential_data.credential_key_bytes != expected_signature_key.as_slice() {
            return Err(CredentialError::InvalidSignatureKey);
        }

        let message = [
            &self.credential_data.identity[..],
            &self.credential_data.credential_key_bytes[..],
            &self.credential_data.not_after.to_le_bytes()[..],
        ]
        .concat();

        let verifying_key = load_verifying_key_from_issuer(self.credential_data.issuer.clone())?;

        let signature = Signature::try_from(&self.credential_data.signature_bytes[..])
            .map_err(|_| CredentialError::InvalidSignature)?;

        verifying_key
            .verify(&message, &signature)
            .map_err(|_| CredentialError::InvalidSignature)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CredentialError::ClockError)?
            .as_secs();

        if now > self.credential_data.not_after {
            return Err(CredentialError::Expired);
        }

        Ok(())
    }

    pub fn from_file(path: &str) -> Result<Self, CredentialError> {
        let bytes = fs::read(path).map_err(|_| CredentialError::DecodingError)?;
        let data: Ed25519CredentialData =
            bincode::deserialize(&bytes).map_err(|_| CredentialError::DecodingError)?;
        Ok(Self::new(data))
    }
}

impl From<Ed25519credential> for Credential {
    fn from(cred: Ed25519credential) -> Self {
        Credential::new(CredentialType::Other(0xF000), cred.serialized_contents())
    }
}

impl TryFrom<Credential> for Ed25519credential {
    type Error = CredentialError;

    fn try_from(credential: Credential) -> Result<Self, Self::Error> {
        if credential.credential_type() == CredentialType::Other(0xF000) {
            let data: Ed25519CredentialData = bincode::deserialize(credential.serialized_content())
                .map_err(|_| CredentialError::DecodingError)?;
            Ok(Self::new(data))
        } else {
            Err(CredentialError::UnsupportedCredentialType)
        }
    }
}

pub fn generate_signed_ed25519_credential(
    identity: &str,
    credential_key_bytes: Vec<u8>,
    issuer: &str,
    not_after: u64,
    store: bool,
) -> Result<Ed25519credential, CredentialError> {
    let message = [
        identity.as_bytes(),
        &credential_key_bytes,
        &not_after.to_le_bytes(),
    ]
    .concat();

    let signing_key = load_signing_key_from_issuer(issuer.as_bytes().to_vec())?;
    let signature = signing_key.sign(&message);

    let credential_data = Ed25519CredentialData {
        identity: identity.as_bytes().to_vec(),
        credential_key_bytes,
        not_after,
        signature_bytes: signature.to_bytes().to_vec(),
        issuer: issuer.as_bytes().to_vec(),
    };

    let credential = Ed25519credential::new(credential_data.clone());

    if store {
        // Store the credential in a file
        let credential_path = format!("{}/credentials/{}.cred", AUTHENTICATION_DIR, identity);
        std::fs::write(
            credential_path,
            bincode::serialize(&credential_data).expect("Serialization failed"),
        )
        .map_err(|_| CredentialError::DecodingError)?;
    }

    Ok(credential)
}
