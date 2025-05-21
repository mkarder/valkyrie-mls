use crate::authentication::error::CredentialError;
use ed25519_dalek::ed25519::signature::rand_core::OsRng;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::issuer::CredentialIssuer;

//const AUTHENTICATION_DIR: &str = "/valkyrie-mls/authentication";

const AUTHENTICATION_DIR: &str = "authentication";
const ONE_YEAR_IN_SECONDS: u64 = 31_556_926; // 1 year in seconds

pub struct Ed25519SignatureKeyPair {
    pub signature_key_pair: SignatureKeyPair,
}

impl Ed25519SignatureKeyPair {
    pub fn new() -> Result<Self, CryptoError> {
        let signature_key_pair = SignatureKeyPair::new(SignatureScheme::ED25519);
        match signature_key_pair {
            Ok(key_pair) => Ok(Self {
                signature_key_pair: key_pair,
            }),
            Err(e) => Err(CryptoError::from(e)),
        }
    }

    pub fn from_file(identity: u32) -> Result<Self, CredentialError> {
        let signature_key = load_signing_key_from_file(identity)?;
        Ok(Self {
            signature_key_pair: SignatureKeyPair::from_raw(
                SignatureScheme::ED25519,
                signature_key.as_bytes().to_vec(),
                signature_key.verifying_key().to_bytes().to_vec(),
            ),
        })
    }

    pub fn signature_key_pair(&self) -> &SignatureKeyPair {
        &self.signature_key_pair
    }

    pub fn public_key(&self) -> &[u8] {
        self.signature_key_pair.public()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519CredentialData {
    pub identity: u32,
    pub credential_key_bytes: Vec<u8>,
    pub not_after: u64,
    pub signature_bytes: Vec<u8>,
    pub issuer: u32,
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
        attached_key: Option<&SignaturePublicKey>,
    ) -> Result<(), CredentialError> {
        if let Some(attached_key) = attached_key {
            if self.credential_data.credential_key_bytes != attached_key.as_slice() {
                return Err(CredentialError::InvalidSignatureKey);
            }
        }

        let message = generate_signing_message(
            self.credential_data.identity,
            &self.credential_data.credential_key_bytes,
            self.credential_data.not_after,
        );

        let verifying_key = load_verifying_key_from_file(self.credential_data.issuer)?;

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

    pub fn from_file(identity: u32) -> Result<Self, CredentialError> {
        let path = credential_file_path(identity);
        if !path.exists() {
            log::error!("Credential file not found at path: {}", path.display());
            return Err(CredentialError::FileReadError);
        }
        let bytes = fs::read(path).map_err(|_| CredentialError::FileReadError)?;
        let data: Ed25519CredentialData =
            bincode::deserialize(&bytes).map_err(|_| CredentialError::SerializationError)?;
        Ok(Self::new(data))
    }

    pub fn store(&self) -> Result<(), CredentialError> {
        let path = credential_file_path(self.credential_data.identity);
        fs::create_dir_all(path.parent().unwrap()).map_err(|_| CredentialError::FileWriteError)?;
        fs::write(path, self.serialized_contents()).map_err(|_| CredentialError::FileWriteError)?;
        Ok(())
    }

    pub fn id(&self) -> u32 {
        self.credential_data.identity
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

pub struct Ed25519Issuer {
    identity: u32,
    signing_key: SigningKey,
}

impl Ed25519Issuer {
    pub fn new(identity: u32) -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self {
            identity,
            signing_key,
        }
    }

    pub fn from_file(identity: u32) -> Result<Self, CredentialError> {
        let signing_key = load_signing_key_from_file(identity)?;
        Ok(Self {
            identity,
            signing_key,
        })
    }

    pub fn identity(&self) -> u32 {
        self.identity
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn store(&self) -> Result<(), CredentialError> {
        let priv_path = key_file_path(self.identity, "priv");
        fs::create_dir_all(priv_path.parent().unwrap())
            .map_err(|_| CredentialError::FileWriteError)?;
        fs::write(priv_path, self.signing_key().to_keypair_bytes())
            .map_err(|_| CredentialError::FileWriteError)?;

        let pub_path = key_file_path(self.identity, "pub");
        fs::create_dir_all(pub_path.parent().unwrap())
            .map_err(|_| CredentialError::FileWriteError)?;
        fs::write(pub_path, self.verifying_key().as_bytes())
            .map_err(|_| CredentialError::FileWriteError)?;
        Ok(())
    }
}

impl CredentialIssuer for Ed25519Issuer {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signing_key().sign(message);
        signature.to_bytes().to_vec()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let ed25519_signature = Signature::from_bytes(signature.try_into().unwrap());
        self.verifying_key()
            .verify(message, &ed25519_signature)
            .is_ok()
    }

    fn public_key(&self) -> Vec<u8> {
        self.verifying_key().to_bytes().to_vec()
    }

    fn issue(
        &self,
        identity: u32,
        key_to_be_signed: &[u8],
    ) -> Result<CredentialWithKey, CredentialError> {
        let _ = VerifyingKey::from_bytes(
            key_to_be_signed
                .try_into()
                .map_err(|_| CredentialError::DecodingError)?,
        );

        let not_after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CredentialError::ClockError)?
            .as_secs()
            + ONE_YEAR_IN_SECONDS;

        let message = generate_signing_message(identity, key_to_be_signed, not_after);

        let signature = self.sign(&message);

        let credential_data = Ed25519CredentialData {
            identity,
            credential_key_bytes: key_to_be_signed.to_vec(),
            not_after,
            signature_bytes: signature,
            issuer: self.identity,
        };
        let credential = Ed25519credential::new(credential_data);
        credential.store()?;

        let signature_public_key = SignaturePublicKey::from(key_to_be_signed);

        Ok(CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_public_key,
        })
    }

    fn create_issuer(identity: u32) -> Self {
        Ed25519Issuer::new(identity)
    }
}

pub fn generate_signing_message(
    identity: u32,
    credential_key_bytes: &[u8],
    not_after: u64,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&identity.to_le_bytes());
    message.extend_from_slice(credential_key_bytes);
    message.extend_from_slice(&not_after.to_le_bytes());
    message
}

fn key_file_path(identity: u32, key_type: &str) -> PathBuf {
    Path::new(AUTHENTICATION_DIR)
        .join("keys")
        .join(format!("{}.{}", identity, key_type))
}

fn credential_file_path(identity: u32) -> PathBuf {
    Path::new(AUTHENTICATION_DIR)
        .join("credentials")
        .join(format!("{}.cred", identity))
}

pub fn load_verifying_key_from_file(identity: u32) -> Result<VerifyingKey, CredentialError> {
    let path = key_file_path(identity, "pub");

    if path.exists() {
        let data = fs::read(&path).map_err(|_| CredentialError::FileReadError)?;
        let pub_key_bytes = extract_raw_ed25519_key_from_der(data)?;
        VerifyingKey::from_bytes(&pub_key_bytes).map_err(|_| CredentialError::VerifyingError)
    } else {
        Err(CredentialError::UnknownIssuer)
    }
}

pub fn load_signing_key_from_file(identity: u32) -> Result<SigningKey, CredentialError> {
    let priv_key_path = key_file_path(identity, "priv");

    if priv_key_path.exists() {
        let data = fs::read(&priv_key_path).map_err(|_| CredentialError::FileReadError)?;
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
