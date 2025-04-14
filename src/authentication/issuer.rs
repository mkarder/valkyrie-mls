use ed25519_dalek::{SigningKey, VerifyingKey};
use openmls::prelude::{CredentialWithKey, Signature};
use std::fs;
use std::path::Path;

use crate::authentication::error::CredentialError;

const AUTHENTICATION_DIR: &str = "authentication";

pub trait CredentialIssuer {
    fn sign(&self, message: &[u8]) -> Vec<u8>;
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
    fn public_key(&self) -> Vec<u8>;
    fn issue(
        &self,
        identity: &str,
        key_to_be_signed: &[u8],
    ) -> Result<CredentialWithKey, CredentialError>;
    fn create_issuer(identity: &str) -> Self;
}
