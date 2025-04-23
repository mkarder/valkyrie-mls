use crate::authentication::error::CredentialError;
use openmls::prelude::CredentialWithKey;

pub trait CredentialIssuer {
    fn sign(&self, message: &[u8]) -> Vec<u8>;
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
    fn public_key(&self) -> Vec<u8>;
    fn issue(
        &self,
        identity: u32,
        key_to_be_signed: &[u8],
    ) -> Result<CredentialWithKey, CredentialError>;
    fn create_issuer(identity: u32) -> Self;
}
