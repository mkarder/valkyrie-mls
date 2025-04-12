use crate::authentication::error::CredentialError;
use openmls::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509Credential {
    certificate: VLBytes,
}

impl X509Credential {
    pub fn new(serialized_credential_content: Vec<u8>) -> Self {
        Self {
            certificate: serialized_credential_content.into(),
        }
    }

    pub fn certificate(&self) -> &[u8] {
        self.certificate.as_slice()
    }

    pub fn validate(&self) -> bool {
        true // Placeholder for real validation
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        // Convert DER-encoded certificate to X509Credential
        Ok(X509Credential::new(der.to_vec()))
    }
}

impl From<X509Credential> for Credential {
    fn from(credential: X509Credential) -> Self {
        Credential::new(CredentialType::X509, credential.certificate().to_vec())
    }
}

impl TryFrom<Credential> for X509Credential {
    type Error = CredentialError;

    fn try_from(credential: Credential) -> Result<Self, Self::Error> {
        match credential.credential_type() {
            CredentialType::X509 => Ok(X509Credential::new(
                credential.serialized_content().to_vec(),
            )),
            _ => Err(CredentialError::UnsupportedCredentialType),
        }
    }
}
