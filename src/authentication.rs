/*
[Operational requirements]
According to the operational requirements described in Section 7 of:
https://www.ietf.org/archive/id/draft-ietf-mls-architecture-15.html#name-operational-requirements

The AS must provide methods for:
1. Issuing new credentials with a relevant credential lifetime,
2. Validating a credential against a reference identifier,
3. Validating whether or not two credentials represent the same client, and
4. Optionally revoking credentials which are no longer authorized.

Our sketched solution for an AS will cover 1, 2, and 3, but we omit 4 due to time constraints.

[Strucutre of the AS and Credentials]
The AS should be a standalone component, which when presented a credential, will validate
it and return a boolean value indicating whether the credential is valid or not.
Issuance of credentials shpould be handled pre-flight and is explained further in the
"Credential issuance" section.

Credentials are represented as a [`Credential`] struct (defined in openmls-0.6.0):
pub struct Credential {
    credential_type: CredentialType,
    serialized_credential_content: VLBytes,
}

We use X.509 Certificates to represent Credentials which implies that the `credential_type`
should be set to `CredentialType::X509`.
The `serialized_credential_content` field is a byte array containing the X.509 certificate.

To validate X.509 certificate, we define a set of valid root CAs, which can sign certificates.
The AS will check if the certificate is signed by one of the root CAs, and if so, it will
return true. Otherwise, it will return false.

We do not use intermediate CAs as of now. This is to both ease the implementation and to
make validation checks more efficient. Current drone swarm architectures will be managed by a
single entity (e.g. troop, company or battalion command), and we assume that such an entity
will be responsible for issuance and therefore also represent the root CA(s).
We wish however, to make the implementation scalable, such that intermediate CAs can be
added in the future. This can be done by valdiating the full certifcate chain and verify that
a root CA is present at the end of the chain.


[Credential issuance]

[Credential validation]
Our application maintains a list of "reference identifiers" for the members of a group,
and the credentials provide "presented identifiers".

A member of a group is authenticated by first validating that the member's credential
legitimately represents some presented identifiers, and then ensuring that the reference
identifiers for the member are authenticated by those presented identifiers.

A member's credential is said to be validated with the AS when the AS verifies that the
credential's presented identifiers are correctly associated with the `signature_key`
field in the member's `LeafNode`, and that those identifiers match the reference
identifiers for the member.

(From RFC 9420)
Whenever a new credential is introduced in the group, it MUST be validated with the AS.
This occurs at the following protocol events:
1. When a member receives a KeyPackage for use in an Add proposal.
2. When a member joins a group via a GroupInfo object (from Welcome or external Commit).
3. When a member receives an Add proposal.
4. When a member receives an Update proposal with a new credential.
5. When a Commit includes a new credential in the UpdatePath.
6. When an external_senders extension is added (not relevant here).
7. When an existing external_senders extension is updated (not relevant here).

In short, validation is required whenever group membership or state is modified.

(From OpenMLS)
Credentials should be checked:
1. When joining a group (by examining the ratchet tree).
2. When processing messages (looking at Add & Update proposals in a StagedCommit).

[Uniquely Identifying Clients]
To simplify our AS implementation, a node (drone) is represented by one unique credential.
Unlike messaging apps where a user may have multiple devices, we assume one credential
per drone, acting as a unique identifier.

When issuing credentials, the AS attests a signature key to a NODE_ID—an identifier unique
to each drone—used to validate presented identifiers.

[Credential Expiry and Revocation]
Not covered in our implementation.
*/
use anyhow::Error;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use ed25519_dalek::{KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};
use openmls::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
        // Validate the X.509 certificate
        true
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        // Convert DER-encoded certificate to X509Credential
        let cert = openssl::x509::X509::from_der(der)?;
        let serialized_credential_content = cert.to_der()?;
        Ok(X509Credential::new(serialized_credential_content))
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519credential {
    serialized_credential_content: VLBytes,
}
impl Ed25519credential {
    pub fn new(serialized_credential_content: Vec<u8>) -> Self {
        Self {
            serialized_credential_content: serialized_credential_content.into(),
        }
    }

    pub fn serialized_contents(&self) -> &[u8] {
        self.serialized_credential_content.as_slice()
    }

    pub fn validate(
        &self,
        expected_signature_key: &SignaturePublicKey,
        trusted_issuers: &HashMap<Vec<u8>, VerifyingKey>,
    ) -> Result<(), CredentialError> {
        let data: Ed25519CredentialData = bincode::deserialize(self.serialized_contents())
            .map_err(|_| CredentialError::DecodingError)?;

        // Step 1: Check public key matches what's in the CredentialWithKey
        if data.signature_key_bytes != expected_signature_key.as_slice() {
            return Err(CredentialError::InvalidSignatureKey);
        }

        // Step 2: Rebuild the signed message
        let mut message = Vec::new();
        message.extend_from_slice(&data.identity);
        message.extend_from_slice(&data.signature_key_bytes);
        message.extend_from_slice(&data.not_after.to_le_bytes());

        // Step 3: Verify the signature with the root CA key
        let verifying_key = trusted_issuers
            .get(&data.issuer)
            .ok_or(CredentialError::UnknownIssuer)?;

        // Step 4: Verify the signature
        let signature = Signature::try_from(&data.signature_bytes[..])
            .map_err(|_| CredentialError::InvalidSignature)?;

        match verifying_key.verify(&message, &signature) {
            Ok(_) => {}
            Err(_) => return Err(CredentialError::InvalidSignature), // Consider using the `SignatureError`` propogated from ed25519_dalek (ed25519::signature::Error)
        }

        // Step 5: Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CredentialError::ClockError)?
            .as_secs();

        if now > data.not_after {
            return Err(CredentialError::Expired);
        }

        Ok(())
    }
}

impl From<Ed25519credential> for Credential {
    fn from(credential: Ed25519credential) -> Self {
        Credential::new(
            CredentialType::Other(0xF000),
            credential.serialized_contents().to_vec(),
        )
    }
}

impl TryFrom<Credential> for Ed25519credential {
    type Error = CredentialError;

    fn try_from(credential: Credential) -> Result<Self, Self::Error> {
        match credential.credential_type() {
            CredentialType::Other(0xF000) => Ok(Ed25519credential::new(
                credential.serialized_content().to_vec(),
            )),
            _ => Err(CredentialError::UnsupportedCredentialType),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519CredentialData {
    pub identity: Vec<u8>,
    pub signature_key_bytes: Vec<u8>, // signature_key_bytes:  [u8; KEYPAIR_LENGTH] = keypair.to_bytes();
    pub signature_bytes: Vec<u8>, // signature_bytes:  [u8; SIGNATURE_LENGTH]  = signature.to_bytes();
    pub issuer: Vec<u8>, // Root CA or authority ID. Should corresponds to name of the keyfile in /autentication/keys/ used to sign the credential.
    pub not_after: u64,  // UNIX timestamp
}

#[derive(Debug)]
pub enum CredentialError {
    InvalidSignature,
    InvalidSignatureKey,
    UnknownIssuer,
    Expired,
    DecodingError,
    ClockError,
    UnsupportedCredentialType,
    VerifyingError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn load_x509_credential_from_file() {
        // Load a sample X.509 certificate from a file
        let cert_data = fs::read("authentication/certificates/rootCA.der").unwrap();
        let credential = X509Credential::from_der(&cert_data).unwrap();

        // Validate the credential
        assert!(credential.validate());
    }

    #[test]
    fn load_ed25519_credential_from_file() {}

    #[test]
    fn valid_ed25519_signature() {}

    #[test]
    fn invalid_ed25519_signature() {}

    #[test]
    fn expired_ed25519_credential() {}

    #[test]
    fn unknown_issuer() {}
}
