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
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use ed25519_dalek::{KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};
use openmls::prelude::*;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// Possible constants and/or config values for the AS
// 1. Authentication directory here keys, certs, etc. can be found.
// 2. A list of trusted issuers (root CAs) for the AS to validate credentials against. The name of the issuer should correspond to the name of its keyfile in the authentication directory.
// -> e.g. issuer "root-ca" should have a keyfile "root-ca.pub" in the authentication directory.
const AUTHENTICATION_DIR: &str = "authentication";

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
        // TODO: Validate the X.509 certificate

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
    credential_data: Ed25519CredentialData,
}
impl Ed25519credential {
    pub fn new(credential_data: Ed25519CredentialData) -> Self {
        Self { credential_data }
    }

    pub fn from(credential_data: Vec<u8>) -> Self {
        let credential_data: Ed25519CredentialData =
            bincode::deserialize(&credential_data).expect("Deserialization failed");
        Self { credential_data }
    }

    pub fn serialized_contents(&self) -> Vec<u8> {
        let serialized_credential_content = bincode::serialize(&self.credential_data)
            .expect("Serialization failed")
            .clone();

        serialized_credential_content
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

        let verifying_key = load_verifying_key_from_issuer(self.credential_data.issuer.clone())
            .map_err(|_| CredentialError::UnknownIssuer)?;

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
        // Load the Ed25519 credential from a file
        let bytes = std::fs::read(path).map_err(|_| CredentialError::DecodingError)?;
        Ok(Ed25519credential::from(bytes))
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
            CredentialType::Other(0xF000) => Ok(Ed25519credential::from(
                credential.serialized_content().to_vec(),
            )),
            _ => Err(CredentialError::UnsupportedCredentialType),
        }
    }
}

impl TryFrom<Ed25519CredentialData> for Ed25519credential {
    type Error = CredentialError;

    fn try_from(credential: Ed25519CredentialData) -> Result<Self, Self::Error> {
        let serialized_credential_content =
            bincode::serialize(&credential).map_err(|_| CredentialError::DecodingError)?;
        Ok(Ed25519credential::from(serialized_credential_content))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519CredentialData {
    pub identity: Vec<u8>,
    pub credential_key_bytes: Vec<u8>, // credential_key_bytes:  [u8; KEYPAIR_LENGTH] = keypair.to_bytes();
    pub not_after: u64,                // UNIX timestamp
    pub signature_bytes: Vec<u8>, // signature_bytes:  [u8; SIGNATURE_LENGTH]  = signature.to_bytes();
    pub issuer: Vec<u8>, // Root CA or authority ID. Should corresponds to name of the keyfile in /autentication/keys/ used to sign the credential.
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
    IssuerEncodingError,
}

fn load_verifying_key_from_issuer(issuer_bytes: Vec<u8>) -> Result<VerifyingKey, CredentialError> {
    // Load trusted issuer from the authentication directory
    let issuer_string =
        String::from_utf8(issuer_bytes).map_err(|_| CredentialError::IssuerEncodingError)?;

    let issuer_path = format!("{}/keys/{}.pub", AUTHENTICATION_DIR, issuer_string);
    if std::path::Path::new(&issuer_path).exists() {
        let data = std::fs::read(&issuer_path).unwrap();
        let pub_key_bytes = extract_raw_ed25519_key_from_der(data);
        match pub_key_bytes {
            Ok(bytes) => {
                let pub_key = VerifyingKey::from_bytes(&bytes);
                return pub_key.map_err(|_| CredentialError::VerifyingError);
            }
            Err(_) => {
                log::error!("Failed to extract public key from DER file");
                return Err(CredentialError::VerifyingError);
            }
        }
    } else {
        log::error!("Issuer key file not found: {}", issuer_path);
        Err(CredentialError::UnknownIssuer)
    }
}

fn load_signing_key_from_issuer(issuer_bytes: Vec<u8>) -> Result<SigningKey, CredentialError> {
    // Load trusted issuer from the authentication directory
    let issuer_string =
        String::from_utf8(issuer_bytes).map_err(|_| CredentialError::IssuerEncodingError)?;

    let issuer_path = format!("{}/keys/{}.priv", AUTHENTICATION_DIR, issuer_string);
    if std::path::Path::new(&issuer_path).exists() {
        let data = std::fs::read(&issuer_path).unwrap();
        let priv_key_bytes = extract_raw_ed25519_key_from_der(data);
        match priv_key_bytes {
            Ok(bytes) => {
                return Ok(SigningKey::from_bytes(&bytes));
            }
            Err(_) => {
                log::error!("Failed to extract private key from DER file");
                return Err(CredentialError::VerifyingError);
            }
        }
    } else {
        log::error!("Issuer key file not found: {}", issuer_path);
        Err(CredentialError::UnknownIssuer)
    }
}

fn extract_raw_ed25519_key_from_der(data: Vec<u8>) -> Result<[u8; 32], CredentialError> {
    // Convert DER-encoded ed25519 key to raw bytes
    // We assume 12-byte ASN.1 header from the .DER encoding
    // and extract the last 32 bytes as the public key
    let key_bytes = &data[data.len() - 32..];
    let key_bytes: &[u8; 32] = key_bytes
        .try_into()
        .map_err(|_| CredentialError::VerifyingError)?;

    Ok(*key_bytes)
}

fn generate_signed_ed25519_credential(
    identity: &str,
    credential_key_bytes: Vec<u8>, // The public key to be attested.
    issuer: &str,
    not_after: u64,
    store: bool,
) -> Result<Ed25519credential, CredentialError> {
    let message = [
        &identity.as_bytes()[..],
        &credential_key_bytes[..],
        &not_after.to_le_bytes()[..],
    ]
    .concat();

    let mut signature_key = load_signing_key_from_issuer(issuer.as_bytes().to_vec())
        .map_err(|_| CredentialError::UnknownIssuer)?;
    let signature = signature_key.sign(&message);

    let credential_data = Ed25519CredentialData {
        identity: identity.as_bytes().to_vec(),
        credential_key_bytes,
        signature_bytes: signature.to_bytes().to_vec(),
        issuer: issuer.as_bytes().to_vec(),
        not_after,
    };

    let credential = Ed25519credential::try_from(credential_data.clone());

    if store {
        // Store the credential in a file
        let credential_path = format!("{}/credentials/{}.cred", AUTHENTICATION_DIR, identity);
        std::fs::write(
            credential_path,
            bincode::serialize(&credential_data).expect("Serialization failed"),
        )
        .map_err(|_| CredentialError::DecodingError)?;
    }
    credential
}

fn generate_credential_with_key(
    ed25519_credential: Ed25519credential,
    signature_key: SignaturePublicKey,
) -> CredentialWithKey {
    CredentialWithKey {
        credential: ed25519_credential.into(),
        signature_key,
    }
}

trait RootSigner {
    fn sign(&self, message: &[u8]) -> Signature;
    fn verify(&self, message: &[u8], signature: &Signature) -> bool;
    fn public_key(&self) -> &[u8];
    fn issue(&self, identity: &str) -> Result<Ed25519credential, CredentialError>;
}

#[cfg(test)]
mod tests {
    use openmls_basic_credential::SignatureKeyPair;

    use super::{generate_signed_ed25519_credential, *};
    use std::fs;

    fn gen_test_ed25519_credential_data() -> Ed25519CredentialData {
        let signature_algorithm =
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm();

        let identity = "test-identity";
        let credential_key = SignatureKeyPair::new(signature_algorithm)
            .expect("Error generating a signature key pair.");

        let credential_key_bytes = credential_key.public().to_vec(); // Should be 32 bytes
        let issuer = b"test-ca".to_vec();
        let not_after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let message = [
            &identity.as_bytes()[..],
            &credential_key_bytes[..],
            &not_after.to_le_bytes()[..],
        ]
        .concat();

        let signature = load_signing_key_from_issuer(issuer.clone())
            .unwrap()
            .sign(&message);
        let signature_bytes = signature.to_bytes().to_vec();

        Ed25519CredentialData {
            identity: identity.as_bytes().to_vec(),
            credential_key_bytes,
            signature_bytes,
            issuer,
            not_after,
        }
    }

    fn gen_test_ed25519_credential() -> Ed25519credential {
        let credential_data = gen_test_ed25519_credential_data();
        Ed25519credential::try_from(credential_data).expect("Failed to create Ed25519 credential")
    }

    #[test]
    fn load_x509_credential_from_file() {
        // Load a sample X.509 certificate from a file
        let cert_data = fs::read("authentication/certificates/rootCA.der").unwrap();
        let credential = X509Credential::from_der(&cert_data).unwrap();

        // Validate the credential
        assert!(credential.validate());
    }

    #[test]
    fn load_ed25519_keys_from_file() {
        let issuer = "test-ca";
        load_verifying_key_from_issuer(issuer.as_bytes().to_vec())
            .expect("Error loading verifying key from test issuer.");
        load_signing_key_from_issuer(issuer.as_bytes().to_vec())
            .expect("Error loading signing key from test issuer.");
    }

    #[test]
    fn ed25519_credentialdata_bincode_roundtrip() {
        // Generate a test Ed25519CredentialData
        let original = gen_test_ed25519_credential_data();

        // Serialize
        let serialized = bincode::serialize(&original).expect("Serialization failed");

        // Deserialize
        let deserialized: Ed25519CredentialData =
            bincode::deserialize(&serialized).expect("Deserialization failed");

        // Check equality
        assert_eq!(original, deserialized);
    }

    #[test]
    fn ed25519_credential() {
        let signature_algorithm =
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm();

        let identity = "test-identity";
        let credential_key = SignatureKeyPair::new(signature_algorithm)
            .expect("Error generating a signature key pair.");

        let issuer = "test-ca";
        let not_after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // 1 hour from now
        let store = true;
        let credential_result = generate_signed_ed25519_credential(
            identity,
            credential_key.public().to_vec(),
            issuer,
            not_after,
            store,
        );

        assert!(credential_result.is_ok(), "{:?}", credential_result);
        let credential = credential_result.unwrap();
        // Assert credential was stored correctly
        let credential_path = format!("{}/credentials/{}.cred", AUTHENTICATION_DIR, identity);
        assert!(std::path::Path::new(&credential_path).exists());

        // Load the credential from the file
        let loaded_credential = Ed25519credential::from_file(&credential_path).unwrap();
        assert_eq!(
            loaded_credential.serialized_contents(),
            credential.serialized_contents()
        );

        // Validate the credential
        let signature_pub_key = SignaturePublicKey::from(credential_key.public().to_vec());
        credential
            .validate(&signature_pub_key)
            .expect("Credential validation failed");

        // Invalid signature

        // Clean up the test file
        std::fs::remove_file(&credential_path).expect("Failed to delete test credential file");
    }

    #[test]
    fn valid_ed25519_signature() {}

    #[test]
    fn invalid_ed25519_signature() {}

    #[test]
    fn expired_ed25519_credential() {}

    #[test]
    fn unknown_issuer() {}
}
