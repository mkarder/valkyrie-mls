#[cfg(test)]
mod tests {
    use ed25519_dalek::ed25519::signature::Signer;
    use openmls::prelude::{Ciphersuite, SignaturePublicKey};
    use openmls_basic_credential::SignatureKeyPair;

    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::authentication::{
        generate_signed_ed25519_credential, load_signing_key_from_issuer,
        load_verifying_key_from_issuer, Ed25519CredentialData, Ed25519credential, X509Credential,
    };

    const AUTHENTICATION_DIR: &str = "authentication";

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
        Ed25519credential::new(credential_data)
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
