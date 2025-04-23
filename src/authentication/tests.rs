/*
 For test identies, use idienties that begin with 'test', as we remove all these files after tests have concluded.
 If one need to obtain identies, we have saved credentials for Alice (9999) and Bob (8888), for those to test with.
*/

#[cfg(test)]
mod tests {
    use ed25519_dalek::ed25519::signature::Signer;
    use glob::glob;
    use openmls::prelude::{Ciphersuite, SignaturePublicKey};
    use openmls_basic_credential::SignatureKeyPair;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::authentication::{
        ed25519::{
            generate_signing_message, load_signing_key_from_file, load_verifying_key_from_file,
            Ed25519CredentialData, Ed25519Issuer, Ed25519SignatureKeyPair,
        },
        issuer::CredentialIssuer,
        x509::X509Credential,
        CredentialError, Ed25519credential,
    };

    const AUTHENTICATION_DIR: &str = "authentication";

    #[allow(dead_code)]
    pub fn generate_signed_ed25519_credential(
        identity: u32,
        credential_key_bytes: Vec<u8>,
        issuer: u32,
        not_after: u64,
        store: bool,
    ) -> Result<Ed25519credential, CredentialError> {
        let message = generate_signing_message(identity, &credential_key_bytes, not_after);

        let signing_key = load_signing_key_from_file(issuer)?;
        let signature = signing_key.sign(&message);

        let credential_data = Ed25519CredentialData {
            identity,
            credential_key_bytes,
            not_after,
            signature_bytes: signature.to_bytes().to_vec(),
            issuer,
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

    fn gen_test_ed25519_credential_data() -> Ed25519CredentialData {
        let signature_algorithm =
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm();

        let identity = 1000;
        let credential_key = SignatureKeyPair::new(signature_algorithm)
            .expect("Error generating a signature key pair.");

        let credential_key_bytes = credential_key.public().to_vec(); // Should be 32 bytes
        let issuer = 9999;
        let not_after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let message = generate_signing_message(identity, &credential_key_bytes, not_after);

        let signature = load_signing_key_from_file(issuer.clone())
            .unwrap()
            .sign(&message);
        let signature_bytes = signature.to_bytes().to_vec();

        Ed25519CredentialData {
            identity,
            credential_key_bytes,
            signature_bytes,
            issuer,
            not_after,
        }
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
        let subject = 9999; //Alice
        load_verifying_key_from_file(subject).expect("Error loading verifying key from 9999.pub");
        load_signing_key_from_file(subject).expect("Error loading signing key from 9999.priv");
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

        let identity = 1003;
        let credential_key = SignatureKeyPair::new(signature_algorithm)
            .expect("Error generating a signature key pair.");

        let issuer = 9999;
        let not_after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // 1 hour from now

        // Generate a valid, signed Ed25519 credential
        let message = generate_signing_message(identity, &credential_key.public(), not_after);

        let signing_key = load_signing_key_from_file(issuer).unwrap();
        let signature = signing_key.sign(&message);

        let credential_data = Ed25519CredentialData {
            identity,
            credential_key_bytes: credential_key.public().to_vec(),
            not_after,
            signature_bytes: signature.to_bytes().to_vec(),
            issuer,
        };

        let credential = Ed25519credential::new(credential_data.clone());

        // Store the credential in a file
        credential.store().expect("Failed to store credential");

        // Assert credential was stored correctly
        let credential_path = format!("{}/credentials/{}.cred", AUTHENTICATION_DIR, identity);
        assert!(std::path::Path::new(&credential_path).exists());

        // Load the credential from the file
        let loaded_credential = Ed25519credential::from_file(identity).unwrap();
        assert_eq!(
            loaded_credential.serialized_contents(),
            credential.serialized_contents()
        );

        // Validate the credential
        let signature_pub_key = SignaturePublicKey::from(credential_key.public().to_vec());

        assert!(
            credential.validate(Some(&signature_pub_key)).is_ok(),
            "Credential validation failed"
        );

        // Invalid signature
        let mut invalid_signature = signature.to_vec().clone();
        invalid_signature[0] ^= 0xFF; // Corrupt the signature
        let invalid_credential = Ed25519credential::new(Ed25519CredentialData {
            identity,
            credential_key_bytes: credential_key.public().to_vec(),
            signature_bytes: invalid_signature,
            issuer,
            not_after,
        });
        assert!(
            invalid_credential
                .validate(Some(&signature_pub_key))
                .is_err(),
            "Invalid signature should fail validation"
        );

        // Expired credential
        let expired_not_after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600; // 1 hour in the past

        let expired_credential = Ed25519credential::new(Ed25519CredentialData {
            identity,
            credential_key_bytes: credential_key.public().to_vec(),
            signature_bytes: signature.to_bytes().to_vec(),
            issuer,
            not_after: expired_not_after,
        });
        assert!(
            expired_credential
                .validate(Some(&signature_pub_key))
                .is_err(),
            "Expired credential should fail validation"
        );

        // Invalid Issuer
        let invalid_issuer = 8888;
        let invalid_credential = Ed25519credential::new(Ed25519CredentialData {
            identity,
            credential_key_bytes: credential_key.public().to_vec(),
            signature_bytes: signature.to_bytes().to_vec(),
            issuer: invalid_issuer,
            not_after,
        });
        assert!(
            invalid_credential
                .validate(Some(&signature_pub_key))
                .is_err(),
            "Invalid issuer should fail validation"
        );
    }

    #[test]
    fn wrong_signature_key_fails_validation() {
        let valid_cred_data = gen_test_ed25519_credential_data();
        let mut wrong_key = valid_cred_data.credential_key_bytes.clone();
        wrong_key[0] ^= 0xFF; // Corrupt the key

        let wrong_pub_key = SignaturePublicKey::from(wrong_key);

        let valid_cred = Ed25519credential::new(valid_cred_data);

        assert!(
            valid_cred.validate(Some(&wrong_pub_key)).is_err(),
            "Validation should fail with incorrect signature key"
        );
    }

    #[test]
    fn ed25519_issuer_issues_valid_credential() {
        let issuer_id = 1004;
        let issuer = Ed25519Issuer::create_issuer(issuer_id);
        assert!(issuer.store().is_ok());

        let signature_algorithm =
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm();
        let client_keypair = SignatureKeyPair::new(signature_algorithm).unwrap();
        let pub_key = client_keypair.public().to_vec();

        let cred_with_key = issuer.issue(1005, &pub_key).unwrap();

        assert_eq!(cred_with_key.signature_key.as_slice(), pub_key.as_slice());

        let parsed_cred = Ed25519credential::try_from(cred_with_key.credential.clone()).unwrap();
        parsed_cred
            .validate(Some(&cred_with_key.signature_key))
            .unwrap();

        // Clean up the test file
        // std::fs::remove_file(&credential_path).expect("Failed to delete test credential file");

        // Load issuer and key from file then issue credential
        let ca = 9999;
        let subject = 8888;

        let issuer = Ed25519Issuer::from_file(ca).expect("Failed to create issuer");

        let subject_key = Ed25519SignatureKeyPair::from_file(subject)
            .expect("Failed to create subject's (8888) key pair");

        let subject_credential = issuer
            .issue(subject, subject_key.public_key())
            .expect("Failed to issue key for subject");

        let parsed_credential = Ed25519credential::from_file(subject).unwrap().into();
        assert_eq!(subject_credential.credential, parsed_credential);
    }

    #[test]
    #[should_panic]
    fn ed25519_issuer_rejects_invalid_pubkey() {
        let issuer = Ed25519Issuer::create_issuer(1006);

        let invalid_key = vec![0u8; 31]; // Invalid length (should be 32)
        issuer.issue(1007, &invalid_key).unwrap();
    }

    #[test]
    fn ed25519_issuer_sign_and_verify() {
        let issuer = Ed25519Issuer::create_issuer(1008);

        let message = b"important auth message";
        let signature = issuer.sign(message);
        assert!(issuer.verify(message, &signature));
    }

    fn cleanup_test_files() {
        let patterns = [
            format!("{}/credentials/100*.cred", AUTHENTICATION_DIR),
            format!("{}/keys/100*.pub", AUTHENTICATION_DIR),
            format!("{}/keys/100*.priv", AUTHENTICATION_DIR),
        ];

        for pattern in &patterns {
            for entry in glob(pattern).expect("Failed to read glob pattern") {
                match entry {
                    Ok(path) => {
                        if let Err(e) = fs::remove_file(&path) {
                            eprintln!("Failed to delete {:?}: {}", path, e);
                        }
                    }
                    Err(e) => eprintln!("Glob error: {}", e),
                }
            }
        }
    }

    #[test]
    fn test_cleanup() {
        cleanup_test_files();
    }
}
