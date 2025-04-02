use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_basic_credential::SignatureKeyPair;

use tls_codec::Serialize;
use tokio::net::UdpSocket;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Setup MLS group configuration
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = &OpenMlsRustCrypto::default();

    // Bob
    let (bob_cred, bob_signer) = generate_credential_with_key(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        provider,
    );
    let bob_key_package = generate_key_package(
        ciphersuite,
        provider,
        &bob_signer,
        bob_cred.clone(),
    );


    let ds_addr = "127.0.0.1:6000";
    let app : &str = "127.0.0.1:7000";

    // Bind to an available UDP port on the local machine
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Test sending arbitrary payload
    match socket.send_to("Test".as_bytes(), app).await {
        Ok(size) => println!("✅ Test application message sent successfully! ({} bytes)", size),
        Err(e) => println!("❌ Failed to application send test message: {}", e),
    }

    
    // Send KeyPackage to network over UDP
    let msg_out = MlsMessageOut::from(bob_key_package.key_package().clone())
        .tls_serialize_detached()
        .expect("Error serializing KeyPackage");
    
        
    match socket.send_to(&msg_out, ds_addr).await {
        Ok(size) => println!("✅ KeyPackageBundle sent successfully as DS! ({} bytes)", size),
        Err(e) => println!("❌ Failed to send KeyPackageBundle: {}", e),
    }



    Ok(())

}

fn generate_credential_with_key(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let _ = credential_type;
    let credential = BasicCredential::new(identity);
    let signature_keys =
        SignatureKeyPair::new(signature_algorithm)
            .expect("Error generating a signature key pair.");
    signature_keys
        .store(provider.storage())
        .expect("Error storing signature keys.");
    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    )
}

fn generate_key_package(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
}