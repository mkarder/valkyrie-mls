use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_basic_credential::SignatureKeyPair;

use tls_codec::Serialize;
use tokio::net::UdpSocket;
use anyhow::{Result, Error};


#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsOperation {
    Add = 0x00,
    AddPending = 0x01,
    Remove = 0x02,
    Update = 0x03,
    RetrieveRatchetTree = 0x04,
    ApplicationMsg = 0x05,
    BroadcastKeyPackage = 0x06,
}

impl TryFrom<u8> for MlsOperation {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> Result<Self, Error> {
        match byte {
            0x00 => Ok(MlsOperation::Add),
            0x01 => Ok(MlsOperation::AddPending),
            0x02 => Ok(MlsOperation::Remove),
            0x03 => Ok(MlsOperation::Update),
            0x04 => Ok(MlsOperation::RetrieveRatchetTree),
            0x05 => Ok(MlsOperation::ApplicationMsg),
            0x06 => Ok(MlsOperation::BroadcastKeyPackage),
            _ => Err(Error::msg("Invalid MlsOperation byte")),
        }
    }
}

#[derive(Debug)]
pub enum Command {
    Add { key_package_bytes: Vec<u8> },
    AddPending ,
    Remove { index: u32 },
    Update,
    RetrieveRatchetTree,
    ApplicationMsg { data: Vec<u8> },
    BroadcastKeyPackage,
}

pub fn parse_command(buffer: &[u8]) -> Result<Command, Error> {
    if buffer.is_empty() {
        return Err(Error::msg("Empty command. Nothing in received buffer."));
    }

    let op_code = buffer[0];
    let payload = &buffer[1..];

    match MlsOperation::try_from(op_code).map_err(|_| "Invalid opcode").unwrap() {
        MlsOperation::Add => Ok(Command::Add {
                        key_package_bytes: payload.to_vec(),
            }),
        MlsOperation::AddPending => Ok(Command::AddPending),
        MlsOperation::Remove => {
                if payload.len() < 4 {
                    return Err(Error::msg("Invalid Remove payload. Should be u32 (4 bytes long)"))
                }
                let index = u32::from_be_bytes(payload[..4].try_into().unwrap());
                Ok(Command::Remove { index })
            }
        MlsOperation::Update => Ok(Command::Update),
        MlsOperation::RetrieveRatchetTree => Ok(Command::RetrieveRatchetTree),
        MlsOperation::ApplicationMsg => Ok(Command::ApplicationMsg {
                data: payload.to_vec(),
            }),
        MlsOperation::BroadcastKeyPackage => Ok(Command::BroadcastKeyPackage),
        }
}

pub fn serialize_command(cmd: &Command) -> Vec<u8> {
    match cmd {
        Command::Add { key_package_bytes } => {
                        let mut buf = vec![MlsOperation::Add as u8];
                        buf.extend_from_slice(key_package_bytes);
                        buf
            }
        Command::Remove { index } => {
                let mut buf = vec![MlsOperation::Remove as u8];
                buf.extend(&index.to_be_bytes());
                buf
            }
        Command::RetrieveRatchetTree => vec![MlsOperation::RetrieveRatchetTree as u8],
        Command::Update => { vec![MlsOperation::Update as u8] },
        Command::AddPending => { vec![MlsOperation::AddPending as u8]},
        Command::ApplicationMsg { data } => {
                let mut buf = vec![MlsOperation::ApplicationMsg as u8];
                buf.extend_from_slice(data);
                buf
            }
        Command::BroadcastKeyPackage => vec![MlsOperation::BroadcastKeyPackage as u8],
    }
}

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


    // 1. Send KeyPackage to a node over UDP
    // 2. 

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