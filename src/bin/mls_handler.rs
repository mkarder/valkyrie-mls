use std::net::SocketAddr;

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_basic_credential::SignatureKeyPair;

use tls_codec::Deserialize;
use tokio::net::UdpSocket;
use tokio::{select, signal};
use anyhow::Result;

const MACHINE_ID : &str = "Server";
const CREDENTIAL_TYPE : CredentialType = CredentialType::Basic;


struct MlsGroupHandler{
    provider: OpenMlsRustCrypto,
    group: MlsGroup,
    signature_key: SignatureKeyPair,
    key_package: KeyPackageBundle,
}


impl MlsGroupHandler {
    fn new() -> Self {
        let provider = OpenMlsRustCrypto::default();
        let cipher = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let (credential, signature_key) = generate_credential_with_key(
            MACHINE_ID.as_bytes().to_vec(),
            CREDENTIAL_TYPE,
            cipher.signature_algorithm(),
            &provider,
        );

        let key_package = generate_key_package(
            cipher,
            &provider,
            &signature_key,
            credential.clone(),
        );

        let group = MlsGroup::new(
            &provider,
            &signature_key,
            &MlsGroupCreateConfig::default(),
            credential.clone(),
        ).expect("Error creating initial group");

        MlsGroupHandler {
            provider,
            group,
            signature_key,
            key_package,
        }
    }
    
    pub fn process_incoming_network_message(&mut self, mut buf: &[u8])  {
        
        // 1 Deserialize the message
        // 2 Check if it is a handshake message or application message
        // 3 If Protocol message, process it
        // 4 If application message, process it

        match MlsMessageIn::tls_deserialize(&mut buf) {
            Ok(msg_in) => {
                match msg_in.extract() {
                    MlsMessageBodyIn::PublicMessage(msg) => {
                        let processed_message = self.group.process_message(&self.provider, msg).expect("Error processing message");
                        self.handle_incoming_protocol_message(processed_message);
                    },
                    MlsMessageBodyIn::PrivateMessage(msg) => {
                        let processed_message = self.group.process_message(&self.provider, msg).expect("Error processing message");
                        self.handle_incoming_protocol_message(processed_message);
                    },
                    _ => {
                        // Ignore other message types for now
                        // Welcome, KeyPackage, GroupInfo
                        println!("Received unsupported message type.");
                    },
                
                
                }
            },
            Err(_) => {
                match String::from_utf8(buf.to_vec()) {
                    Ok(plaintext) => println!("Regular message received: {}", plaintext),
                    Err(_) => println!("Received unknown binary data!"),
                }
            }
        }
    }
    
    fn handle_incoming_protocol_message(&mut self, message : ProcessedMessage) {
        match message.content() {
            
            ProcessedMessageContent::ApplicationMessage(_msg) => {
                println!(
                    "Received Application Message:"
                );
            },
            ProcessedMessageContent::ProposalMessage(_msg) => {
                println!("Received Proposal Message:");
            },
            ProcessedMessageContent::ExternalJoinProposalMessage(_msg) => {
                println!("Received External Join Proposal Message:");
            },
            ProcessedMessageContent::StagedCommitMessage(_msg) => {
                println!("Received Commit Message:");
            },
        }
    }   
    
    pub fn process_incoming_delivery_service_message(&mut self, mut buf: &[u8]) {
        match MlsMessageIn::tls_deserialize(&mut buf) {
            Ok(msg_in) => {
                match msg_in.extract() {
                    MlsMessageBodyIn::PublicMessage(msg) => println!("Public message received! \n {:?}", msg),
                    MlsMessageBodyIn::PrivateMessage(msg) => println!("Private message received! \n {:?}", msg),
                    MlsMessageBodyIn::Welcome(msg) => println!("Welcome message received! \n {:?}", msg),
                    MlsMessageBodyIn::GroupInfo(msg) => println!("GroupInfo message received! \n {:?}", msg),
                    MlsMessageBodyIn::KeyPackage(msg) => println!("KeyPackage message received! \n {:?}", msg),
                }
            },
        Err(_) => {
            match String::from_utf8(buf.to_vec()) {
                Ok(plaintext) => println!("Regular message received: {}", plaintext),
                Err(_) => println!("Received unknown binary data!"),
                }
            }
        }
    }
    
    pub fn process_outgoing_application_message(&mut self, buf: &[u8]) {
        let msg_out = self.group
            .create_message(&self.provider, &self.signature_key, buf)
            .expect("msg_out: Error creating message");
        self.send_to_network(msg_out);
    }   

    fn send_to_network(&self, message: MlsMessageOut) {
        // Send message to network
        println!("Sending message to network! \n {:?}", message);
    }

    pub fn process_outgoing_handshake_message(&mut self, buf: &[u8]) {
        let msg_out = self.group
            .create_message(&self.provider, &self.signature_key, buf)
            .expect("msg_out: Error creating message");
        self.send_to_delivery_service(msg_out);
    }

    fn send_to_delivery_service(&self, message: MlsMessageOut) {
        // Send message to network
        println!("Sending message to delivery service! \n {:?}", message);
    }

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