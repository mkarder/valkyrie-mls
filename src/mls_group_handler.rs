use anyhow::{Context, Error, Ok};
use openmls::prelude::{group_info::VerifiableGroupInfo, *};
use openmls::group::MlsGroup;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

const MACHINE_ID : &str = "NODE";
const CREDENTIAL_TYPE : CredentialType = CredentialType::Basic;

#[allow(dead_code)]
pub struct MlsGroupHandler{
    provider: OpenMlsRustCrypto,
    group: MlsGroup,
    signature_key: SignatureKeyPair,
    key_package: KeyPackageBundle,
}

#[allow(dead_code)]
pub trait MlsSwarmLogic {
    fn process_incoming_network_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>; 
    fn process_incoming_delivery_service_message(&mut self, message: &[u8]) -> Result<(), Error>;
    fn process_outgoing_application_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>;
    
    fn handle_incoming_welcome(&mut self, welcome: Welcome);
    fn handle_incoming_group_info(&mut self, group_info: VerifiableGroupInfo);
    fn handle_incoming_key_package(&mut self, key_package_in: KeyPackageIn) -> (MlsMessageOut, MlsMessageOut);
}

#[allow(dead_code)]
enum CorosyncOperation {
    Add, 
    Remove 
}

#[allow(dead_code)]
impl MlsGroupHandler {
    pub fn new() -> Self {
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

    fn update_corosyn_state(operation : CorosyncOperation, node : &str, ip: &str) {

    }
}


impl MlsSwarmLogic for MlsGroupHandler {
    fn process_incoming_network_message(&mut self, mut buf: &[u8]) -> Result<Vec<u8>, Error> {
        let message_in = MlsMessageIn::tls_deserialize(&mut buf).expect("Error deserializing message");
        match message_in.extract() {
            MlsMessageBodyIn::PublicMessage(msg) => {
                let processed_message = self.group.process_message(&self.provider, msg).expect("Error processing message");
                match processed_message.into_content() {
                    ProcessedMessageContent::ApplicationMessage(payload) => {
                        let content_bytes = payload.into_bytes();
                        Ok(content_bytes)
                    }
                    ProcessedMessageContent::ExternalJoinProposalMessage(_)
                    | ProcessedMessageContent::StagedCommitMessage(_)
                    | ProcessedMessageContent::ProposalMessage(_) => {
                        Err(Error::msg("Expected ApplicationMessage from Network. Received Proposal or Commit."))
                    }
                }
            }
            MlsMessageBodyIn::PrivateMessage(msg) => {
                let processed_message = self.group.process_message(&self.provider, msg).expect("Error processing message");
                match processed_message.into_content() {
                    ProcessedMessageContent::ApplicationMessage(payload) => {
                        let content_bytes = payload.into_bytes();
                        Ok(content_bytes)
                    }
                    ProcessedMessageContent::ExternalJoinProposalMessage(_)
                    | ProcessedMessageContent::StagedCommitMessage(_)
                    | ProcessedMessageContent::ProposalMessage(_) => {
                        Err(Error::msg("Expected ApplicationMessage from Network. Received Proposal or Commit."))
                    }
                }
            }
            MlsMessageBodyIn::Welcome(_) => Err(Error::msg("Expected ApplicationMessage from Network. Received Welcome.")),
            MlsMessageBodyIn::GroupInfo(_) => Err(Error::msg("Expected ApplicationMessage from Network. Received GroupInfo.")),
            MlsMessageBodyIn::KeyPackage(_) => Err(Error::msg("Expected ApplicationMessage from Network. Received KeyPackage.")),
        }
    }

    fn process_outgoing_application_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mls_message = self.group
            .create_message(&self.provider, &self.signature_key, message)
            .expect("Error encrypting message.");
        
        let serialized_message = mls_message
            .tls_serialize_detached()
            .expect("Error serializing message.");
        Ok(serialized_message)
    }
    
    fn process_incoming_delivery_service_message(&mut self, mut buf: &[u8]) -> Result<(), Error>{
        let message_in = MlsMessageIn::tls_deserialize(&mut buf).expect("Error deserializing message");
        match message_in.extract() {
            MlsMessageBodyIn::PublicMessage(msg) => {
                let processed_message = self.group.process_message(&self.provider, msg).expect("Error processing message");
                match processed_message.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(staged_commit) => { 
                        // TODO: Apply policy for handling incoming commits.
                        let _ = self.group.merge_staged_commit(&self.provider, *staged_commit).context("Error handling staged commit.");
                        Ok(())
                     },
                    ProcessedMessageContent::ProposalMessage(proposal) => {
                        // TODO: Apply policy for handling incoming proposals.
                        let _ = self.group.store_pending_proposal(self.provider.storage(), *proposal.clone()).context("Error storing proposal.");
                        Ok(())
                    },              
                    ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                        Err(Error::msg("No support for External Joins."))
                    }, 
                    ProcessedMessageContent::ApplicationMessage(_) => {
                        Err(Error::msg("Expected Handshake Message from DS. Received ApplicationMessage."))
                    }
                }
            }
            MlsMessageBodyIn::PrivateMessage(msg) => {
                let processed_message = self.group.process_message(&self.provider, msg).expect("Error processing message");
                match processed_message.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(staged_commit) => { 
                        let _ = self.group.merge_staged_commit(&self.provider, *staged_commit).context("Error handling staged commit.");
                        Ok(())
                     },
                    ProcessedMessageContent::ProposalMessage(proposal) => {
                        let _ = self.group.store_pending_proposal(self.provider.storage(), *proposal.clone()).context("Error storing proposal.");
                        Ok(())
                    },              
                    ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                        Err(Error::msg("No support for External Joins."))
                    }, 
                    ProcessedMessageContent::ApplicationMessage(_) => {
                        Err(Error::msg("Expected Handshake Message from DS. Received ApplicationMessage."))
                    }
                }
            },
            MlsMessageBodyIn::Welcome(welcome) => {
                self.handle_incoming_welcome(welcome);
                Ok(())
            },
            MlsMessageBodyIn::GroupInfo(group_info) => {
                self.handle_incoming_group_info(group_info);
                Ok(())
            },
            MlsMessageBodyIn::KeyPackage(key_package_in) => {
                self.handle_incoming_key_package(key_package_in);
                Ok(())
            },
        }
    }

    fn handle_incoming_welcome(&mut self, welcome: Welcome) {
        log::info!("TODO: Verify welcome message before joining group.");
        let staged_join = StagedWelcome::new_from_welcome(
            &self.provider, 
            &MlsGroupJoinConfig::default(), 
            welcome, 
            None 
        ).expect("Error constructing staged join");
        let group = staged_join.into_group(&self.provider).expect("Error joining group from StagedWelcome");
        self.group = group;
    }
    
    fn handle_incoming_group_info(&mut self, _group_info: VerifiableGroupInfo) {
        log::info!("TODO: Implement Policy for incoming GroupInfo.");
    }

    fn handle_incoming_key_package(&mut self, key_package_in: KeyPackageIn) -> (MlsMessageOut, MlsMessageOut) {
        log::info!("TODO: Implement policy for incoming KeyPackage.");
        let key_package = key_package_in.validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .expect("Incoming KeyPackage could not be verified");
 
        let (mls_message_out, welcome, _group_info) = self.group
            .add_members(
                &self.provider,
                &self.signature_key,
                &[key_package],
            )
            .expect("Could not add members.");
        (mls_message_out, welcome)
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