use std::collections::HashMap;

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
    pending_key_packages: HashMap<KeyPackageRef, KeyPackage>,
}

pub trait MlsSwarmLogic {
    fn add_new_member(&mut self, key_package: KeyPackage) -> (MlsMessageOut, MlsMessageOut);
    fn add_pending_key_packages(&mut self) -> Result<Vec<(MlsMessageOut,MlsMessageOut)>, Error>; 

    fn remove_member(&mut self, leaf_node: LeafNodeIndex) -> (MlsMessageOut, Option<MlsMessageOut>);

    fn update_self(&mut self) -> (MlsMessageOut, Option<MlsMessageOut>); 

    fn process_incoming_network_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>; 
    fn process_incoming_delivery_service_message(&mut self, message: &[u8]) -> Result<Option<(MlsMessageOut, MlsMessageOut)>, Error>;
    fn process_outgoing_application_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>;
    
    fn handle_incoming_welcome(&mut self, welcome: Welcome);
    fn handle_incoming_group_info(&mut self, group_info: VerifiableGroupInfo);
    fn handle_incoming_key_package(&mut self, key_package_in: KeyPackageIn);
    fn handle_incoming_commit(&mut self, commit: StagedCommit);
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
        
        let group = MlsGroup::builder()
            .padding_size(0)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                10,   // out_of_order_tolerance
                2000, // maximum_forward_distance
            ))
            .ciphersuite(cipher)
            .use_ratchet_tree_extension(true)
            .build(&provider, &signature_key, credential.clone())
            .expect("An unexpected error occurred.");

        // let group = MlsGroup::new(
        //     &provider,
        //     &signature_key,
        //     &MlsGroupCreateConfig::default(),
        //     credential.clone(),
        // ).expect("Error creating initial group");

        MlsGroupHandler {
            provider,
            group,
            signature_key,
            key_package,
            pending_key_packages: HashMap::new(),
        }
    }
    
    fn load_group(&mut self, group_id: Vec<u8>) -> Option<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(&group_id))
            .expect("Error loading group")
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
    
    fn process_incoming_delivery_service_message(&mut self, mut buf: &[u8]) -> Result<Option<(MlsMessageOut, MlsMessageOut)>, Error>{
        let message_in = MlsMessageIn::tls_deserialize(&mut buf).expect("Error deserializing message");
        match message_in.extract() {
            MlsMessageBodyIn::PublicMessage(msg) => {
                let processed_message = self.group.process_message(&self.provider, msg).expect("Error processing message");
                match processed_message.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(staged_commit) => { 
                        // TODO: Apply authentication for incoming commits.
                        let _ = self.group.merge_staged_commit(&self.provider, *staged_commit).context("Error handling staged commit.");
                     },
                    ProcessedMessageContent::ProposalMessage(proposal) => {
                        // TODO: Apply authentication for incoming proposals.
                        let _ = self.group.store_pending_proposal(self.provider.storage(), *proposal.clone()).context("Error storing proposal.");
                    },              
                    ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                        return Err(Error::msg("No support for External Joins."))
                    }, 
                    ProcessedMessageContent::ApplicationMessage(_) => {
                        return Err(Error::msg("Expected Handshake Message from DS. Received ApplicationMessage."))
                    }
                }
                Ok(None)
            }
            MlsMessageBodyIn::PrivateMessage(msg) => {
                let processed_message = self.group.process_message(&self.provider, msg).expect("Error processing message");
                match processed_message.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                        self.handle_incoming_commit(*staged_commit);
                        
                     },
                    ProcessedMessageContent::ProposalMessage(proposal) => {
                        let _ = self.group.store_pending_proposal(self.provider.storage(), *proposal.clone()).context("Error storing proposal.");
                    },              
                    ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                        return Err(Error::msg("No support for External Joins."))
                    }, 
                    ProcessedMessageContent::ApplicationMessage(_) => {
                        return Err(Error::msg("Expected Handshake Message from DS. Received ApplicationMessage."))
                    }
                }
                Ok(None)
            },
            MlsMessageBodyIn::Welcome(welcome) => {
                self.handle_incoming_welcome(welcome);
                Ok(None)
            },
            MlsMessageBodyIn::GroupInfo(group_info) => {
                self.handle_incoming_group_info(group_info);
                Ok(None)
            },
            MlsMessageBodyIn::KeyPackage(key_package_in) => {
                self.handle_incoming_key_package(key_package_in);
                Ok(None)
            },
        }
    }

    fn handle_incoming_welcome(&mut self, welcome: Welcome) {
        // We assume we join every welcome message we receive.
        log::warn!("TODO: Verify welcome message before joining group.");
        let staged_join = StagedWelcome::new_from_welcome(
            &self.provider, 
            &MlsGroupJoinConfig::default(), 
            welcome, 
            None 
        ).expect("Error constructing staged join");
        
        // TODO: Validate sender. Check credential through Authentication Seervice. 
        // let sender = staged_join.welcome_sender()
        //     .expect("Error getting sender from staged join");
        // validate(sender);

        let group = staged_join.into_group(&self.provider).expect("Error joining group from StagedWelcome");
        log::info!("Joined group with ID: {:?}", group.group_id().as_slice());
        self.group = group;
    }
    
    fn handle_incoming_group_info(&mut self, _group_info: VerifiableGroupInfo) {
        log::warn!("Received GroupInfo message. No action taken. GroupInfo implies the use of external joins, which it not supported.");

    }

    fn handle_incoming_key_package(&mut self, key_package_in: KeyPackageIn) {
        log::warn!("TODO: Implement policy for incoming KeyPackage.");

        // TODO: Validate sender. Check credential through Authentication Seervice.
        let key_package = key_package_in.validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .expect("Incoming KeyPackage could not be verified");
        let key_ref = key_package.hash_ref(self.provider.crypto())
            .expect("Error getting hash_ref from KeyPackage");
        self.pending_key_packages.insert(key_ref, key_package.clone());
    }

    fn add_new_member(&mut self, key_package: KeyPackage) -> (MlsMessageOut, MlsMessageOut) {
        let (group_commit, welcome, _group_info) = self.group
            .add_members(
                &self.provider,
                &self.signature_key,
                &[key_package.clone()],
            )
            .expect("Could not add members.");

        log::info!("Added new member to group with ID: {:?}", self.group.group_id());
        log::debug!("GroupCommit: {:?}", group_commit);
        log::debug!("Welcome: {:?}", welcome);
        (group_commit, welcome)
    }
    
    fn add_pending_key_packages(&mut self) -> Result<Vec<(MlsMessageOut,MlsMessageOut)>, Error> {
        let mut welcome_and_commits = Vec::new();
        for (_key_ref, key_package) in self.pending_key_packages.iter() {
            let (group_commit, welcome, _group_info) = self.group
                .add_members(
                    &self.provider,
                    &self.signature_key,
                    &[key_package.clone()],
                )
                .expect("Could not add members.");
            log::info!("Added new member to group with ID: {:?}", self.group.group_id());
            log::debug!("GroupCommit: {:?}", group_commit);
            log::debug!("Welcome: {:?}", welcome);
            welcome_and_commits.push((group_commit, welcome));
        }
        self.pending_key_packages.clear();
        Ok(welcome_and_commits)
    }
    
    fn handle_incoming_commit(&mut self, commit: StagedCommit) {
        for add in commit.add_proposals() {
            let key_package = add.add_proposal().key_package().clone();
            let key_ref = key_package.hash_ref(self.provider.crypto())
                .expect("Error getting hash_ref from KeyPackage");
            
            if let Some(removed) = self.pending_key_packages.remove(&key_ref) {
                log::info!("Removed pending KeyPackage: {:?}", removed);
            }
        }
        
        let _ = self.group.merge_staged_commit(&self.provider, commit).context("Error handling staged commit.");
    }
    
    fn remove_member(&mut self, leaf_node: LeafNodeIndex) -> (MlsMessageOut, Option<MlsMessageOut>) {
        let (group_commit, welcome_option, _group_info) = self.group
            .remove_members(
                &self.provider,
                &self.signature_key,
                &[leaf_node],
            )
            .expect("Error removing member");

        (group_commit, welcome_option)
    }
    
    fn update_self(&mut self) -> (MlsMessageOut, Option<MlsMessageOut>) {
        let (group_commit, welcome_option, _group_info) = self.group
            .self_update(
                &self.provider,
                &self.signature_key,
                LeafNodeParameters::default(),
            )
            .expect("Error updating self");

        (group_commit, welcome_option)
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