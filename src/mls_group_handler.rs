use crate::authentication::ed25519::Ed25519SignatureKeyPair;
use crate::authentication::{self, Ed25519credential};
use crate::config::MlsConfig;
use anyhow::{Context, Error};
use openmls::group::MlsGroup;
use openmls::prelude::{group_info::VerifiableGroupInfo, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use std::collections::HashMap;
use std::time::SystemTime;
use tls_codec::{Deserialize, Serialize};

pub enum MlsSwarmState {
    Alone,
    SubGroup,
    MainGroup,
}

#[allow(dead_code)]
pub struct MlsEngine {
    config: MlsConfig,
    group_join_config: MlsGroupJoinConfig,
    provider: OpenMlsRustCrypto,
    group: MlsGroup,
    signature_key: SignatureKeyPair,
    key_package: KeyPackageBundle,
    pending_key_packages: HashMap<KeyPackageRef, KeyPackage>,
    update_interval_secs: u64,
    credential_with_key: CredentialWithKey,
    capabilities: Capabilities,
    last_received: HashMap<LeafNodeIndex, SystemTime>,
    pending_removals: Vec<LeafNodeIndex>,
    totem_group_size: u32,
}

pub trait MlsSwarmLogic {
    fn add_new_member(&mut self, key_package: KeyPackage) -> (Vec<u8>, Vec<u8>);
    fn add_new_member_from_bytes(&mut self, key_package_bytes: &[u8]) -> (Vec<u8>, Vec<u8>);
    fn add_pending_key_packages(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error>;

    fn remove_member(&mut self, leaf_node: LeafNodeIndex) -> (Vec<u8>, Option<Vec<u8>>);

    fn update_self(&mut self) -> Result<(Vec<u8>, Option<Vec<u8>>), Error>;

    fn store_key_package(&mut self, key_package: KeyPackage);

    fn verify_credential(
        &self,
        unverified_credential: Credential,
        attached_key: Option<&SignaturePublicKey>,
    ) -> Result<(), Error>;

    fn credential_present_in_group(&self, credential: Credential) -> bool;

    #[allow(dead_code)]
    fn retrieve_ratchet_tree(&self) -> Vec<u8>;

    fn process_incoming_network_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>;
    fn process_incoming_delivery_service_message(
        &mut self,
        message: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error>;
    fn process_outgoing_application_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>;

    fn handle_incoming_welcome(&mut self, welcome: Welcome) -> Result<(), Error>;
    fn handle_incoming_group_info(&mut self, group_info: VerifiableGroupInfo);
    fn handle_incoming_key_package(&mut self, key_package_in: KeyPackageIn);
    fn handle_incoming_commit(&mut self, commit: StagedCommit) -> Result<(), Error>;
}

#[allow(dead_code)]
impl MlsEngine {
    pub fn new(config: MlsConfig) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let cipher = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let (credential_type, capabilities) = match config.credential_type.to_lowercase().as_str() {
            "basic" => (CredentialType::Basic, capabilities("basic")),
            "x509" => (CredentialType::X509, capabilities("x509")),
            "ed25519" => (CredentialType::Other(0xF000), capabilities("ed25519")),
            other => panic!(
                "Cannot initialize Mls Component. Unsupported credential type: {}",
                other
            ),
        };
        let (credential_with_key, signature_key) = generate_credential_with_key(
            config.node_id.clone(),
            credential_type,
            cipher.signature_algorithm(),
            &provider,
        );

        let key_package = generate_key_package(
            cipher,
            &provider,
            &signature_key,
            credential_with_key.clone(),
            capabilities.clone(),
        );
        let group_join_config = generate_group_config();

        let group = MlsGroup::new(
            &provider,
            &signature_key,
            &generate_group_create_config(capabilities.clone()),
            credential_with_key.clone(),
        )
        .expect("Error creating group");

        let update_interval_secs = config.update_interval_secs;

        MlsEngine {
            config,
            group_join_config,
            provider,
            group,
            signature_key,
            key_package,
            pending_key_packages: HashMap::new(),
            update_interval_secs,
            credential_with_key,
            capabilities,
            last_received: HashMap::new(),
            pending_removals: Vec::new(),
            totem_group_size: 1, // We always start with ourself in a group of 1
        }
    }

    pub fn load_group(&mut self, group_id: Vec<u8>) -> Option<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(&group_id))
            .expect("Error loading group")
    }

    pub fn get_key_package(&self) -> Result<Vec<u8>, Error> {
        let key_package = MlsMessageOut::from(self.key_package.key_package().clone());
        key_package
            .tls_serialize_detached()
            .context("Error serializing key package")
    }

    pub fn refresh_key_package(&mut self) -> Result<(), Error> {
        self.key_package = generate_key_package(
            self.group.ciphersuite(),
            &self.provider,
            &self.signature_key,
            self.credential_with_key.clone(),
            self.capabilities.clone(),
        );
        Ok(())
    }

    pub fn pending_key_packages(&self) -> &HashMap<KeyPackageRef, KeyPackage> {
        &self.pending_key_packages
    }

    pub fn group(&self) -> &MlsGroup {
        &self.group
    }

    pub fn update_interval_secs(&self) -> u64 {
        self.update_interval_secs
    }

    pub fn update_totem_group_size(&mut self, size: u32) {
        self.totem_group_size = size;
    }
}

impl MlsSwarmLogic for MlsEngine {
    fn process_incoming_network_message(&mut self, mut buf: &[u8]) -> Result<Vec<u8>, Error> {
        /*
               let message_in =
                   MlsMessageIn::tls_deserialize(&mut buf).expect("Error deserializing message");
        */

        let message_in = MlsMessageIn::tls_deserialize(&mut buf).map_err(|e| {
            log::error!("Error processing message: {:?}", e);
            Error::msg("Error processing message.")
        })?;

        match message_in.extract() {
            MlsMessageBodyIn::PublicMessage(msg) => {
                let processed_message = self
                    .group
                    .process_message(&self.provider, msg)
                    .expect("[MlsEngine] Error processing message");
                match processed_message.into_content() {
                    ProcessedMessageContent::ApplicationMessage(payload) => {
                        let content_bytes = payload.into_bytes();
                        let preview = std::str::from_utf8(&content_bytes)
                            .map(|text| &text[..text.len().min(50)])
                            .unwrap_or("<non-UTF8 data>");
                        log::info!("[MlsEngine] Decrypted application message: {}", preview);
                        Ok(content_bytes)
                    }
                    ProcessedMessageContent::ExternalJoinProposalMessage(_)
                    | ProcessedMessageContent::StagedCommitMessage(_)
                    | ProcessedMessageContent::ProposalMessage(_) => Err(Error::msg(
                        "[MlsEngine] Expected ApplicationMessage from Network. Received Proposal or Commit.",
                    )),
                }
            }
            MlsMessageBodyIn::PrivateMessage(msg) => {
                let processed_message =
                    self.group
                        .process_message(&self.provider, msg)
                        .map_err(|e| {
                            log::error!("[MlsEngine] Error processing message: {:?}", e);
                            Error::msg("[MlsEngine] Error processing message.")
                        })?;

                if let Sender::Member(leaf_index) = processed_message.sender() {
                    self.last_received.insert(*leaf_index, SystemTime::now());
                }

                match processed_message.into_content() {
                    ProcessedMessageContent::ApplicationMessage(payload) => {
                        let content_bytes = payload.into_bytes();
                        let preview = std::str::from_utf8(&content_bytes)
                            .map(|text| &text[..text.len().min(50)])
                            .unwrap_or("<non-UTF8 data>");
                        log::info!("[MlsEngine] Decrypted application message: {}", preview);
                        Ok(content_bytes)
                    }
                    ProcessedMessageContent::ExternalJoinProposalMessage(_)
                    | ProcessedMessageContent::StagedCommitMessage(_)
                    | ProcessedMessageContent::ProposalMessage(_) => Err(Error::msg(
                        "[MlsEngine] Expected ApplicationMessage from Network. Received Proposal or Commit.",
                    )),
                }
            }
            MlsMessageBodyIn::Welcome(_) => Err(Error::msg(
                "[MlsEngine] Expected ApplicationMessage from Network. Received Welcome.",
            )),
            MlsMessageBodyIn::GroupInfo(_) => Err(Error::msg(
                "[MlsEngine] Expected ApplicationMessage from Network. Received GroupInfo.",
            )),
            MlsMessageBodyIn::KeyPackage(_) => Err(Error::msg(
                "[MlsEngine] Expected ApplicationMessage from Network. Received KeyPackage.",
            )),
        }
    }

    fn process_outgoing_application_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mls_message = self
            .group
            .create_message(&self.provider, &self.signature_key, message)
            .expect("Error encrypting message.");

        let serialized_message = mls_message
            .tls_serialize_detached()
            .expect("Error serializing message.");
        Ok(serialized_message)
    }

    fn process_incoming_delivery_service_message(
        &mut self,
        mut buf: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
        log::debug!(
            "Processing incoming delivery service message. \n Group epoch before processing: {:?}",
            self.group.epoch()
        );

        let message_in =
            MlsMessageIn::tls_deserialize(&mut buf).expect("Error deserializing message");

        match message_in.extract() {
            MlsMessageBodyIn::PublicMessage(msg) => {
                let processed_message = self
                    .group
                    .process_message(&self.provider, msg)
                    .expect("Error processing message");

                // Validate sender's Credential
                match self.verify_credential(processed_message.credential().clone(), None) {
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("Error verifying sender's credential: {:?}", e);
                        return Err(e);
                    }
                }

                match processed_message.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                        log::warn!(
                            "Received PublicMessage containing StagedCommitMessage. Should be sent as PrivateMessage.",
                        );
                        match self.handle_incoming_commit(*staged_commit) {
                            Ok(_) => {}
                            Err(e) => {
                                log::error!("Error handling incoming commit: {:?}", e);
                            }
                        }
                    }
                    ProcessedMessageContent::ProposalMessage(proposal) => {
                        log::warn!(
                            "Received PublicMessage containing Proposal. Should be sent as PrivateMessage.",
                        );
                        let _ = self
                            .group
                            .store_pending_proposal(self.provider.storage(), *proposal.clone())
                            .context("Error storing proposal.");
                    }
                    ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                        return Err(Error::msg("No support for External Joins."))
                    }
                    ProcessedMessageContent::ApplicationMessage(_) => {
                        return Err(Error::msg(
                            "Expected Handshake Message from DS. Received ApplicationMessage.",
                        ))
                    }
                }
                Ok(None)
            }

            MlsMessageBodyIn::PrivateMessage(msg) => {
                let processed_message = self.group.process_message(&self.provider, msg)?;
                // Validate sender's Credential
                match self.verify_credential(processed_message.credential().clone(), None) {
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("Error verifying sender's credential: {:?}", e);
                        return Err(e);
                    }
                }

                if let Sender::Member(leaf_index) = processed_message.sender() {
                    self.last_received.insert(*leaf_index, SystemTime::now());
                }

                match processed_message.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                        match self.handle_incoming_commit(*staged_commit) {
                            Ok(_) => {}
                            Err(e) => {
                                log::error!("Error handling incoming commit: {:?}", e);
                            }
                        }
                    }
                    ProcessedMessageContent::ProposalMessage(proposal) => {
                        let _ = self
                            .group
                            .store_pending_proposal(self.provider.storage(), *proposal.clone())
                            .context("Error storing proposal.");
                    }
                    ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                        return Err(Error::msg("No support for External Joins."))
                    }
                    ProcessedMessageContent::ApplicationMessage(_) => {
                        return Err(Error::msg(
                            "Expected Handshake Message from DS. Received ApplicationMessage.",
                        ))
                    }
                }
                Ok(None)
            }
            MlsMessageBodyIn::Welcome(welcome) => match self.handle_incoming_welcome(welcome) {
                Ok(_) => Ok(None),
                Err(e) => Err(e),
            },
            MlsMessageBodyIn::GroupInfo(group_info) => {
                self.handle_incoming_group_info(group_info);
                Ok(None)
            }
            MlsMessageBodyIn::KeyPackage(key_package_in) => {
                self.handle_incoming_key_package(key_package_in);
                Ok(None)
            }
        }
    }

    fn handle_incoming_welcome(&mut self, welcome: Welcome) -> Result<(), Error> {
        log::debug!(
            "[MlsEngine] Node {:?} received Welcome message",
            self.config.node_id,
        );

        let staged_join =
            StagedWelcome::new_from_welcome(&self.provider, &self.group_join_config, welcome, None)
                .map_err(|e| {
                    log::error!("[MlsEngine] Error constructing staged join: {:?}", e);
                    e
                })?;

        let sender_index = staged_join.welcome_sender_index();

        let future_group = staged_join.into_group(&self.provider).map_err(|e| {
            log::error!(
                "[MlsEngine] Error joining group from StagedWelcome: {:?}",
                e
            );
            log::error!(
                "[MlsEngine] Error joining group from StagedWelcome: {:?}",
                e
            );
            Error::msg("Failed to convert staged join into group")
        })?;

        let sender = future_group.member(sender_index).ok_or_else(|| {
            log::error!("[MlsEngine] Sender not found in group.");
            Error::msg("Sender not found in group.")
        })?;

        self.verify_credential(sender.clone(), None).map_err(|e| {
            log::error!("[MlsEngine] Error verifying sender's credential: {:?}", e);
            e
        })?;

        if self.should_join(&future_group) {
            self.group = future_group;
            log::info!(
                "[MlsEngine] Joined group with ID: {:?}",
                self.group.group_id().as_slice()
            );
            self.last_received.clear(); // Flush old, as we join a new roup.
            self.last_received.insert(sender_index, SystemTime::now());
            self.refresh_key_package()?;

            return Ok(());
        }

        log::debug!("Received Welcome for a subgroup smaller than ours. Discarding.");
        Ok(())
    }

    fn handle_incoming_group_info(&mut self, _group_info: VerifiableGroupInfo) {
        log::warn!("Received GroupInfo message. No action taken. GroupInfo implies the use of external joins, which it not supported.");
    }

    fn handle_incoming_key_package(&mut self, key_package_in: KeyPackageIn) {
        // Check if KeyPackage is from someone within the group
        if self.credential_present_in_group(key_package_in.unverified_credential().credential) {
            log::debug!(
                "[MlsEngine] Received KeyPackage from someone in our group. Discarding it."
            );
            return;
        }

        // Verify credential and store key package
        log::info!("Received KeyPackage message. Verifying and  storing it.");
        match self.verify_credential(
            key_package_in.unverified_credential().credential,
            Some(&key_package_in.unverified_credential().signature_key),
        ) {
            Ok(_) => {
                log::info!("Credential verified successfully.");
                let key_package = key_package_in
                    .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                    .expect("Error validating KeyPackage");
                self.store_key_package(key_package.clone());
            }
            Err(e) => log::error!("Error verifying credential: {:?}", e),
        }
    }

    fn add_new_member(&mut self, key_package: KeyPackage) -> (Vec<u8>, Vec<u8>) {
        let (group_commit, welcome, _group_info) = self
            .group
            .add_members(&self.provider, &self.signature_key, &[key_package.clone()])
            .expect("Could not add members.");

        log::info!(
            "Added new member {:?} for group: {:?}",
            key_package.leaf_node().credential(),
            self.group.group_id()
        );

        // TODO: Fix error handling. This will panic if serialization fails.
        let group_commit_out = group_commit
            .tls_serialize_detached()
            .expect("Error serializing group commit");
        let welcome_out = welcome
            .tls_serialize_detached()
            .expect("Error serializing welcome");
        (group_commit_out, welcome_out)
    }

    fn add_pending_key_packages(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
        let mut key_packages = Vec::new();
        for (_key_ref, key_package) in self.pending_key_packages.iter() {
            key_packages.push(key_package.clone());
        }

        // Early return if there are no key packages to add
        if key_packages.is_empty() {
            return Ok(None);
        }

        let (group_commit, welcome, _group_info) =
            self.group
                .add_members(&self.provider, &self.signature_key, &key_packages)?;

        let group_commit_out = group_commit
            .tls_serialize_detached()
            .expect("Error serializing group commit");

        let welcome_out = welcome
            .tls_serialize_detached()
            .expect("Error serializing welcome");

        let _ = self.group.merge_pending_commit(&self.provider);
        self.pending_key_packages.clear();

        Ok(Some((group_commit_out, welcome_out)))
    }

    fn handle_incoming_commit(&mut self, commit: StagedCommit) -> Result<(), Error> {
        // Handle ADD operations: remove from pending_key_packages & verify new credentials
        for add in commit.add_proposals() {
            let key_package = add.add_proposal().key_package().clone();

            let key_ref: hash_ref::HashReference = key_package
                .hash_ref(self.provider.crypto())
                .expect("Error getting hash_ref from KeyPackage");

            if let Some(removed) = self.pending_key_packages.remove(&key_ref) {
                log::info!("Removed pending KeyPackage: {:?}", removed);
            }
        }

        for unverified_credential in commit.credentials_to_verify() {
            match self.verify_credential(unverified_credential.clone(), None) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("Error verifying credential: {:?}", e);
                    return Err(e);
                }
            }
        }

        // Handle REMOVE operations: remove LeafNodeIndex in pending_removals list (array)
        for remove in commit.remove_proposals() {
            let removed_index = remove.remove_proposal().removed();
            self.pending_removals.retain(|idx| *idx != removed_index);
        }

        let _ = self
            .group
            .merge_staged_commit(&self.provider, commit)
            .expect("Error handling staged commit.");
        Ok(())
    }

    fn remove_member(&mut self, leaf_node: LeafNodeIndex) -> (Vec<u8>, Option<Vec<u8>>) {
        let (group_commit, welcome_option, _group_info) = self
            .group
            .remove_members(&self.provider, &self.signature_key, &[leaf_node])
            .expect("Failed to remove member from group");

        let commit_bytes = group_commit
            .tls_serialize_detached()
            .expect("Failed to serialize group commit");

        let welcome_bytes = welcome_option.map(|welcome| {
            welcome
                .tls_serialize_detached()
                .expect("Failed to serialize Welcome message")
        });

        self.group
            .merge_pending_commit(&self.provider)
            .expect("Failed to merge pending commit");

        self.last_received.remove(&leaf_node);
        (commit_bytes, welcome_bytes)
    }

    fn update_self(&mut self) -> Result<(Vec<u8>, Option<Vec<u8>>), Error> {
        let pending = self.group.pending_commit();
        if pending.is_some() {
            log::error!(
                "Pending commit exists. Cannot update self. \n Pending commit: {:?}",
                pending
            );
            return Err(Error::msg("Pending commit exists. Cannot update self."));
        }

        match self.group.self_update(
            &self.provider,
            &self.signature_key,
            LeafNodeParameters::default(),
        ) {
            Ok((group_commit, welcome_option, _group_info)) => {
                let group_commit_out = group_commit
                    .tls_serialize_detached()
                    .expect("Error serializing group commit");
                let welcome_out = welcome_option // Only process welcome if it is Some
                    .map(|welcome| {
                        welcome
                            .tls_serialize_detached()
                            .expect("Error serializing welcome")
                    });
                let _ = self.group.merge_pending_commit(&self.provider);
                log::info!("Updated self in group with ID: {:?}", self.group.group_id());
                return Ok((group_commit_out, welcome_out));
            }
            Err(e) => {
                log::error!("Error updating self: {:?}", e);
                return Err(Error::msg("Error updating self"));
            }
        }
    }

    /// Helper function to retrieve the ratchet tree from the group.
    /// For obtaining index of nodes.  
    fn retrieve_ratchet_tree(&self) -> Vec<u8> {
        self.group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .expect("Error serializing ratchet tree")
    }

    fn add_new_member_from_bytes(&mut self, mut key_package_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let message_in = MlsMessageIn::tls_deserialize(&mut key_package_bytes)
            .expect("Error deserializing message");
        let key_package_in = match message_in.extract() {
            MlsMessageBodyIn::KeyPackage(kp) => kp,
            _ => panic!("Expected KeyPackage. Received: Something completely else!"),
        };
        let key_package = key_package_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .expect("Incoming KeyPackage could not be verified");
        self.add_new_member(key_package)
    }

    fn store_key_package(&mut self, key_package: KeyPackage) {
        let key_ref = key_package
            .hash_ref(self.provider.crypto())
            .expect("Error getting hash_ref from KeyPackage");
        self.pending_key_packages
            .insert(key_ref, key_package.clone());
    }

    fn verify_credential(
        &self,
        unverified_credential: Credential,
        attached_key: Option<&SignaturePublicKey>,
    ) -> Result<(), Error> {
        log::info!("[MlsEngine] Verifying incoming Credential!");
        match unverified_credential.credential_type() {
            CredentialType::Basic => {
                log::debug!("[MlsEngine] Received Basic credential. Continuing...");
                Ok(())
            }
            CredentialType::X509 => {
                log::warn!(
                    "[MlsEngine] Received X509 credential. This is NOT YET SUPPORTED. Verifying as Basic credential..."
                );
                Ok(())
            }
            CredentialType::Other(custom_type) => match custom_type {
                0xF000 => {
                    log::info!("[MlsEngine] Received Ed25519 credential. Validating...");
                    let credential = Ed25519credential::try_from(unverified_credential.clone());
                    if credential.is_err() {
                        log::error!(
                            "[MlsEngine] Error converting openmls::credentials::Credential to valkyrie-mls::Ed25519credential."
                        );
                        return Err(Error::msg(
                            "[MlsEngine] Error converting openmls::credentials::Credential to valkyrie-mls::Ed25519credential."
                        ));
                    }
                    let credential = credential.unwrap();
                    credential
                        .validate(attached_key)
                        .map_err(authentication::CredentialError::from)?;
                    Ok(())
                }
                _ => {
                    log::error!("[MlsEngine] Received unsupported credential type!");
                    Err(Error::msg(
                        "[MlsEngine] Received unsupported credential type!",
                    ))
                }
            },
        }
    }

    fn credential_present_in_group(&self, credential: Credential) -> bool {
        self.group.members().any(|m| m.credential == credential)
    }
}

pub trait MlsAutomaticRemoval {
    fn have_pending_removals(&self) -> bool;
    fn remove_pending(&mut self) -> Result<(Vec<u8>, Option<Vec<u8>>), Error>;
    fn schedule_removal(&mut self, node_ids: Vec<u32>);
    fn get_leaf_index_from_id(&self, group: &MlsGroup, id: u32) -> Result<LeafNodeIndex, Error>;
}

impl MlsAutomaticRemoval for MlsEngine {
    fn have_pending_removals(&self) -> bool {
        !self.pending_removals.is_empty()
    }
    fn remove_pending(&mut self) -> Result<(Vec<u8>, Option<Vec<u8>>), Error> {
        // See if we need to remove from anyone we haven't heard of

        let (group_commit, welcome_option, _group_info) = self
            .group
            .remove_members(&self.provider, &self.signature_key, &self.pending_removals)
            .map_err(|e| anyhow::anyhow!("[MlsAutomaticRemoval] remove_members() failed: {}", e))?;
        log::debug!(
            "[MlsAutomaticRemoval] Sucessfully removed {:?}",
            self.pending_removals
        );
        let commit_bytes = group_commit.tls_serialize_detached().map_err(|e| {
            anyhow::anyhow!("[MlsAutomaticRemoval] Failed to serialize commit: {}", e)
        })?;

        let welcome_bytes = match welcome_option {
            Some(welcome) => Some(welcome.tls_serialize_detached().map_err(|e| {
                anyhow::anyhow!("[MlsAutomaticRemoval] Failed to serialize Welcome: {}", e)
            })?),
            None => None,
        };

        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| {
                anyhow::anyhow!(
                    "[MlsAutomaticRemoval] Failed to merge pending commit: {}",
                    e
                )
            })?;

        self.pending_removals.clear();

        Ok((commit_bytes, welcome_bytes))
    }

    fn schedule_removal(&mut self, node_ids: Vec<u32>) {
        for target_id in node_ids {
            match self.get_leaf_index_from_id(self.group(), target_id) {
                Ok(index) => {
                    self.pending_removals.push(index);
                }
                Err(e) => {
                    log::error!(
                        "[MlsAutomaticRemoval] Could not resolve LeafNodeIndex for ID {}: {}",
                        target_id,
                        e
                    );
                }
            }
        }
    }

    fn get_leaf_index_from_id(
        &self,
        group: &MlsGroup,
        target_id: u32,
    ) -> Result<LeafNodeIndex, Error> {
        for member in group.members() {
            let id_match = match member.credential.credential_type() {
                CredentialType::Basic => {
                    let cred = BasicCredential::try_from(member.credential.clone())
                        .map_err(|_| anyhow::anyhow!("Failed to parse BasicCredential"))?;
                    let id_bytes = cred.identity();
                    u32::from_le_bytes(
                        id_bytes
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Basic identity is not 4 bytes"))?,
                    ) == target_id
                }

                CredentialType::X509 => {
                    // Not implemented — skip X509 members
                    false
                }
                CredentialType::Other(0xF000) => {
                    let cred = Ed25519credential::try_from(member.credential.clone())
                        .map_err(|_| anyhow::anyhow!("Failed to parse Ed25519Credential"))?;
                    cred.credential_data.identity == target_id
                }

                CredentialType::Other(_) => false,
            };

            if id_match {
                return Ok(member.index);
            }
        }

        Err(anyhow::anyhow!(
            "No group member matched node_id = {}",
            target_id
        ))
    }
}

pub trait MlsGroupDiscovery {
    fn get_group_state(&self) -> MlsSwarmState;
    fn contains_gcs(&self, group: &MlsGroup) -> bool;
    fn should_join(&self, group_to_join: &MlsGroup) -> bool;
    fn min_node_id(group: &MlsGroup) -> Option<u32>;
}

impl MlsGroupDiscovery for MlsEngine {
    fn get_group_state(&self) -> MlsSwarmState {
        // Could possibly cache this state to avoid checking every time, and then just update state whenever we see group changes.
        if self.contains_gcs(self.group()) {
            MlsSwarmState::MainGroup
        } else if self.group.members().count() == 1 {
            MlsSwarmState::Alone
        } else {
            MlsSwarmState::SubGroup
        }
    }

    fn contains_gcs(&self, group: &MlsGroup) -> bool {
        self.get_leaf_index_from_id(group, self.config.gcs_id)
            .is_ok()
    }

    fn should_join(&self, group_to_join: &MlsGroup) -> bool {
        if self.config.node_id == self.config.gcs_id || self.contains_gcs(self.group()) {
            log::debug!(
                "[MlsEngine] Received Welcome but current group contains GCS. Discarding Welcome."
            );
            return false;
        }

        // Check if future group contains GCS
        if self.contains_gcs(group_to_join) {
            log::debug!("[MlsEngine] Group from Welcome contained GCS ");
            return true;
        }

        // If we are alone, we join anyway
        let own_size = self.group.members().count();
        if own_size == 1 {
            return true;
        }

        // Check if future group is larger than current group
        let other_size = group_to_join.members().count() - 1; // They have added you
        if own_size < other_size {
            log::debug!("[MlsEngine] No GCS present. Group from Welcome  were larger than our own group. Joining.");
            return true;
        }

        // Check if groups are equal in size.
        // If so, find lowest id in group and join that.
        if own_size == other_size {
            let own_min = Self::min_node_id(self.group());
            let other_min = Self::min_node_id(group_to_join);

            if other_min < own_min {
                log::debug!("[MlsEngine] Groups equal in size. Other group had lower min node ID.");
                return true;
            } else {
                log::debug!("[MlsEngine] Groups equal in size. Our group has lower min node ID.");
                return false;
            }
        }

        log::debug!("[MlsEngine] Received Welcome for a subgroup smaller than ours. Discarding.");
        return false;
    }

    fn min_node_id(group: &MlsGroup) -> Option<u32> {
        group
            .members()
            .filter_map(|member| match member.credential.credential_type() {
                CredentialType::Basic => BasicCredential::try_from(member.credential.clone())
                    .ok()
                    .map(|cred| {
                        u32::from_le_bytes(
                            cred.identity()[..4]
                                .try_into()
                                .expect("Error converting Basic Identity to u32."),
                        )
                    }),
                CredentialType::Other(_) => Ed25519credential::try_from(member.credential.clone())
                    .ok()
                    .map(|cred| cred.credential_data.identity),
                _ => None,
            })
            .min()
    }
}

fn generate_credential_with_key(
    identity: u32,
    credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    match credential_type {
        CredentialType::Basic => {
            log::info!("Generating Basic credential.");
            let id = identity.to_le_bytes().to_vec();
            let credential = BasicCredential::new(id);
            let signature_keys = SignatureKeyPair::new(signature_algorithm)
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
        CredentialType::X509 => {
            log::info!("Generating X.509 credential.");
            log::error!("X.509 credential generation not implemented. Using Basic credential.");
            let id = identity.to_le_bytes().to_vec();
            let credential = BasicCredential::new(id);
            let signature_keys = SignatureKeyPair::new(signature_algorithm)
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
        CredentialType::Other(custom_type) => match custom_type {
            0xF000 => {
                log::info!("Generating Ed25519 credential.");
                let credential = Ed25519credential::from_file(identity)
                    .expect("Error loading Ed25519 credential from file.");
                let ed25519_key_pair = Ed25519SignatureKeyPair::from_file(identity)
                    .expect("Error loading Ed25519 signature key from file.");

                (
                    CredentialWithKey {
                        credential: credential.into(),
                        signature_key: ed25519_key_pair.signature_key_pair().public().into(),
                    },
                    ed25519_key_pair.signature_key_pair,
                )
            }
            _ => {
                log::error!("Unsupported credential type: {}", custom_type);
                panic!("Unsupported credential type.");
            }
        },
    }
}

fn generate_key_package(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    capabilities: Capabilities,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
}

fn generate_group_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .padding_size(0)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            5,    // out_of_order_tolerance
            1000, // maximum_forward_distance
        ))
        .use_ratchet_tree_extension(true)
        .build()
}

fn generate_group_create_config(capabilities: Capabilities) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .padding_size(0)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            5,    // out_of_order_tolerance
            1000, // maximum_forward_distance
        ))
        .capabilities(capabilities)
        .use_ratchet_tree_extension(true)
        .build()
}

fn capabilities(credential_type: &str) -> Capabilities {
    match credential_type {
        "basic" => Capabilities::new(
            None,                           // Defaults to the group's protocol version
            None,                           // Defaults to the group's ciphersuite
            None,                           // Defaults to all basic extension types
            None,                           // Defaults to all basic proposal types
            Some(&[CredentialType::Basic]), // Basic credential type
        ),
        "x509" => Capabilities::new(
            None,                           // Defaults to the group's protocol version
            None,                           // Defaults to the group's ciphersuite
            None,                           // Defaults to all basic extension types
            None,                           // Defaults to all basic proposal types
            Some(&[CredentialType::Basic]), // X.509 credential type not supported yet
        ),
        "ed25519" => Capabilities::new(
            None,                                   // Defaults to the group's protocol version
            None,                                   // Defaults to the group's ciphersuite
            None,                                   // Defaults to all basic extension types
            None,                                   // Defaults to all basic proposal types
            Some(&[CredentialType::Other(0xF000)]), // Ed25519 credential type
        ),
        _ => panic!("Unsupported credential type: {}", credential_type),
    }
}
