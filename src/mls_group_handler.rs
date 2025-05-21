use crate::authentication::ed25519::Ed25519SignatureKeyPair;
use crate::authentication::{self, Ed25519credential};
use crate::config::MlsConfig;
use anyhow::{Context, Error, Result};
use openmls::group::MlsGroup;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::SystemTime;
use tls_codec::{Deserialize, Serialize};

pub enum MlsSwarmState {
    Alone,
    SubGroup,
    MainGroup,
}

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
    totem_group: HashSet<u32>,
}

pub trait MlsSwarmLogic {
    fn add_new_member(&mut self, key_package: KeyPackage) -> Result<(Vec<u8>, Vec<u8>)>;
    fn add_new_member_from_bytes(&mut self, key_package_bytes: &[u8])
        -> Result<(Vec<u8>, Vec<u8>)>;
    fn add_pending_key_packages(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error>;

    fn remove_member(&mut self, leaf_node: LeafNodeIndex) -> Result<(Vec<u8>, Option<Vec<u8>>)>;

    fn update_self(&mut self) -> Result<(Vec<u8>, Option<Vec<u8>>), Error>;

    fn store_key_package(&mut self, key_package: KeyPackage);

    fn verify_credential(
        &self,
        unverified_credential: Credential,
        attached_key: Option<&SignaturePublicKey>,
    ) -> Result<(), Error>;

    fn credential_present_in_group(&self, credential: Credential) -> bool;

    fn process_incoming_network_message(&mut self, message: &[u8]) -> Result<Vec<u8>>;
    fn process_incoming_delivery_service_message(
        &mut self,
        message: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>>;
    fn process_protocol_message<M>(&mut self, msg: M) -> Result<Option<(Vec<u8>, Vec<u8>)>>
    where
        M: Into<ProtocolMessage> + std::fmt::Debug;
    fn process_outgoing_application_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>;

    fn handle_incoming_welcome(&mut self, welcome: Welcome) -> Result<()>;
    fn handle_incoming_key_package(&mut self, key_package_in: KeyPackageIn);
    fn handle_incoming_commit(&mut self, commit: StagedCommit) -> Result<(), Error>;
}

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

        // Initialize totem group
        let mut totem_group = HashSet::new();
        totem_group.insert(config.node_id);

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
            totem_group, // We always start with ourself in a group of 1
        }
    }

    pub fn load_group(&mut self, group_id: Vec<u8>) -> Option<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(&group_id))
            .expect("Error loading group")
    }

    pub fn get_key_package(&mut self) -> Result<Vec<u8>> {
        let key_package = MlsMessageOut::from(self.key_package.key_package().clone());
        key_package
            .tls_serialize_detached()
            .context("Error serializing key package")
    }

    pub fn refresh_key_package(&mut self) -> Result<()> {
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

    pub fn update_totem_group(&mut self, group: Vec<u32>) {
        self.totem_group = group.into_iter().collect(); // Update group
    }
}

impl MlsSwarmLogic for MlsEngine {
    fn process_incoming_network_message(&mut self, buf: &[u8]) -> Result<Vec<u8>> {
        let message_in = MlsMessageIn::tls_deserialize(&mut &*buf)
            .context("Failed to deserialize incoming MLS message")?;

        let protocol_msg = ProtocolMessage::try_from(message_in)
            .context("Failed to convert to ProtocolMessage")?;

        let result = self.group.process_message(&self.provider, protocol_msg);

        match result {
            Ok(processed) => {
                let sender = processed.sender().clone(); // get sender first

                match processed.into_content() {
                    ProcessedMessageContent::ApplicationMessage(app_msg) => {
                        log::debug!("[MLS] Received AppData message from sender {:?}", sender);
                        Ok(app_msg.into_bytes())
                    }
                    other => Err(anyhow::anyhow!(
                        "Expected ApplicationMessage, got: {:?}",
                        other
                    )),
                }
            }

            Err(e) => Err(anyhow::anyhow!(e).context("Failed to process MLS message")),
        }
    }

    fn process_outgoing_application_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mls_message = self
            .group
            .create_message(&self.provider, &self.signature_key, message)
            .context("Error encrypting message.")?;

        let serialized_message = mls_message
            .tls_serialize_detached()
            .context("Error serializing message.")?;
        Ok(serialized_message)
    }

    fn process_incoming_delivery_service_message(
        &mut self,
        buf: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let message_in = MlsMessageIn::tls_deserialize(&mut &*buf)
            .context("Failed to deserialize delivery service MLS message")?;

        match message_in.extract() {
            MlsMessageBodyIn::Welcome(welcome) => {
                self.handle_incoming_welcome(welcome)
                    .context("Failed to process Welcome message")?;
                Ok(None)
            }

            MlsMessageBodyIn::KeyPackage(kp_in) => {
                self.handle_incoming_key_package(kp_in);
                Ok(None)
            }

            MlsMessageBodyIn::GroupInfo(group_info) => Err(anyhow::anyhow!(
                "Received unsupported GroupInfo message: {:?}. External joins are not supported.",
                group_info
            )),

            MlsMessageBodyIn::PrivateMessage(msg) => self.process_protocol_message(msg),

            MlsMessageBodyIn::PublicMessage(msg) => self.process_protocol_message(msg),
        }
    }

    fn handle_incoming_welcome(&mut self, welcome: Welcome) -> Result<()> {
        let staged_join =
            StagedWelcome::new_from_welcome(&self.provider, &self.group_join_config, welcome, None)
                .context("Error constructing staged join from Welocme")?;

        let sender_index = staged_join.welcome_sender_index();

        let future_group = staged_join
            .into_group(&self.provider)
            .context("Error constructing group from staged_join")?;

        let sender = future_group
            .member(sender_index)
            .ok_or_else(|| Error::msg("Sender not found in group."))?;

        self.verify_credential(sender.clone(), None)
            .context("Error verifying credential from Welcome message")?;

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

        log::debug!("[MlsEngine] Welcome message discarded: subgroup does not satisfy join policy");
        Ok(())
    }

    fn handle_incoming_key_package(&mut self, key_package_in: KeyPackageIn) {
        let id = id_from_credential(&key_package_in.unverified_credential().credential);
        log::debug!(
            "[MlsEngine] Received KeyPackage for credential ID {:?}.",
            id
        );
        // Check if KeyPackage is from someone within the group
        if self.credential_present_in_group(key_package_in.unverified_credential().credential) {
            log::debug!("[MlsEngine] KeyPackage was from someone in our group. Discarding it.");
            return;
        }

        // Verify credential and store key package
        if let Err(e) = self.verify_credential(
            key_package_in.unverified_credential().credential,
            Some(&key_package_in.unverified_credential().signature_key),
        ) {
            log::warn!("[MlsEngine] Could not verify KeyPackage. Error: {}", e);
            return;
        }
        let key_package =
            match key_package_in.validate(self.provider.crypto(), ProtocolVersion::Mls10) {
                Ok(kp) => kp,
                Err(e) => {
                    log::error!("[MlsEngine] Error validating KeyPackage: {}", e);
                    return;
                }
            };

        self.store_key_package(key_package.clone());
        log::debug!("[MlsEngine] Credential verified and validated successfully.");
    }

    fn process_protocol_message<M>(&mut self, msg: M) -> Result<Option<(Vec<u8>, Vec<u8>)>>
    where
        M: Into<ProtocolMessage> + std::fmt::Debug,
    {
        let protocol_msg = msg.into();

        let processed = self
            .group
            .process_message(&self.provider, protocol_msg)
            .context("Failed to process ProtocolMessage")?;

        let sender = processed.sender().clone();

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                log::debug!("[MLS] Received staged commit from {:?}, merging.", sender);
                self.handle_incoming_commit(*commit)
                    .context("Failed to handle incoming commit")?;
                Ok(None)
            }

            ProcessedMessageContent::ProposalMessage(_) => {
                log::debug!("[MLS] Received proposal from {:?}.", sender);
                Ok(None)
            }

            other => Err(anyhow::anyhow!(
                "Unexpected message type in delivery service: {:?}",
                other
            )),
        }
    }

    fn add_pending_key_packages(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        if self.pending_key_packages.is_empty() {
            log::debug!("[MlsEngine] No pending key packages to add.");
            return Ok(None);
        }

        // If we can't add pending key packages, clear the list. Write to log.
        if !self.can_add() {
            log::debug!(
                "[MlsEngine] Group policy prevents adding pending key packages. Clearing list."
            );
            self.pending_key_packages.clear();
            return Ok(None);
        }

        let key_packages: Vec<KeyPackage> = self.pending_key_packages.values().cloned().collect();

        let (group_commit, welcome, _group_info) =
            self.group
                .add_members(&self.provider, &self.signature_key, &key_packages)?;

        let group_commit_out = group_commit
            .tls_serialize_detached()
            .context("Error serializing group commit")?;

        let welcome_out = welcome
            .tls_serialize_detached()
            .context("Error serializing welcome")?;

        self.group
            .merge_pending_commit(&self.provider)
            .context("Failed to merge pending commit")?;

        self.pending_key_packages.clear();

        log::info!(
            "[MLS] Added {} pending key package(s) to group {:?}",
            key_packages.len(),
            self.group.group_id()
        );

        Ok(Some((group_commit_out, welcome_out)))
    }

    fn handle_incoming_commit(&mut self, commit: StagedCommit) -> Result<()> {
        // Handle ADD operations: remove from pending_key_packages & verify new credentials
        println!("!!COMMIT!!");
        for add in commit.add_proposals() {
            println!("FOUND ADD IN COMMIT!!");
            let key_package = add.add_proposal().key_package().clone();

            let key_ref: hash_ref::HashReference = key_package
                .hash_ref(self.provider.crypto())
                .context("Error getting hash_ref from KeyPackage")?;
            println!("Key_ref: {:?}", key_ref);
            if let Some(removed) = self.pending_key_packages.remove(&key_ref) {
                log::info!("Removed pending KeyPackage: {:?}", removed);
            }
        }

        // Handle REMOVE operations: remove LeafNodeIndex in pending_removals list (array)
        for remove in commit.remove_proposals() {
            let removed_index = remove.remove_proposal().removed();
            self.pending_removals.retain(|idx| *idx != removed_index);
        }

        self.group
            .merge_staged_commit(&self.provider, commit)
            .context("Error handling staged commit.")?;
        Ok(())
    }

    fn remove_member(&mut self, target: LeafNodeIndex) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        let (commit, welcome, _group_info) = self
            .group
            .remove_members(&self.provider, &self.signature_key, &[target])
            .with_context(|| format!("Failed to remove member at index {:?}", target))?;

        let commit_out = commit
            .tls_serialize_detached()
            .context("Failed to serialize removal commit")?;

        // Should not result in a Welcome
        let welcome_out = match welcome {
            Some(welcome) => Some(
                welcome
                    .tls_serialize_detached()
                    .context("Failed to serialize removal welcome")?,
            ),
            None => None,
        };

        self.group
            .merge_pending_commit(&self.provider)
            .context("Failed to merge pending removal commit")?;

        log::info!(
            "[MLS] Removed member {:?} from group {:?}",
            target,
            self.group.group_id()
        );

        Ok((commit_out, welcome_out))
    }

    fn update_self(&mut self) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        let (commit, welcome, _group_info) = self
            .group
            .self_update(
                &self.provider,
                &self.signature_key,
                LeafNodeParameters::default(),
            )
            .context("Failed to perform self-update")?;

        let commit_out = commit
            .tls_serialize_detached()
            .context("Failed to serialize self-update commit")?;

        let welcome_out = match welcome {
            Some(welcome) => Some(
                welcome
                    .tls_serialize_detached()
                    .context("Failed to serialize welcome (self-update)")?,
            ),
            None => None,
        };

        self.group
            .merge_pending_commit(&self.provider)
            .context("Failed to merge self-update commit")?;

        log::info!(
            "[MLS] Successfully performed self-update for node {:?} in group {:?}",
            self.config.node_id,
            self.group.group_id()
        );

        Ok((commit_out, welcome_out))
    }

    // Only used for testing purposes, when a command is received.
    fn add_new_member_from_bytes(
        &mut self,
        key_package_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let message_in = MlsMessageIn::tls_deserialize(&mut &*key_package_bytes)
            .context("Failed to deserialize incoming key package bytes")?;

        let key_package_in = match message_in.extract() {
            MlsMessageBodyIn::KeyPackage(kp) => kp,
            other => {
                return Err(anyhow::anyhow!(
                    "Expected KeyPackage, but received different message type: {:?}",
                    other
                ));
            }
        };

        let key_package = key_package_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .context("Failed to validate key package")?;

        self.add_new_member(key_package)
    }

    fn add_new_member(&mut self, key_package: KeyPackage) -> Result<(Vec<u8>, Vec<u8>)> {
        let (group_commit, welcome, _group_info) = self
            .group
            .add_members(&self.provider, &self.signature_key, &[key_package.clone()])
            .context(format!(
                "Could not add member for KeyPackage with credential: {:?}",
                key_package.leaf_node().credential()
            ))?;

        let group_commit_out = group_commit
            .tls_serialize_detached()
            .context("Error serializing group commit")?;
        let welcome_out = welcome
            .tls_serialize_detached()
            .context("Error serializing welcome")?;

        self.group.merge_pending_commit(&self.provider)?;

        log::info!(
            "Added new member {:?} for group: {:?}",
            key_package.leaf_node().credential(),
            self.group.group_id()
        );
        Ok((group_commit_out, welcome_out))
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

/// This trait ensures that we remove nodes when they disappear from our corosync group.
impl MlsAutomaticRemoval for MlsEngine {
    fn have_pending_removals(&self) -> bool {
        !self.pending_removals.is_empty()
    }

    // Removes nodes scheduled for removal. Creates a commit over all removals.
    fn remove_pending(&mut self) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        let (commit, welcome, _group_info) = self
            .group
            .remove_members(&self.provider, &self.signature_key, &self.pending_removals)
            .context("Failed to remove pending members")?;

        let commit_out = commit
            .tls_serialize_detached()
            .context("Failed to serialize commit for removal")?;

        let welcome_out = match welcome {
            Some(welcome) => Some(
                welcome
                    .tls_serialize_detached()
                    .context("Failed to serialize welcome for removal")?,
            ),
            None => None,
        };

        self.group
            .merge_pending_commit(&self.provider)
            .context("Failed to merge commit for removal")?;

        log::info!(
            "[MLS] Removed {} member(s) from group {:?}",
            self.pending_removals.len(),
            self.group.group_id()
        );
        self.pending_removals.clear();

        Ok((commit_out, welcome_out))
    }

    // Corosync provides us with a list of IDs (u32) that have left the corosync group.
    // This list is translated into LeafNodeIndexes for us to remove.
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
    fn get_mls_group_state(&self) -> MlsSwarmState;
    fn mls_group_contains_gcs(&self, group: &MlsGroup) -> bool;
    fn should_join(&self, group_to_join: &MlsGroup) -> bool;
    fn min_node_id(group: &MlsGroup) -> Option<u32>;
    fn can_add(&self) -> bool;
    fn id_from_key_package(&self, kp: KeyPackage) -> Option<u32>;
}

impl MlsGroupDiscovery for MlsEngine {
    fn get_mls_group_state(&self) -> MlsSwarmState {
        // Could possibly cache this state to avoid checking every time, and then just update state whenever we see group changes.
        if self.mls_group_contains_gcs(self.group()) {
            MlsSwarmState::MainGroup
        } else if self.group.members().count() == 1 {
            MlsSwarmState::Alone
        } else {
            MlsSwarmState::SubGroup
        }
    }

    fn mls_group_contains_gcs(&self, group: &MlsGroup) -> bool {
        self.config.node_id == self.config.gcs_id
            || self
                .get_leaf_index_from_id(group, self.config.gcs_id)
                .is_ok()
    }

    fn should_join(&self, group_to_join: &MlsGroup) -> bool {
        match self.get_mls_group_state() {
            MlsSwarmState::MainGroup => {
                log::debug!(
                    "[MlsEngine] Received Welcome for group {:?} but current group contains GCS. Discarding Welcome.", 
                    group_to_join.group_id().as_slice()
                );
                return false;
            }
            MlsSwarmState::Alone | MlsSwarmState::SubGroup => {
                // Check if incoming group contains GCS
                if self.mls_group_contains_gcs(group_to_join) {
                    log::debug!("[MlsEngine] Group from Welcome contained GCS ");
                    return true;
                }

                // No GCS present. Check if we are a majority group
                if self.group().members().count() > self.totem_group.len() / 2 {
                    log::debug!("[MlsEngine] No GCS present. Current is a majority group. Discarding Welcome.");
                    return false;
                }

                //
                if group_to_join.members().count() > self.totem_group.len() / 2 {
                    log::debug!("[MlsEngine] No GCS present. Group from Welcome were a majority group. Joining.");
                    return true;
                }

                // Accept only if sender MIN NODE ID < your MIN NODE ID
                return Self::min_node_id(group_to_join).unwrap_or(u32::MAX)
                    < Self::min_node_id(self.group()).unwrap_or(u32::MAX);
            }
        }
    }

    fn min_node_id(group: &MlsGroup) -> Option<u32> {
        group
            .members()
            .filter_map(|member| match member.credential.credential_type() {
                CredentialType::Basic => BasicCredential::try_from(member.credential.clone())
                    .ok()
                    .and_then(|cred| {
                        let bytes: [u8; 4] = cred.identity().get(..4)?.try_into().ok()?;
                        Some(u32::from_le_bytes(bytes))
                    }),
                CredentialType::Other(_) => Ed25519credential::try_from(member.credential.clone())
                    .ok()
                    .map(|cred| cred.credential_data.identity),
                _ => None,
            })
            .min()
    }

    fn can_add(&self) -> bool {
        match self.get_mls_group_state() {
            MlsSwarmState::MainGroup => true,
            MlsSwarmState::Alone | MlsSwarmState::SubGroup => {
                // Check if a GCS is present in the Totem Group
                if self.totem_group.contains(&self.config.gcs_id) {
                    return false;
                }

                // Check if we are a majority group
                if self.group().members().count() > self.totem_group.len() / 2 {
                    return true;
                }

                match Self::min_node_id(self.group()) {
                    Some(id) => {
                        let lowest_id_in_mls_group = id;

                        if self.pending_key_packages.values().any(|kp| {
                            self.id_from_key_package(kp.clone()) < Some(lowest_id_in_mls_group)
                        }) {
                            // If any of the pending key packages have a lower ID than the lowest in our group
                            // that implies we should join that group.
                            return false;
                        }
                        // ...else we should add the received key packages
                        return true;
                    }
                    None => {
                        log::error!("[MlsEngine] Could not resolve MINIMUM GROUP ID. Not allowing to add to thius group.");
                        false
                    }
                }
            }
        }
    }

    fn id_from_key_package(&self, kp: KeyPackage) -> Option<u32> {
        match kp.leaf_node().credential().credential_type() {
            CredentialType::Basic => BasicCredential::try_from(kp.leaf_node().credential().clone())
                .ok()
                .and_then(|cred| {
                    let bytes: [u8; 4] = cred.identity().get(..4)?.try_into().ok()?;
                    Some(u32::from_le_bytes(bytes))
                }),
            CredentialType::Other(_) => {
                Ed25519credential::try_from(kp.leaf_node().credential().clone())
                    .ok()
                    .map(|cred| cred.credential_data.identity)
            }
            _ => None,
        }
    }
}

pub trait MlsGroupReset {
    fn reset_group(&mut self);
    fn extract_epoch_from_private_message(message: &PrivateMessageIn) -> Option<u64>;
}

impl MlsGroupReset for MlsEngine {
    fn reset_group(&mut self) {
        log::debug!("[MlsEngine] Reseting MLS group.");
        let (_credential_type, capabilities) =
            match self.config.credential_type.to_lowercase().as_str() {
                "basic" => (CredentialType::Basic, capabilities("basic")),
                "x509" => (CredentialType::X509, capabilities("x509")),
                "ed25519" => (CredentialType::Other(0xF000), capabilities("ed25519")),
                other => panic!(
                    "Cannot initialize Mls Component. Unsupported credential type: {}",
                    other
                ),
            };
        match MlsGroup::new(
            &self.provider,
            &self.signature_key,
            &generate_group_create_config(capabilities.clone()),
            self.credential_with_key.clone(),
        ) {
            Ok(group) => {
                self.group = group;
            }
            Err(e) => {
                log::error!("[MlsEngine] Failed to reset group with new state: {}", e);
            }
        }
    }

    fn extract_epoch_from_private_message(message: &PrivateMessageIn) -> Option<u64> {
        let serialized = message.tls_serialize_detached().ok()?;
        let mut cursor = serialized.as_slice();

        // Parse the GroupId length prefix (2 bytes, u16)
        let group_id_len = u16::tls_deserialize(&mut cursor).ok()? as usize;

        // Skip the GroupId bytes
        if cursor.len() < group_id_len {
            return None;
        }
        let (_group_id_bytes, rest) = cursor.split_at(group_id_len);
        cursor = rest;

        // Now the next 8 bytes are the epoch (u64)
        let epoch = u64::tls_deserialize(&mut cursor).ok()?;

        Some(epoch)
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
        .max_past_epochs(1) //Increase max past epochs stored
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
        .max_past_epochs(1) //Increase max past epochs stored
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

fn id_from_credential(credential: &Credential) -> Option<u32> {
    match credential.credential_type() {
        CredentialType::Basic => {
            let cred = BasicCredential::try_from(credential.clone()).ok()?;
            let bytes: [u8; 4] = cred.identity().get(..4)?.try_into().ok()?;
            Some(u32::from_le_bytes(bytes))
        }

        CredentialType::Other(_) => {
            let cred = Ed25519credential::try_from(credential.clone()).ok()?;
            Some(cred.credential_data.identity)
        }

        _ => {
            log::warn!(
                "[MlsEngine] Unknown credential type: {:?}. Skipping identity extraction.",
                credential.credential_type()
            );
            None
        }
    }
}

#[derive(Debug)]
pub enum MlsEngineError {
    TlsSerializationError,
    ProposalOverApplicationChannel,
    CommitOverApplicationChannel,
    WelcomeOverApplicationChannel,
    GroupInfoOverApplicationChannel,
    KeyPackageOverApplicationChannel,
    UnauthorizedExternalApplicationMessage,
    ValidationError(ValidationError),
    WrongGroupId,
    FutureEpoch,
    UnknownMember,
    ProcessMessageError,
    TrailingEpoch,
    CredentialVerificationError,
    NotSupported,
    ApplicationMessageOverPublicChannel,
    GeneralError(Error),
}

impl From<ProcessMessageError> for MlsEngineError {
    fn from(error: ProcessMessageError) -> Self {
        match error {
            ProcessMessageError::UnauthorizedExternalApplicationMessage => {
                Self::ProposalOverApplicationChannel
            }
            ProcessMessageError::UnsupportedProposalType => Self::ProposalOverApplicationChannel,
            ProcessMessageError::ValidationError(e) => match e {
                ValidationError::WrongGroupId => Self::WrongGroupId,
                ValidationError::WrongEpoch => Self::FutureEpoch,
                ValidationError::UnknownMember => Self::UnknownMember,
                ValidationError::UnableToDecrypt(_) => Self::TrailingEpoch,
                _ => Self::ValidationError(e),
            },
            _ => Self::ProcessMessageError,
        }
    }
}

impl fmt::Display for MlsEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            MlsEngineError::TlsSerializationError => {
                                        "Error serializing or deserializing using tls_codec."
                                    }
            MlsEngineError::ProposalOverApplicationChannel => {
                                        "Proposals are not allowed to be sent over the application channel."
                                    }
            MlsEngineError::CommitOverApplicationChannel => {
                                        "Commits are not allowed to be sent over the application channel."
                                    }
            MlsEngineError::WelcomeOverApplicationChannel => {
                                        "Welcome messages are not allowed to be sent over the application channel."
                                    }
            MlsEngineError::GroupInfoOverApplicationChannel => {
                                        "GroupInfo messages are not allowed to be sent over the application channel."
                                    }
            MlsEngineError::KeyPackageOverApplicationChannel => {
                                        "KeyPackage messages are not allowed to be sent over the application channel."
                                    }
            MlsEngineError::UnauthorizedExternalApplicationMessage => {
                                        "External application messages are not permitted without proper authorization."
                                    }
            MlsEngineError::ValidationError(e) => {
                                        &e.to_string()
                                    }
            MlsEngineError::WrongGroupId => "The message was intended for a different group ID.",
            MlsEngineError::FutureEpoch => {
                                        "The message was created for a different, future epoch than the current group epoch."
                                    }
            MlsEngineError::UnknownMember => {
                                        "The message originated from an unknown member not recognized in the current group."
                                    }
            MlsEngineError::ProcessMessageError => {
                                        "An unexpected error occurred while processing the MLS message."
                                    }
            MlsEngineError::TrailingEpoch => {"The message was created for a different, trailing epoch than the current group epoch."},
            MlsEngineError::CredentialVerificationError => {"Error verifying the credential."},
            MlsEngineError::NotSupported => "Functionality is currently not supported.",
            MlsEngineError::ApplicationMessageOverPublicChannel => "Cannot send application messages ov DS.",
            MlsEngineError::GeneralError(error) => &error.to_string(),
        };
        write!(f, "{}", description)
    }
}

impl std::error::Error for MlsEngineError {}
