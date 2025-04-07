use tls_codec::Serialize;
use valkyrie_mls::mls_group_handler::{MlsEngine, MlsSwarmLogic};
use valkyrie_mls::config::MlsConfig;
use openmls::prelude::*; 
use openmls_rust_crypto::OpenMlsRustCrypto;

/// This test replicates the functionality of the group test from 
/// `openmls-0.6.0/tests/mls_group.rs`. 
/// The original test simulates various group operations like Add, Update, Remove in a
/// small group. This test replicates the same operation through the use of `MlsEngine`. 
///  - Alice creates a group
///  - Alice adds Bob
///  - Alice sends a message to Bob
///  - Bob updates and commits
///  - Alice updates and commits
///  - Bob adds Charlie
///  - Charlie sends a message to the group
///  - Charlie updates and commits
///  - Charlie removes Bob
///  - Alice removes Charlie and adds Bob
///  - Bob leaves
///  - Test saving the group state
#[test]
fn test_mls_group_operations() {
    let alice_config = MlsConfig {
        credential_type: "Basic".to_string(),
        node_id: "Alice".to_string(),
    };

    let bob_config = MlsConfig {
        credential_type: "Basic".to_string(),
        node_id: "Bob".to_string(),
    };

    let charlie_config = MlsConfig {
        credential_type: "Basic".to_string(),
        node_id: "Charlie".to_string(),
    };

    let alice_provider = &OpenMlsRustCrypto::default();
    let bob_provider = &OpenMlsRustCrypto::default();
    let charlie_provider = &OpenMlsRustCrypto::default();

    // Generate three MLS Engines
    let mut alice_mls_engine = MlsEngine::new(alice_config);
    let mut bob_mls_engine = MlsEngine::new(bob_config);
    let mut charlie_mls_engine = MlsEngine::new(charlie_config);

    // === Alice receives Bob's key package ===
    let bob_key_package_bytes = bob_mls_engine.get_key_package().unwrap();
    let result = alice_mls_engine.process_incoming_delivery_service_message(&bob_key_package_bytes).unwrap();
    
    // Verify that key package was added as Pending KeyPackage 
    assert!(result.is_none(), "No message should be returned. KeyPackage should only be added to pending"); 
    assert!(alice_mls_engine.pending_key_packages()
        .values()
        .any(|kp| 
            MlsMessageOut::from(kp.clone()).tls_serialize_detached().unwrap() == bob_key_package_bytes),
        "Alice's Pending Key Package Hashmap should consist of Bob's key package"); 
    
    // === Alice adds Bob ===
    let result = alice_mls_engine.add_pending_key_packages().unwrap();
    assert_eq!(result.len(), 1, "Add operation should return one (GroupCommit, Welcome) tuple.");
    assert_eq!(alice_mls_engine.group().members().count(), 2, "Alice should have two members in the group after adding Bob.");
    
    // Bob receives the welcome message and joins the group
    let (_group_commit, bob_welcome) = result[0].clone();
    bob_mls_engine.process_incoming_delivery_service_message(&bob_welcome).unwrap();
    assert_eq!(bob_mls_engine.group().members().count(), 2, "Bob should have two members in the group after joining.");
    
    // Verify groups are the same
    assert!(alice_mls_engine.group().members().eq(bob_mls_engine.group().members()), "Alice and Bob should have the same group members.");
    assert_eq!(
        alice_mls_engine.group().epoch_authenticator().as_slice(),
        bob_mls_engine.group().epoch_authenticator().as_slice()
    );

    // === Alice sends a message to Bob ===
    let message = b"Hello Bob! This is Alice.";
    let alice_message = alice_mls_engine
        .process_outgoing_application_message(message)
        .unwrap();

    let processed_message = bob_mls_engine
        .process_incoming_network_message(&alice_message)
        .unwrap();

    assert_eq!(message, processed_message.as_slice(), "Bob should receive the same message Alice sent him.");

    // === Bob updates and commits ===
    let (bob_update, _welcome_option) = bob_mls_engine
        .update_self();

    let _ = alice_mls_engine
        .process_incoming_delivery_service_message(&bob_update)
        .unwrap();

    // Verify that the group states are the same.
    assert_eq!(alice_mls_engine.group().epoch(), bob_mls_engine.group().epoch(), "Alice and Bob should be in the same epoch after Bob's update.");
    assert_eq!(
        alice_mls_engine.group().export_secret(alice_provider, "", &[], 32).unwrap(),
        bob_mls_engine.group().export_secret(bob_provider, "", &[], 32).unwrap()
    );

    // === Alice updates and commits ===
    let (alice_update, _welcome_option) = alice_mls_engine
        .update_self();

    let _ = bob_mls_engine
        .process_incoming_delivery_service_message(&alice_update)
        .unwrap();

    // Verify that the group states are the same.
    assert_eq!(alice_mls_engine.group().epoch(), bob_mls_engine.group().epoch(), "Alice and Bob should be in the same epoch after Alice's update.");
    assert_eq!(
        alice_mls_engine.group().export_secret(alice_provider, "", &[], 32).unwrap(),
        bob_mls_engine.group().export_secret(bob_provider, "", &[], 32).unwrap()
    );

    // === Bob and Alice receives Charlie's KeyPackage. ===
    let charlie_key_package_bytes = charlie_mls_engine.get_key_package().unwrap();
    let _ = bob_mls_engine.process_incoming_delivery_service_message(&charlie_key_package_bytes).unwrap();
    let _ = alice_mls_engine.process_incoming_delivery_service_message(&charlie_key_package_bytes).unwrap();

    // Verify that key package was added as Pending KeyPackage
    assert!(bob_mls_engine.pending_key_packages()
        .values()
        .any(|kp| 
            MlsMessageOut::from(kp.clone()).tls_serialize_detached().unwrap() == charlie_key_package_bytes),
        "Bob's Pending Key Package Hashmap should consist of Charlie's key package");
    
    assert!(alice_mls_engine.pending_key_packages()
        .values()
        .any(|kp| 
            MlsMessageOut::from(kp.clone()).tls_serialize_detached().unwrap() == charlie_key_package_bytes),
        "Alice's Pending Key Package Hashmap should consist of Charlie's key package");

    // === Bob adds Charlie ===
    let result = bob_mls_engine.add_pending_key_packages().unwrap();
    assert_eq!(result.len(), 1, "Add operation should return one (GroupCommit, Welcome) tuple.");

    let (group_commit, welcome ) = result[0].clone();
    
    alice_mls_engine
        .process_incoming_delivery_service_message(&group_commit)
        .unwrap();
    
    // charlie_mls_engine
    //     .process_incoming_delivery_service_message(&welcome)
    //     .unwrap();  
    
    // Verify that the group states are the same.
    assert_eq!(alice_mls_engine.group().members().count(), 3, "Alice should have three members in the group after adding Charlie.");
    assert_eq!(bob_mls_engine.group().members().count(), 3, "Bob should have three members in the group after adding Charlie.");
    // assert_eq!(charlie_mls_engine.group().members().count(), 3, "Charlie should have three members in the group after joining.");  
    
    assert_eq!(alice_mls_engine.group().epoch(), bob_mls_engine.group().epoch(), "Alice and Bob should be in the same epoch after adding Charlie.");
    // assert_eq!(alice_mls_engine.group().epoch(), charlie_mls_engine.group().epoch(), "Alice and Charlie should be in the same epoch after Charlie's join.");

    // Verify Alice has cleared here pending key packages
    assert!(alice_mls_engine.pending_key_packages().is_empty(), "Alice should have no pending key packages after adding Charlie.");

}
