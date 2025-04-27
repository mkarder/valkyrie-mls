use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Serialize;
use valkyrie_mls::config::MlsConfig;
use valkyrie_mls::mls_group_handler::{
    MlsAutomaticRemoval, MlsEngine, MlsGroupDiscovery, MlsSwarmLogic,
};

/// Alice   <--> ID 9999
/// Bob     <--> ID 8888
/// Alice has a self-signed, valid Ed25519 Credential.
/// Bob has a valid Ed25519 Credential signed by Alice.

/// This test replicates the functionality of the group test from
/// `openmls-0.6.0/tests/mls_group.rs`.
/// The original test simulates various group operations like Add, Update, Remove in a
/// small group. This test replicates the same operation through the use of `MlsEngine`.
///  + Alice creates a group
///  + Alice adds Bob
///  + Alice sends a message to Bob
///  + Bob updates and commits
///  + Alice updates and commits
///  + Bob adds Charlie
///  - Charlie sends a message to the group
///  - Charlie updates and commits
///  - Charlie removes Bob
///  - Alice removes Charlie and adds Bob
///  - Bob leaves
///  - Test saving the group state
#[test]
fn test_mls_group_operations() {
    let alice_config = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 9999,
        update_interval_secs: 100,
    };

    let bob_config = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 8888,
        update_interval_secs: 100,
    };

    let charlie_config = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 7777,
        update_interval_secs: 100,
    };

    let alice_provider = &OpenMlsRustCrypto::default();
    let bob_provider = &OpenMlsRustCrypto::default();

    // Generate three MLS Engines
    let mut alice_mls_engine = MlsEngine::new(alice_config);
    let mut bob_mls_engine = MlsEngine::new(bob_config);
    let mut charlie_mls_engine = MlsEngine::new(charlie_config);

    // === Alice receives Bob's key package ===
    let bob_key_package_bytes = bob_mls_engine.get_key_package().unwrap();
    let result = alice_mls_engine
        .process_incoming_delivery_service_message(&bob_key_package_bytes)
        .unwrap();

    // Verify that key package was added as Pending KeyPackage
    assert!(
        result.is_none(),
        "No message should be returned. KeyPackage should only be added to pending"
    );
    assert!(
        alice_mls_engine
            .pending_key_packages()
            .values()
            .any(|kp| MlsMessageOut::from(kp.clone())
                .tls_serialize_detached()
                .unwrap()
                == bob_key_package_bytes),
        "Alice's Pending Key Package Hashmap should consist of Bob's key package"
    );

    // === Alice adds Bob ===
    let (_group_commit, bob_welcome) = alice_mls_engine
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected key packages to be available");

    assert_eq!(
        alice_mls_engine.group().members().count(),
        2,
        "Alice should have two members in the group afterq adding Bob."
    );

    // Bob receives the welcome message and joins the group
    bob_mls_engine
        .process_incoming_delivery_service_message(&bob_welcome)
        .unwrap();
    assert_eq!(
        bob_mls_engine.group().members().count(),
        2,
        "Bob should have two members in the group after joining."
    );

    // Verify groups are the same
    assert!(
        alice_mls_engine
            .group()
            .members()
            .eq(bob_mls_engine.group().members()),
        "Alice and Bob should have the same group members."
    );
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

    assert_eq!(
        message,
        processed_message.as_slice(),
        "Bob should receive the same message Alice sent him."
    );

    // === Bob updates and commits ===
    let (bob_update, _welcome_option) = bob_mls_engine.update_self().unwrap();

    let _ = alice_mls_engine
        .process_incoming_delivery_service_message(&bob_update)
        .unwrap();

    // Verify that the group states are the same.
    assert_eq!(
        alice_mls_engine.group().epoch(),
        bob_mls_engine.group().epoch(),
        "Alice and Bob should be in the same epoch after Bob's update."
    );
    assert_eq!(
        alice_mls_engine
            .group()
            .export_secret(alice_provider, "", &[], 32)
            .unwrap(),
        bob_mls_engine
            .group()
            .export_secret(bob_provider, "", &[], 32)
            .unwrap()
    );

    // === Alice updates and commits ===
    let (alice_update, _welcome_option) = alice_mls_engine.update_self().unwrap();

    let _ = bob_mls_engine
        .process_incoming_delivery_service_message(&alice_update)
        .unwrap();

    // Verify that the group states are the same.
    assert_eq!(
        alice_mls_engine.group().epoch(),
        bob_mls_engine.group().epoch(),
        "Alice and Bob should be in the same epoch after Alice's update."
    );
    assert_eq!(
        alice_mls_engine
            .group()
            .export_secret(alice_provider, "", &[], 32)
            .unwrap(),
        bob_mls_engine
            .group()
            .export_secret(bob_provider, "", &[], 32)
            .unwrap()
    );

    // === Bob and Alice receives Charlie's KeyPackage. ===
    let charlie_key_package_bytes = charlie_mls_engine.get_key_package().unwrap();
    let _ = bob_mls_engine
        .process_incoming_delivery_service_message(&charlie_key_package_bytes)
        .unwrap();
    let _ = alice_mls_engine
        .process_incoming_delivery_service_message(&charlie_key_package_bytes)
        .unwrap();

    // Verify that key package was added as Pending KeyPackage
    assert!(
        bob_mls_engine
            .pending_key_packages()
            .values()
            .any(|kp| MlsMessageOut::from(kp.clone())
                .tls_serialize_detached()
                .unwrap()
                == charlie_key_package_bytes),
        "Bob's Pending Key Package Hashmap should consist of Charlie's key package"
    );

    assert!(
        alice_mls_engine
            .pending_key_packages()
            .values()
            .any(|kp| MlsMessageOut::from(kp.clone())
                .tls_serialize_detached()
                .unwrap()
                == charlie_key_package_bytes),
        "Alice's Pending Key Package Hashmap should consist of Charlie's key package"
    );

    // === Bob adds Charlie ===
    let (group_commit, welcome) = bob_mls_engine
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected key packages to be available");

    alice_mls_engine
        .process_incoming_delivery_service_message(&group_commit)
        .unwrap();

    charlie_mls_engine
        .process_incoming_delivery_service_message(&welcome)
        .unwrap();

    // Verify that the group states are the same.
    assert_eq!(
        alice_mls_engine.group().members().count(),
        3,
        "Alice should have three members in the group after adding Charlie."
    );
    assert_eq!(
        bob_mls_engine.group().members().count(),
        3,
        "Bob should have three members in the group after adding Charlie."
    );
    assert_eq!(
        charlie_mls_engine.group().members().count(),
        3,
        "Charlie should have three members in the group after joining."
    );

    assert_eq!(
        alice_mls_engine.group().epoch(),
        bob_mls_engine.group().epoch(),
        "Alice and Bob should be in the same epoch after adding Charlie."
    );
    assert_eq!(
        alice_mls_engine.group().epoch(),
        charlie_mls_engine.group().epoch(),
        "Alice and Charlie should be in the same epoch after Charlie's join."
    );

    // Verify Alice has cleared here pending key packages
    assert!(
        alice_mls_engine.pending_key_packages().is_empty(),
        "Alice should have no pending key packages after adding Charlie."
    );
}

#[test]
fn test_mls_operations_with_ed25519_credential() {
    let alice_config = MlsConfig {
        gcs_id: 1,
        credential_type: "ed25519".to_string(),
        node_id: 9999,
        update_interval_secs: 100,
    };

    let bob_config = MlsConfig {
        gcs_id: 1,
        credential_type: "ed25519".to_string(),
        node_id: 8888,
        update_interval_secs: 100,
    };

    // Generate two MLS Engines
    let mut alice_mls_engine = MlsEngine::new(alice_config);
    let mut bob_mls_engine = MlsEngine::new(bob_config);

    // === Alice receives Bob's key package ===
    let bob_key_package_bytes = bob_mls_engine.get_key_package().unwrap();
    let result = alice_mls_engine
        .process_incoming_delivery_service_message(&bob_key_package_bytes)
        .unwrap();

    // Verify that key package was added as Pending KeyPackage
    assert!(
        result.is_none(),
        "No message should be returned. KeyPackage should only be added to pending"
    );
    assert!(
        alice_mls_engine
            .pending_key_packages()
            .values()
            .any(|kp| MlsMessageOut::from(kp.clone())
                .tls_serialize_detached()
                .unwrap()
                == bob_key_package_bytes),
        "Alice's Pending Key Package Hashmap should consist of Bob's key package"
    );

    // === Alice adds Bob ===
    let (_group_commit, bob_welcome) = alice_mls_engine
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected key packages to be available");

    assert_eq!(
        alice_mls_engine.group().members().count(),
        2,
        "Alice should have two members in the group after adding Bob."
    );

    // Bob receives the welcome message and joins the group
    match bob_mls_engine.process_incoming_delivery_service_message(&bob_welcome) {
        Ok(_) => {}
        Err(e) => {
            panic!(
                "Failed to process incoming delivery service message: {:?}",
                e
            );
        }
    }

    assert_eq!(
        bob_mls_engine.group().members().count(),
        2,
        "Bob should have two members in the group after joining."
    );

    // Verify groups are the same
    assert!(
        alice_mls_engine
            .group()
            .members()
            .eq(bob_mls_engine.group().members()),
        "Alice and Bob should have the same group members."
    );
    assert_eq!(
        alice_mls_engine.group().epoch_authenticator().as_slice(),
        bob_mls_engine.group().epoch_authenticator().as_slice()
    );
}

#[test]
fn test_basic_credential_identity_matching() {
    // Generate Alice (9999) and Bob (8888)
    let config = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 9999,
        update_interval_secs: 100,
    };

    let mut alice = MlsEngine::new(config);

    let bob_config = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 8888,
        update_interval_secs: 100,
    };
    let bob = MlsEngine::new(bob_config.clone());

    let bob_key_package_bytes = bob.get_key_package().unwrap();
    alice
        .process_incoming_delivery_service_message(&bob_key_package_bytes)
        .unwrap();

    alice.add_pending_key_packages().unwrap();

    // Now test lookup of Bob
    let bob_index = alice.get_leaf_index_from_id(alice.group(), 8888);
    assert!(
        bob_index.is_ok(),
        "Expected to find Bob (node_id = 8888), but got error"
    );

    // Lookup of a non-existent node
    let missing_index = alice.get_leaf_index_from_id(alice.group(), 1234);
    assert!(
        missing_index.is_err(),
        "Expected lookup of non-existent node_id to fail"
    );
}

#[test]
fn test_ed25519_credential_identity_matching() {
    // Generate Alice (9999) and Bob (8888)
    let config = MlsConfig {
        gcs_id: 1,
        credential_type: "ed25519".to_string(),
        node_id: 9999,
        update_interval_secs: 100,
    };

    let mut alice = MlsEngine::new(config);

    let bob_config = MlsConfig {
        gcs_id: 1,
        credential_type: "ed25519".to_string(),
        node_id: 8888,
        update_interval_secs: 100,
    };
    let bob = MlsEngine::new(bob_config.clone());

    let bob_key_package_bytes = bob.get_key_package().unwrap();
    alice
        .process_incoming_delivery_service_message(&bob_key_package_bytes)
        .unwrap();

    alice.add_pending_key_packages().unwrap();

    let bob_index = alice.get_leaf_index_from_id(alice.group(), 8888);
    assert!(
        bob_index.is_ok(),
        "Expected to find Bob (node_id = 8888), but got error"
    );

    let missing_index = alice.get_leaf_index_from_id(alice.group(), 1234);
    assert!(
        missing_index.is_err(),
        "Expected lookup of non-existent node_id to fail"
    );
}

#[test]
fn test_min_node_id_with_basic_credentials() {
    // Alice group (only Alice with node_id 9999)
    let config_alice = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 9999,
        update_interval_secs: 100,
    };
    let alice = MlsEngine::new(config_alice);
    let alice_min =
        MlsEngine::min_node_id(alice.group()).expect("Expected a min ID in Alice's group");
    assert_eq!(alice_min, 9999);

    // Bob group (Bob and Charlie with node_ids 8888 and 7777)
    let config_bob = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 8888,
        update_interval_secs: 100,
    };
    let mut bob = MlsEngine::new(config_bob);

    let config_carol = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 7777,
        update_interval_secs: 100,
    };
    let carol = MlsEngine::new(config_carol);

    // Bob processes Charlies's key package
    let carol_key_pkg = carol.get_key_package().unwrap();
    bob.process_incoming_delivery_service_message(&carol_key_pkg)
        .unwrap();
    bob.add_pending_key_packages().unwrap();

    assert_eq!(
        bob.group().members().count(),
        2,
        "Expected Bob to have added Charlie"
    );
    let bob_min = MlsEngine::min_node_id(bob.group()).expect("Expected a min ID in Bob's group");
    assert_eq!(bob_min, 7777); // Charlie should be the min
}

#[test]
fn test_tiebreaker_join_withouth_gcs_basic_credential() {
    // Create engines with IDs 2, 3, 4, and 5
    let config_2 = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 2,
        update_interval_secs: 100,
    };
    let config_3 = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 3,
        update_interval_secs: 100,
    };
    let config_4 = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 4,
        update_interval_secs: 100,
    };
    let config_5 = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 5,
        update_interval_secs: 100,
    };

    let mut node2 = MlsEngine::new(config_2);
    let mut node3 = MlsEngine::new(config_3);
    let mut node4 = MlsEngine::new(config_4);
    let mut node5 = MlsEngine::new(config_5);

    // === Setup: create two initial groups of the same size ===
    // Node 2 and 5 merge to one group
    let kp_2 = node2.get_key_package().unwrap();
    node5
        .process_incoming_delivery_service_message(&kp_2)
        .unwrap();
    let (_commit, fivewelcometwo) = node5
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected Add operation to result in a commit and welcome");

    let _ = node2.process_incoming_delivery_service_message(&fivewelcometwo);
    assert_eq!(
        node2.group().members().count(),
        2,
        "Node 2 should join 5, as it is the only node in its group."
    );
    assert_eq!(node5.group().members().count(), 2, "Node 2 should join 5");
    assert!(
        node2.group().members().eq(node5.group().members()),
        "Node 2 should join 5"
    );

    // Node 3 and 4 merge
    let kp_3 = node3.get_key_package().unwrap();
    node4
        .process_incoming_delivery_service_message(&kp_3)
        .unwrap();
    let (_commit, welcome) = node4
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected Add operation to result in a commit and welcome");

    let _ = node3.process_incoming_delivery_service_message(&welcome);
    assert_eq!(
        node3.group().members().count(),
        2,
        "Node 3 should join 4, as it is the only node in its group."
    );
    assert!(
        node3.group().members().eq(node4.group().members()),
        "Node 3 should join 4"
    );

    // === Merge two groups of equal size ===
    // Node 3 receives node 2's key package
    let kp_2 = node2.get_key_package().unwrap();
    node3
        .process_incoming_delivery_service_message(&kp_2)
        .unwrap();

    let (_commit, welcome) = node3
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected Add operation to result in a commit and welcome");

    let _ = node2.process_incoming_delivery_service_message(&welcome);
    assert_eq!(
        node2.group().members().count(),
        2,
        "Node 2 should not join the group, as they have the same size but the MIN ID of the group is higher."
    );
    assert_eq!(
        node3.group().members().count(),
        3,
        "Node 3 should have added Node 2 anyway."
    );

    let kp_3 = node3.get_key_package().unwrap();
    node2
        .process_incoming_delivery_service_message(&kp_3)
        .unwrap();

    let (commit, welcome) = node2
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected Add operation to result in a commit and welcome");

    let _ = node3.process_incoming_delivery_service_message(&welcome);
    let _ = node5.process_incoming_delivery_service_message(&commit);

    println!("\n #### Members of node 3: ####");
    for m in node3.group().members() {
        println!("{:?}", m.credential.serialized_content());
    }

    assert!(
        node3.group().members().eq(node2.group().members()),
        "Node 3 should join the group."
    );
    assert!(
        node3.group().members().eq(node5.group().members()),
        "Node 5 should also have added Node 3 to the group."
    );

    // // Group 2: node3 and node4
    // let kp_4 = node4.get_key_package().unwrap();
    // node3
    //     .process_incoming_delivery_service_message(&kp_4)
    //     .unwrap();
    // node3.add_pending_key_packages().unwrap();

    // // Welcome from group 1 (node2) to group 2 (node3)
    // let welcome_from_2 = node2.export_welcome().unwrap();
    // assert!(
    //     !node3.should_join(&welcome_from_2),
    //     "Group 2 should not join group 1 because it contains higher min ID"
    // );

    // // Welcome from group 2 (node3) to group 1 (node2)
    // let welcome_from_3 = node3.export_welcome().unwrap();
    // assert!(
    //     node2.should_join(&welcome_from_3),
    //     "Group 1 should join group 2 because it contains lower min ID"
    // );
}
