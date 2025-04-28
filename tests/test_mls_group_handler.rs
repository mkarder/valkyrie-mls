use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Serialize;
use valkyrie_mls::config::MlsConfig;
use valkyrie_mls::mls_group_handler::{
    MlsAutomaticRemoval, MlsEngine, MlsGroupDiscovery, MlsSwarmLogic,
};

/// Alice   <--> ID 7777
/// Bob     <--> ID 8888
/// Charlie <--> ID 9999
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
        node_id: 7777,
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
        node_id: 9999,
        update_interval_secs: 100,
    };

    let alice_provider = &OpenMlsRustCrypto::default();
    let bob_provider = &OpenMlsRustCrypto::default();

    // Generate three MLS Engines
    let mut alice_mls_engine = MlsEngine::new(alice_config);
    let mut bob_mls_engine = MlsEngine::new(bob_config);
    let mut charlie_mls_engine = MlsEngine::new(charlie_config);
    alice_mls_engine.update_totem_group(vec![7777, 8888, 9999]);
    bob_mls_engine.update_totem_group(vec![7777, 8888, 9999]);
    charlie_mls_engine.update_totem_group(vec![7777, 8888, 9999]);

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
        node_id: 7777,
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
    alice_mls_engine.update_totem_group(vec![7777, 8888]);
    bob_mls_engine.update_totem_group(vec![7777, 8888]);

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
        .expect("Expected Welcome for Bob to be available");

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
    // Generate Alice (7777) and Bob (8888)
    let config = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 7777,
        update_interval_secs: 100,
    };

    let mut alice = MlsEngine::new(config);

    let bob_config = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 8888,
        update_interval_secs: 100,
    };
    let mut bob = MlsEngine::new(bob_config.clone());

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
    // Generate Alice (7777) and Bob (8888)
    let config = MlsConfig {
        gcs_id: 1,
        credential_type: "ed25519".to_string(),
        node_id: 7777,
        update_interval_secs: 100,
    };

    let mut alice = MlsEngine::new(config);

    let bob_config = MlsConfig {
        gcs_id: 1,
        credential_type: "ed25519".to_string(),
        node_id: 8888,
        update_interval_secs: 100,
    };
    let mut bob = MlsEngine::new(bob_config.clone());

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
    // Alice group (only Alice with node_id 7777)
    let config_alice = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 7777,
        update_interval_secs: 100,
    };
    let alice = MlsEngine::new(config_alice);
    let alice_min =
        MlsEngine::min_node_id(alice.group()).expect("Expected a min ID in Alice's group");
    assert_eq!(alice_min, 7777);

    // Bob group (Bob and Charlie with node_ids 8888 and 9999)
    let config_bob = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 8888,
        update_interval_secs: 100,
    };
    let mut bob = MlsEngine::new(config_bob);

    let config_charlie = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 9999,
        update_interval_secs: 100,
    };
    let mut charlie = MlsEngine::new(config_charlie);

    // Bob processes Charlies's key package
    let charlie_key_pkg = charlie.get_key_package().unwrap();
    bob.process_incoming_delivery_service_message(&charlie_key_pkg)
        .unwrap();
    bob.add_pending_key_packages().unwrap();

    assert_eq!(
        bob.group().members().count(),
        2,
        "Expected Bob to have added Charlie"
    );
    let bob_min = MlsEngine::min_node_id(bob.group()).expect("Expected a min ID in Bob's group");
    assert_eq!(bob_min, 8888); // Charlie should be the min
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

    let nodes = vec![&mut node2, &mut node3, &mut node4, &mut node5];

    // Update the totem group status
    for node in nodes {
        node.update_totem_group(vec![2, 3, 4, 5]);
    }

    // === Setup: create two initial groups of the same size ===
    // Node 2 and 5 merge to one group. 5 Should join 2, not vthe other way around.
    let kp_2 = node2.get_key_package().unwrap();
    node5
        .process_incoming_delivery_service_message(&kp_2)
        .unwrap();
    assert!(
        node5.add_pending_key_packages().unwrap().is_none(),
        "5 Should not add 2. Result of add operation should be None.",
    );

    assert_eq!(
        node5.group().members().count(),
        1,
        "Group size of 5 should remain 1."
    );

    let kp_5 = node5.get_key_package().unwrap();
    node2
        .process_incoming_delivery_service_message(&kp_5)
        .unwrap();
    let (_commit, twowelcomefive) = node2
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected Add operation to result in a commit and welcome");

    let _ = node5.process_incoming_delivery_service_message(&twowelcomefive);
    assert!(
        node2.group().members().eq(node5.group().members()),
        "Node 2 should join 5"
    );

    // Node 3 adds node 4 to its group
    let kp_4 = node4.get_key_package().unwrap();
    node3
        .process_incoming_delivery_service_message(&kp_4)
        .unwrap();
    let (_commit, threewelcomefour) = node3
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected Add operation to result in a commit and welcome");

    let _ = node4.process_incoming_delivery_service_message(&threewelcomefour);
    assert_eq!(node4.group().members().count(), 2, "Node 4 should join 3.");
    assert!(
        node3.group().members().eq(node4.group().members()),
        "Node 3 and node 4 should show the same group."
    );

    // === Merge two groups of equal size ===
    // Node 3 receives node 2's key package
    let kp_2 = node2.get_key_package().unwrap();
    node3
        .process_incoming_delivery_service_message(&kp_2)
        .unwrap();

    assert!(
        node3.add_pending_key_packages().unwrap().is_none(),
        "3 Should not add 2. Result of add operation should be None.",
    );

    let kp_5 = node5.get_key_package().unwrap();
    node4
        .process_incoming_delivery_service_message(&kp_2)
        .unwrap();
    node4
        .process_incoming_delivery_service_message(&kp_5)
        .unwrap();

    assert!(
        node4.add_pending_key_packages().unwrap().is_none(),
        "4 Should not add 2 and 5, even though this constitues the full group. Result of add operation should be None.",
    );

    let kp_3 = node3.get_key_package().unwrap();
    let kp_4 = node4.get_key_package().unwrap();
    node5
        .process_incoming_delivery_service_message(&kp_3)
        .unwrap();

    node5
        .process_incoming_delivery_service_message(&kp_4)
        .unwrap();

    let (commit3and4, welcome3and4) = node5
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected Add operation to result in a commit and welcome");

    node2
        .process_incoming_delivery_service_message(&commit3and4)
        .unwrap();

    node3
        .process_incoming_delivery_service_message(&welcome3and4)
        .unwrap();

    assert!(
        node3.group().members().eq(node2.group().members()),
        "Node 2 and 3 should show the same group."
    );

    node4
        .process_incoming_delivery_service_message(&welcome3and4)
        .unwrap();

    assert!(
        node5.group().members().eq(node4.group().members()),
        "Node 5 and 4 should show the same group."
    );
}

#[test]
fn test_majority_group_join_withouth_gcs_basic_credential() {
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

    let nodes = vec![&mut node2, &mut node3, &mut node4, &mut node5];

    // Update the totem group status
    for node in nodes {
        node.update_totem_group(vec![2, 3, 4, 5]);
    }

    // === Setup: Create two groups of unequal size [{2}, {3, 4, 5}] ===
    let kp_4 = node4.get_key_package().unwrap();
    let kp_5 = node5.get_key_package().unwrap();
    node3
        .process_incoming_delivery_service_message(&kp_4)
        .unwrap();
    node3
        .process_incoming_delivery_service_message(&kp_5)
        .unwrap();
    let (_commit, welcome) = node3
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected Add operation to result in a commit and welcome");

    let _ = node4.process_incoming_delivery_service_message(&welcome);
    let _ = node5.process_incoming_delivery_service_message(&welcome);
    assert!(
        node3.group().members().eq(node4.group().members()),
        "Node 4 should join 3"
    );
    assert!(
        node3.group().members().eq(node5.group().members()),
        "Node 5 should join 3"
    );

    // Node 3 should not join node 2
    let kp_3 = node3.get_key_package().unwrap();
    node2
        .process_incoming_delivery_service_message(&kp_3)
        .unwrap();

    let (_commit, welcome3) = node2.add_pending_key_packages().unwrap().expect(
        "Expected add operation to add in welocme. 2 is not awarte of current group size of 3.",
    );

    node3
        .process_incoming_delivery_service_message(&welcome3)
        .unwrap();

    assert_eq!(
        node3.group().members().count(),
        3,
        "3 should not accept Welcome from 2."
    );

    // Node 2 should join the majority group consisting of {3, 4, 5}
    let kp_2 = node2.get_key_package().unwrap();
    node3
        .process_incoming_delivery_service_message(&kp_2)
        .unwrap();

    let (commit2, welcome2) = node3.add_pending_key_packages().unwrap().expect(
        "Expected add operation to add in welocme. 2 is not awarte of current group size of 3.",
    );

    node2
        .process_incoming_delivery_service_message(&welcome2)
        .unwrap();

    node4
        .process_incoming_delivery_service_message(&commit2)
        .unwrap();

    node5
        .process_incoming_delivery_service_message(&commit2)
        .unwrap();

    assert!(
        node3.group().members().eq(node2.group().members()),
        "2 should have joined 3"
    );

    assert!(
        node4.group().members().eq(node2.group().members()),
        "2 should also share group with 4"
    );

    assert!(
        node5.group().members().eq(node2.group().members()),
        "2 should also share group with 5"
    );
}

#[test]
fn test_reject_joins_in_presence_of_gcs_basic_credential() {
    // This test verifies that only the GCS or members of its MLS group
    // adds other nodes in the presence of a GCS in the Totem group.
    let config_gcs = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 1,
        update_interval_secs: 100,
    };

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

    let mut gcs = MlsEngine::new(config_gcs);
    let mut node2 = MlsEngine::new(config_2);
    let mut node3 = MlsEngine::new(config_3);
    let mut node4 = MlsEngine::new(config_4);

    let nodes = vec![&mut gcs, &mut node2, &mut node3, &mut node4];

    // Update Totem Group. Ensure GCS (node1) is present.
    for node in nodes {
        node.update_totem_group(vec![1, 2, 3, 4]);
    }

    // Node 3 and 4 tries to join 2.
    let kp_3 = node3.get_key_package().unwrap();
    let kp_4 = node4.get_key_package().unwrap();
    node2
        .process_incoming_delivery_service_message(&kp_3)
        .unwrap();
    node2
        .process_incoming_delivery_service_message(&kp_4)
        .unwrap();
    assert!(
        node2.add_pending_key_packages().unwrap().is_none(),
        "Expected Add operation in node 2 to result in None, as GCS is present in Totem Group."
    );

    // GCS adds 2, 3, and 4
    let kp_2 = node2.get_key_package().unwrap();
    gcs.process_incoming_delivery_service_message(&kp_2)
        .unwrap();

    gcs.process_incoming_delivery_service_message(&kp_3)
        .unwrap();

    gcs.process_incoming_delivery_service_message(&kp_4)
        .unwrap();

    let (_commit, welcome_from_gcs) = gcs
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected GCS' add operation to result in Welcome.");

    node2
        .process_incoming_delivery_service_message(&welcome_from_gcs)
        .unwrap();
    node3
        .process_incoming_delivery_service_message(&welcome_from_gcs)
        .unwrap();
    node4
        .process_incoming_delivery_service_message(&welcome_from_gcs)
        .unwrap();

    assert!(
        gcs.group().members().eq(node2.group().members()),
        "Node 2 should now be part of GCS group"
    );
    assert!(
        gcs.group().members().eq(node3.group().members()),
        "Node 3 should now be part of GCS group"
    );
    assert!(
        gcs.group().members().eq(node4.group().members()),
        "Node 4 should now be part of GCS group"
    );
}

#[test]
fn test_larger_groups_join_gcs_basic_credential() {
    let config_gcs = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 1,
        update_interval_secs: 100,
    };

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

    let mut gcs = MlsEngine::new(config_gcs);
    let mut node2 = MlsEngine::new(config_2);
    let mut node3 = MlsEngine::new(config_3);
    let mut node4 = MlsEngine::new(config_4);
    let mut node5 = MlsEngine::new(config_5);

    let not_gcs = vec![&mut node2, &mut node3, &mut node4, &mut node5];

    // Update Totem group. NB! GCS (node 1) should not be present.
    for node in not_gcs {
        node.update_totem_group(vec![2, 3, 4, 5]);
    }

    // Node 2, 3, 4 join each other
    let kp_3 = node3.get_key_package().unwrap();
    let kp_4 = node4.get_key_package().unwrap();
    node2
        .process_incoming_delivery_service_message(&kp_3)
        .unwrap();
    node2
        .process_incoming_delivery_service_message(&kp_4)
        .unwrap();
    let (_commit, welcome) = node2
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected commit and welcome");

    node3
        .process_incoming_delivery_service_message(&welcome)
        .unwrap();
    node4
        .process_incoming_delivery_service_message(&welcome)
        .unwrap();

    assert_eq!(node2.group().members().count(), 3);

    // GCS joins the totem group
    // Groups: {GCS}, {2, 3, 4}, {5}
    node2.update_totem_group(vec![1, 2, 3, 4, 5]);
    node3.update_totem_group(vec![1, 2, 3, 4, 5]);
    node4.update_totem_group(vec![1, 2, 3, 4, 5]);
    node5.update_totem_group(vec![1, 2, 3, 4, 5]);
    gcs.update_totem_group(vec![1, 2, 3, 4, 5]);

    // Node 5 should not join majority group in presence of GCS
    let kp_5 = node5.get_key_package().unwrap();

    node2
        .process_incoming_delivery_service_message(&kp_5)
        .unwrap();
    assert!(
        node2.add_pending_key_packages().unwrap().is_none(),
        "Node 2 should not Add 5 in presence of GCS"
    );

    // GCS Adds node 2
    let kp_2 = node2.get_key_package().unwrap();
    gcs.process_incoming_delivery_service_message(&kp_2)
        .unwrap();
    let (_commit, welcome2) = gcs
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected GCS Add operatin to result in Welcome.");

    node2
        .process_incoming_delivery_service_message(&welcome2)
        .unwrap();
    assert!(
        gcs.group().members().eq(node2.group().members()),
        "Expected node 2 to join GCS"
    );

    // Node 2 (now part of MAINGROUP) adds node 5
    let kp_5 = node5.get_key_package().unwrap();
    node2
        .process_incoming_delivery_service_message(&kp_5)
        .unwrap();

    let (commit5, welcome5) = node2
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected Node 2's Add operatin to result in Welcome.");

    gcs.process_incoming_delivery_service_message(&commit5)
        .unwrap();
    node5
        .process_incoming_delivery_service_message(&welcome5)
        .unwrap();

    assert!(
        gcs.group().members().eq(node5.group().members()),
        "Expected node 5 to join MAINGROUP [GCS, Node2]"
    );

    // GCS adds 3 and 4
    let kp_3 = node3.get_key_package().unwrap();
    let kp_4 = node4.get_key_package().unwrap();

    gcs.process_incoming_delivery_service_message(&kp_3)
        .unwrap();
    gcs.process_incoming_delivery_service_message(&kp_4)
        .unwrap();
    let (commit34, welcome34) = gcs
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected GCS Add operatin to result in Welcome.");

    node3
        .process_incoming_delivery_service_message(&welcome34)
        .unwrap();

    node4
        .process_incoming_delivery_service_message(&welcome34)
        .unwrap();

    node2
        .process_incoming_delivery_service_message(&commit34)
        .unwrap();
    node5
        .process_incoming_delivery_service_message(&commit34)
        .unwrap();

    // Verify that everybody is in the same group
    assert!(
        gcs.group().members().eq(node3.group().members()),
        "Node 3 should now be part of GCS group"
    );
    assert!(
        node2.group().members().eq(node4.group().members()),
        "Node 4 should now be part of GCS group"
    );

    assert!(
        node4.group().members().eq(node5.group().members()),
        "Node 4 and 5 should share group"
    );

    assert!(
        gcs.group().members().eq(node5.group().members()),
        "GCS and 5 should share group"
    );
}
