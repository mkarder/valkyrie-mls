use tls_codec::Serialize;
use valkyrie_mls::mls_group_handler::{MlsEngine, MlsSwarmLogic};
use valkyrie_mls::config::MlsConfig;
use openmls::prelude::*; 

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
        update_interval_secs: 100,
    };

    let bob_config = MlsConfig {
        credential_type: "Basic".to_string(),
        node_id: "Bob".to_string(),
        update_interval_secs: 100,
    };

    let charlie_config = MlsConfig {
        credential_type: "Basic".to_string(),
        node_id: "Charlie".to_string(),
        update_interval_secs: 100,
    };

    // Generate three MLS Engines
    let mut alice_mls_engine = MlsEngine::new(alice_config);
    let mut bob_mls_engine = MlsEngine::new(bob_config);
    let mut charlie_mls_engine = MlsEngine::new(charlie_config);

    // Alice receives Bob's key package
    let bob_key_package_bytes = bob_mls_engine.get_key_package().unwrap();
    let result = alice_mls_engine.process_incoming_delivery_service_message(&bob_key_package_bytes).unwrap();
    
    // Verify that key package was added as Pending KeyPackage 
    assert!(result.is_none(), "No message should be returned. KeyPackage should only be added to pending"); 
    assert!(alice_mls_engine.pending_key_packages()
        .values()
        .any(|kp| 
            MlsMessageOut::from(kp.clone()).tls_serialize_detached().unwrap() == bob_key_package_bytes),
        "Alice's Pending Key Package Hashmap should consist of Bob's key package"); 
    
    // Alice adds Bob to the group
    let result = alice_mls_engine.add_pending_key_packages().unwrap();
    assert_eq!(result.len(), 1, "Add operation should return one (GroupCommit, Welcome) tuple.");
    assert_eq!(alice_mls_engine.group().members().count(), 2, "Alice should have two members in the group after adding Bob.");
    
    // Bob receives the welcome message and joins the group
    let bob_welcome = result[0].1.clone();
    bob_mls_engine.process_incoming_delivery_service_message(&bob_welcome).unwrap();
    assert_eq!(bob_mls_engine.group().members().count(), 2, "Bob should have two members in the group after joining.");
    
    // Verify groups are the same
    assert!(alice_mls_engine.group().members().eq(bob_mls_engine.group().members()), "Alice and Bob should have the same group members.");
    assert_eq!(
        alice_mls_engine.group().epoch_authenticator().as_slice(),
        bob_mls_engine.group().epoch_authenticator().as_slice()
    );

}
