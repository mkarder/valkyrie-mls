## Unit Test Coverage

This section documents the included unit tests designed to verify and validate the correct functioning of our *valkyrie-mls* system. The tests focus on various aspects of group lifecycle management, identity handling, and GCS-enforced behavior.


### Group Lifecycle and Messaging

- **`test_mls_group_operations()`**:  
  Simulates a full group lifecycle involving three nodes: Alice (7777), Bob (8888), and Charlie (9999). Alice initializes the group and sequentially adds Bob and Charlie. Each member performs updates and commits, and messages are exchanged between them. Node identities are represented as `u32` values, as defined in our authentication scheme.

- **`test_mls_operations_with_ed25519_credential()`**:  
  A variant of the above test using Ed25519 credentials instead of Basic credentials. It verifies correct handling of Ed25519-based identities during key package exchange, welcome message processing, and group synchronization.


### Group Merge Logic Without GCS

- **`test_tiebreaker_join_without_gcs_basic_credential()`**:  
  Simulates two separate MLS groups of equal size attempting to merge in the absence of a GCS. Verifies that tiebreaker logic prevents both from initiating adds and ensures the lower-ID group absorbs the other.

- **`test_majority_group_join_without_gcs_basic_credential()`**:  
  Tests majority-based merging: one small group (1 node) and one larger group (3 nodes) exist independently. The larger group should not absorb the smaller until the smaller group initiates the join.

### GCS-Enforced Group Behavior

- **`test_reject_joins_in_presence_of_gcs_basic_credential()`**:  
  Ensures that nodes cannot add new members to the group when a GCS is present in the Totem group. Any attempted additions should fail, enforcing the GCS's authority over group membership.

- **`test_larger_groups_join_gcs_basic_credential()`**:  
  Tests how independently formed groups behave when the GCS later joins the Totem group. Ensures they do not merge autonomously but are instead absorbed into the GCS-controlled group through controlled add operations.

### Credential Handling and Identity Matching

- **`test_basic_credential_identity_matching()`**:  
  Validates that node IDs can be correctly matched with group member identities using Basic credentials. After adding Bob to Alice's group, the system should resolve Bob by his node ID and fail gracefully when queried for an unknown ID.

- **`test_ed25519_credential_identity_matching()`**:  
  Mirrors the identity matching test above, but under Ed25519 credentials. It ensures that identity lookup and resolution also work with cryptographically authenticated identities.

- **`test_min_node_id_with_basic_credentials()`**:  
  Tests whether the MLS group handler can determine the member with the lowest node ID in the group. This supports leader election or tiebreaking scenarios, e.g., during group merges.

### Specifici Ed25519 Validation
These tests is currently placed under `/src/authentication/tests.rs` and aim to verify the creation, verification and handling of the [`Ed25519Credential`]. 