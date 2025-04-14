use valkyrie_mls::authentication::{
    ed25519::{Ed25519Issuer, Ed25519SignatureKeyPair},
    issuer::CredentialIssuer,
    Ed25519credential,
};

fn main() {
    let ca = "test-ca";
    let alice = "Alice";
    let bob = "Bob";

    let issuer = Ed25519Issuer::from_file(ca.as_bytes().to_vec()).expect("Failed to create issuer");

    let alice_key = Ed25519SignatureKeyPair::from_file(alice.as_bytes().to_vec())
        .expect("Failed to create Alice's key pair");

    let alice_credential = issuer
        .issue(alice, alice_key.public_key())
        .expect("Failed to issue key for Alice");

    assert_eq!(
        alice_credential.credential,
        Ed25519credential::from_file(alice.as_bytes().to_vec())
            .unwrap()
            .into()
    );
    println!(
        "Sucesfully issued Alice's credential: {:?}",
        alice_credential.credential
    );

    let bob_key = Ed25519SignatureKeyPair::from_file(bob.as_bytes().to_vec())
        .expect("Failed to create Bob's key pair");
    let bob_credential = issuer
        .issue(bob, bob_key.public_key())
        .expect("Failed to issue key for Bob");

    assert_eq!(
        bob_credential.credential,
        Ed25519credential::from_file(bob.as_bytes().to_vec())
            .unwrap()
            .into()
    );

    println!(
        "Sucesfully issued Bob's credential: {:?}",
        bob_credential.credential
    );
}
