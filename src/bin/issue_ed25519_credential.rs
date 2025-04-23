use std::env;
use valkyrie_mls::authentication::{
    ed25519::{Ed25519Issuer, Ed25519SignatureKeyPair, Ed25519credential},
    issuer::CredentialIssuer,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: issue_ed25519_credential <ca> <subject>");
        std::process::exit(1);
    }

    let ca = &args[1].parse::<u32>().unwrap();
    let subject = &args[2].parse::<u32>().unwrap();

    let issuer = Ed25519Issuer::from_file(*ca).expect("Failed to load issuer/CA");

    let subject_key =
        Ed25519SignatureKeyPair::from_file(*subject).expect("Failed to load subject's keypair");

    let credential = issuer
        .issue(*subject, subject_key.public_key())
        .expect("Failed to issue credential");

    assert_eq!(
        credential.credential,
        Ed25519credential::from_file(*subject).unwrap().into()
    );

    println!("✅ Issued credential for {}", subject);
}
