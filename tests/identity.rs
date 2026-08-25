use kivo::core::crypto;
use kivo::core::identity::Identity;

#[test]
fn new_identity_deterministic_id() {
    let pubkey = crypto::generate_keypair().verifying_key.to_bytes().to_vec();
    let a = Identity::new("alice", pubkey.clone());
    let b = Identity::new("alice", pubkey);
    assert_eq!(a.id, b.id);
}

#[test]
fn different_keys_different_ids() {
    let a = Identity::new(
        "a",
        crypto::generate_keypair().verifying_key.to_bytes().to_vec(),
    );
    let b = Identity::new(
        "b",
        crypto::generate_keypair().verifying_key.to_bytes().to_vec(),
    );
    assert_ne!(a.id, b.id);
}

#[test]
fn id_starts_with_kivo() {
    let id = Identity::new(
        "test",
        crypto::generate_keypair().verifying_key.to_bytes().to_vec(),
    );
    assert!(id.id.starts_with("kivo:"));
}

#[test]
fn fingerprint_deterministic() {
    let pubkey = crypto::generate_keypair().verifying_key.to_bytes().to_vec();
    let id = Identity::new("test", pubkey);
    assert_eq!(id.fingerprint(), id.fingerprint());
}
