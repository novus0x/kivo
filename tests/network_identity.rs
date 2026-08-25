use kivo::core::crypto;
use kivo::network::identity;

#[test]
fn peer_id_deterministic_from_pubkey() {
    let kp = crypto::generate_keypair();
    let pubkey = kp.verifying_key.to_bytes();
    let pid1 = identity::kivo_pubkey_to_peer_id(&pubkey).unwrap();
    let pid2 = identity::kivo_pubkey_to_peer_id(&pubkey).unwrap();
    assert_eq!(pid1, pid2);
}

#[test]
fn different_pubkeys_different_peer_ids() {
    let kp1 = crypto::generate_keypair();
    let kp2 = crypto::generate_keypair();
    let pid1 = identity::kivo_pubkey_to_peer_id(&kp1.verifying_key.to_bytes()).unwrap();
    let pid2 = identity::kivo_pubkey_to_peer_id(&kp2.verifying_key.to_bytes()).unwrap();
    assert_ne!(pid1, pid2);
}

#[test]
fn keypair_to_libp2p_matches_pubkey_peer_id() {
    let kp = crypto::generate_keypair();
    let signing_bytes = kp.signing_key.to_bytes();
    let verifying_bytes = kp.verifying_key.to_bytes();

    let (_, peer_id_from_keypair) =
        identity::kivo_keypair_to_libp2p(&signing_bytes, &verifying_bytes).unwrap();
    let peer_id_from_pubkey = identity::kivo_pubkey_to_peer_id(&verifying_bytes).unwrap();

    assert_eq!(peer_id_from_keypair, peer_id_from_pubkey);
}

#[test]
fn libp2p_keypair_peer_id_matches_swarm_derived_peer_id() {
    let kp = crypto::generate_keypair();
    let signing_bytes = kp.signing_key.to_bytes();
    let verifying_bytes = kp.verifying_key.to_bytes();

    let (libp2p_keypair, peer_id_from_kivo) =
        identity::kivo_keypair_to_libp2p(&signing_bytes, &verifying_bytes).unwrap();

    let peer_id_from_keypair_public =
        libp2p::identity::PeerId::from_public_key(&libp2p_keypair.public());

    assert_eq!(
        peer_id_from_kivo, peer_id_from_keypair_public,
        "kivo_keypair_to_libp2p PeerId must equal PeerId::from_public_key(&keypair.public()). \
         If these differ, the swarm derives a different identity than what NetworkNode advertises."
    );
}

#[test]
fn libp2p_keypair_public_matches_kivo_verifying_key() {
    let kp = crypto::generate_keypair();
    let signing_bytes = kp.signing_key.to_bytes();
    let verifying_bytes = kp.verifying_key.to_bytes();

    let (libp2p_keypair, _) =
        identity::kivo_keypair_to_libp2p(&signing_bytes, &verifying_bytes).unwrap();

    let libp2p_pubkey = libp2p_keypair
        .public()
        .try_into_ed25519()
        .expect("libp2p keypair is not Ed25519");
    let libp2p_pubkey_bytes = libp2p_pubkey.to_bytes();

    assert_eq!(
        libp2p_pubkey_bytes.as_ref(),
        verifying_bytes.as_ref(),
        "libp2p keypair public key must equal Kivo's verifying_key_bytes. \
         If these differ, the keypair was reconstructed from different secret material."
    );
}

#[test]
fn invalid_pubkey_returns_error() {
    assert!(identity::kivo_pubkey_to_peer_id(&[0u8; 16]).is_err());
}
