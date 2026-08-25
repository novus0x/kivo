use kivo::core::crypto;
use kivo::core::identity::Identity;
use kivo::network::identity;
use kivo::network::node::{NetworkNode, NetworkState};

#[test]
fn initial_state_is_offline() {
    let node = NetworkNode::new();
    assert_eq!(*node.state(), NetworkState::Offline);
    assert!(!node.is_online());
}

#[test]
fn stop_when_offline_returns_error() {
    let mut node = NetworkNode::new();
    assert!(node.stop().is_err());
}

#[test]
fn reset_clears_state() {
    let mut node = NetworkNode::new();
    node.reset();
    assert_eq!(*node.state(), NetworkState::Offline);
    assert!(node.peer_id().is_none());
}

#[test]
fn peer_id_deterministic() {
    let kp = crypto::generate_keypair();
    let identity = Identity::new("test", kp.verifying_key.to_bytes().to_vec());
    let pid1 = identity::kivo_pubkey_to_peer_id(&identity.public_key).unwrap();
    let pid2 = identity::kivo_pubkey_to_peer_id(&identity.public_key).unwrap();
    assert_eq!(pid1, pid2);
}

#[test]
fn different_identity_different_peer_id() {
    let kp1 = crypto::generate_keypair();
    let kp2 = crypto::generate_keypair();
    let id1 = Identity::new("a", kp1.verifying_key.to_bytes().to_vec());
    let id2 = Identity::new("b", kp2.verifying_key.to_bytes().to_vec());
    let pid1 = identity::kivo_pubkey_to_peer_id(&id1.public_key).unwrap();
    let pid2 = identity::kivo_pubkey_to_peer_id(&id2.public_key).unwrap();
    assert_ne!(pid1, pid2);
}

#[test]
fn start_and_stop_network() {
    let mut node = NetworkNode::new();
    let kp = crypto::generate_keypair();
    let identity = Identity::new("test", kp.verifying_key.to_bytes().to_vec());

    node.start(&identity, &kp.signing_key.to_bytes()).unwrap();
    assert!(node.is_online());
    assert!(node.peer_id().is_some());

    node.stop().unwrap();
    assert_eq!(*node.state(), NetworkState::Stopped);
}

#[test]
fn start_twice_rejected() {
    let mut node = NetworkNode::new();
    let kp = crypto::generate_keypair();
    let identity = Identity::new("test", kp.verifying_key.to_bytes().to_vec());

    node.start(&identity, &kp.signing_key.to_bytes()).unwrap();
    let result = node.start(&identity, &kp.signing_key.to_bytes());
    assert!(result.is_err());
    node.stop().unwrap();
}

#[test]
fn stop_twice_safe() {
    let mut node = NetworkNode::new();
    let kp = crypto::generate_keypair();
    let identity = Identity::new("test", kp.verifying_key.to_bytes().to_vec());

    node.start(&identity, &kp.signing_key.to_bytes()).unwrap();
    node.stop().unwrap();
    assert!(node.stop().is_err());
}

#[test]
fn network_uses_current_identity() {
    let mut node = NetworkNode::new();
    let kp = crypto::generate_keypair();
    let identity = Identity::new("test", kp.verifying_key.to_bytes().to_vec());
    let expected_peer_id = identity::kivo_pubkey_to_peer_id(&identity.public_key).unwrap();

    node.start(&identity, &kp.signing_key.to_bytes()).unwrap();
    assert_eq!(node.peer_id(), Some(expected_peer_id));
    node.stop().unwrap();
}

#[test]
fn advertised_peer_id_matches_keypair_derived_peer_id() {
    let mut node = NetworkNode::new();
    let kp = crypto::generate_keypair();
    let identity = Identity::new("test", kp.verifying_key.to_bytes().to_vec());

    node.start(&identity, &kp.signing_key.to_bytes()).unwrap();

    let advertised = node.peer_id().unwrap();

    let (libp2p_keypair, _) = identity::kivo_keypair_to_libp2p(
        &kp.signing_key.to_bytes(),
        &identity.public_key.as_slice().try_into().unwrap(),
    )
    .unwrap();

    let from_keypair = libp2p::PeerId::from_public_key(&libp2p_keypair.public());

    assert_eq!(
        advertised, from_keypair,
        "Advertised PeerId ({advertised}) must equal PeerId derived from libp2p keypair public key ({from_keypair})"
    );

    node.stop().unwrap();
}

#[test]
fn get_listen_addresses_offline_fails() {
    let node = NetworkNode::new();
    assert!(node.get_listen_addresses().is_err());
}

#[test]
fn get_connected_peers_offline_fails() {
    let node = NetworkNode::new();
    assert!(node.get_connected_peers().is_err());
}

#[test]
fn connect_while_offline_fails() {
    let node = NetworkNode::new();
    let addr: libp2p::Multiaddr = "/ip4/127.0.0.1/udp/4000/quic-v1".parse().unwrap();
    let result = node.dial(addr, libp2p::PeerId::random(), "kivo:test".to_string());
    assert!(result.is_err());
}
