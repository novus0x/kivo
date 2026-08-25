#![allow(dead_code)]

use std::time::{Duration, Instant};

use kivo::app::KivoApp;
use kivo::core::crypto;
use kivo::core::identity::Identity;
use kivo::network::node::NetworkNode;
use kivo::storage::local::LocalStore;

pub fn create_test_identity(name: &str) -> (Identity, ed25519_dalek::SigningKey) {
    let kp = crypto::generate_keypair();
    let identity = Identity::new(name, kp.verifying_key.to_bytes().to_vec());
    (identity, kp.signing_key)
}

pub fn make_running_node(name: &str) -> (NetworkNode, Identity, [u8; 32]) {
    let mut node = NetworkNode::new();
    let kp = crypto::generate_keypair();
    let identity = Identity::new(name, kp.verifying_key.to_bytes().to_vec());
    let signing_key = kp.signing_key.to_bytes();
    node.start(&identity, &signing_key).unwrap();
    (node, identity, signing_key)
}

pub fn connected_pair() -> (NetworkNode, NetworkNode) {
    let (node_a, id_a, _) = make_running_node("alice");
    let (node_b, _id_b, _) = make_running_node("bob");

    let addrs_a = node_a.get_listen_addresses().unwrap();
    let peer_id_a = node_a.peer_id().unwrap();
    let mut dial_addr = addrs_a[0].clone();
    dial_addr.push(libp2p::multiaddr::Protocol::P2p(peer_id_a));

    node_b.dial(dial_addr, peer_id_a, id_a.id.clone()).unwrap();

    wait_until(Duration::from_secs(5), || {
        node_a.connection_count() >= 1 && node_b.connection_count() >= 1
    });

    (node_a, node_b)
}

pub fn create_test_app(name: &str) -> KivoApp {
    let store = LocalStore::open_memory().unwrap();
    let kp = crypto::generate_keypair();
    let identity = Identity::new(name, kp.verifying_key.to_bytes().to_vec());
    KivoApp::new_with_identity(identity, kp.signing_key, store)
}

pub fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    loop {
        if condition() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("Condition not met within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn wait_until_msg(timeout: Duration, msg: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    loop {
        if condition() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("{msg}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
