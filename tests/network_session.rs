use std::time::Duration;

mod common;
use common::*;

#[test]
fn basic_two_node_connection() {
    let (mut node_a, id_a, _) = make_running_node("alice");
    let (mut node_b, _id_b, _) = make_running_node("bob");

    let addrs_a = node_a.get_listen_addresses().unwrap();
    assert!(!addrs_a.is_empty());

    let peer_id_a = node_a.peer_id().unwrap();
    let kivo_id_a = id_a.id.clone();

    let mut dial_addr = addrs_a[0].clone();
    dial_addr.push(libp2p::multiaddr::Protocol::P2p(peer_id_a));

    node_b.dial(dial_addr, peer_id_a, kivo_id_a).unwrap();

    wait_until(Duration::from_secs(5), || {
        node_a.connection_count() >= 1 && node_b.connection_count() >= 1
    });

    wait_until(Duration::from_secs(5), || {
        let peers_a = node_a.get_connected_peers().unwrap();
        let peers_b = node_b.get_connected_peers().unwrap();
        peers_a.iter().any(|p| p.session_active) && peers_b.iter().any(|p| p.session_active)
    });

    let peers_b = node_b.get_connected_peers().unwrap();
    assert!(!peers_b.is_empty());
    assert_eq!(peers_b[0].peer_id, peer_id_a);
    assert!(peers_b[0].session_active);

    node_a.stop().unwrap();
    node_b.stop().unwrap();
}

#[test]
fn session_persistence() {
    let (mut node_a, mut node_b) = connected_pair();

    wait_until(Duration::from_secs(5), || {
        let peers_a = node_a.get_connected_peers().unwrap();
        let peers_b = node_b.get_connected_peers().unwrap();
        peers_a.iter().any(|p| p.session_active) && peers_b.iter().any(|p| p.session_active)
    });

    std::thread::sleep(Duration::from_secs(5));

    let peers_a = node_a.get_connected_peers().unwrap();
    let peers_b = node_b.get_connected_peers().unwrap();
    assert!(
        peers_a.iter().any(|p| p.session_active),
        "A session dropped within 5s"
    );
    assert!(
        peers_b.iter().any(|p| p.session_active),
        "B session dropped within 5s"
    );

    node_a.stop().unwrap();
    node_b.stop().unwrap();
}

#[test]
#[ignore]
fn session_survives_30_seconds() {
    let (mut node_a, _id_a, _) = make_running_node("alice");
    let (mut node_b, id_b, _) = make_running_node("bob");

    let addrs_a = node_a.get_listen_addresses().unwrap();
    let peer_id_a = node_a.peer_id().unwrap();
    let mut dial_addr = addrs_a[0].clone();
    dial_addr.push(libp2p::multiaddr::Protocol::P2p(peer_id_a));

    node_b.dial(dial_addr, peer_id_a, id_b.id.clone()).unwrap();

    wait_until(Duration::from_secs(5), || {
        node_a.connection_count() >= 1 && node_b.connection_count() >= 1
    });

    for i in 0..6 {
        std::thread::sleep(Duration::from_secs(5));
        assert!(
            node_a.connection_count() >= 1,
            "Node A connection dropped at {}s",
            (i + 1) * 5
        );
        assert!(
            node_b.connection_count() >= 1,
            "Node B connection dropped at {}s",
            (i + 1) * 5
        );
    }

    node_b.stop().unwrap();
    wait_until_msg(
        Duration::from_secs(10),
        "Node A did not see close within 10s",
        || node_a.connection_count() == 0,
    );

    node_a.stop().unwrap();
}

#[test]
fn multiple_peers_keep_independent_sessions() {
    let (mut node_a, id_a, _) = make_running_node("alice");
    let (mut node_b, _id_b, _) = make_running_node("bob");
    let (mut node_c, _id_c, _) = make_running_node("charlie");

    let addrs_a = node_a.get_listen_addresses().unwrap();
    let peer_id_a = node_a.peer_id().unwrap();

    let mut dial_addr_b = addrs_a[0].clone();
    dial_addr_b.push(libp2p::multiaddr::Protocol::P2p(peer_id_a));
    node_b
        .dial(dial_addr_b, peer_id_a, id_a.id.clone())
        .unwrap();

    let mut dial_addr_c = addrs_a[0].clone();
    dial_addr_c.push(libp2p::multiaddr::Protocol::P2p(peer_id_a));
    node_c
        .dial(dial_addr_c, peer_id_a, id_a.id.clone())
        .unwrap();

    wait_until_msg(
        Duration::from_secs(5),
        "Connections not established within 5s",
        || {
            node_a.connection_count() >= 2
                && node_b.connection_count() >= 1
                && node_c.connection_count() >= 1
        },
    );

    wait_until_msg(
        Duration::from_secs(5),
        "A sessions not active within 5s",
        || {
            let peers_a = node_a.get_connected_peers().unwrap();
            peers_a.iter().filter(|p| p.session_active).count() >= 2
        },
    );

    let peers_a = node_a.get_connected_peers().unwrap();
    assert_eq!(peers_a.len(), 2);
    assert!(peers_a.iter().all(|p| p.session_active));

    node_b.stop().unwrap();

    wait_until_msg(
        Duration::from_secs(10),
        "A did not see B disconnect within 10s",
        || node_a.connection_count() == 1,
    );

    std::thread::sleep(Duration::from_secs(1));
    let peers_a = node_a.get_connected_peers().unwrap();
    assert_eq!(peers_a.len(), 1);
    assert!(peers_a[0].session_active);
    assert_eq!(peers_a[0].peer_id, node_c.peer_id().unwrap());

    node_a.stop().unwrap();
    node_c.stop().unwrap();
}

#[test]
fn disconnect_removes_session() {
    let (mut node_a, _id_a, _) = make_running_node("alice");
    let (mut node_b, _id_b, _) = make_running_node("bob");

    let addrs_a = node_a.get_listen_addresses().unwrap();
    let peer_id_a = node_a.peer_id().unwrap();
    let mut dial_addr = addrs_a[0].clone();
    dial_addr.push(libp2p::multiaddr::Protocol::P2p(peer_id_a));

    node_b
        .dial(dial_addr, peer_id_a, "kivo:alice".to_string())
        .unwrap();

    wait_until(Duration::from_secs(5), || {
        node_a.connection_count() >= 1 && node_b.connection_count() >= 1
    });

    wait_until(Duration::from_secs(5), || {
        let peers = node_a.get_connected_peers().unwrap();
        peers.iter().any(|p| p.session_active)
    });

    node_b.stop().unwrap();

    wait_until_msg(
        Duration::from_secs(10),
        "A did not see close within 10s",
        || node_a.connection_count() == 0,
    );

    let peers_a = node_a.get_connected_peers().unwrap();
    assert!(
        peers_a.is_empty(),
        "A should have no peers after B disconnects"
    );

    node_a.stop().unwrap();
}

#[test]
fn duplicate_connection_no_duplicate_session() {
    let (mut node_a, id_a, _) = make_running_node("alice");
    let (mut node_b, _id_b, _) = make_running_node("bob");

    let addrs_a = node_a.get_listen_addresses().unwrap();
    let peer_id_a = node_a.peer_id().unwrap();
    let mut dial_addr = addrs_a[0].clone();
    dial_addr.push(libp2p::multiaddr::Protocol::P2p(peer_id_a));

    node_b
        .dial(dial_addr.clone(), peer_id_a, id_a.id.clone())
        .unwrap();

    wait_until(Duration::from_secs(5), || {
        node_a.connection_count() >= 1 && node_b.connection_count() >= 1
    });

    let _ = node_b.dial(dial_addr, peer_id_a, id_a.id.clone());

    std::thread::sleep(Duration::from_secs(2));

    let peers_a = node_a.get_connected_peers().unwrap();
    let active_sessions = peers_a.iter().filter(|p| p.session_active).count();
    assert_eq!(
        active_sessions, 1,
        "Should have exactly 1 active session, got {active_sessions}"
    );

    node_a.stop().unwrap();
    node_b.stop().unwrap();
}
