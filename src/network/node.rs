use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use libp2p::{swarm::SwarmEvent, Multiaddr, PeerId};

use crate::core::identity::Identity;

use super::identity as kivo_identity;

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkState {
    Offline,
    Starting,
    Online,
    Stopped,
    Error,
}

pub struct NetworkNode {
    state: NetworkState,
    peer_id: Option<PeerId>,
    listen_address: Option<Multiaddr>,
    connection_count: Arc<AtomicUsize>,
    shutdown_tx: Option<std::sync::mpsc::Sender<()>>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl NetworkNode {
    pub fn new() -> Self {
        NetworkNode {
            state: NetworkState::Offline,
            peer_id: None,
            listen_address: None,
            connection_count: Arc::new(AtomicUsize::new(0)),
            shutdown_tx: None,
            runtime: None,
        }
    }

    pub fn state(&self) -> &NetworkState {
        &self.state
    }

    pub fn peer_id(&self) -> Option<PeerId> {
        self.peer_id
    }

    pub fn listen_address(&self) -> Option<&Multiaddr> {
        self.listen_address.as_ref()
    }

    pub fn connection_count(&self) -> usize {
        self.connection_count.load(Ordering::Relaxed)
    }

    pub fn is_online(&self) -> bool {
        self.state == NetworkState::Online
    }

    pub fn start(&mut self, identity: &Identity, signing_key: &[u8; 32]) -> Result<(), String> {
        if self.state == NetworkState::Online || self.state == NetworkState::Starting {
            return Err("Network is already running.".to_string());
        }

        self.state = NetworkState::Starting;

        let (libp2p_keypair, peer_id) = kivo_identity::kivo_keypair_to_libp2p(
            signing_key,
            identity
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid public key length".to_string())?,
        )?;

        self.peer_id = Some(peer_id);

        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let connection_count = self.connection_count.clone();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("kivo-network")
            .build()
            .map_err(|e| format!("Failed to create tokio runtime: {e}"))?;

        let (state_tx, state_rx) = std::sync::mpsc::channel();
        let (listen_addr_tx, listen_addr_rx) = std::sync::mpsc::channel();

        rt.spawn(async move {
            let result = run_swarm(
                libp2p_keypair,
                peer_id,
                connection_count,
                shutdown_rx,
                state_tx,
                listen_addr_tx,
            )
            .await;

            if let Err(e) = result {
                eprintln!("Network error: {e}");
            }
        });

        match listen_addr_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(addr) => {
                self.listen_address = Some(addr);
            }
            Err(_) => {
                self.cleanup_runtime();
                self.state = NetworkState::Offline;
                self.peer_id = None;
                return Err("Unable to start network.".to_string());
            }
        }

        match state_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(NetworkState::Online) => {
                self.state = NetworkState::Online;
                self.runtime = Some(rt);
                Ok(())
            }
            Ok(_) | Err(_) => {
                self.cleanup_runtime();
                self.state = NetworkState::Offline;
                self.peer_id = None;
                self.listen_address = None;
                Err("Unable to start network.".to_string())
            }
        }
    }

    pub fn stop(&mut self) -> Result<(), String> {
        if self.state != NetworkState::Online && self.state != NetworkState::Starting {
            return Err("Network is not running.".to_string());
        }

        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        self.cleanup_runtime();

        self.state = NetworkState::Stopped;
        self.listen_address = None;
        self.connection_count.store(0, Ordering::Relaxed);

        Ok(())
    }

    pub fn reset(&mut self) {
        let _ = self.stop();
        self.state = NetworkState::Offline;
        self.peer_id = None;
    }

    fn cleanup_runtime(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_timeout(Duration::from_secs(5));
        }
    }
}

async fn run_swarm(
    keypair: libp2p::identity::Keypair,
    _peer_id: PeerId,
    connection_count: Arc<AtomicUsize>,
    shutdown_rx: std::sync::mpsc::Receiver<()>,
    state_tx: std::sync::mpsc::Sender<NetworkState>,
    listen_addr_tx: std::sync::mpsc::Sender<Multiaddr>,
) -> Result<(), String> {
    use libp2p::futures::StreamExt;
    use libp2p::swarm::dummy::Behaviour;
    use libp2p::SwarmBuilder;

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic_config(|config| config)
        .with_behaviour(|_| Ok(Behaviour))
        .map_err(|e| format!("Failed to build swarm: {e}"))?
        .build();

    let listen_addr: Multiaddr = "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap();
    swarm
        .listen_on(listen_addr)
        .map_err(|e| format!("Failed to listen: {e}"))?;

    let _ = state_tx.send(NetworkState::Online);

    loop {
        tokio::select! {
            event = swarm.next() => {
                match event {
                    Some(SwarmEvent::NewListenAddr { address, .. }) => {
                        let _ = listen_addr_tx.send(address);
                    }
                    Some(SwarmEvent::ConnectionEstablished { .. }) => {
                        connection_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Some(SwarmEvent::ConnectionClosed { .. }) => {
                        let _ = connection_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
                    }
                    Some(SwarmEvent::IncomingConnectionError { .. }) => {}
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }
            }
        }
    }

    Ok(())
}

impl Default for NetworkNode {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let kp = crate::core::crypto::generate_keypair();
        let identity = Identity::new("test", kp.verifying_key.to_bytes().to_vec());
        let pid1 = kivo_identity::kivo_pubkey_to_peer_id(&identity.public_key).unwrap();
        let pid2 = kivo_identity::kivo_pubkey_to_peer_id(&identity.public_key).unwrap();
        assert_eq!(pid1, pid2);
    }

    #[test]
    fn different_identity_different_peer_id() {
        let kp1 = crate::core::crypto::generate_keypair();
        let kp2 = crate::core::crypto::generate_keypair();
        let id1 = Identity::new("a", kp1.verifying_key.to_bytes().to_vec());
        let id2 = Identity::new("b", kp2.verifying_key.to_bytes().to_vec());
        let pid1 = kivo_identity::kivo_pubkey_to_peer_id(&id1.public_key).unwrap();
        let pid2 = kivo_identity::kivo_pubkey_to_peer_id(&id2.public_key).unwrap();
        assert_ne!(pid1, pid2);
    }

    #[test]
    fn start_and_stop_network() {
        let mut node = NetworkNode::new();
        let kp = crate::core::crypto::generate_keypair();
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
        let kp = crate::core::crypto::generate_keypair();
        let identity = Identity::new("test", kp.verifying_key.to_bytes().to_vec());

        node.start(&identity, &kp.signing_key.to_bytes()).unwrap();
        let result = node.start(&identity, &kp.signing_key.to_bytes());
        assert!(result.is_err());
        node.stop().unwrap();
    }

    #[test]
    fn stop_twice_safe() {
        let mut node = NetworkNode::new();
        let kp = crate::core::crypto::generate_keypair();
        let identity = Identity::new("test", kp.verifying_key.to_bytes().to_vec());

        node.start(&identity, &kp.signing_key.to_bytes()).unwrap();
        node.stop().unwrap();
        assert!(node.stop().is_err());
    }

    #[test]
    fn network_uses_current_identity() {
        let mut node = NetworkNode::new();
        let kp = crate::core::crypto::generate_keypair();
        let identity = Identity::new("test", kp.verifying_key.to_bytes().to_vec());
        let expected_peer_id = kivo_identity::kivo_pubkey_to_peer_id(&identity.public_key).unwrap();

        node.start(&identity, &kp.signing_key.to_bytes()).unwrap();
        assert_eq!(node.peer_id(), Some(expected_peer_id));
        node.stop().unwrap();
    }
}
