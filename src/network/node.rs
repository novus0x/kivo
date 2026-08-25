use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use libp2p::{swarm::SwarmEvent, Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot};

use crate::core::identity::Identity;

use super::identity as kivo_identity;
use super::session;

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkState {
    Offline,
    Starting,
    Online,
    Stopped,
    Error,
}

#[derive(Debug, Clone)]
pub struct ConnectedPeer {
    pub peer_id: PeerId,
    pub kivo_id: Option<String>,
    pub session_active: bool,
}

pub enum NetworkCommand {
    Dial {
        address: Multiaddr,
        expected_peer_id: PeerId,
        kivo_id: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    GetListenAddresses {
        response: oneshot::Sender<Result<Vec<Multiaddr>, String>>,
    },
    GetConnectedPeers {
        response: oneshot::Sender<Result<Vec<ConnectedPeer>, String>>,
    },
    DisconnectAll,
    Shutdown,
}

pub struct NetworkHandle {
    cmd_tx: mpsc::Sender<NetworkCommand>,
    runtime: tokio::runtime::Runtime,
}

impl NetworkHandle {
    pub fn dial(
        &self,
        address: Multiaddr,
        expected_peer_id: PeerId,
        kivo_id: String,
    ) -> Result<(), String> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .blocking_send(NetworkCommand::Dial {
                address,
                expected_peer_id,
                kivo_id,
                response: response_tx,
            })
            .map_err(|_| "Network task stopped.".to_string())?;
        response_rx
            .blocking_recv()
            .map_err(|_| "Network task stopped.".to_string())?
    }

    pub fn get_listen_addresses(&self) -> Result<Vec<Multiaddr>, String> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .blocking_send(NetworkCommand::GetListenAddresses {
                response: response_tx,
            })
            .map_err(|_| "Network task stopped.".to_string())?;
        response_rx
            .blocking_recv()
            .map_err(|_| "Network task stopped.".to_string())?
            .map_err(|_| "Network task stopped.".to_string())
    }

    pub fn get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, String> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .blocking_send(NetworkCommand::GetConnectedPeers {
                response: response_tx,
            })
            .map_err(|_| "Network task stopped.".to_string())?;
        response_rx
            .blocking_recv()
            .map_err(|_| "Network task stopped.".to_string())?
            .map_err(|_| "Network task stopped.".to_string())
    }

    pub fn shutdown(&self) {
        let _ = self.cmd_tx.blocking_send(NetworkCommand::DisconnectAll);
        std::thread::sleep(Duration::from_millis(200));
        let _ = self.cmd_tx.blocking_send(NetworkCommand::Shutdown);
    }
}

pub struct NetworkNode {
    state: NetworkState,
    peer_id: Option<PeerId>,
    connection_count: Arc<AtomicUsize>,
    handle: Option<NetworkHandle>,
}

impl NetworkNode {
    pub fn new() -> Self {
        NetworkNode {
            state: NetworkState::Offline,
            peer_id: None,
            connection_count: Arc::new(AtomicUsize::new(0)),
            handle: None,
        }
    }

    pub fn state(&self) -> &NetworkState {
        &self.state
    }

    pub fn peer_id(&self) -> Option<PeerId> {
        self.peer_id
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

        let connection_count = self.connection_count.clone();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("kivo-network")
            .build()
            .map_err(|e| format!("Failed to create tokio runtime: {e}"))?;

        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (state_tx, state_rx) = std::sync::mpsc::channel();
        let (listen_addr_tx, listen_addr_rx) = std::sync::mpsc::channel();

        rt.spawn(async move {
            let result = run_swarm(
                libp2p_keypair,
                peer_id,
                connection_count,
                cmd_rx,
                state_tx,
                listen_addr_tx,
            )
            .await;

            if let Err(e) = result {
                eprintln!("Network error: {e}");
            }
        });

        match listen_addr_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(_) => {}
            Err(_) => {
                self.cleanup_handle();
                self.state = NetworkState::Offline;
                self.peer_id = None;
                return Err("Unable to start network.".to_string());
            }
        }

        match state_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(NetworkState::Online) => {
                self.state = NetworkState::Online;
                self.handle = Some(NetworkHandle {
                    cmd_tx,
                    runtime: rt,
                });
                Ok(())
            }
            Ok(_) | Err(_) => {
                self.cleanup_handle();
                self.state = NetworkState::Offline;
                self.peer_id = None;
                Err("Unable to start network.".to_string())
            }
        }
    }

    pub fn stop(&mut self) -> Result<(), String> {
        if self.state != NetworkState::Online && self.state != NetworkState::Starting {
            return Err("Network is not running.".to_string());
        }

        if let Some(handle) = self.handle.take() {
            handle.shutdown();
            handle.runtime.shutdown_timeout(Duration::from_secs(3));
        }

        self.state = NetworkState::Stopped;
        self.connection_count.store(0, Ordering::Relaxed);

        Ok(())
    }

    pub fn reset(&mut self) {
        let _ = self.stop();
        self.state = NetworkState::Offline;
        self.peer_id = None;
    }

    pub fn dial(
        &self,
        address: Multiaddr,
        expected_peer_id: PeerId,
        kivo_id: String,
    ) -> Result<(), String> {
        let handle = self
            .handle
            .as_ref()
            .ok_or("Network is not running.".to_string())?;
        handle.dial(address, expected_peer_id, kivo_id)
    }

    pub fn get_listen_addresses(&self) -> Result<Vec<Multiaddr>, String> {
        let handle = self
            .handle
            .as_ref()
            .ok_or("Network is not running.".to_string())?;
        handle.get_listen_addresses()
    }

    pub fn get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, String> {
        let handle = self
            .handle
            .as_ref()
            .ok_or("Network is not running.".to_string())?;
        handle.get_connected_peers()
    }

    fn cleanup_handle(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
            handle.runtime.shutdown_timeout(Duration::from_secs(5));
        }
    }
}

async fn run_swarm(
    keypair: libp2p::identity::Keypair,
    local_peer_id: PeerId,
    connection_count: Arc<AtomicUsize>,
    mut cmd_rx: mpsc::Receiver<NetworkCommand>,
    state_tx: std::sync::mpsc::Sender<NetworkState>,
    listen_addr_tx: std::sync::mpsc::Sender<Multiaddr>,
) -> Result<(), String> {
    use libp2p::futures::StreamExt;
    use libp2p::SwarmBuilder;

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic_config(|config| config)
        .with_behaviour(|_| Ok(session::SessionBehaviour::new()))
        .map_err(|e| format!("Failed to build swarm: {e}"))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();

    let swarm_peer_id = *swarm.local_peer_id();
    if swarm_peer_id != local_peer_id {
        return Err(format!(
            "Identity mismatch: advertised PeerId={local_peer_id} but swarm derived PeerId={swarm_peer_id}"
        ));
    }

    let listen_addr: Multiaddr = "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap();
    swarm
        .listen_on(listen_addr)
        .map_err(|e| format!("Failed to listen: {e}"))?;

    let mut peer_kivo_ids: HashMap<PeerId, String> = HashMap::new();
    let mut listen_addresses: Vec<Multiaddr> = Vec::new();
    let mut peer_sessions: HashMap<PeerId, session::SessionState> = HashMap::new();

    let _ = state_tx.send(NetworkState::Online);

    loop {
        tokio::select! {
            event = swarm.next() => {
                match event {
                    Some(SwarmEvent::NewListenAddr { address, .. }) => {
                        listen_addresses.push(address.clone());
                        let _ = listen_addr_tx.send(address);
                    }
                    Some(SwarmEvent::ConnectionEstablished { peer_id: _, connection_id: _, num_established: _, .. }) => {
                        connection_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Some(SwarmEvent::ConnectionClosed { peer_id, connection_id: _, cause: _, .. }) => {
                        let _ = connection_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
                        peer_sessions.remove(&peer_id);
                    }
                    Some(SwarmEvent::OutgoingConnectionError { peer_id: _, error: _, .. }) => {
                    }
                    Some(SwarmEvent::IncomingConnectionError { error: _, .. }) => {
                    }
                    Some(SwarmEvent::Dialing { peer_id: _, .. }) => {
                    }
                    Some(SwarmEvent::Behaviour(session_event)) => {
                        peer_sessions.insert(session_event.peer, session_event.state);
                    }
                    _ => {}
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(NetworkCommand::Dial { address, expected_peer_id, kivo_id, response }) => {
                        peer_kivo_ids.insert(expected_peer_id, kivo_id);
                        let result = swarm.dial(address).map_err(|e| format!("Dial failed: {e}"));
                        let _ = response.send(result);
                    }
                    Some(NetworkCommand::GetListenAddresses { response }) => {
                        let addrs: Vec<Multiaddr> = swarm.listeners().cloned().collect();
                        let _ = response.send(Ok(addrs));
                    }
                    Some(NetworkCommand::GetConnectedPeers { response }) => {
                        let peers: Vec<ConnectedPeer> = swarm.connected_peers().map(|pid| {
                            ConnectedPeer {
                                peer_id: *pid,
                                kivo_id: peer_kivo_ids.get(pid).cloned(),
                                session_active: peer_sessions.get(pid) == Some(&session::SessionState::Active),
                            }
                        }).collect();
                        let _ = response.send(Ok(peers));
                    }
                    Some(NetworkCommand::DisconnectAll) => {
                        let peers: Vec<PeerId> = swarm.connected_peers().cloned().collect();
                        for peer in &peers {
                            let _ = swarm.disconnect_peer_id(*peer);
                        }
                    }
                    Some(NetworkCommand::Shutdown) => {
                        break;
                    }
                    None => break,
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
