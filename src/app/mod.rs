use ed25519_dalek::SigningKey;
use libp2p::{Multiaddr, PeerId};

use crate::core::crypto;
use crate::core::identity::Identity;
use crate::network::node::{ConnectedPeer, NetworkNode};
use crate::storage::local::LocalStore;

pub struct KivoApp {
    pub identity: Identity,
    pub store: LocalStore,
    pub signing_key: Option<SigningKey>,
    pub network: NetworkNode,
}

impl KivoApp {
    pub fn new_with_identity(
        identity: Identity,
        signing_key: SigningKey,
        store: LocalStore,
    ) -> Self {
        KivoApp {
            identity,
            store,
            signing_key: Some(signing_key),
            network: NetworkNode::new(),
        }
    }

    pub fn verify_current_password(&self, password: &str) -> Result<(), String> {
        self.store.verify_password(password)
    }

    pub fn reset_identity(&mut self, new_username: &str, new_password: &str) -> Result<(), String> {
        if self.network.is_online() {
            self.network
                .stop()
                .map_err(|e| format!("Cannot reset identity while network is running: {e}"))?;
        }

        let kp = crypto::generate_keypair();
        let new_identity = Identity::new(new_username, kp.verifying_key.to_bytes().to_vec());

        self.store
            .replace_identity(&new_identity, &kp.signing_key, new_password)?;

        self.identity = new_identity;
        self.signing_key = Some(kp.signing_key);
        self.network.reset();

        Ok(())
    }

    pub fn network_start(&mut self) -> Result<(), String> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or("No signing key available.".to_string())?;

        self.network.start(&self.identity, &signing_key.to_bytes())
    }

    pub fn network_stop(&mut self) -> Result<(), String> {
        self.network.stop()
    }

    pub fn network_connect(
        &self,
        address: Multiaddr,
        expected_peer_id: PeerId,
        kivo_id: String,
    ) -> Result<(), String> {
        self.network.dial(address, expected_peer_id, kivo_id)
    }

    pub fn network_listen_addresses(&self) -> Result<Vec<Multiaddr>, String> {
        self.network.get_listen_addresses()
    }

    pub fn network_connected_peers(&self) -> Result<Vec<ConnectedPeer>, String> {
        self.network.get_connected_peers()
    }
}
