use ed25519_dalek::SigningKey;

use crate::core::crypto;
use crate::core::identity::Identity;
use crate::network::node::Node;
use crate::storage::local::LocalStore;

pub struct KivoApp {
    pub node: Node,
    pub store: LocalStore,
    pub signing_key: Option<SigningKey>,
}

impl KivoApp {
    pub fn new_with_identity(
        identity: Identity,
        signing_key: SigningKey,
        store: LocalStore,
    ) -> Self {
        let node = Node::new(identity);
        KivoApp {
            node,
            store,
            signing_key: Some(signing_key),
        }
    }

    pub fn start(&mut self) {
        self.node.start();
    }

    pub fn stop(&mut self) {
        self.node.stop();
    }

    pub fn verify_current_password(&self, password: &str) -> Result<(), String> {
        self.store.verify_password(password)
    }

    pub fn reset_identity(&mut self, new_username: &str, new_password: &str) -> Result<(), String> {
        let kp = crypto::generate_keypair();
        let new_identity = Identity::new(new_username, kp.verifying_key.to_bytes().to_vec());

        self.store
            .replace_identity(&new_identity, &kp.signing_key, new_password)?;

        self.node.identity = new_identity;
        self.signing_key = Some(kp.signing_key);

        Ok(())
    }
}
