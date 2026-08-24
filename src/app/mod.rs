use ed25519_dalek::SigningKey;

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
}
