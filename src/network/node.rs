use crate::core::identity::Identity;

pub struct Node {
    pub identity: Identity,
    pub is_running: bool,
}

impl Node {
    pub fn new(identity: Identity) -> Self {
        Node {
            identity,
            is_running: false,
        }
    }

    pub fn start(&mut self) {
        // TODO: initialise libp2p swarm and begin listening.
        self.is_running = true;
    }

    pub fn stop(&mut self) {
        // TODO: shut down swarm and release ports.
        self.is_running = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_starts_and_stops() {
        let identity = Identity::new("Test", vec![0u8; 32]);
        let mut node = Node::new(identity);
        assert!(!node.is_running);

        node.start();
        assert!(node.is_running);

        node.stop();
        assert!(!node.is_running);
    }
}
