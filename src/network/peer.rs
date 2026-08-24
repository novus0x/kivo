pub struct Peer {
    pub identity_id: String,
    pub address: String,
}

impl Peer {
    pub fn new(identity_id: &str, address: &str) -> Self {
        Peer {
            identity_id: identity_id.to_string(),
            address: address.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_stores_fields() {
        let peer = Peer::new("kivo-3", "127.0.0.1:4000");
        assert_eq!(peer.identity_id, "kivo-3");
        assert_eq!(peer.address, "127.0.0.1:4000");
    }
}
