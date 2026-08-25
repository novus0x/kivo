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


