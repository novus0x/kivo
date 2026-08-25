use crate::core::crypto;

pub struct Identity {
    pub id: String,
    pub name: String,
    pub public_key: Vec<u8>,
}

impl Identity {
    pub fn new(name: &str, public_key: Vec<u8>) -> Self {
        let id = crypto::public_key_to_id(&public_key);
        Identity {
            id,
            name: name.to_string(),
            public_key,
        }
    }

    pub fn fingerprint(&self) -> String {
        crypto::public_key_fingerprint(&self.public_key)
    }
}
