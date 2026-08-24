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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_identity_deterministic_id() {
        let pubkey = crypto::generate_keypair().verifying_key.to_bytes().to_vec();
        let a = Identity::new("alice", pubkey.clone());
        let b = Identity::new("alice", pubkey);
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn different_keys_different_ids() {
        let a = Identity::new(
            "a",
            crypto::generate_keypair().verifying_key.to_bytes().to_vec(),
        );
        let b = Identity::new(
            "b",
            crypto::generate_keypair().verifying_key.to_bytes().to_vec(),
        );
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn id_starts_with_kivo() {
        let id = Identity::new(
            "test",
            crypto::generate_keypair().verifying_key.to_bytes().to_vec(),
        );
        assert!(id.id.starts_with("kivo:"));
    }

    #[test]
    fn fingerprint_deterministic() {
        let pubkey = crypto::generate_keypair().verifying_key.to_bytes().to_vec();
        let id = Identity::new("test", pubkey);
        assert_eq!(id.fingerprint(), id.fingerprint());
    }
}
