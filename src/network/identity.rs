use libp2p::identity;

pub fn kivo_pubkey_to_peer_id(pubkey_bytes: &[u8]) -> Result<identity::PeerId, String> {
    let public_key = identity::ed25519::PublicKey::try_from_bytes(pubkey_bytes)
        .map_err(|e| format!("Invalid Ed25519 public key: {e}"))?;
    Ok(identity::PeerId::from_public_key(&public_key.into()))
}

pub fn kivo_keypair_to_libp2p(
    signing_key_bytes: &[u8; 32],
    verifying_key_bytes: &[u8; 32],
) -> Result<(identity::Keypair, identity::PeerId), String> {
    let keypair = identity::Keypair::ed25519_from_bytes(signing_key_bytes.to_vec())
        .map_err(|e| format!("Failed to create libp2p keypair: {e}"))?;

    let public_key = identity::ed25519::PublicKey::try_from_bytes(verifying_key_bytes)
        .map_err(|e| format!("Invalid Ed25519 public key: {e}"))?;
    let peer_id = identity::PeerId::from_public_key(&public_key.into());

    Ok((keypair, peer_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_deterministic_from_pubkey() {
        let kp = crate::core::crypto::generate_keypair();
        let pubkey = kp.verifying_key.to_bytes();
        let pid1 = kivo_pubkey_to_peer_id(&pubkey).unwrap();
        let pid2 = kivo_pubkey_to_peer_id(&pubkey).unwrap();
        assert_eq!(pid1, pid2);
    }

    #[test]
    fn different_pubkeys_different_peer_ids() {
        let kp1 = crate::core::crypto::generate_keypair();
        let kp2 = crate::core::crypto::generate_keypair();
        let pid1 = kivo_pubkey_to_peer_id(&kp1.verifying_key.to_bytes()).unwrap();
        let pid2 = kivo_pubkey_to_peer_id(&kp2.verifying_key.to_bytes()).unwrap();
        assert_ne!(pid1, pid2);
    }

    #[test]
    fn keypair_to_libp2p_matches_pubkey_peer_id() {
        let kp = crate::core::crypto::generate_keypair();
        let signing_bytes = kp.signing_key.to_bytes();
        let verifying_bytes = kp.verifying_key.to_bytes();

        let (_, peer_id_from_keypair) =
            kivo_keypair_to_libp2p(&signing_bytes, &verifying_bytes).unwrap();
        let peer_id_from_pubkey = kivo_pubkey_to_peer_id(&verifying_bytes).unwrap();

        assert_eq!(peer_id_from_keypair, peer_id_from_pubkey);
    }

    #[test]
    fn invalid_pubkey_returns_error() {
        assert!(kivo_pubkey_to_peer_id(&[0u8; 16]).is_err());
    }
}
