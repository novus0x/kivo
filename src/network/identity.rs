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
