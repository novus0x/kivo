use argon2::Config;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};

pub const PUBKEY_LEN: usize = 32;
pub const PRIVKEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

pub struct GeneratedKeypair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

pub fn generate_keypair() -> GeneratedKeypair {
    let mut csprng = UnwrapErr(SysRng);
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    GeneratedKeypair {
        signing_key,
        verifying_key,
    }
}

pub fn public_key_to_id(pubkey_bytes: &[u8]) -> String {
    let hash = Sha256::digest(pubkey_bytes);
    let hex_str = hex::encode(hash);
    format!("kivo:{hex_str}")
}

pub fn public_key_fingerprint(pubkey_bytes: &[u8]) -> String {
    let hash = Sha256::digest(pubkey_bytes);
    let hex_str = hex::encode(hash);
    let upper = hex_str.to_uppercase();
    upper
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_LEN];
    rand::fill(&mut salt[..]);
    salt
}

pub fn derive_encryption_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let config = Config {
        variant: argon2::Variant::Argon2id,
        ..Config::default()
    };
    let hash = argon2::hash_raw(password.as_bytes(), salt, &config).expect("Argon2id failed");
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&hash[..KEY_LEN]);
    key
}

pub fn encrypt_private_key(
    privkey_bytes: &[u8],
    encryption_key: &[u8; KEY_LEN],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = XChaCha20Poly1305::new(encryption_key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::fill(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, privkey_bytes)
        .map_err(|e| format!("Encrypt: {e}"))?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

pub fn decrypt_private_key(
    ciphertext: &[u8],
    nonce: &[u8],
    encryption_key: &[u8; KEY_LEN],
) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(encryption_key.into());
    let nonce = XNonce::try_from(nonce).map_err(|e| format!("Invalid nonce: {e}"))?;
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| "Decryption failed.".to_string())
}

pub fn verify_password_argon2(password: &str, encoded_hash: &str) -> bool {
    argon2::verify_encoded(encoded_hash, password.as_bytes()).unwrap_or(false)
}

pub fn hash_password_argon2(password: &str, salt: &[u8]) -> Result<String, String> {
    let config = Config::default();
    argon2::hash_encoded(password.as_bytes(), salt, &config).map_err(|e| e.to_string())
}
