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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generation() {
        let kp = generate_keypair();
        let pubkey_bytes = kp.verifying_key.to_bytes();
        assert_eq!(pubkey_bytes.len(), PUBKEY_LEN);
    }

    #[test]
    fn two_keypairs_differ() {
        let a = generate_keypair();
        let b = generate_keypair();
        assert_ne!(a.verifying_key.to_bytes(), b.verifying_key.to_bytes());
    }

    #[test]
    fn kivo_id_deterministic() {
        let kp = generate_keypair();
        let pubkey = kp.verifying_key.to_bytes();
        let id1 = public_key_to_id(&pubkey);
        let id2 = public_key_to_id(&pubkey);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("kivo:"));
    }

    #[test]
    fn fingerprint_deterministic() {
        let kp = generate_keypair();
        let pubkey = kp.verifying_key.to_bytes();
        let f1 = public_key_fingerprint(&pubkey);
        let f2 = public_key_fingerprint(&pubkey);
        assert_eq!(f1, f2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_encryption_key("password", &generate_salt());
        let privkey = generate_keypair().signing_key.to_bytes();
        let (ciphertext, nonce) = encrypt_private_key(&privkey, &key).unwrap();
        assert_ne!(ciphertext, privkey.as_slice());
        let decrypted = decrypt_private_key(&ciphertext, &nonce, &key).unwrap();
        assert_eq!(decrypted, privkey.as_slice());
    }

    #[test]
    fn wrong_password_fails_decrypt() {
        let key_correct = derive_encryption_key("correct", &generate_salt());
        let key_wrong = derive_encryption_key("wrong", &generate_salt());
        let privkey = generate_keypair().signing_key.to_bytes();
        let (ciphertext, nonce) = encrypt_private_key(&privkey, &key_correct).unwrap();
        assert!(decrypt_private_key(&ciphertext, &nonce, &key_wrong).is_err());
    }

    #[test]
    fn modified_ciphertext_fails_decrypt() {
        let key = derive_encryption_key("password", &generate_salt());
        let privkey = generate_keypair().signing_key.to_bytes();
        let (mut ciphertext, nonce) = encrypt_private_key(&privkey, &key).unwrap();
        ciphertext[0] ^= 0xff;
        assert!(decrypt_private_key(&ciphertext, &nonce, &key).is_err());
    }

    #[test]
    fn modified_nonce_fails_decrypt() {
        let key = derive_encryption_key("password", &generate_salt());
        let privkey = generate_keypair().signing_key.to_bytes();
        let (ciphertext, mut nonce) = encrypt_private_key(&privkey, &key).unwrap();
        nonce[0] ^= 0xff;
        assert!(decrypt_private_key(&ciphertext, &nonce, &key).is_err());
    }

    #[test]
    fn password_hash_and_verify() {
        let salt = generate_salt();
        let encoded = hash_password_argon2("secret", &salt).unwrap();
        assert!(verify_password_argon2("secret", &encoded));
        assert!(!verify_password_argon2("wrong", &encoded));
    }
}
