use kivo::core::crypto;

#[test]
fn keypair_generation() {
    let kp = crypto::generate_keypair();
    let pubkey_bytes = kp.verifying_key.to_bytes();
    assert_eq!(pubkey_bytes.len(), crypto::PUBKEY_LEN);
}

#[test]
fn two_keypairs_differ() {
    let a = crypto::generate_keypair();
    let b = crypto::generate_keypair();
    assert_ne!(a.verifying_key.to_bytes(), b.verifying_key.to_bytes());
}

#[test]
fn kivo_id_deterministic() {
    let kp = crypto::generate_keypair();
    let pubkey = kp.verifying_key.to_bytes();
    let id1 = crypto::public_key_to_id(&pubkey);
    let id2 = crypto::public_key_to_id(&pubkey);
    assert_eq!(id1, id2);
    assert!(id1.starts_with("kivo:"));
}

#[test]
fn fingerprint_deterministic() {
    let kp = crypto::generate_keypair();
    let pubkey = kp.verifying_key.to_bytes();
    let f1 = crypto::public_key_fingerprint(&pubkey);
    let f2 = crypto::public_key_fingerprint(&pubkey);
    assert_eq!(f1, f2);
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = crypto::derive_encryption_key("password", &crypto::generate_salt());
    let privkey = crypto::generate_keypair().signing_key.to_bytes();
    let (ciphertext, nonce) = crypto::encrypt_private_key(&privkey, &key).unwrap();
    assert_ne!(ciphertext, privkey.as_slice());
    let decrypted = crypto::decrypt_private_key(&ciphertext, &nonce, &key).unwrap();
    assert_eq!(decrypted, privkey.as_slice());
}

#[test]
fn wrong_password_fails_decrypt() {
    let key_correct = crypto::derive_encryption_key("correct", &crypto::generate_salt());
    let key_wrong = crypto::derive_encryption_key("wrong", &crypto::generate_salt());
    let privkey = crypto::generate_keypair().signing_key.to_bytes();
    let (ciphertext, nonce) = crypto::encrypt_private_key(&privkey, &key_correct).unwrap();
    assert!(crypto::decrypt_private_key(&ciphertext, &nonce, &key_wrong).is_err());
}

#[test]
fn modified_ciphertext_fails_decrypt() {
    let key = crypto::derive_encryption_key("password", &crypto::generate_salt());
    let privkey = crypto::generate_keypair().signing_key.to_bytes();
    let (mut ciphertext, nonce) = crypto::encrypt_private_key(&privkey, &key).unwrap();
    ciphertext[0] ^= 0xff;
    assert!(crypto::decrypt_private_key(&ciphertext, &nonce, &key).is_err());
}

#[test]
fn modified_nonce_fails_decrypt() {
    let key = crypto::derive_encryption_key("password", &crypto::generate_salt());
    let privkey = crypto::generate_keypair().signing_key.to_bytes();
    let (ciphertext, mut nonce) = crypto::encrypt_private_key(&privkey, &key).unwrap();
    nonce[0] ^= 0xff;
    assert!(crypto::decrypt_private_key(&ciphertext, &nonce, &key).is_err());
}

#[test]
fn password_hash_and_verify() {
    let salt = crypto::generate_salt();
    let encoded = crypto::hash_password_argon2("secret", &salt).unwrap();
    assert!(crypto::verify_password_argon2("secret", &encoded));
    assert!(!crypto::verify_password_argon2("wrong", &encoded));
}
