use std::fs;

use kivo::storage::local::LocalStore;
use rusqlite::Connection;

mod common;
use common::create_test_identity;

fn test_store() -> LocalStore {
    LocalStore::open_memory().expect("Failed to open in-memory DB")
}

#[test]
fn new_database_has_no_identity() {
    let store = test_store();
    assert!(!store.has_identity());
}

#[test]
fn save_and_load_identity() {
    let store = test_store();
    let (identity, signing_key) = create_test_identity("alice");
    store
        .save_new_identity(&identity, &signing_key, "pass123")
        .unwrap();

    let loaded = store.load_public_identity().expect("Identity not found");
    assert_eq!(loaded.name, "alice");
    assert_eq!(loaded.id, identity.id);
    assert_eq!(loaded.public_key, identity.public_key);
}

#[test]
fn unlock_with_correct_password() {
    let store = test_store();
    let (identity, signing_key) = create_test_identity("bob");
    store
        .save_new_identity(&identity, &signing_key, "secret")
        .unwrap();

    let unlocked = store.unlock_with_password("secret").unwrap();
    assert_eq!(unlocked.identity.name, "bob");
    assert_eq!(unlocked.identity.id, identity.id);

    assert_eq!(
        unlocked.signing_key.verifying_key().as_bytes(),
        identity.public_key.as_slice()
    );
}

#[test]
fn unlock_with_wrong_password_fails() {
    let store = test_store();
    let (identity, signing_key) = create_test_identity("bob");
    store
        .save_new_identity(&identity, &signing_key, "secret")
        .unwrap();

    assert!(store.unlock_with_password("wrong").is_err());
}

#[test]
fn identity_survives_reopen() {
    let dir = std::env::temp_dir().join("kivo_test_reopen_ext");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("test.db");

    let (identity, signing_key) = create_test_identity("dave");

    {
        let store = LocalStore::open(&db_path).unwrap();
        store
            .save_new_identity(&identity, &signing_key, "mypass")
            .unwrap();
    }

    {
        let store = LocalStore::open(&db_path).unwrap();
        let loaded = store.load_public_identity().unwrap();
        assert_eq!(loaded.name, "dave");
        assert_eq!(loaded.id, identity.id);
        assert_eq!(loaded.public_key, identity.public_key);

        let unlocked = store.unlock_with_password("mypass").unwrap();
        assert_eq!(
            unlocked.signing_key.verifying_key().as_bytes(),
            identity.public_key.as_slice()
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn legacy_schema_detected() {
    let dir = std::env::temp_dir().join("kivo_test_legacy_ext");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("test.db");

    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE identity (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                identity_id TEXT NOT NULL,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO identity (id, identity_id, username, password_hash) VALUES (1, 'old-id', 'olduser', 'hash')",
            [],
        )
        .unwrap();
    }

    let result = LocalStore::open(&db_path);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(e.contains("Legacy"));
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn verify_password_correct() {
    let store = test_store();
    let (identity, signing_key) = create_test_identity("alice");
    store
        .save_new_identity(&identity, &signing_key, "pass123")
        .unwrap();
    assert!(store.verify_password("pass123").is_ok());
}

#[test]
fn verify_password_wrong() {
    let store = test_store();
    let (identity, signing_key) = create_test_identity("alice");
    store
        .save_new_identity(&identity, &signing_key, "pass123")
        .unwrap();
    assert!(store.verify_password("wrong").is_err());
}

#[test]
fn verify_password_no_identity() {
    let store = test_store();
    assert!(store.verify_password("anything").is_err());
}

#[test]
fn replace_identity_works() {
    let mut store = test_store();
    let (old_identity, old_key) = create_test_identity("old");
    store
        .save_new_identity(&old_identity, &old_key, "oldpass")
        .unwrap();

    let (new_identity, new_key) = create_test_identity("new");
    store
        .replace_identity(&new_identity, &new_key, "newpass")
        .unwrap();

    let loaded = store.load_public_identity().unwrap();
    assert_eq!(loaded.name, "new");
    assert_eq!(loaded.id, new_identity.id);
    assert!(store.verify_password("newpass").is_ok());
    assert!(store.verify_password("oldpass").is_err());
}

#[test]
fn replace_identity_old_password_fails() {
    let mut store = test_store();
    let (old_identity, old_key) = create_test_identity("old");
    store
        .save_new_identity(&old_identity, &old_key, "oldpass")
        .unwrap();

    let (new_identity, new_key) = create_test_identity("new");
    store
        .replace_identity(&new_identity, &new_key, "newpass")
        .unwrap();

    assert!(store.unlock_with_password("oldpass").is_err());
    assert!(store.unlock_with_password("newpass").is_ok());
}

#[test]
fn replace_identity_different_kivo_id() {
    let mut store = test_store();
    let (old_identity, old_key) = create_test_identity("old");
    store
        .save_new_identity(&old_identity, &old_key, "oldpass")
        .unwrap();

    let (new_identity, new_key) = create_test_identity("new");
    store
        .replace_identity(&new_identity, &new_key, "newpass")
        .unwrap();

    assert_ne!(old_identity.id, new_identity.id);
    assert_ne!(old_identity.public_key, new_identity.public_key);
}

#[test]
fn replace_identity_persists() {
    let dir = std::env::temp_dir().join("kivo_test_replace_persist_ext");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("test.db");

    let (old_identity, old_key) = create_test_identity("old");
    {
        let store = LocalStore::open(&db_path).unwrap();
        store
            .save_new_identity(&old_identity, &old_key, "oldpass")
            .unwrap();
    }

    let (new_identity, new_key) = create_test_identity("new");
    {
        let mut store = LocalStore::open(&db_path).unwrap();
        store
            .replace_identity(&new_identity, &new_key, "newpass")
            .unwrap();
    }

    {
        let store = LocalStore::open(&db_path).unwrap();
        let loaded = store.load_public_identity().unwrap();
        assert_eq!(loaded.name, "new");
        assert_eq!(loaded.id, new_identity.id);
        assert!(store.unlock_with_password("newpass").is_ok());
        assert!(store.unlock_with_password("oldpass").is_err());
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn stores_with_different_paths_are_independent() {
    let dir_a = std::env::temp_dir().join("kivo_test_indep_a_ext");
    let dir_b = std::env::temp_dir().join("kivo_test_indep_b_ext");
    let _ = fs::remove_dir_all(&dir_a);
    let _ = fs::remove_dir_all(&dir_b);

    let db_a = dir_a.join("kivo.db");
    let db_b = dir_b.join("kivo.db");

    let store_a = LocalStore::open(&db_a).unwrap();
    let (identity_a, key_a) = create_test_identity("alice");
    store_a
        .save_new_identity(&identity_a, &key_a, "pass_a")
        .unwrap();
    drop(store_a);

    let store_b = LocalStore::open(&db_b).unwrap();
    assert!(!store_b.has_identity());
    drop(store_b);

    let store_a = LocalStore::open(&db_a).unwrap();
    assert!(store_a.has_identity());
    let loaded = store_a.load_public_identity().unwrap();
    assert_eq!(loaded.name, "alice");
    assert_eq!(loaded.id, identity_a.id);

    let _ = fs::remove_dir_all(&dir_a);
    let _ = fs::remove_dir_all(&dir_b);
}
