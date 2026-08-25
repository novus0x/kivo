use std::path::PathBuf;

use kivo::cli;
use kivo::core::crypto;
use kivo::core::identity::Identity;
use kivo::storage::local::LocalStore;

mod common;
use common::*;

#[test]
fn dispatch_help() {
    let mut app = create_test_app("test");
    assert!(!cli::dispatch("help", &mut app));
}

#[test]
fn dispatch_status() {
    let mut app = create_test_app("test");
    assert!(!cli::dispatch("status", &mut app));
}

#[test]
fn dispatch_identity() {
    let mut app = create_test_app("test");
    assert!(!cli::dispatch("identity", &mut app));
}

#[test]
fn dispatch_version() {
    let mut app = create_test_app("test");
    assert!(!cli::dispatch("version", &mut app));
}

#[test]
fn dispatch_exit() {
    let mut app = create_test_app("test");
    assert!(cli::dispatch("exit", &mut app));
}

#[test]
fn dispatch_quit() {
    let mut app = create_test_app("test");
    assert!(cli::dispatch("quit", &mut app));
}

#[test]
fn dispatch_unknown() {
    let mut app = create_test_app("test");
    assert!(!cli::dispatch("banana", &mut app));
}

#[test]
fn dispatch_network_stop() {
    let mut app = create_test_app("test");
    assert!(!cli::dispatch("network stop", &mut app));
}

#[test]
fn dispatch_network_status() {
    let mut app = create_test_app("test");
    assert!(!cli::dispatch("network status", &mut app));
}

#[test]
fn dispatch_network_address() {
    let mut app = create_test_app("test");
    assert!(!cli::dispatch("network address", &mut app));
}

#[test]
fn dispatch_network_peers() {
    let mut app = create_test_app("test");
    assert!(!cli::dispatch("network peers", &mut app));
}

#[test]
fn dispatch_network_connect_invalid_addr() {
    let mut app = create_test_app("test");
    assert!(!cli::dispatch("network connect not-an-address", &mut app));
}

#[test]
fn identity_persists_during_session() {
    let mut app = create_test_app("alice");
    let id = app.identity.id.clone();

    cli::dispatch("identity", &mut app);
    cli::dispatch("status", &mut app);
    assert_eq!(app.identity.id, id);
    assert_eq!(app.identity.name, "alice");
}

#[test]
fn no_identity_persisted_before_confirmation() {
    let store = LocalStore::open_memory().unwrap();
    assert!(!store.has_identity());
}

#[test]
fn identity_only_persisted_after_save() {
    let store = LocalStore::open_memory().unwrap();
    let kp = crypto::generate_keypair();
    let identity = Identity::new("testuser", kp.verifying_key.to_bytes().to_vec());

    store
        .save_new_identity(&identity, &kp.signing_key, "password123")
        .unwrap();
    assert!(store.has_identity());
    let loaded = store.load_public_identity().unwrap();
    assert_eq!(loaded.name, "testuser");
    assert_eq!(loaded.id, identity.id);
}

#[test]
fn reset_identity_works() {
    let mut app = create_test_app("old");
    let old_id = app.identity.id.clone();

    app.reset_identity("new", "newpass").unwrap();

    assert_eq!(app.identity.name, "new");
    assert_ne!(app.identity.id, old_id);
    assert!(app.verify_current_password("newpass").is_ok());
}

#[test]
fn reset_identity_new_id_different() {
    let mut app = create_test_app("old");
    let old_id = app.identity.id.clone();
    let old_pubkey = app.identity.public_key.clone();

    app.reset_identity("new", "newpass").unwrap();

    assert_ne!(app.identity.id, old_id);
    assert_ne!(app.identity.public_key, old_pubkey);
}

#[test]
fn reset_identity_persists_after_reopen() {
    let mut app = create_test_app("old");
    let old_id = app.identity.id.clone();
    let old_pubkey = app.identity.public_key.clone();

    app.reset_identity("new", "newpass").unwrap();

    assert_eq!(app.identity.name, "new");
    assert_ne!(app.identity.id, old_id);
    assert_ne!(app.identity.public_key, old_pubkey);
    assert!(app.verify_current_password("newpass").is_ok());
    assert!(app.verify_current_password("oldpass").is_err());
}

#[test]
fn network_initially_offline() {
    let app = create_test_app("test");
    assert!(!app.network.is_online());
}

#[test]
fn network_stop_when_offline_fails() {
    let mut app = create_test_app("test");
    assert!(app.network_stop().is_err());
}

#[test]
fn parse_data_dir_missing_value() {
    let args: Vec<String> = vec!["kivo".into(), "--data-dir".into()];
    let result = cli::parse_args(&args);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing value"));
}

#[test]
fn parse_data_dir_duplicate() {
    let args: Vec<String> = vec![
        "kivo".into(),
        "--data-dir".into(),
        "/tmp/a".into(),
        "--data-dir".into(),
        "/tmp/b".into(),
    ];
    let result = cli::parse_args(&args);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Duplicate"));
}

#[test]
fn parse_data_dir_with_status() {
    let args: Vec<String> = vec![
        "kivo".into(),
        "--data-dir".into(),
        "/tmp/a".into(),
        "status".into(),
    ];
    let (data_dir, filtered) = cli::parse_args(&args).unwrap();
    assert_eq!(data_dir, Some(PathBuf::from("/tmp/a")));
    assert_eq!(filtered, vec!["kivo", "status"]);
}

#[test]
fn parse_relative_path() {
    let args: Vec<String> = vec!["kivo".into(), "--data-dir".into(), "./dev/kivo-b".into()];
    let (data_dir, filtered) = cli::parse_args(&args).unwrap();
    assert_eq!(data_dir, Some(PathBuf::from("./dev/kivo-b")));
    assert_eq!(filtered, vec!["kivo"]);
}

#[test]
fn parse_no_data_dir() {
    let args: Vec<String> = vec!["kivo".into(), "status".into()];
    let (data_dir, filtered) = cli::parse_args(&args).unwrap();
    assert_eq!(data_dir, None);
    assert_eq!(filtered, vec!["kivo", "status"]);
}

#[test]
fn parse_unknown_args_preserved() {
    let args: Vec<String> = vec!["kivo".into(), "--unknown".into(), "foo".into()];
    let (data_dir, filtered) = cli::parse_args(&args).unwrap();
    assert_eq!(data_dir, None);
    assert_eq!(filtered, vec!["kivo", "--unknown", "foo"]);
}
