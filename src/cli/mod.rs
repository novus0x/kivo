use std::io::{self, BufRead, Write};

use crate::app::KivoApp;
use crate::core::crypto;
use crate::core::identity::Identity;
use crate::storage::local::LocalStore;

pub fn run(args: Vec<String>) {
    match args.get(1).map(|s| s.as_str()) {
        Some("status") => one_shot_status(),
        Some("version") => version(),
        Some(unknown) => {
            eprintln!("Unknown command: {unknown}\n");
            print_help();
        }
        None => interactive(),
    }
}

fn interactive() {
    println!("Welcome to Kivo\n");

    let store = LocalStore::open().expect("Failed to open database");

    if store.is_legacy_schema() {
        eprintln!("Legacy development identity detected.");
        eprintln!("This version requires a new cryptographic identity.");
        eprintln!("Delete ~/.kivo/kivo.db and restart.\n");
        return;
    }

    let mut app = if store.has_identity() {
        let identity = store.load_public_identity().expect("Identity disappeared");
        println!("Identity: {}\n", identity.name);

        let password = prompt_password();
        let unlocked = match store.unlock_with_password(&password) {
            Ok(u) => u,
            Err(_) => loop {
                eprintln!("Invalid password.\n");
                let retry = prompt_password();
                match store.unlock_with_password(&retry) {
                    Ok(u) => break u,
                    Err(_) => continue,
                }
            },
        };
        drop(password);

        println!("\nWelcome back, {}.\n", unlocked.identity.name);

        KivoApp::new_with_identity(unlocked.identity, unlocked.signing_key, store)
    } else {
        println!("No local identity found.\n");
        println!("Create a local identity\n");

        let username = prompt_username();
        let password = prompt_password_confirm();

        let kp = crypto::generate_keypair();
        let identity = Identity::new(&username, kp.verifying_key.to_bytes().to_vec());

        store
            .save_new_identity(&identity, &kp.signing_key, &password)
            .expect("Failed to save identity");

        drop(password);

        println!("\nIdentity created.\n");
        println!("Username: {}", identity.name);
        println!("ID: {}\n", identity.id);

        KivoApp::new_with_identity(identity, kp.signing_key, store)
    };

    println!("Network: offline\n");
    println!("Kivo ready.\n");
    shell(&mut app);
}

fn shell(app: &mut KivoApp) {
    loop {
        print!("kivo> ");
        io::stdout().flush().unwrap();

        let mut line = String::new();
        let read_result = io::stdin().lock().read_line(&mut line);

        match read_result {
            Ok(0) => {
                println!("\nGoodbye.");
                break;
            }
            Ok(_) => {
                let input = line.trim().to_string();
                if input.is_empty() {
                    continue;
                }
                if dispatch(&input, app) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn dispatch(input: &str, app: &mut KivoApp) -> bool {
    match input {
        "help" => {
            shell_help();
            false
        }
        "status" => {
            status(app);
            false
        }
        "identity" => {
            identity(app);
            false
        }
        "version" => {
            version();
            false
        }
        "reset identity" => {
            reset_identity(app);
            false
        }
        "network start" => {
            network_start(app);
            false
        }
        "network stop" => {
            network_stop(app);
            false
        }
        "network status" => {
            network_status(app);
            false
        }
        "exit" | "quit" => {
            if app.network.is_online() {
                println!("Stopping network...");
                if app.network_stop().is_ok() {
                    println!("Network stopped.");
                }
            }
            println!("Goodbye.");
            true
        }
        other => {
            println!("Unknown command: {other}");
            println!("Type 'help' to see available commands.");
            false
        }
    }
}

fn one_shot_status() {
    match LocalStore::open() {
        Ok(store) => {
            println!("\nKivo status\n");
            println!("Storage: persistent");
            if store.has_identity() {
                println!("Identity: configured\n");
            } else {
                println!("Identity: not configured\n");
            }
        }
        Err(_) => {
            println!("\nKivo status\n");
            println!("Storage: not available");
            println!("Identity: not configured\n");
        }
    }
}

fn shell_help() {
    println!("Commands:\n");
    println!("  help            Show available commands");
    println!("  status          Show node and identity status");
    println!("  identity        Show current identity");
    println!("  network start   Start the local P2P node");
    println!("  network stop    Stop the local P2P node");
    println!("  network status  Show network status");
    println!("  reset identity  Permanently delete the current identity and start over");
    println!("  version         Show version information");
    println!("  exit            Exit Kivo");
    println!("  quit            Exit Kivo");
}

fn print_help() {
    println!("Kivo - decentralized peer-to-peer messaging\n");
    println!("Usage:\n");
    println!("  kivo             Start Kivo and create a local identity");
    println!("  kivo status      Show current node status");
    println!("  kivo version     Show version information");
}

fn prompt_username() -> String {
    loop {
        print!("Username: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let trimmed = input.trim().to_string();

        if !trimmed.is_empty() {
            return trimmed;
        }
        eprintln!("Username cannot be empty.");
    }
}

fn prompt_password() -> String {
    loop {
        let password = rpassword::prompt_password("Password: ").unwrap();
        if password.is_empty() {
            eprintln!("Password cannot be empty.");
            continue;
        }
        return password;
    }
}

fn prompt_password_confirm() -> String {
    loop {
        let password = prompt_password();
        let confirm = rpassword::prompt_password("Confirm password: ").unwrap();
        if passwords_match(&password, &confirm) {
            return password;
        }
        eprintln!("Passwords do not match.\n");
    }
}

fn passwords_match(a: &str, b: &str) -> bool {
    a == b
}

fn status(app: &KivoApp) {
    println!("\nKivo status\n");
    println!("Identity: {}", app.identity.name);
    println!("Identity ID: {}", app.identity.id);
    println!("Storage: persistent");
    let net = if app.network.is_online() {
        "online"
    } else {
        "offline"
    };
    println!("Network: {net}\n");
}

fn identity(app: &KivoApp) {
    println!("\nUsername: {}", app.identity.name);
    println!("ID: {}", app.identity.id);
    println!("Public key: {}", hex::encode(&app.identity.public_key));
    println!("Fingerprint: {}\n", app.identity.fingerprint());
}

fn network_start(app: &mut KivoApp) {
    println!("Starting Kivo network...\n");

    match app.network_start() {
        Ok(()) => {
            println!("Network: online");
            println!("Identity: {}", app.identity.id);
            println!("Transport: QUIC");
            if let Some(pid) = app.network.peer_id() {
                println!("Peer ID: {pid}");
            }
            println!();
        }
        Err(e) => {
            eprintln!("{e}\n");
        }
    }
}

fn network_stop(app: &mut KivoApp) {
    match app.network_stop() {
        Ok(()) => {
            println!("Network stopped.\n");
        }
        Err(e) => {
            eprintln!("{e}\n");
        }
    }
}

fn network_status(app: &KivoApp) {
    println!();
    if app.network.is_online() {
        println!("Network: online");
        println!("Identity: {}", app.identity.id);
        println!("Transport: QUIC");
        println!("Connections: {}", app.network.connection_count());
        if let Some(pid) = app.network.peer_id() {
            println!("Peer ID: {pid}");
        }
    } else {
        println!("Network: offline");
    }
    println!();
}

fn reset_identity(app: &mut KivoApp) {
    println!("This will permanently delete your current identity and all local data.\n");
    println!("Current identity:");
    println!("Username: {}", app.identity.name);
    println!("ID: {}\n", app.identity.id);

    let password = prompt_password_custom("Current password: ");

    if app.verify_current_password(&password).is_err() {
        eprintln!("\nInvalid password.");
        eprintln!("Identity was not changed.\n");
        return;
    }

    println!("\nThis action cannot be undone.\n");
    print!("Type RESET to continue: ");
    io::stdout().flush().unwrap();

    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm).unwrap();

    if confirm.trim() != "RESET" {
        eprintln!("\nReset cancelled.\n");
        return;
    }

    println!("\nCreate a new local identity\n");
    let username = prompt_username();
    let password = prompt_password_confirm();

    match app.reset_identity(&username, &password) {
        Ok(()) => {
            println!("\nIdentity reset successfully.\n");
            println!("Username: {}", app.identity.name);
            println!("ID: {}\n", app.identity.id);
            println!("Network: offline\n");
        }
        Err(_) => {
            eprintln!("\nUnable to reset identity.");
            eprintln!("Your existing identity was not changed.\n");
        }
    }
}

fn prompt_password_custom(msg: &str) -> String {
    loop {
        let password = rpassword::prompt_password(msg).unwrap();
        if !password.is_empty() {
            return password;
        }
        eprintln!("Password cannot be empty.");
    }
}

fn version() {
    println!("kivo {}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto;

    fn create_test_app(name: &str) -> KivoApp {
        let store = LocalStore::open_memory().unwrap();
        let kp = crypto::generate_keypair();
        let identity = Identity::new(name, kp.verifying_key.to_bytes().to_vec());
        KivoApp::new_with_identity(identity, kp.signing_key, store)
    }

    #[test]
    fn dispatch_help() {
        let mut app = create_test_app("test");
        assert!(!dispatch("help", &mut app));
    }

    #[test]
    fn dispatch_status() {
        let mut app = create_test_app("test");
        assert!(!dispatch("status", &mut app));
    }

    #[test]
    fn dispatch_identity() {
        let mut app = create_test_app("test");
        assert!(!dispatch("identity", &mut app));
    }

    #[test]
    fn dispatch_version() {
        let mut app = create_test_app("test");
        assert!(!dispatch("version", &mut app));
    }

    #[test]
    fn dispatch_exit() {
        let mut app = create_test_app("test");
        assert!(dispatch("exit", &mut app));
    }

    #[test]
    fn dispatch_quit() {
        let mut app = create_test_app("test");
        assert!(dispatch("quit", &mut app));
    }

    #[test]
    fn dispatch_unknown() {
        let mut app = create_test_app("test");
        assert!(!dispatch("banana", &mut app));
    }

    #[test]
    fn dispatch_network_stop() {
        let mut app = create_test_app("test");
        assert!(!dispatch("network stop", &mut app));
    }

    #[test]
    fn dispatch_network_status() {
        let mut app = create_test_app("test");
        assert!(!dispatch("network status", &mut app));
    }

    #[test]
    fn identity_persists_during_session() {
        let mut app = create_test_app("alice");
        let id = app.identity.id.clone();

        dispatch("identity", &mut app);
        dispatch("status", &mut app);
        assert_eq!(app.identity.id, id);
        assert_eq!(app.identity.name, "alice");
    }

    #[test]
    fn passwords_match_positive() {
        assert!(passwords_match("secret", "secret"));
    }

    #[test]
    fn passwords_match_negative() {
        assert!(!passwords_match("secret", "other"));
    }

    #[test]
    fn passwords_match_empty() {
        assert!(passwords_match("", ""));
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
}
