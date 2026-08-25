use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use crate::app::KivoApp;
use crate::core::crypto;
use crate::core::identity::Identity;
use crate::storage::local::LocalStore;
use crate::utils::paths::KivoPaths;

pub fn run(args: Vec<String>) {
    let (data_dir, filtered_args) = parse_args(&args).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    let paths = KivoPaths::resolve(data_dir).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    match filtered_args.get(1).map(|s| s.as_str()) {
        Some("status") => one_shot_status(&paths),
        Some("version") => version(),
        Some(unknown) => {
            eprintln!("Unknown command: {unknown}\n");
            print_help();
        }
        None => interactive(&paths),
    }
}

pub fn parse_args(args: &[String]) -> Result<(Option<PathBuf>, Vec<String>), String> {
    let mut data_dir = None;
    let mut filtered = vec![args[0].clone()];
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--data-dir" {
            if data_dir.is_some() {
                return Err("Duplicate --data-dir flag.".to_string());
            }
            i += 1;
            if i >= args.len() {
                return Err("Missing value for --data-dir.".to_string());
            }
            data_dir = Some(PathBuf::from(&args[i]));
        } else {
            filtered.push(args[i].clone());
        }
        i += 1;
    }
    Ok((data_dir, filtered))
}

fn interactive(paths: &KivoPaths) {
    println!("Welcome to Kivo\n");

    let store = LocalStore::open(&paths.database).expect("Failed to open database");

    if store.is_legacy_schema() {
        eprintln!("Legacy development identity detected.");
        eprintln!("This version requires a new cryptographic identity.");
        eprintln!("Delete {} and restart.\n", paths.database.display());
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

pub fn dispatch(input: &str, app: &mut KivoApp) -> bool {
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
        "network address" => {
            network_address(app);
            false
        }
        "network peers" => {
            network_peers(app);
            false
        }
        line if line.starts_with("network connect ") => {
            let addr_str = line.strip_prefix("network connect ").unwrap().trim();
            network_connect(app, addr_str);
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

fn one_shot_status(paths: &KivoPaths) {
    match LocalStore::open(&paths.database) {
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
    println!("  help                           Show available commands");
    println!("  status                         Show node and identity status");
    println!("  identity                       Show current identity");
    println!("  network start                  Start the local P2P node");
    println!("  network stop                   Stop the local P2P node");
    println!("  network status                 Show network status");
    println!("  network address                Show listening addresses (dev)");
    println!("  network connect <multiaddr>    Connect to a peer");
    println!("  network peers                  Show connected peers");
    println!(
        "  reset identity                 Permanently delete the current identity and start over"
    );
    println!("  version                        Show version information");
    println!("  exit                           Exit Kivo");
    println!("  quit                           Exit Kivo");
}

fn print_help() {
    println!("Kivo - decentralized peer-to-peer messaging\n");
    println!("Usage:\n");
    println!("  kivo [--data-dir <path>]                    Start Kivo");
    println!("  kivo [--data-dir <path>] status             Show current node status");
    println!("  kivo [--data-dir <path>] version            Show version information");
    println!();
    println!("Options:\n");
    println!("  --data-dir <path>  Use an alternative local data directory");
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

fn network_address(app: &KivoApp) {
    if !app.network.is_online() {
        eprintln!("Network is not running.\n");
        return;
    }

    match app.network_listen_addresses() {
        Ok(addrs) if addrs.is_empty() => {
            println!("\nNo listening addresses.\n");
        }
        Ok(addrs) => {
            println!();
            for addr in &addrs {
                println!("{addr}");
            }
            println!();
        }
        Err(e) => {
            eprintln!("{e}\n");
        }
    }
}

fn network_connect(app: &mut KivoApp, addr_str: &str) {
    if !app.network.is_online() {
        eprintln!("Network is not running.\n");
        return;
    }

    let address: libp2p::Multiaddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("Invalid peer address.\n");
            return;
        }
    };

    let peer_id = match extract_peer_id_from_address(&address) {
        Some(pid) => pid,
        None => {
            eprintln!("Invalid peer address: missing PeerId.\n");
            return;
        }
    };

    println!("\nDialing...\n");

    match app.network_connect(address, peer_id, String::new()) {
        Ok(()) => {
            println!("Dial initiated. Use 'network status' to check connection.\n");
        }
        Err(e) => {
            eprintln!("Unable to dial peer: {e}\n");
        }
    }
}

fn extract_peer_id_from_address(address: &libp2p::Multiaddr) -> Option<libp2p::PeerId> {
    use libp2p::multiaddr::Protocol;
    for protocol in address.iter() {
        if let Protocol::P2p(peer_id) = protocol {
            return Some(peer_id);
        }
    }
    None
}

fn network_peers(app: &KivoApp) {
    if !app.network.is_online() {
        eprintln!("Network is not running.\n");
        return;
    }

    match app.network_connected_peers() {
        Ok(peers) => {
            println!();
            println!("Connected peers: {}", peers.len());
            for peer in &peers {
                println!();
                if let Some(ref kivo_id) = peer.kivo_id {
                    println!("Kivo ID: {kivo_id}");
                }
                println!("Peer ID: {}", peer.peer_id);
                if peer.session_active {
                    println!("Session: active");
                } else {
                    println!("Session: opening");
                }
            }
            println!();
        }
        Err(e) => {
            eprintln!("{e}\n");
        }
    }
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
