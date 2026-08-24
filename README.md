# Kivo

Experimental decentralized peer-to-peer messaging written in Rust.

Kivo is built around a simple idea: the network should not depend on a single central server.

Each installation participates as a node. Direct peer-to-peer communication is preferred when possible, while discovery and relay infrastructure is designed to be replaceable.

> Kivo is experimental. Do not use it for sensitive or production communication.

## Current Status

Implemented:

* Ed25519 local cryptographic identity
* Deterministic Kivo ID derived from the public key
* Public key fingerprint
* XChaCha20-Poly1305 protection for the private identity key
* Argon2id password derivation and verification
* Persistent SQLite storage at `~/.kivo/kivo.db`
* Password-protected identity unlock
* Interactive CLI
* One-shot CLI commands
* Isolated in-memory databases for tests
* Basic node, peer, message, and contact structures

Not implemented yet:

* Contact exchange and verification
* Real peer-to-peer networking
* Message encryption
* Peer discovery
* DHT
* NAT traversal
* Hole punching
* Relay support
* Mobile clients
* Desktop GUI
* Group messaging
* Multi-device synchronization
* Full database encryption
* Security audit

## Design

Kivo keeps application interfaces separate from the protocol and core logic.

```text
CLI
Mobile UI
Desktop UI
     |
     v
  KivoApp
     |
     v
 Kivo Core
     |
     +--------+
     |        |
     v        v
 Network   Storage
```

The CLI is currently the primary interface.

Future mobile and desktop clients should use the same Kivo core rather than reimplementing identity, storage, networking, or protocol logic.

## Identity

Each Kivo identity is backed by an Ed25519 keypair.

The public key is used to derive a stable Kivo ID:

```text
public key
    |
    v
 SHA-256
    |
    v
kivo:<hex>
```

Example:

```text
Username: novus0x
ID: kivo:685a86d98b55941a97bcc88d133627316ff324041afcb7d726cbeacc1c120d24
Public key: 5004d82f82d55ef5d2898fc50786eb493ee3ffe055def512e3a6a8ca33c742f7
Fingerprint: 685A 86D9 8B55 941A 97BC C88D 1336 2731 6FF3 2404 1AFC B7D7 26CB EACC 1C12 0D24
```

The username is only a local display name. It is not a global identifier and does not need to be unique.

The private key is never shown by the CLI and is not stored in plaintext.

## Local Key Protection

When an identity is created:

```text
Password
   |
   v
Argon2id
   |
   v
Derived encryption key
   |
   v
XChaCha20-Poly1305
   |
   v
Encrypted Ed25519 private key
```

The encrypted private key is stored in SQLite together with the public identity information required to unlock it later.

Kivo also stores an Argon2id password verifier in PHC format.

The plaintext password is never stored.

The SQLite database itself is not encrypted yet.

## Storage

Kivo currently stores its local state at:

```text
~/.kivo/kivo.db
```

The database is created automatically when needed.

Current persistent identity data includes:

* username
* public key
* encrypted private key
* encryption nonce
* Argon2id password verifier
* key derivation salt

Tests do not use the real user database. Storage tests use isolated in-memory SQLite databases.

## CLI

The CLI is currently the main way to use Kivo.

Run:

```bash
cargo run
```

On the first run, Kivo creates a local identity:

```text
Welcome to Kivo

No local identity found.

Create a local identity

Username: novus
Password:
Confirm password:

Identity created.

Username: novus
ID: kivo:a1b2c3d4...

Kivo ready.

kivo>
```

On later runs, the existing identity is unlocked using the password:

```text
Welcome to Kivo

Identity: novus
Password:

Welcome back, novus.

Kivo ready.

kivo>
```

The interactive shell currently supports:

```text
help
status
identity
version
exit
quit
```

Example:

```text
kivo> identity

Username: novus
ID: kivo:a1b2c3d4...
Public key: 8f13d2...
Fingerprint: A1B2 C3D4 E5F6 ...

kivo> status

Kivo status

Node: running
Identity: novus
Storage: persistent
Network: not implemented

kivo> exit

Goodbye.
```

One-shot commands are also available:

```bash
cargo run -- status
cargo run -- version
cargo run -- help
```

## Architecture

The project is currently organized as:

```text
src/
├── app/
│   └── mod.rs
├── cli/
│   └── mod.rs
├── core/
│   ├── identity.rs
│   ├── crypto.rs
│   ├── contact.rs
│   └── message.rs
├── network/
│   ├── node.rs
│   ├── peer.rs
│   └── transport.rs
├── storage/
│   └── local.rs
├── utils/
│   └── mod.rs
└── main.rs
```

### `app`

Coordinates the application state and exposes the shared entry point used by interfaces.

### `cli`

Interactive and one-shot command-line interface.

### `core`

Identity, cryptography, contacts, messages, and other protocol-level domain types.

### `network`

Networking-related types and placeholders.

Real peer-to-peer transport is not implemented yet.

### `storage`

Local persistent storage backed by SQLite.

## Node Model

Kivo is designed so different devices can participate with different capabilities while speaking the same protocol.

A mobile device may eventually provide:

```text
messaging
peer-to-peer connectivity
```

A desktop may additionally provide:

```text
optional relay
```

An always-on machine such as a VPS or Raspberry Pi may eventually provide:

```text
peer-to-peer connectivity
optional relay
optional bootstrap
```

These roles are design targets and are not implemented yet.

## Design Principles

### No mandatory central server

Kivo should not require a permanent server controlled by the project creator.

### Replaceable infrastructure

Bootstrap and relay nodes must not become permanent trusted authorities.

Any individual node should be able to disappear without permanently breaking an established network.

### Local ownership

Identity data and conversation history should primarily belong to participating devices rather than a central service.

### Direct communication first

Direct peer-to-peer connections should be preferred whenever technically possible.

### Same protocol, different capabilities

Phones, desktops, Raspberry Pis, VPS nodes, and future clients should communicate using the same protocol.

### No custom cryptography

Kivo should use established cryptographic primitives and maintained libraries instead of inventing cryptographic algorithms.

### Keep the core independent

The CLI, mobile application, and future interfaces should not contain duplicate protocol logic.

## Security

Kivo is still experimental and provides no production security guarantees.

Currently implemented security-related components include:

* Ed25519 identity
* Argon2id password processing
* XChaCha20-Poly1305 private key protection
* password-protected local identity unlock

Important limitations:

* the SQLite database itself is not encrypted
* networking is not implemented
* message encryption is not implemented
* contact verification is not implemented
* the protocol has not been audited
* metadata protection has not been designed yet
* anonymity is not currently a guarantee

Do not use Kivo for sensitive or production communication.

## Roadmap

* [x] Initial Rust architecture
* [x] CLI-first application structure
* [x] Persistent local storage
* [x] Password-protected local identity
* [x] Ed25519 cryptographic identity
* [x] Deterministic Kivo ID
* [x] Encrypted private key at rest
* [ ] Contact identity model
* [ ] Contact exchange
* [ ] Fingerprint verification
* [ ] Authenticated connection between two local nodes
* [ ] Key agreement
* [ ] Encrypted one-to-one sessions
* [ ] Direct peer connectivity
* [ ] Peer discovery
* [ ] NAT traversal
* [ ] Hole punching
* [ ] Relay support
* [ ] Distributed routing / DHT
* [ ] Mobile integration
* [ ] Multi-device support
* [ ] Group messaging
* [ ] Database encryption
* [ ] Security review and hardening

The order may change as the protocol evolves.

## Development

Run the application:

```bash
cargo run
```

Run checks:

```bash
cargo fmt
cargo check
cargo test
```

Build the binary:

```bash
cargo build
```

Then run it directly on Linux or macOS:

```bash
./target/debug/kivo
```

## Contributing

Kivo is still defining its protocol and network architecture.

Contributions are welcome, but large architectural or cryptographic changes should be discussed before implementation.

Keep changes focused and avoid adding abstractions or dependencies without a concrete need.
