use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};

use crate::core::crypto;
use crate::core::identity::Identity;

pub struct LocalStore {
    conn: Connection,
}

impl LocalStore {
    pub fn open(db_path: &Path) -> Result<Self, String> {
        ensure_parent_dir(db_path)?;
        let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
        init_schema(&conn, db_path)?;
        Ok(LocalStore { conn })
    }

    pub fn open_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        init_schema(&conn, Path::new(":memory:"))?;
        Ok(LocalStore { conn })
    }

    pub fn has_identity(&self) -> bool {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM identity", [], |row| row.get(0))
            .unwrap_or(0);
        count > 0
    }

    pub fn save_new_identity(
        &self,
        identity: &Identity,
        signing_key: &SigningKey,
        password: &str,
    ) -> Result<(), String> {
        insert_identity(&self.conn, identity, signing_key, password)
    }

    pub fn verify_password(&self, password: &str) -> Result<(), String> {
        let password_hash: String = self
            .conn
            .query_row(
                "SELECT password_hash FROM identity WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| "No identity found.".to_string())?;

        if crypto::verify_password_argon2(password, &password_hash) {
            Ok(())
        } else {
            Err("Invalid password.".to_string())
        }
    }

    pub fn replace_identity(
        &mut self,
        new_identity: &Identity,
        new_signing_key: &SigningKey,
        new_password: &str,
    ) -> Result<(), String> {
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM identity WHERE id = 1", [])
            .map_err(|e| e.to_string())?;
        insert_identity(&tx, new_identity, new_signing_key, new_password)?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn load_public_identity(&self) -> Option<Identity> {
        self.conn
            .query_row(
                "SELECT username, identity_id, public_key FROM identity WHERE id = 1",
                [],
                |row| {
                    let name: String = row.get(0)?;
                    let id: String = row.get(1)?;
                    let public_key: Vec<u8> = row.get(2)?;
                    Ok(Identity {
                        id,
                        name,
                        public_key,
                    })
                },
            )
            .ok()
    }

    pub fn unlock_with_password(&self, password: &str) -> Result<UnlockedIdentity, String> {
        let row: (String, String, Vec<u8>, Vec<u8>, Vec<u8>, String, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT identity_id, username, public_key, encrypted_private_key, private_key_nonce, password_hash, encryption_salt FROM identity WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .map_err(|e| e.to_string())?;

        let (id, name, public_key, encrypted_privkey, nonce, password_hash, enc_salt) = row;

        if !crypto::verify_password_argon2(password, &password_hash) {
            return Err("Invalid password.".to_string());
        }

        let enc_key = crypto::derive_encryption_key(password, &enc_salt);
        let privkey_bytes = crypto::decrypt_private_key(&encrypted_privkey, &nonce, &enc_key)?;

        let signing_key = SigningKey::from_bytes(
            privkey_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid private key length".to_string())?,
        );
        let verifying_key = signing_key.verifying_key();

        // Validate that the public key matches the private key.

        if verifying_key.as_bytes() != public_key.as_slice() {
            return Err("Identity corrupted: key mismatch.".to_string());
        }

        let identity = Identity {
            id,
            name,
            public_key,
        };

        Ok(UnlockedIdentity {
            identity,
            signing_key,
        })
    }

    // Legacy schema detection for migration guidance.

    pub fn is_legacy_schema(&self) -> bool {
        self.conn
            .query_row("SELECT public_key FROM identity WHERE id = 1", [], |_row| {
                Ok(())
            })
            .is_err()
            && self.has_identity()
    }
}

pub struct UnlockedIdentity {
    pub identity: Identity,
    pub signing_key: SigningKey,
}

fn insert_identity(
    conn: &Connection,
    identity: &Identity,
    signing_key: &SigningKey,
    password: &str,
) -> Result<(), String> {
    let password_salt = crypto::generate_salt();
    let password_hash = crypto::hash_password_argon2(password, &password_salt)?;
    let enc_key = crypto::derive_encryption_key(password, &password_salt);
    let privkey_bytes = signing_key.to_bytes();
    let (encrypted_privkey, nonce) = crypto::encrypt_private_key(&privkey_bytes, &enc_key)?;

    conn.execute(
        "INSERT INTO identity (id, identity_id, username, public_key, encrypted_private_key, private_key_nonce, password_hash, encryption_salt) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            identity.id,
            identity.name,
            identity.public_key,
            encrypted_privkey,
            nonce,
            password_hash,
            password_salt,
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o700);
                fs::set_permissions(parent, perms).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

fn init_schema(conn: &Connection, db_path: &Path) -> Result<(), String> {
    let has_legacy = conn
        .query_row("SELECT public_key FROM identity WHERE id = 1", [], |_row| {
            Ok(())
        })
        .is_err();

    if has_legacy {
        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='identity'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;

        if table_exists {
            return Err(format!(
                "Legacy development identity detected. This version requires a new cryptographic identity.\nDelete {} and restart.",
                db_path.display()
            ));
        }
    }

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS identity (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            identity_id TEXT NOT NULL,
            username TEXT NOT NULL,
            public_key BLOB NOT NULL,
            encrypted_private_key BLOB NOT NULL,
            private_key_nonce BLOB NOT NULL,
            password_hash TEXT NOT NULL,
            encryption_salt BLOB NOT NULL
        );",
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
