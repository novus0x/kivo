use std::fs;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};

use crate::core::crypto;
use crate::core::identity::Identity;

pub struct LocalStore {
    conn: Connection,
}

impl LocalStore {
    pub fn open() -> Result<Self, String> {
        let db_path = kivo_db_path()?;
        ensure_parent_dir(&db_path)?;
        let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
        init_schema(&conn)?;
        Ok(LocalStore { conn })
    }

    pub fn open_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        init_schema(&conn)?;
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
        let password_salt = crypto::generate_salt();
        let password_hash = crypto::hash_password_argon2(password, &password_salt)?;

        let enc_key = crypto::derive_encryption_key(password, &password_salt);
        let privkey_bytes = signing_key.to_bytes();
        let (encrypted_privkey, nonce) = crypto::encrypt_private_key(&privkey_bytes, &enc_key)?;

        self.conn
            .execute(
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

fn kivo_db_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("Cannot determine home directory")?;
    Ok(home.join(".kivo").join("kivo.db"))
}

fn ensure_parent_dir(path: &PathBuf) -> Result<(), String> {
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

fn init_schema(conn: &Connection) -> Result<(), String> {
    // Check if old schema exists (no public_key column).

    let has_legacy = conn
        .query_row("SELECT public_key FROM identity WHERE id = 1", [], |_row| {
            Ok(())
        })
        .is_err();

    if has_legacy {
        // Check if the table exists at all.

        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='identity'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;

        if table_exists {
            return Err(
                "Legacy development identity detected. This version requires a new cryptographic identity.\nDelete ~/.kivo/kivo.db and restart.".to_string()
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> LocalStore {
        LocalStore::open_memory().expect("Failed to open in-memory DB")
    }

    fn create_test_identity(name: &str) -> (Identity, SigningKey) {
        let kp = crypto::generate_keypair();
        let identity = Identity::new(name, kp.verifying_key.to_bytes().to_vec());
        (identity, kp.signing_key)
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
        // Verify key relationship.

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
    fn modified_ciphertext_fails_unlock() {
        let store = test_store();
        let (identity, signing_key) = create_test_identity("bob");
        store
            .save_new_identity(&identity, &signing_key, "secret")
            .unwrap();

        // Tamper with the encrypted private key in the DB.

        store
            .conn
            .execute(
                "UPDATE identity SET encrypted_private_key = zeroblob(64) WHERE id = 1",
                [],
            )
            .unwrap();

        assert!(store.unlock_with_password("secret").is_err());
    }

    #[test]
    fn identity_survives_reopen() {
        let dir = std::env::temp_dir().join("kivo_test_reopen_v2");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test.db");

        let (identity, signing_key) = create_test_identity("dave");

        {
            let conn = Connection::open(&db_path).unwrap();
            init_schema(&conn).unwrap();
            let store = LocalStore { conn };
            store
                .save_new_identity(&identity, &signing_key, "mypass")
                .unwrap();
        }

        {
            let conn = Connection::open(&db_path).unwrap();
            let store = LocalStore { conn };
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
        let store = test_store();
        // Create old-style table.

        store
            .conn
            .execute_batch("DROP TABLE IF EXISTS identity;")
            .unwrap();
        store
            .conn
            .execute_batch(
                "CREATE TABLE identity (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                identity_id TEXT NOT NULL,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL
            );",
            )
            .unwrap();
        store.conn.execute(
            "INSERT INTO identity (id, identity_id, username, password_hash) VALUES (1, 'old-id', 'olduser', 'hash')",
            [],
        ).unwrap();

        assert!(store.is_legacy_schema());
    }
}
