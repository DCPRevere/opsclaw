//! Secret references and the encrypted at-rest store.
//!
//! Config refers to secrets by name only: `env:VAR` or `store:KEY` (brief
//! invariant #3). Values are resolved at connect time; every resolved value
//! must be registered with the policy layer's output scrubber so it can never
//! appear in tool output, logs, or audit records.
//!
//! The store is a single AES-256-GCM-encrypted JSON map on disk
//! (`~/.opsclaw/secrets.enc`), keyed by a 32-byte key file
//! (`~/.opsclaw/secret.key`, mode 0600) — the same primitives gianna uses for
//! OAuth-token encryption at rest.

use std::fmt;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// A by-name reference to a secret. Serialized as `"env:VAR"` / `"store:KEY"`.
/// Cannot hold a value — that is the point.
#[derive(Clone, PartialEq, Eq)]
pub enum SecretRef {
    Env(String),
    Store(String),
}

impl SecretRef {
    pub fn env(name: impl Into<String>) -> Self {
        SecretRef::Env(name.into())
    }

    pub fn store(name: impl Into<String>) -> Self {
        SecretRef::Store(name.into())
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s.split_once(':') {
            Some(("env", name)) if !name.is_empty() => Ok(SecretRef::Env(name.to_string())),
            Some(("store", name)) if !name.is_empty() => Ok(SecretRef::Store(name.to_string())),
            _ => Err(Error::Config(format!(
                "malformed secret reference {s:?} (expected env:VAR or store:KEY)"
            ))),
        }
    }

    /// Resolve to the actual value. Callers must hand the value to the output
    /// scrubber before first use against a remote system.
    pub fn resolve(&self, store: &SecretStore) -> Result<String> {
        match self {
            SecretRef::Env(name) => std::env::var(name)
                .map_err(|_| Error::Config(format!("secret env var {name} is not set"))),
            SecretRef::Store(name) => store
                .get(name)?
                .ok_or_else(|| Error::Config(format!("secret {name:?} not found in store"))),
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretRef::Env(n) => write!(f, "env:{n}"),
            SecretRef::Store(n) => write!(f, "store:{n}"),
        }
    }
}

// Debug prints the reference, never a value (it cannot hold one, but keep the
// output identical to Display so log lines stay name-only by inspection).
impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretRef({self})")
    }
}

impl Serialize for SecretRef {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SecretRef::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Encrypted key/value store for secrets at rest.
pub struct SecretStore {
    key_path: PathBuf,
    store_path: PathBuf,
}

const NONCE_LEN: usize = 12;

impl SecretStore {
    /// Open the store rooted at `dir`, creating the key file on first use.
    pub fn open(dir: &Path) -> Result<SecretStore> {
        std::fs::create_dir_all(dir)?;
        let store =
            SecretStore { key_path: dir.join("secret.key"), store_path: dir.join("secrets.enc") };
        if !store.key_path.exists() {
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key);
            std::fs::write(&store.key_path, key)?;
            restrict_permissions(&store.key_path)?;
        }
        Ok(store)
    }

    pub fn get(&self, name: &str) -> Result<Option<String>> {
        Ok(self.read_map()?.remove(name))
    }

    pub fn set(&self, name: &str, value: &str) -> Result<()> {
        let mut map = self.read_map()?;
        map.insert(name.to_string(), value.to_string());
        self.write_map(&map)
    }

    pub fn remove(&self, name: &str) -> Result<bool> {
        let mut map = self.read_map()?;
        let existed = map.remove(name).is_some();
        if existed {
            self.write_map(&map)?;
        }
        Ok(existed)
    }

    /// Names only — safe to show in `opsclaw_config` inventory output.
    pub fn names(&self) -> Result<Vec<String>> {
        let mut names: Vec<String> = self.read_map()?.into_keys().collect();
        names.sort();
        Ok(names)
    }

    fn cipher(&self) -> Result<Aes256Gcm> {
        let key = std::fs::read(&self.key_path)?;
        Aes256Gcm::new_from_slice(&key)
            .map_err(|_| Error::Config("secret.key is not a valid 32-byte key".into()))
    }

    fn read_map(&self) -> Result<std::collections::HashMap<String, String>> {
        if !self.store_path.exists() {
            return Ok(Default::default());
        }
        let raw = std::fs::read(&self.store_path)?;
        if raw.len() < NONCE_LEN {
            return Err(Error::Config("secrets.enc is corrupt (too short)".into()));
        }
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::try_from(nonce)
            .map_err(|_| Error::Config("secrets.enc is corrupt (bad nonce)".into()))?;
        let pt = self.cipher()?.decrypt(&nonce, ct).map_err(|_| {
            Error::Config("secrets.enc failed to decrypt (wrong key or corrupt file)".into())
        })?;
        serde_json::from_slice(&pt).map_err(|e| Error::Config(format!("secrets.enc payload: {e}")))
    }

    fn write_map(&self, map: &std::collections::HashMap<String, String>) -> Result<()> {
        let pt = serde_json::to_vec(map).map_err(|e| Error::other(e.to_string()))?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let nonce_arr =
            Nonce::try_from(&nonce[..]).map_err(|_| Error::other("nonce construction failed"))?;
        let ct = self
            .cipher()?
            .encrypt(&nonce_arr, pt.as_slice())
            .map_err(|_| Error::other("encryption failed"))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        std::fs::write(&self.store_path, out)?;
        restrict_permissions(&self.store_path)
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_ref_parse_and_display() {
        assert_eq!(SecretRef::parse("env:FOO").unwrap().to_string(), "env:FOO");
        assert_eq!(SecretRef::parse("store:bar").unwrap().to_string(), "store:bar");
        assert!(SecretRef::parse("FOO").is_err());
        assert!(SecretRef::parse("vault:x").is_err());
        assert!(SecretRef::parse("env:").is_err());
    }

    #[test]
    fn store_roundtrip_and_encryption_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(dir.path()).unwrap();
        assert_eq!(store.get("k").unwrap(), None);
        store.set("k", "the-secret-value").unwrap();
        assert_eq!(store.get("k").unwrap().as_deref(), Some("the-secret-value"));
        assert_eq!(store.names().unwrap(), vec!["k".to_string()]);

        // The value must not sit in cleartext on disk.
        let raw = std::fs::read(dir.path().join("secrets.enc")).unwrap();
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(!raw_str.contains("the-secret-value"));

        assert!(store.remove("k").unwrap());
        assert_eq!(store.get("k").unwrap(), None);
    }

    #[test]
    fn env_resolution() {
        unsafe { std::env::set_var("OPSCLAW_SECRET_TEST_VAR", "v") };
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(dir.path()).unwrap();
        assert_eq!(SecretRef::env("OPSCLAW_SECRET_TEST_VAR").resolve(&store).unwrap(), "v");
        assert!(SecretRef::env("OPSCLAW_SECRET_TEST_MISSING").resolve(&store).is_err());
        assert!(SecretRef::store("missing").resolve(&store).is_err());
    }
}
