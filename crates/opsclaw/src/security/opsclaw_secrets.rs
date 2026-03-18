// OpsClaw secret store — encrypted JSON-based named secret storage.
//
// Stores named secrets (SSH keys, tokens, etc.) in an encrypted JSON file
// at `~/.opsclaw/secrets.enc`. Uses the existing `SecretStore` infrastructure
// for encryption/decryption (ChaCha20-Poly1305 AEAD).

use zeroclaw::security::SecretStore;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// On-disk format: a map of secret names to encrypted values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SecretsFile {
    secrets: BTreeMap<String, String>,
}

/// Named secret store backed by an encrypted JSON file.
#[derive(Debug, Clone)]
pub struct OpsClawSecretStore {
    file_path: PathBuf,
    store: SecretStore,
}

impl OpsClawSecretStore {
    /// Create a new OpsClaw secret store.
    ///
    /// `opsclaw_dir` is the base directory (e.g. `~/.opsclaw`).
    /// The encryption key is stored alongside the secrets file.
    pub fn new(opsclaw_dir: &Path) -> Self {
        Self {
            file_path: opsclaw_dir.join("secrets.enc"),
            store: SecretStore::new(opsclaw_dir, true),
        }
    }

    /// Store a named secret (encrypts and persists).
    pub fn set(&self, name: &str, value: &str) -> Result<()> {
        let mut secrets = self.load()?;
        let encrypted = self.store.encrypt(value)?;
        secrets.secrets.insert(name.to_string(), encrypted);
        self.save(&secrets)
    }

    /// Retrieve a named secret (decrypts and returns plaintext).
    pub fn get(&self, name: &str) -> Result<Option<String>> {
        let secrets = self.load()?;
        match secrets.secrets.get(name) {
            Some(encrypted) => {
                let plaintext = self.store.decrypt(encrypted)?;
                Ok(Some(plaintext))
            }
            None => Ok(None),
        }
    }

    /// List all secret names (never exposes values).
    pub fn list(&self) -> Result<Vec<String>> {
        let secrets = self.load()?;
        Ok(secrets.secrets.keys().cloned().collect())
    }

    /// Remove a named secret.
    pub fn remove(&self, name: &str) -> Result<bool> {
        let mut secrets = self.load()?;
        let removed = secrets.secrets.remove(name).is_some();
        if removed {
            self.save(&secrets)?;
        }
        Ok(removed)
    }

    fn load(&self) -> Result<SecretsFile> {
        if !self.file_path.exists() {
            return Ok(SecretsFile::default());
        }
        let contents =
            std::fs::read_to_string(&self.file_path).context("Failed to read secrets file")?;
        serde_json::from_str(&contents).context("Failed to parse secrets file")
    }

    fn save(&self, secrets: &SecretsFile) -> Result<()> {
        if let Some(parent) = self.file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(secrets)?;
        std::fs::write(&self.file_path, json).context("Failed to write secrets file")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.file_path, std::fs::Permissions::from_mode(0o600))
                .context("Failed to set secrets file permissions")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn set_get_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store = OpsClawSecretStore::new(tmp.path());

        store.set("my-key", "my-secret-value").unwrap();
        let result = store.get("my-key").unwrap();
        assert_eq!(result, Some("my-secret-value".to_string()));
    }

    #[test]
    fn get_missing_returns_none() {
        let tmp = TempDir::new().unwrap();
        let store = OpsClawSecretStore::new(tmp.path());
        assert_eq!(store.get("nonexistent").unwrap(), None);
    }

    #[test]
    fn list_returns_names_only() {
        let tmp = TempDir::new().unwrap();
        let store = OpsClawSecretStore::new(tmp.path());

        store.set("alpha", "secret-a").unwrap();
        store.set("beta", "secret-b").unwrap();

        let names = store.list().unwrap();
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn remove_existing_secret() {
        let tmp = TempDir::new().unwrap();
        let store = OpsClawSecretStore::new(tmp.path());

        store.set("to-remove", "value").unwrap();
        assert!(store.remove("to-remove").unwrap());
        assert_eq!(store.get("to-remove").unwrap(), None);
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let tmp = TempDir::new().unwrap();
        let store = OpsClawSecretStore::new(tmp.path());
        assert!(!store.remove("nonexistent").unwrap());
    }

    #[test]
    fn persistence_across_instances() {
        let tmp = TempDir::new().unwrap();

        let store1 = OpsClawSecretStore::new(tmp.path());
        store1.set("persistent", "value123").unwrap();

        let store2 = OpsClawSecretStore::new(tmp.path());
        assert_eq!(
            store2.get("persistent").unwrap(),
            Some("value123".to_string())
        );
    }

    #[test]
    fn overwrite_existing_secret() {
        let tmp = TempDir::new().unwrap();
        let store = OpsClawSecretStore::new(tmp.path());

        store.set("key", "old-value").unwrap();
        store.set("key", "new-value").unwrap();
        assert_eq!(store.get("key").unwrap(), Some("new-value".to_string()));
    }
}
