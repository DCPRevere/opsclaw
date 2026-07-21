//! `opsclaw-cli secret set/list/rm` — operator intake for the encrypted
//! at-rest store (`config::SecretStore`, `~/.opsclaw/secrets.enc`).
//!
//! This is THE sanctioned path for handing opsclaw a credential (ES
//! password, kubeconfig path, webhook secret): values never pass through
//! argv (visible in `ps`/shell history) and NEVER through chat (a value in
//! chat enters LLM context before any scrubber could know it — brief
//! invariant #3: config refers to secrets by name only). The binary layer
//! acquires the value (hidden prompt / stdin / `--from-env` /
//! `--from-file`) and hands it here; this module is argv-free and testable.
//!
//! The daemon resolves store secrets at boot — an operator changing a value
//! restarts the daemon to pick it up; `set` says so rather than letting the
//! stale value surprise anyone.

use std::path::Path;

use serde::Serialize;

use crate::Result;
use crate::config::SecretStore;

#[derive(Debug, Serialize)]
pub struct SetOutcome {
    pub name: String,
    /// Whether an existing value was overwritten (names are visible; values
    /// never are).
    pub replaced: bool,
}

/// Store `value` under `name`. Rejects an empty value loudly — an empty
/// credential is always a mistake (a stray Ctrl-D, an unset env var) and
/// storing it would fail much later, at connect time, far from the cause.
pub fn set(home: &Path, name: &str, value: &str) -> Result<SetOutcome> {
    if name.trim().is_empty() {
        return Err(crate::Error::validation("secret name must not be empty"));
    }
    if value.is_empty() {
        return Err(crate::Error::validation(format!(
            "refusing to store an EMPTY value for {name:?} — check the input source"
        )));
    }
    let store = SecretStore::open(home)?;
    let replaced = store.get(name)?.is_some();
    store.set(name, value)?;
    Ok(SetOutcome { name: name.to_string(), replaced })
}

/// Stored secret NAMES, sorted — never values.
pub fn list(home: &Path) -> Result<Vec<String>> {
    SecretStore::open(home)?.names()
}

/// Remove one secret. `Ok(false)` when no such name existed.
pub fn rm(home: &Path, name: &str) -> Result<bool> {
    SecretStore::open(home)?.remove(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretRef;

    #[test]
    fn set_list_rm_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let out = set(dir.path(), "es-password", "hunter2").unwrap();
        assert!(!out.replaced);
        assert_eq!(list(dir.path()).unwrap(), vec!["es-password".to_string()]);

        // The stored value resolves through the normal SecretRef path.
        let store = SecretStore::open(dir.path()).unwrap();
        assert_eq!(SecretRef::store("es-password").resolve(&store).unwrap(), "hunter2");

        let out = set(dir.path(), "es-password", "new-value").unwrap();
        assert!(out.replaced);

        assert!(rm(dir.path(), "es-password").unwrap());
        assert!(!rm(dir.path(), "es-password").unwrap());
        assert!(list(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn empty_value_and_empty_name_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(set(dir.path(), "k", "").is_err());
        assert!(set(dir.path(), "  ", "v").is_err());
        assert!(list(dir.path()).unwrap().is_empty());
    }
}
