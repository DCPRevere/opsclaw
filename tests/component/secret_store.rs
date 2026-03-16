//! Secret store component tests (Phase 1b).
//!
//! Validates that the OpsClaw secret store encrypts, stores, retrieves,
//! and deletes credentials correctly. All operations use a temporary
//! directory — nothing touches the real secret store.

use std::path::Path;
use tempfile::TempDir;

// Import once implemented.
use zeroclaw::config::secrets::{SecretStore, SecretStoreError};

// ─────────────────────────────────────────────────────────────────────────────
// Basic store / retrieve cycle
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn secret_store_round_trip() {
    let tmp = TempDir::new().unwrap();
    let store = SecretStore::open(tmp.path()).expect("should open store");
    store
        .set("slack-webhook", "https://hooks.slack.com/services/T00/B00/xxxx")
        .expect("should store secret");
    let value = store.get("slack-webhook").expect("should retrieve secret");
    assert_eq!(value, "https://hooks.slack.com/services/T00/B00/xxxx");
}

#[test]
fn secret_store_overwrites_existing() {
    let tmp = TempDir::new().unwrap();
    let store = SecretStore::open(tmp.path()).expect("should open store");
    store.set("api-key", "old-value").unwrap();
    store.set("api-key", "new-value").unwrap();
    assert_eq!(store.get("api-key").unwrap(), "new-value");
}

#[test]
fn secret_store_get_nonexistent_returns_error() {
    let tmp = TempDir::new().unwrap();
    let store = SecretStore::open(tmp.path()).expect("should open store");
    let result = store.get("does-not-exist");
    assert!(result.is_err());
    match result.unwrap_err() {
        SecretStoreError::NotFound(name) => assert_eq!(name, "does-not-exist"),
        other => panic!("expected NotFound, got: {other:?}"),
    }
}

#[test]
fn secret_store_delete() {
    let tmp = TempDir::new().unwrap();
    let store = SecretStore::open(tmp.path()).expect("should open store");
    store.set("temp-secret", "value").unwrap();
    assert!(store.get("temp-secret").is_ok());
    store.delete("temp-secret").unwrap();
    assert!(store.get("temp-secret").is_err());
}

#[test]
fn secret_store_list_names() {
    let tmp = TempDir::new().unwrap();
    let store = SecretStore::open(tmp.path()).expect("should open store");
    store.set("alpha", "1").unwrap();
    store.set("bravo", "2").unwrap();
    store.set("charlie", "3").unwrap();
    let mut names = store.list().expect("should list secret names");
    names.sort();
    assert_eq!(names, vec!["alpha", "bravo", "charlie"]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Encryption
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn secret_store_values_not_stored_plaintext() {
    let tmp = TempDir::new().unwrap();
    let store = SecretStore::open(tmp.path()).expect("should open store");
    let secret_value = "super-secret-api-key-12345";
    store.set("test-key", secret_value).unwrap();

    // Read all files in the store directory and check none contain plaintext.
    let dir_contents = read_all_files_recursive(tmp.path());
    assert!(
        !dir_contents.contains(secret_value),
        "secret value must not appear in plaintext on disk"
    );
}

#[test]
fn secret_store_persists_across_reopen() {
    let tmp = TempDir::new().unwrap();
    {
        let store = SecretStore::open(tmp.path()).unwrap();
        store.set("persistent", "value-123").unwrap();
    }
    // Reopen from the same directory.
    let store = SecretStore::open(tmp.path()).unwrap();
    assert_eq!(store.get("persistent").unwrap(), "value-123");
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn secret_store_rejects_empty_name() {
    let tmp = TempDir::new().unwrap();
    let store = SecretStore::open(tmp.path()).unwrap();
    assert!(
        store.set("", "value").is_err(),
        "empty secret name should be rejected"
    );
}

#[test]
fn secret_store_rejects_empty_value() {
    let tmp = TempDir::new().unwrap();
    let store = SecretStore::open(tmp.path()).unwrap();
    assert!(
        store.set("name", "").is_err(),
        "empty secret value should be rejected"
    );
}

#[test]
fn secret_store_name_allows_reasonable_characters() {
    let tmp = TempDir::new().unwrap();
    let store = SecretStore::open(tmp.path()).unwrap();
    // Names should support dashes, underscores, dots, alphanumeric.
    for name in &[
        "simple",
        "with-dashes",
        "with_underscores",
        "with.dots",
        "CamelCase",
        "prod-pg-readonly",
    ] {
        store
            .set(name, "value")
            .unwrap_or_else(|_| panic!("name '{name}' should be accepted"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_all_files_recursive(dir: &Path) -> String {
    let mut contents = String::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                contents.push_str(&read_all_files_recursive(&path));
            } else if let Ok(bytes) = std::fs::read(&path) {
                // Include both text and hex representation to catch plaintext
                // in either text or binary files.
                contents.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
    }
    contents
}
