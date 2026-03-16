use tempfile::TempDir;
use zeroclaw::OpsClawSecretStore;

#[test]
fn set_get_list_remove_cycle() {
    let tmp = TempDir::new().unwrap();
    let store = OpsClawSecretStore::new(tmp.path());

    // Initially empty
    assert!(store.list().unwrap().is_empty());

    // Set
    store
        .set(
            "ssh-key-1",
            "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
        )
        .unwrap();
    store.set("api-token", "sk-secret-123").unwrap();

    // List
    let names = store.list().unwrap();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"api-token".to_string()));
    assert!(names.contains(&"ssh-key-1".to_string()));

    // Get
    let value = store.get("api-token").unwrap();
    assert_eq!(value, Some("sk-secret-123".to_string()));

    // Get missing
    assert_eq!(store.get("nonexistent").unwrap(), None);

    // Remove
    assert!(store.remove("api-token").unwrap());
    assert_eq!(store.get("api-token").unwrap(), None);
    assert_eq!(store.list().unwrap().len(), 1);

    // Remove nonexistent
    assert!(!store.remove("api-token").unwrap());
}

#[test]
fn encryption_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let store = OpsClawSecretStore::new(tmp.path());

    let secret = "super-secret-value-🔑";
    store.set("enc-test", secret).unwrap();

    // Read the raw file to verify it's not plaintext
    let raw = std::fs::read_to_string(tmp.path().join("secrets.enc")).unwrap();
    assert!(!raw.contains(secret), "Secret should be encrypted on disk");

    // Verify decryption works
    let decrypted = store.get("enc-test").unwrap();
    assert_eq!(decrypted, Some(secret.to_string()));
}

#[test]
fn persistence_across_store_instances() {
    let tmp = TempDir::new().unwrap();

    {
        let store = OpsClawSecretStore::new(tmp.path());
        store.set("persistent-key", "persistent-value").unwrap();
    }

    // New instance, same directory
    let store2 = OpsClawSecretStore::new(tmp.path());
    assert_eq!(
        store2.get("persistent-key").unwrap(),
        Some("persistent-value".to_string())
    );
}

#[test]
fn overwrite_secret() {
    let tmp = TempDir::new().unwrap();
    let store = OpsClawSecretStore::new(tmp.path());

    store.set("mutable", "v1").unwrap();
    assert_eq!(store.get("mutable").unwrap(), Some("v1".to_string()));

    store.set("mutable", "v2").unwrap();
    assert_eq!(store.get("mutable").unwrap(), Some("v2".to_string()));

    // Only one entry
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn unicode_secret_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let store = OpsClawSecretStore::new(tmp.path());

    let secret = "密码-пароль-🦀-émojis";
    store.set("unicode", secret).unwrap();
    assert_eq!(store.get("unicode").unwrap(), Some(secret.to_string()));
}

#[test]
fn long_secret_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let store = OpsClawSecretStore::new(tmp.path());

    let secret = "a".repeat(10_000);
    store.set("long", &secret).unwrap();
    assert_eq!(store.get("long").unwrap(), Some(secret));
}

#[cfg(unix)]
#[test]
fn secrets_file_has_restricted_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let store = OpsClawSecretStore::new(tmp.path());
    store.set("perm-test", "value").unwrap();

    let perms = std::fs::metadata(tmp.path().join("secrets.enc"))
        .unwrap()
        .permissions();
    assert_eq!(
        perms.mode() & 0o777,
        0o600,
        "Secrets file must be owner-only (0600)"
    );
}
