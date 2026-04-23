//! Secret resolution for opsclaw.
//!
//! A config value that looks like `env:NAME` or `k8s:<ns>/<name>/<key>` is
//! dereferenced at load time to the actual secret value, instead of being
//! read from the local encrypted store. This lets the same binary run
//! unchanged on a laptop (encrypted file at rest), in a container (env
//! vars), or in-cluster (mounted k8s Secret volumes).
//!
//! All schemes share one choke-point: [`CompositeResolver`]. Downstream
//! tools never see the reference string — they only see resolved plaintext.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Environment variable naming the root directory where k8s Secret
/// volumes are mounted. Each secret key is one file under
/// `<root>/<namespace>/<secret-name>/<key>`.
pub const K8S_MOUNT_ROOT_ENV: &str = "OPSCLAW_K8S_SECRETS_ROOT";

/// Default mount root, matching typical projected-volume conventions.
pub const DEFAULT_K8S_MOUNT_ROOT: &str = "/var/run/secrets";

/// Is `value` a reference that should *not* be re-encrypted when the
/// config is written back to disk? Returns true for existing encrypted
/// values (`enc:` / `enc2:`) and for the new external-resolver schemes
/// (`env:` / `k8s:`).
#[must_use]
pub fn is_reference(value: &str) -> bool {
    value.starts_with("enc2:")
        || value.starts_with("enc:")
        || value.starts_with("env:")
        || value.starts_with("k8s:")
}

/// One source of secret values. Returns `Ok(Some(plaintext))` when this
/// resolver owns the reference scheme, `Ok(None)` to let the next
/// resolver try, and `Err` when the scheme matched but the lookup
/// failed (missing env var, missing k8s key, etc.).
#[async_trait]
pub trait SecretResolver: Send + Sync {
    async fn resolve(&self, value: &str) -> Result<Option<String>>;
}

/// Wraps the upstream [`zeroclaw::security::SecretStore`]. Handles
/// `enc2:` / `enc:` prefixes and plaintext passthrough.
#[derive(Clone)]
pub struct EncryptedStoreResolver {
    store: Arc<zeroclaw::security::SecretStore>,
}

impl EncryptedStoreResolver {
    pub fn new(config_dir: &Path, encryption_enabled: bool) -> Self {
        Self {
            store: Arc::new(zeroclaw::security::SecretStore::new(
                config_dir,
                encryption_enabled,
            )),
        }
    }
}

#[async_trait]
impl SecretResolver for EncryptedStoreResolver {
    async fn resolve(&self, value: &str) -> Result<Option<String>> {
        if value.starts_with("enc2:") || value.starts_with("enc:") {
            let plain = self.store.decrypt(value)?;
            return Ok(Some(plain));
        }
        // Plaintext passthrough is what SecretStore::decrypt already does;
        // we treat it as "unhandled" so the composite reports a better
        // error if nothing else matches either. But upstream behaviour is
        // that plaintext is legal, so we mirror it.
        if !value.contains(':') {
            return Ok(Some(value.to_string()));
        }
        // Plaintext that happens to contain a colon but no recognised
        // scheme — also passthrough.
        if !value.starts_with("env:") && !value.starts_with("k8s:") {
            return Ok(Some(value.to_string()));
        }
        Ok(None)
    }
}

/// Resolves `env:NAME` references from the process environment.
#[derive(Default, Clone)]
pub struct EnvVarResolver;

#[async_trait]
impl SecretResolver for EnvVarResolver {
    async fn resolve(&self, value: &str) -> Result<Option<String>> {
        let Some(name) = value.strip_prefix("env:") else {
            return Ok(None);
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(anyhow!("empty env var name in reference `{value}`"));
        }
        let val = std::env::var(name)
            .with_context(|| format!("env var `{name}` referenced by config is not set"))?;
        Ok(Some(val))
    }
}

/// Resolves `k8s:<namespace>/<secret-name>/<key>` references.
///
/// Two lookup paths, tried in order:
/// 1. Mounted volume: `<mount_root>/<namespace>/<secret-name>/<key>` as a
///    UTF-8 file. This is the cheap, preferred path in-cluster.
/// 2. API fallback: `kube::Api::<Secret>::namespaced().get()` — only
///    attempted when the mount file is absent. Requires a kube client,
///    supplied via the injectable [`KubeSecretFetcher`] trait so tests
///    don't need a live cluster.
#[derive(Clone)]
pub struct K8sSecretResolver {
    mount_root: PathBuf,
    fetcher: Arc<dyn KubeSecretFetcher>,
}

/// Indirection over `kube::Api::<Secret>::get` so the resolver can be
/// unit-tested without a cluster.
#[async_trait]
pub trait KubeSecretFetcher: Send + Sync {
    /// Return the raw (already base64-decoded) bytes for `namespace/name/key`,
    /// or `None` if the key is missing in an otherwise-readable Secret.
    async fn fetch(&self, namespace: &str, name: &str, key: &str) -> Result<Option<Vec<u8>>>;
}

/// Default fetcher backed by the real kube API. Returns a "not configured"
/// error until a kube client is wired in — keeping the dependency optional
/// at startup time so laptops without a kubeconfig still start cleanly.
#[derive(Default)]
pub struct NullKubeFetcher;

#[async_trait]
impl KubeSecretFetcher for NullKubeFetcher {
    async fn fetch(&self, _ns: &str, _name: &str, _key: &str) -> Result<Option<Vec<u8>>> {
        Err(anyhow!(
            "k8s secret API fallback is unavailable (no kube client configured); \
             mount the Secret as a volume under the configured mount root"
        ))
    }
}

impl K8sSecretResolver {
    pub fn new(mount_root: impl Into<PathBuf>, fetcher: Arc<dyn KubeSecretFetcher>) -> Self {
        Self {
            mount_root: mount_root.into(),
            fetcher,
        }
    }

    /// Convenience constructor: mount root from `OPSCLAW_K8S_SECRETS_ROOT`
    /// env var or [`DEFAULT_K8S_MOUNT_ROOT`], API fallback disabled.
    pub fn from_env_default() -> Self {
        let root = std::env::var(K8S_MOUNT_ROOT_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_K8S_MOUNT_ROOT));
        Self::new(root, Arc::new(NullKubeFetcher))
    }
}

/// Parse `k8s:<ns>/<name>/<key>` into its three parts. Namespaces and
/// names are validated to be non-empty and free of path separators, so
/// a malicious reference can't walk out of the mount root.
fn parse_k8s_ref(value: &str) -> Result<(&str, &str, &str)> {
    let rest = value
        .strip_prefix("k8s:")
        .ok_or_else(|| anyhow!("not a k8s reference"))?;
    let mut parts = rest.splitn(3, '/');
    let ns = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    let key = parts.next().unwrap_or("");
    if ns.is_empty() || name.is_empty() || key.is_empty() {
        return Err(anyhow!(
            "k8s reference `{value}` must have the form `k8s:<namespace>/<secret-name>/<key>`"
        ));
    }
    for (label, part) in [("namespace", ns), ("secret name", name), ("key", key)] {
        if part.contains('/') || part == "." || part == ".." {
            return Err(anyhow!(
                "k8s reference `{value}` has an invalid {label} segment"
            ));
        }
    }
    Ok((ns, name, key))
}

#[async_trait]
impl SecretResolver for K8sSecretResolver {
    async fn resolve(&self, value: &str) -> Result<Option<String>> {
        if !value.starts_with("k8s:") {
            return Ok(None);
        }
        let (ns, name, key) = parse_k8s_ref(value)?;

        // 1. Mounted-file path.
        let file_path = self.mount_root.join(ns).join(name).join(key);
        match tokio::fs::read(&file_path).await {
            Ok(bytes) => {
                let s = String::from_utf8(bytes).with_context(|| {
                    format!(
                        "k8s secret at {} is not valid UTF-8",
                        file_path.display()
                    )
                })?;
                // Trim a single trailing newline — projected volumes don't
                // add one, but `kubectl create secret --from-file` does
                // when users read/paste values, and the ambiguity is
                // worse than the rare intentional-trailing-newline case.
                return Ok(Some(trim_one_trailing_newline(s)));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Fall through to API.
            }
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!(
                    "failed to read mounted k8s secret at {}",
                    file_path.display()
                )));
            }
        }

        // 2. API fallback.
        let bytes = self
            .fetcher
            .fetch(ns, name, key)
            .await
            .with_context(|| format!("k8s API lookup failed for {ns}/{name}/{key}"))?
            .ok_or_else(|| {
                anyhow!("k8s secret {ns}/{name} has no key `{key}`")
            })?;
        let s = String::from_utf8(bytes)
            .with_context(|| format!("k8s secret {ns}/{name}/{key} is not valid UTF-8"))?;
        Ok(Some(s))
    }
}

fn trim_one_trailing_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s
}

/// Composes multiple resolvers. The first one to return `Some(_)` wins.
/// Ordering matters: encrypted store is last so it can safely claim all
/// plaintext-passthrough values without shadowing `env:` / `k8s:`.
pub struct CompositeResolver {
    resolvers: Vec<Arc<dyn SecretResolver>>,
}

impl CompositeResolver {
    #[must_use]
    pub fn new(resolvers: Vec<Arc<dyn SecretResolver>>) -> Self {
        Self { resolvers }
    }

    /// Default composition for production use.
    pub fn default_for(config_dir: &Path, encryption_enabled: bool) -> Self {
        Self::new(vec![
            Arc::new(EnvVarResolver),
            Arc::new(K8sSecretResolver::from_env_default()),
            Arc::new(EncryptedStoreResolver::new(config_dir, encryption_enabled)),
        ])
    }

    pub async fn resolve(&self, value: &str) -> Result<String> {
        for r in &self.resolvers {
            if let Some(v) = r.resolve(value).await? {
                return Ok(v);
            }
        }
        Err(anyhow!(
            "no resolver accepted secret reference (value length {})",
            value.len()
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_store(encryption_enabled: bool) -> (TempDir, EncryptedStoreResolver) {
        let tmp = TempDir::new().unwrap();
        let r = EncryptedStoreResolver::new(tmp.path(), encryption_enabled);
        (tmp, r)
    }

    // ── is_reference ────────────────────────────────────────────

    #[test]
    fn is_reference_matches_known_schemes() {
        assert!(is_reference("enc2:abcd"));
        assert!(is_reference("enc:abcd"));
        assert!(is_reference("env:FOO"));
        assert!(is_reference("k8s:ns/name/key"));
        assert!(!is_reference("plaintext-secret"));
        assert!(!is_reference(""));
        assert!(!is_reference("https://example.com"));
    }

    // ── EncryptedStoreResolver ──────────────────────────────────

    #[tokio::test]
    async fn encrypted_store_roundtrip_via_resolver() {
        let (dir, resolver) = tmp_store(true);
        let store = zeroclaw::security::SecretStore::new(dir.path(), true);
        let ciphertext = store.encrypt("hunter2").unwrap();
        let plain = resolver.resolve(&ciphertext).await.unwrap();
        assert_eq!(plain, Some("hunter2".to_string()));
    }

    #[tokio::test]
    async fn encrypted_store_passes_through_plaintext() {
        let (_dir, resolver) = tmp_store(true);
        let plain = resolver.resolve("sk-plain").await.unwrap();
        assert_eq!(plain, Some("sk-plain".to_string()));
    }

    #[tokio::test]
    async fn encrypted_store_defers_on_env_reference() {
        let (_dir, resolver) = tmp_store(true);
        // Must not claim env:FOO; leaves it for EnvVarResolver.
        let r = resolver.resolve("env:FOO").await.unwrap();
        assert!(r.is_none());
    }

    #[tokio::test]
    async fn encrypted_store_defers_on_k8s_reference() {
        let (_dir, resolver) = tmp_store(true);
        let r = resolver.resolve("k8s:ns/name/key").await.unwrap();
        assert!(r.is_none());
    }

    // ── EnvVarResolver ──────────────────────────────────────────

    #[tokio::test]
    async fn env_resolver_reads_env_var() {
        let key = "OPSCLAW_TEST_ENV_RESOLVER_READS";
        // SAFETY: test-only, single-threaded per test.
        std::env::set_var(key, "from-env");
        let got = EnvVarResolver.resolve(&format!("env:{key}")).await.unwrap();
        std::env::remove_var(key);
        assert_eq!(got, Some("from-env".to_string()));
    }

    #[tokio::test]
    async fn env_resolver_missing_var_errors() {
        let key = "OPSCLAW_TEST_ENV_RESOLVER_MISSING";
        std::env::remove_var(key);
        let err = EnvVarResolver
            .resolve(&format!("env:{key}"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains(key));
    }

    #[tokio::test]
    async fn env_resolver_empty_name_errors() {
        let err = EnvVarResolver.resolve("env:").await.unwrap_err();
        assert!(err.to_string().contains("empty env var name"));
    }

    #[tokio::test]
    async fn env_resolver_ignores_non_env_reference() {
        let r = EnvVarResolver.resolve("enc2:deadbeef").await.unwrap();
        assert!(r.is_none());
        let r = EnvVarResolver.resolve("k8s:ns/name/key").await.unwrap();
        assert!(r.is_none());
        let r = EnvVarResolver.resolve("plaintext").await.unwrap();
        assert!(r.is_none());
    }

    // ── parse_k8s_ref ───────────────────────────────────────────

    #[test]
    fn parse_k8s_ref_happy_path() {
        let (ns, name, key) = parse_k8s_ref("k8s:ops/opsclaw-creds/api_key").unwrap();
        assert_eq!((ns, name, key), ("ops", "opsclaw-creds", "api_key"));
    }

    #[test]
    fn parse_k8s_ref_rejects_missing_parts() {
        assert!(parse_k8s_ref("k8s:").is_err());
        assert!(parse_k8s_ref("k8s:ops").is_err());
        assert!(parse_k8s_ref("k8s:ops/name").is_err());
        assert!(parse_k8s_ref("k8s:/name/key").is_err());
        assert!(parse_k8s_ref("k8s:ops//key").is_err());
    }

    #[test]
    fn parse_k8s_ref_rejects_path_traversal() {
        assert!(parse_k8s_ref("k8s:../etc/passwd").is_err());
        assert!(parse_k8s_ref("k8s:ops/../passwd").is_err());
        assert!(parse_k8s_ref("k8s:ops/name/..").is_err());
    }

    #[test]
    fn parse_k8s_ref_allows_dotted_but_not_traversal() {
        // `.env` and similar should still work — only literal `.` / `..`
        // segments are rejected.
        let (ns, name, key) =
            parse_k8s_ref("k8s:ops/my-secret/.tls.crt").unwrap();
        assert_eq!((ns, name, key), ("ops", "my-secret", ".tls.crt"));
    }

    // ── K8sSecretResolver (mount path) ──────────────────────────

    struct FailingFetcher;
    #[async_trait]
    impl KubeSecretFetcher for FailingFetcher {
        async fn fetch(&self, _: &str, _: &str, _: &str) -> Result<Option<Vec<u8>>> {
            Err(anyhow!("should not be called when mount file exists"))
        }
    }

    fn write_mounted(root: &Path, ns: &str, name: &str, key: &str, contents: &[u8]) {
        let dir = root.join(ns).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(key), contents).unwrap();
    }

    #[tokio::test]
    async fn k8s_resolver_reads_mounted_file() {
        let tmp = TempDir::new().unwrap();
        write_mounted(tmp.path(), "ops", "creds", "api_key", b"super-secret");
        let r = K8sSecretResolver::new(tmp.path(), Arc::new(FailingFetcher));
        let got = r.resolve("k8s:ops/creds/api_key").await.unwrap();
        assert_eq!(got, Some("super-secret".to_string()));
    }

    #[tokio::test]
    async fn k8s_resolver_trims_single_trailing_newline() {
        let tmp = TempDir::new().unwrap();
        write_mounted(tmp.path(), "ops", "creds", "api_key", b"super-secret\n");
        let r = K8sSecretResolver::new(tmp.path(), Arc::new(FailingFetcher));
        let got = r.resolve("k8s:ops/creds/api_key").await.unwrap();
        assert_eq!(got, Some("super-secret".to_string()));
    }

    #[tokio::test]
    async fn k8s_resolver_preserves_internal_newlines() {
        // Multi-line PEM secret: only one trailing newline is trimmed.
        let tmp = TempDir::new().unwrap();
        let pem = b"-----BEGIN CERT-----\nAAAA\n-----END CERT-----\n";
        write_mounted(tmp.path(), "ops", "tls", "crt", pem);
        let r = K8sSecretResolver::new(tmp.path(), Arc::new(FailingFetcher));
        let got = r.resolve("k8s:ops/tls/crt").await.unwrap().unwrap();
        assert_eq!(got, "-----BEGIN CERT-----\nAAAA\n-----END CERT-----");
    }

    #[tokio::test]
    async fn k8s_resolver_non_utf8_errors() {
        let tmp = TempDir::new().unwrap();
        write_mounted(tmp.path(), "ops", "bin", "blob", &[0xff, 0xfe, 0x00]);
        let r = K8sSecretResolver::new(tmp.path(), Arc::new(FailingFetcher));
        let err = r.resolve("k8s:ops/bin/blob").await.unwrap_err();
        assert!(err.to_string().contains("UTF-8"));
    }

    // ── K8sSecretResolver (API fallback) ────────────────────────

    struct StubFetcher {
        value: Option<Vec<u8>>,
    }
    #[async_trait]
    impl KubeSecretFetcher for StubFetcher {
        async fn fetch(&self, _: &str, _: &str, _: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.value.clone())
        }
    }

    #[tokio::test]
    async fn k8s_resolver_falls_back_to_api_when_file_missing() {
        let tmp = TempDir::new().unwrap();
        let r = K8sSecretResolver::new(
            tmp.path(),
            Arc::new(StubFetcher {
                value: Some(b"from-api".to_vec()),
            }),
        );
        let got = r.resolve("k8s:ops/creds/api_key").await.unwrap();
        assert_eq!(got, Some("from-api".to_string()));
    }

    #[tokio::test]
    async fn k8s_resolver_api_missing_key_errors() {
        let tmp = TempDir::new().unwrap();
        let r = K8sSecretResolver::new(
            tmp.path(),
            Arc::new(StubFetcher { value: None }),
        );
        let err = r.resolve("k8s:ops/creds/absent").await.unwrap_err();
        assert!(err.to_string().contains("absent"));
    }

    #[tokio::test]
    async fn null_fetcher_errors() {
        let tmp = TempDir::new().unwrap();
        let r = K8sSecretResolver::new(tmp.path(), Arc::new(NullKubeFetcher));
        let err = r.resolve("k8s:ops/creds/api_key").await.unwrap_err();
        // The outer context mentions the ns/name/key; the inner source
        // mentions "kube client". Walk the chain.
        let chain: String = err.chain().map(|e| e.to_string()).collect::<Vec<_>>().join(" | ");
        assert!(
            chain.contains("kube client"),
            "expected kube-client mention in error chain, got: {chain}"
        );
    }

    #[tokio::test]
    async fn k8s_resolver_ignores_non_k8s_reference() {
        let tmp = TempDir::new().unwrap();
        let r = K8sSecretResolver::new(tmp.path(), Arc::new(FailingFetcher));
        assert!(r.resolve("env:FOO").await.unwrap().is_none());
        assert!(r.resolve("enc2:abcd").await.unwrap().is_none());
        assert!(r.resolve("plaintext").await.unwrap().is_none());
    }

    // ── CompositeResolver ───────────────────────────────────────

    #[tokio::test]
    async fn composite_prefers_env_over_encrypted_store() {
        let tmp = TempDir::new().unwrap();
        let key = "OPSCLAW_TEST_COMPOSITE_ENV_WINS";
        std::env::set_var(key, "from-env-composite");
        let composite = CompositeResolver::default_for(tmp.path(), true);
        let got = composite.resolve(&format!("env:{key}")).await.unwrap();
        std::env::remove_var(key);
        assert_eq!(got, "from-env-composite");
    }

    #[tokio::test]
    async fn composite_routes_k8s_to_mount() {
        let tmp = TempDir::new().unwrap();
        let mount = TempDir::new().unwrap();
        write_mounted(mount.path(), "ops", "creds", "tok", b"mounted-tok");
        let composite = CompositeResolver::new(vec![
            Arc::new(EnvVarResolver),
            Arc::new(K8sSecretResolver::new(
                mount.path(),
                Arc::new(NullKubeFetcher),
            )),
            Arc::new(EncryptedStoreResolver::new(tmp.path(), true)),
        ]);
        let got = composite.resolve("k8s:ops/creds/tok").await.unwrap();
        assert_eq!(got, "mounted-tok");
    }

    #[tokio::test]
    async fn composite_decrypts_enc2_via_store() {
        let tmp = TempDir::new().unwrap();
        let store = zeroclaw::security::SecretStore::new(tmp.path(), true);
        let ciphertext = store.encrypt("stored-plaintext").unwrap();
        let composite = CompositeResolver::default_for(tmp.path(), true);
        let got = composite.resolve(&ciphertext).await.unwrap();
        assert_eq!(got, "stored-plaintext");
    }

    #[tokio::test]
    async fn composite_passes_plaintext_through() {
        let tmp = TempDir::new().unwrap();
        let composite = CompositeResolver::default_for(tmp.path(), true);
        let got = composite.resolve("sk-plaintext").await.unwrap();
        assert_eq!(got, "sk-plaintext");
    }

    #[tokio::test]
    async fn composite_reports_missing_env_clearly() {
        let tmp = TempDir::new().unwrap();
        let composite = CompositeResolver::default_for(tmp.path(), true);
        let err = composite
            .resolve("env:OPSCLAW_TEST_COMPOSITE_DEFINITELY_UNSET_XYZ")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("OPSCLAW_TEST_COMPOSITE_DEFINITELY_UNSET_XYZ"),
            "error should name the missing var: {msg}"
        );
    }

    // ── base64 sanity (so the dependency isn't dead if only the API
    //    fallback uses it in downstream KubeSecretFetcher impls) ──

    #[test]
    fn base64_decodes_standard() {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode("c3VwZXItc2VjcmV0")
            .unwrap();
        assert_eq!(decoded, b"super-secret");
    }
}
