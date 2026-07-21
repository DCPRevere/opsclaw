//! Config → executor map: the daemon's composition root for transport.
//!
//! This is the credential-handling seam `main.rs` deferred to the main
//! session: every configured target becomes exactly one registered executor
//! (keyed `project::env::target`), every resource with a URL becomes an
//! [`EndpointExecutor`] under its resource-qualified key, and every resolved
//! resource credential is registered with the [`Scrubber`] BEFORE the
//! executor that could leak it exists. `cli doctor` builds through the same
//! [`executor_for_target`] so probe behaviour and boot behaviour can't
//! diverge.
//!
//! Failure direction: a target whose credential cannot be resolved is a boot
//! ERROR (config::validate's fail-closed stance — a half-wired daemon must
//! not run), while a declared resource with no `url` is a WARNING and is
//! skipped (its read tools won't register either; nothing fails open).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use super::{
    EndpointExecutor, KubernetesExecutor, KubernetesParams, NotImplementedExecutor, SshExecutor,
    SshParams, TargetExecutor, local::LocalExecutor,
};
use crate::Result;
use crate::config::{Config, SecretStore, TargetCfg, TargetKindName};
use crate::domain::FqTarget;
use crate::policy::Scrubber;

/// The policy executor registry: fq-path string → executor. Base targets are
/// keyed `project::env::target`; endpoint executors by the resource-qualified
/// form of the same path.
pub type ExecutorMap = HashMap<String, Arc<dyn TargetExecutor>>;

/// Build one target's executor. The shared path for daemon boot and
/// `doctor`'s per-target probe — same construction, same errors.
pub fn executor_for_target(
    target: &TargetCfg,
    store: &SecretStore,
) -> Result<Arc<dyn TargetExecutor>> {
    match target.kind {
        TargetKindName::Local => Ok(Arc::new(LocalExecutor::new())),
        TargetKindName::Ssh => {
            let identity_file = match &target.credential {
                Some(r) => Some(PathBuf::from(r.resolve(store)?)),
                None => None,
            };
            let host = target.address.clone().ok_or_else(|| {
                crate::Error::Config(format!("ssh target {:?} has no address", target.name))
            })?;
            Ok(Arc::new(SshExecutor::new(SshParams {
                host,
                port: None,
                user: None,
                identity_file,
                jump_host: None,
                known_hosts_path: None,
                strict_host_key_checking: None,
            })))
        }
        TargetKindName::Kubernetes => {
            let kubeconfig = match &target.credential {
                Some(r) => PathBuf::from(r.resolve(store)?),
                None => {
                    return Err(crate::Error::Config(format!(
                        "kubernetes target {:?} has no credential (kubeconfig path)",
                        target.name
                    )));
                }
            };
            Ok(Arc::new(KubernetesExecutor::new(KubernetesParams {
                kubeconfig,
                context: target.address.clone(),
            })))
        }
        // Honest stub: probes report "not built", commands error — never a
        // silent skip (targets/stub.rs).
        TargetKindName::Cloud => Ok(Arc::new(NotImplementedExecutor::cloud())),
    }
}

/// Build the full policy executor map from config. Returns the map plus
/// human-readable warnings for skipped (non-fatal) declarations; the caller
/// logs them at boot so a skipped resource is visible, never silent.
pub fn build_executors(
    config: &Config,
    store: &SecretStore,
    scrubber: &Scrubber,
) -> Result<(ExecutorMap, Vec<String>)> {
    let mut map: ExecutorMap = HashMap::new();
    let mut warnings = Vec::new();

    for project in &config.projects {
        for env in &project.envs {
            for target in &env.targets {
                let base = FqTarget::new(&project.name, &env.name, &target.name);
                map.insert(base.to_string(), executor_for_target(target, store)?);

                for resource in &target.resources {
                    let Some(url) = &resource.url else {
                        warnings.push(format!(
                            "resource {}::{}::{}::{}::{} has no url — its tools will not \
                             register and no executor is wired",
                            project.name, env.name, target.name, resource.rtype, resource.name
                        ));
                        continue;
                    };
                    let token = match &resource.credential {
                        Some(r) => {
                            let value = r.resolve(store)?;
                            // Register BEFORE any executor that could echo it
                            // exists: an endpoint error body or env dump must
                            // come back `<redacted:...>`.
                            scrubber.register(
                                &format!("{}_{}_TOKEN", resource.rtype, resource.name),
                                &value,
                            );
                            Some(value)
                        }
                        None => None,
                    };
                    let mut fq = base.clone();
                    fq.resource = Some((resource.rtype, resource.name.clone()));
                    map.insert(
                        fq.to_string(),
                        Arc::new(EndpointExecutor::new(resource.rtype, url, token)),
                    );
                }
            }
        }
    }
    Ok((map, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_from(toml: &str) -> Config {
        toml::from_str(toml).expect("test config parses")
    }

    fn store() -> (tempfile::TempDir, SecretStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn wires_targets_and_resource_qualified_endpoints() {
        // SAFETY of env mutation: test-local unique var name.
        unsafe { std::env::set_var("WIRING_TEST_ARGOCD_TOKEN", "argo-secret-token") };
        let config = config_from(
            r#"
            [[project]]
            name = "remundo"
            [[project.env]]
            name = "prod"
            [[project.env.target]]
            name = "bastion"
            kind = "local"
            [[project.env.target.resource]]
            type = "argocd"
            name = "main"
            url = "https://argocd.example"
            credential = "env:WIRING_TEST_ARGOCD_TOKEN"
            "#,
        );
        let (_dir, store) = store();
        let scrubber = Scrubber::new();
        let (map, warnings) = build_executors(&config, &store, &scrubber).unwrap();
        assert!(map.contains_key("remundo::prod::bastion"));
        assert!(map.contains_key("remundo::prod::bastion::argocd::main"));
        assert!(warnings.is_empty(), "{warnings:?}");
        // The resolved token was registered before anything could leak it.
        assert_eq!(scrubber.scrub("token=argo-secret-token"), "token=<redacted:argocd_main_TOKEN>");
    }

    #[test]
    fn resource_without_url_is_a_warning_not_an_executor() {
        let config = config_from(
            r#"
            [[project]]
            name = "p"
            [[project.env]]
            name = "e"
            [[project.env.target]]
            name = "t"
            kind = "local"
            [[project.env.target.resource]]
            type = "prometheus"
            name = "prom"
            "#,
        );
        let (_dir, store) = store();
        let (map, warnings) = build_executors(&config, &store, &Scrubber::new()).unwrap();
        assert_eq!(map.len(), 1, "only the base target");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("no url"));
    }

    #[test]
    fn ssh_without_address_is_a_boot_error() {
        let config = config_from(
            r#"
            [[project]]
            name = "p"
            [[project.env]]
            name = "e"
            [[project.env.target]]
            name = "t"
            kind = "ssh"
            "#,
        );
        let (_dir, store) = store();
        let err = build_executors(&config, &store, &Scrubber::new()).err().expect("must fail");
        assert!(err.to_string().contains("no address"), "{err}");
    }

    #[test]
    fn cloud_target_gets_the_honest_stub() {
        let config = config_from(
            r#"
            [[project]]
            name = "p"
            [[project.env]]
            name = "e"
            [[project.env.target]]
            name = "t"
            kind = "cloud"
            provider = "azure"
            "#,
        );
        let (_dir, store) = store();
        let (map, _) = build_executors(&config, &store, &Scrubber::new()).unwrap();
        assert!(map.contains_key("p::e::t"));
    }
}
