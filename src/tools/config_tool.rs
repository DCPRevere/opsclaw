//! `opsclaw_config` — read-only, secret-free config inventory (brief §10,
//! DESIGN.md §4 "Tool surface" item 3): "names/addresses/types/autonomy
//! only, never values." So the agent can answer "what do you manage?"
//! without shelling into config files.
//!
//! Safe by construction, not by redaction: `config::Config` holds
//! [`crate::config::SecretRef`]s (references by NAME), never resolved
//! secret VALUES (see that module's doc) — so this tool cannot leak a
//! credential even in principle, because the value was never in the struct
//! it reads. It renders `SecretRef`'s `Display` form (`env:VAR` /
//! `store:KEY`, the name only) exactly as `Config`'s own `Debug` redaction
//! does, rather than reaching for the runtime output scrubber (which lives
//! in `policy/`, out of scope for this module and unnecessary here — there
//! is no resolved value in scope to scrub).

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct ConfigTool;

#[async_trait]
impl Tool for ConfigTool {
    fn name(&self) -> &'static str {
        "opsclaw_config"
    }

    fn description(&self) -> &str {
        "Read-only inventory of what this daemon manages: projects, environments, targets \
         (name, kind, address, autonomy), and resources (type, name). Never returns secret \
         values — only names/addresses/types/autonomy, per policy. Use this to answer 'what \
         do you manage?' or to check a target's configured autonomy before proposing an \
         action."
    }

    fn schema(&self) -> Value {
        json!({"type": "object", "properties": {}})
    }

    fn risk(&self) -> RiskClass {
        RiskClass::Read
    }

    fn is_action(&self) -> bool {
        false
    }

    fn allowed_in_heartbeat(&self) -> bool {
        true
    }

    async fn call(&self, ctx: &ToolCtx, _args: Value) -> Result<ToolResult, ToolError> {
        let config = ctx
            .config
            .as_ref()
            .ok_or_else(|| ToolError::Internal("opsclaw_config called with no config wired".to_string()))?;

        Ok(ToolResult { output: render_inventory(config) })
    }
}

/// Render the inventory as plain text. A free function (not a method on
/// `ConfigTool`) so it's directly unit-testable without constructing a
/// `ToolCtx`.
fn render_inventory(config: &crate::config::Config) -> String {
    if config.projects.is_empty() {
        return "no projects configured.".to_string();
    }
    let mut out = String::new();
    for p in &config.projects {
        out.push_str(&format!(
            "project {} (autonomy: {})\n",
            p.name,
            p.autonomy.map(|a| a.to_string()).unwrap_or_else(|| "(inherits default)".to_string())
        ));
        for e in &p.envs {
            out.push_str(&format!(
                "  env {} (autonomy: {})\n",
                e.name,
                e.autonomy.map(|a| a.to_string()).unwrap_or_else(|| "(inherits project)".to_string())
            ));
            for t in &e.targets {
                out.push_str(&format!(
                    "    target {} kind={:?}{}{}\n",
                    t.name,
                    t.kind,
                    t.address.as_ref().map(|a| format!(" address={a}")).unwrap_or_default(),
                    t.autonomy
                        .map(|a| format!(" autonomy={a}"))
                        .unwrap_or_else(|| " (inherits env)".to_string())
                ));
                for r in &t.resources {
                    out.push_str(&format!("      resource {} type={:?}\n", r.name, r.rtype));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn parse(s: &str) -> Config {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn empty_config_says_so() {
        assert_eq!(render_inventory(&Config::default()), "no projects configured.");
    }

    #[test]
    fn renders_the_full_hierarchy() {
        let cfg = parse(
            r#"
            [[project]]
            name = "remundo"
            autonomy = "observe"
            [[project.env]]
            name = "prod"
            [[project.env.target]]
            name = "web-1"
            kind = "ssh"
            address = "10.0.0.5"
            credential = "store:remundo-web-1-ssh-key"
            [[project.env.target.resource]]
            type = "postgres"
            name = "primary"
            "#,
        );
        let out = render_inventory(&cfg);
        assert!(out.contains("project remundo (autonomy: observe)"));
        assert!(out.contains("env prod"));
        assert!(out.contains("target web-1"));
        assert!(out.contains("address=10.0.0.5"));
        assert!(out.contains("resource primary type=Postgres"));
    }

    #[test]
    fn never_emits_a_secret_value() {
        // Register a distinctive fake secret VALUE in the environment, point
        // a target's credential reference at it, then assert the value
        // itself never appears in the rendered output — only the reference
        // NAME should surface (and only via the SecretRef Display form,
        // which this tool doesn't even print for target credentials today,
        // but the assertion holds regardless of what fields get added).
        const SECRET_VALUE: &str = "s3cr3t-value-should-never-print-9f8e7d";
        unsafe { std::env::set_var("OPSCLAW_TOOL_TEST_SECRET", SECRET_VALUE) };
        let cfg = parse(
            r#"
            [[project]]
            name = "remundo"
            [[project.env]]
            name = "prod"
            [[project.env.target]]
            name = "web-1"
            kind = "ssh"
            address = "10.0.0.5"
            credential = "env:OPSCLAW_TOOL_TEST_SECRET"
            "#,
        );
        let out = render_inventory(&cfg);
        assert!(!out.contains(SECRET_VALUE), "secret VALUE must never appear: {out}");
    }

    #[tokio::test]
    async fn tool_call_requires_config_wired() {
        use crate::domain::Principal;
        use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
        use std::sync::Arc;

        struct NoopPolicy;
        #[async_trait]
        impl PolicyExecute for NoopPolicy {
            async fn execute(&self, _req: CommandRequest) -> crate::Result<PolicyOutcome> {
                Ok(PolicyOutcome::EStopped)
            }
        }
        let ctx = ToolCtx {
            principal: Principal::Agent { job: None },
            policy: Arc::new(NoopPolicy),
            known_targets: vec![],
            incidents: None,
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
            endpoints: None,
            runbooks: None,
        };
        let err = ConfigTool.call(&ctx, json!({})).await.unwrap_err();
        assert!(matches!(err, ToolError::Internal(_)));
    }

    #[test]
    fn is_read_only() {
        assert!(!ConfigTool.is_action());
        assert_eq!(ConfigTool.risk(), RiskClass::Read);
    }
}
