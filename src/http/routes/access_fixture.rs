//! Shared fixture for the access route tests: a fake daemon on the `team`
//! preset with a few people.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::access::{Access, RepoDirectory};
use crate::db::{Account, AccountRepo};
use crate::domain::{FqTarget, Incident, IncidentState, Severity};
use crate::http::handlers::Ctx;
use crate::http::state::AppState;

pub const CONFIG: &str = r#"
[[project]]
name = "acme"
[[project.env]]
name = "prod"
[[project.env.target]]
name = "aks"
kind = "local"

[access]
preset = "team"

[[access.role]]
name = "readers"
members = ["reader@acme.com"]
where = ["acme::prod"]
data = ["state"]
findings = "summary"

[[access.role]]
name = "oncall"
idp_groups = ["oncall"]
where = ["acme::prod"]
data = ["state", "logs"]
findings = "full"

[[access.role]]
name = "investigators"
members = ["ivy@acme.com"]
where = ["acme::prod"]
data = ["logs:raw"]
findings = "full"
elevation = "approval"

[[access.role]]
name = "leads"
members = ["lead@acme.com"]
where = ["*"]
data = ["state"]
actions = "approve"
"#;

pub struct Fixture {
    pub state: AppState,
}

impl Fixture {
    pub fn new() -> Self {
        let config: crate::config::Config = toml::from_str(CONFIG).unwrap();
        let mut state = AppState::fake_with_config(config.clone());
        let access = Arc::new(Access::new(&config.access, std::path::Path::new(".")).unwrap());
        access.set_directory(Arc::new(RepoDirectory(state.repos.clone())));
        state.access = access;
        Fixture { state }
    }

    pub async fn person(&self, email: &str, groups: &[&str]) -> Ctx {
        let id = Uuid::new_v4();
        AccountRepo::insert(
            &*self.state.repos,
            &Account {
                id,
                email: email.into(),
                display_name: email.into(),
                password_hash: "x".into(),
                token_version: 0,
                created_at: Utc::now(),
                auth_provider: "local".into(),
                external_subject: None,
            },
        )
        .await
        .unwrap();
        let groups: Vec<String> = groups.iter().map(|g| g.to_string()).collect();
        self.state.repos.set_groups(id, &groups).await.unwrap();
        Ctx { account_id: id, via: crate::access::Via::Web }
    }

    pub async fn incident(&self, signals: &str, labels: &[(&str, &str)]) -> Uuid {
        let id = Uuid::new_v4();
        crate::db::IncidentRepo::insert(
            &*self.state.repos,
            &Incident {
                id,
                fingerprint: id.to_string(),
                fault_class: "other".into(),
                target: FqTarget::new("acme", "prod", "aks"),
                severity: Severity::Warning,
                state: IncidentState::Active,
                signals: signals.into(),
                hypothesis: format!("because {signals}"),
                recommended_action: None,
                opened_at: Utc::now(),
                reopened_at: None,
                acked_at: None,
                acked_by: None,
                resolved_at: None,
                last_notified_at: None,
                notify_count: 0,
                escalation_step: 0,
                step_started_at: None,
            },
        )
        .await
        .unwrap();
        let labels: Vec<crate::access::Label> = labels
            .iter()
            .map(|(t, c)| crate::access::Label { target: t.to_string(), class: c.to_string() })
            .collect();
        self.state.repos.add_labels("incident", &id.to_string(), &labels).await.unwrap();
        id
    }
}
