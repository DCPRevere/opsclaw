//! Who may see and do what (docs/plans/ACCESS.md).
//!
//! The mechanisms here are fixed; the policy is configuration:
//! - every tool call is classified into a data class ([`classes`]);
//! - `policy::execute` asks [`Access`] before running it, as the person
//!   who asked (an agent turn carries the asker's principal);
//! - the answer comes from Cedar policies compiled from `[access]` roles,
//!   built-in invariants, and an optional custom Cedar file ([`cedar`]);
//! - results a person may only see redacted pass through [`redact`];
//! - every call records a [`Label`] so findings built from it can be
//!   filtered for each reader.

mod cedar;
pub mod classes;
pub mod config;
pub mod findings;
pub mod redact;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use config::{AccessCfg, ActionsLevel, ElevationMode, FindingsLevel, McpRaw, Preset, RoleCfg};

use crate::domain::{FqTarget, Principal};

/// Does the scope prefix `prefix` cover the fq path `path`?
pub fn scope_covers(prefix: &str, path: &str) -> bool {
    prefix == "*"
        || path == prefix
        || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with("::"))
}

/// Which surface a request came through. Policies can tell them apart
/// (`context.client`); the built-ins treat `mcp` specially.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// The daemon itself: scheduled scans, webhooks, housekeeping.
    #[default]
    Internal,
    Web,
    Cli,
    Mcp,
    /// A chat channel such as Telegram.
    Channel,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Internal => "internal",
            Via::Web => "web",
            Via::Cli => "cli",
            Via::Mcp => "mcp",
            Via::Channel => "channel",
        }
    }
}

/// One source a finding was built from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Label {
    pub target: String,
    pub class: String,
}

/// The labels gathered during one turn. Cheap to clone; clones share.
#[derive(Debug, Clone, Default)]
pub struct Labels(Arc<std::sync::Mutex<BTreeSet<Label>>>);

impl Labels {
    pub fn add(&self, target: &str, class: &str) {
        let mut set = self.0.lock().unwrap_or_else(|p| p.into_inner());
        set.insert(Label { target: target.to_string(), class: class.to_string() });
    }

    pub fn snapshot(&self) -> Vec<Label> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).iter().cloned().collect()
    }
}

/// How a permitted read is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    Raw,
    Redacted,
}

/// A signed-in person, as the access check needs them.
#[derive(Debug, Clone)]
pub struct Subject {
    pub account: Uuid,
    pub email: String,
    /// Groups or app roles from the IdP's token, refreshed at each sign-in.
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElevationState {
    Pending,
    Active,
    Denied,
    Revoked,
}

impl ElevationState {
    pub fn as_str(self) -> &'static str {
        match self {
            ElevationState::Pending => "pending",
            ElevationState::Active => "active",
            ElevationState::Denied => "denied",
            ElevationState::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => ElevationState::Pending,
            "active" => ElevationState::Active,
            "denied" => ElevationState::Denied,
            "revoked" => ElevationState::Revoked,
            _ => return None,
        })
    }
}

/// A time-boxed window of raw access to one class in one scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Elevation {
    pub id: Uuid,
    pub account: Uuid,
    pub scope: String,
    pub class: String,
    pub reason: String,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub state: ElevationState,
    /// Set when someone else approved it (or denied/revoked it).
    pub decided_by: Option<Uuid>,
}

impl Elevation {
    pub fn live(&self, now: DateTime<Utc>) -> bool {
        self.state == ElevationState::Active && self.expires_at > now
    }

    pub fn approved(&self) -> bool {
        self.decided_by.is_some_and(|d| d != self.account)
    }
}

/// Where the access check looks people and elevations up.
#[async_trait]
pub trait Directory: Send + Sync {
    async fn subject(&self, account: Uuid) -> crate::Result<Option<Subject>>;
    async fn elevations(&self, account: Uuid) -> crate::Result<Vec<Elevation>>;
}

/// The access engine. One per daemon, shared by the policy layer and every
/// read surface.
pub struct Access {
    cfg: AccessCfg,
    classes: classes::ClassTable,
    redactor: redact::Redactor,
    policies: cedar_policy::PolicySet,
    source: String,
    directory: OnceLock<Arc<dyn Directory>>,
}

/// A refusal, with the reason a person (or model) is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied(pub String);

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

struct Actor {
    who: cedar::CedarPrincipal,
    elevations: Vec<Elevation>,
    account: Option<Uuid>,
}

impl Access {
    /// Build from config. `home` resolves a relative `cedar_policies` path.
    pub fn new(cfg: &AccessCfg, home: &Path) -> crate::Result<Self> {
        validate(cfg)?;
        let classes = classes::ClassTable::new(cfg);
        let redactor = redact::Redactor::new(cfg)?;
        let mut source = cedar::compile(cfg);
        if let Some(path) = &cfg.cedar_policies {
            let path = if path.is_absolute() { path.clone() } else { home.join(path) };
            let extra = std::fs::read_to_string(&path).map_err(|e| {
                crate::Error::Config(format!("access.cedar_policies {}: {e}", path.display()))
            })?;
            source.push_str("\n// From ");
            source.push_str(&path.display().to_string());
            source.push('\n');
            source.push_str(&extra);
        }
        let policies = cedar::parse(&source)?;
        Ok(Access {
            cfg: cfg.clone(),
            classes,
            redactor,
            policies,
            source,
            directory: OnceLock::new(),
        })
    }

    /// Everything allowed, as before `[access]` existed. For tests and
    /// tools that never see a person.
    pub fn solo() -> Self {
        Self::new(&AccessCfg::default(), Path::new(".")).expect("the solo preset compiles")
    }

    /// Nobody but OpsClaw itself: the fail-closed fallback when the
    /// configured rules can't be built.
    pub fn nobody() -> Self {
        let cfg = AccessCfg { preset: Preset::Team, ..Default::default() };
        Self::new(&cfg, Path::new(".")).expect("an empty team preset compiles")
    }

    /// Install where people and elevations are looked up. Without it, any
    /// person outside `solo` is refused (fail closed).
    pub fn set_directory(&self, directory: Arc<dyn Directory>) {
        let _ = self.directory.set(directory);
    }

    pub fn config(&self) -> &AccessCfg {
        &self.cfg
    }

    /// The compiled Cedar source, for `access policies`.
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn classify(&self, tool: &str, target: &str, command: &str) -> String {
        classes::classify(&self.cfg, tool, target, command)
    }

    pub fn redacts(&self, class: &str) -> bool {
        self.classes.redacted(class)
    }

    pub fn redact(&self, class: &str, text: &str) -> String {
        self.redactor.redact(class, text)
    }

    async fn actor(&self, principal: &Principal) -> Result<Actor, Denied> {
        match principal {
            Principal::Agent { .. } => Ok(Actor {
                who: cedar::CedarPrincipal {
                    uid: cedar::uid("OpsClaw::Agent", "opsclaw"),
                    roles: vec![],
                    groups: vec![],
                    email: None,
                },
                elevations: vec![],
                account: None,
            }),
            Principal::System => Ok(Actor {
                who: cedar::CedarPrincipal {
                    uid: cedar::uid("OpsClaw::System", "daemon"),
                    roles: vec![],
                    groups: vec![],
                    email: None,
                },
                elevations: vec![],
                account: None,
            }),
            Principal::Operator { account } => {
                let uid = cedar::uid("OpsClaw::User", &account.to_string());
                let Some(dir) = self.directory.get() else {
                    if self.cfg.preset == Preset::Solo {
                        return Ok(Actor {
                            who: cedar::CedarPrincipal {
                                uid,
                                roles: vec![],
                                groups: vec![],
                                email: None,
                            },
                            elevations: vec![],
                            account: Some(*account),
                        });
                    }
                    return Err(Denied("access: no account directory is configured".into()));
                };
                let subject = dir
                    .subject(*account)
                    .await
                    .map_err(|e| Denied(format!("access: account lookup failed: {e}")))?
                    .ok_or_else(|| Denied("access: unknown account".into()))?;
                let elevations = dir
                    .elevations(*account)
                    .await
                    .map_err(|e| Denied(format!("access: elevation lookup failed: {e}")))?;
                Ok(Actor {
                    who: cedar::CedarPrincipal {
                        uid,
                        roles: self.roles_of(&subject),
                        groups: subject.groups.clone(),
                        email: Some(subject.email.clone()),
                    },
                    elevations,
                    account: Some(*account),
                })
            }
        }
    }

    /// The configured roles this person holds.
    pub fn roles_of(&self, subject: &Subject) -> Vec<String> {
        self.cfg
            .roles
            .iter()
            .filter(|r| {
                r.members.iter().any(|m| m.eq_ignore_ascii_case(&subject.email))
                    || r.idp_groups.iter().any(|g| subject.groups.contains(g))
            })
            .map(|r| r.name.clone())
            .collect()
    }

    fn ask(
        &self,
        actor: &Actor,
        action: &str,
        scope: &str,
        class: &str,
        raw: bool,
        via: Via,
        level: &str,
    ) -> cedar::Answer {
        let now = Utc::now();
        let covering: Vec<&Elevation> = actor
            .elevations
            .iter()
            .filter(|e| e.live(now) && e.class == class && scope_covers(&e.scope, scope))
            .collect();
        let answer = cedar::ask(
            &self.policies,
            &actor.who,
            &cedar::Ask {
                action,
                scope,
                class,
                raw,
                elevated: !covering.is_empty(),
                elevation_approved: covering.iter().any(|e| e.approved()),
                client: via.as_str(),
                level,
            },
        );
        for e in &answer.errors {
            tracing::warn!(action, scope, class, "access policy error: {e}");
        }
        answer
    }

    /// May `principal` read `class` on `target`, and how?
    pub async fn read(
        &self,
        principal: &Principal,
        via: Via,
        target: &str,
        class: &str,
    ) -> Result<Exposure, Denied> {
        let actor = self.actor(principal).await?;
        self.read_as(&actor, via, target, class)
    }

    fn read_as(
        &self,
        actor: &Actor,
        via: Via,
        target: &str,
        class: &str,
    ) -> Result<Exposure, Denied> {
        if self.ask(actor, "read", target, class, true, via, "").allowed {
            return Ok(Exposure::Raw);
        }
        if self.ask(actor, "read", target, class, false, via, "").allowed {
            // A class that is never redacted has no redacted form: allowed
            // at all means allowed as it is.
            return Ok(if self.redacts(class) { Exposure::Redacted } else { Exposure::Raw });
        }
        Err(Denied(format!("you have no access to {class} on {target}")))
    }

    /// May `principal` ask for a mutation on `target`?
    pub async fn request(
        &self,
        principal: &Principal,
        via: Via,
        target: &str,
    ) -> Result<(), Denied> {
        let actor = self.actor(principal).await?;
        if self.ask(&actor, "request", target, "", false, via, "").allowed {
            Ok(())
        } else {
            Err(Denied(format!("you may not request actions on {target}")))
        }
    }

    /// May `approver` decide a request (or elevation) on `target` that
    /// `requested_by` made? Never their own.
    pub async fn approve(
        &self,
        approver: &Principal,
        via: Via,
        target: &str,
        requested_by: &Principal,
    ) -> Result<(), Denied> {
        if self.cfg.preset != Preset::Solo && approver == requested_by {
            return Err(Denied("you cannot approve your own request".into()));
        }
        let actor = self.actor(approver).await?;
        if self.ask(&actor, "approve", target, "", false, via, "").allowed {
            Ok(())
        } else {
            Err(Denied(format!("you may not approve requests on {target}")))
        }
    }

    /// How much of the findings about `target` this person may see.
    pub async fn findings(&self, principal: &Principal, via: Via, target: &str) -> FindingsLevel {
        let Ok(actor) = self.actor(principal).await else { return FindingsLevel::None };
        self.findings_as(&actor, via, target)
    }

    fn findings_as(&self, actor: &Actor, via: Via, target: &str) -> FindingsLevel {
        if self.ask(actor, "view_findings", target, "", false, via, "full").allowed {
            FindingsLevel::Full
        } else if self.ask(actor, "view_findings", target, "", false, via, "summary").allowed {
            FindingsLevel::Summary
        } else {
            FindingsLevel::None
        }
    }

    /// A reader's view of a finding with these labels about `target`.
    pub async fn view(
        &self,
        principal: &Principal,
        via: Via,
        target: &str,
        labels: &[Label],
    ) -> FindingView {
        let Ok(actor) = self.actor(principal).await else {
            return FindingView { level: FindingsLevel::None, hidden: vec![], redact: vec![] };
        };
        let level = self.findings_as(&actor, via, target);
        let mut hidden = Vec::new();
        let mut redact = Vec::new();
        if level == FindingsLevel::Full {
            for l in labels {
                match self.read_as(&actor, via, &l.target, &l.class) {
                    Ok(Exposure::Raw) => {}
                    Ok(Exposure::Redacted) => redact.push(l.clone()),
                    Err(_) => hidden.push(l.clone()),
                }
            }
        }
        FindingView { level, hidden, redact }
    }

    /// May this person open an elevation for `class` on `scope`, and does
    /// it need someone else's approval?
    pub async fn may_elevate(
        &self,
        principal: &Principal,
        scope: &str,
        class: &str,
    ) -> Result<ElevationMode, Denied> {
        let actor = self.actor(principal).await?;
        if !self.ask(&actor, "elevate", scope, class, true, Via::Web, "").allowed {
            return Err(Denied(format!("no role lets you elevate to raw {class} on {scope}")));
        }
        let held: Vec<&RoleCfg> =
            self.cfg.roles.iter().filter(|r| actor.who.roles.contains(&r.name)).collect();
        let self_service = held.iter().any(|r| {
            r.elevation == ElevationMode::SelfService
                && r.scopes.iter().any(|s| scope_covers(s, scope))
                && r.data.iter().any(|d| d.strip_suffix(":raw") == Some(class))
        });
        if self_service && self.cfg.preset != Preset::Regulated {
            Ok(ElevationMode::SelfService)
        } else {
            Ok(ElevationMode::Approval)
        }
    }

    /// Is this person on a hand-set restriction list (emails or groups)?
    /// OpsClaw itself always is.
    pub async fn is_listed(&self, principal: &Principal, list: &[String]) -> bool {
        let Principal::Operator { account } = principal else { return true };
        let Some(dir) = self.directory.get() else { return false };
        match dir.subject(*account).await {
            Ok(Some(s)) => list.iter().any(|entry| {
                entry.eq_ignore_ascii_case(&s.email) || s.groups.iter().any(|g| g == entry)
            }),
            _ => false,
        }
    }

    /// The live account id behind a principal, if any.
    pub async fn account_of(&self, principal: &Principal) -> Option<Uuid> {
        self.actor(principal).await.ok().and_then(|a| a.account)
    }

    /// Explain a decision, for `opsclaw-cli access explain`.
    pub async fn explain(
        &self,
        principal: &Principal,
        via: Via,
        action: &str,
        target: &str,
        class: &str,
    ) -> Vec<String> {
        let actor = match self.actor(principal).await {
            Ok(a) => a,
            Err(d) => return vec![format!("refused: {d}")],
        };
        let mut lines = vec![format!(
            "roles: {}",
            if actor.who.roles.is_empty() { "(none)".into() } else { actor.who.roles.join(", ") }
        )];
        let asks: Vec<(&str, bool, &str)> = match action {
            "read" => vec![("raw", true, ""), ("redacted", false, "")],
            "view_findings" => vec![("full", false, "full"), ("summary", false, "summary")],
            _ => vec![("", false, "")],
        };
        for (label, raw, level) in asks {
            let a = self.ask(&actor, action, target, class, raw, via, level);
            lines.push(format!(
                "{action}{}{}: {} ({})",
                if label.is_empty() { "" } else { " " },
                label,
                if a.allowed { "ALLOW" } else { "DENY" },
                if a.because.is_empty() {
                    "no policy matched".into()
                } else {
                    a.because.join(", ")
                }
            ));
        }
        lines
    }

    /// Elevation length limit.
    pub fn max_elevation(&self) -> chrono::Duration {
        chrono::Duration::hours(self.cfg.elevation.max_hours.max(1) as i64)
    }

    /// Is this MCP client allowed to connect?
    pub fn mcp_client_allowed(&self, client: &str) -> bool {
        self.cfg.mcp.clients.is_empty() || self.cfg.mcp.clients.iter().any(|c| c == client)
    }
}

/// What a reader may see of one finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingView {
    pub level: FindingsLevel,
    /// Sources whose evidence is hidden from this reader.
    pub hidden: Vec<Label>,
    /// Sources whose evidence this reader sees redacted.
    pub redact: Vec<Label>,
}

/// Convenience for FqTarget call sites.
pub fn path(target: &FqTarget) -> String {
    target.to_string()
}

/// Check `[access]` without loading a custom Cedar file (config
/// validation; boot loads and checks the file too).
pub fn check(cfg: &AccessCfg) -> crate::Result<()> {
    validate(cfg)?;
    redact::Redactor::new(cfg)?;
    cedar::parse(&cedar::compile(cfg)).map(|_| ())
}

fn validate(cfg: &AccessCfg) -> crate::Result<()> {
    let table = classes::ClassTable::new(cfg);
    let err = |m: String| Err(crate::Error::Config(m));
    let mut names = std::collections::HashSet::new();
    for c in &cfg.classes {
        if classes::BUILT_IN.iter().any(|(n, _)| *n == c.name) {
            return err(format!("access.class {:?} is a built-in class", c.name));
        }
        if c.name.is_empty() || c.name.contains(':') {
            return err(format!("access.class {:?}: names cannot be empty or contain ':'", c.name));
        }
    }
    for role in &cfg.roles {
        if !names.insert(role.name.as_str()) {
            return err(format!("access.role {:?} is defined twice", role.name));
        }
        if role.scopes.is_empty() {
            return err(format!("access.role {:?} has no `where`", role.name));
        }
        if role.idp_groups.is_empty() && role.members.is_empty() {
            return err(format!(
                "access.role {:?} has neither idp_groups nor members, so nobody holds it",
                role.name
            ));
        }
        for d in &role.data {
            let class = d.strip_suffix(":raw").unwrap_or(d);
            if class == classes::SECRETS {
                return err(format!("access.role {:?}: `secrets` can never be granted", role.name));
            }
            if !table.exists(class) {
                return err(format!(
                    "access.role {:?}: unknown data class {class:?} (known: {})",
                    role.name,
                    table.names().collect::<Vec<_>>().join(", ")
                ));
            }
        }
    }
    for rule in &cfg.class_rules {
        if !table.exists(&rule.class) {
            return err(format!(
                "access.class_rule for {:?}: unknown class {:?}",
                rule.tool, rule.class
            ));
        }
    }
    for r in &cfg.redact {
        for c in &r.classes {
            if !table.exists(c) {
                return err(format!("access.redact {:?}: unknown class {c:?}", r.name));
            }
        }
    }
    for d in &cfg.disable_builtin_redaction {
        if !redact::Redactor::builtin_names().any(|n| n == d) {
            return err(format!("access.disable_builtin_redaction: no built-in pattern {d:?}"));
        }
    }
    if cfg.preset == Preset::Solo && !cfg.roles.is_empty() {
        return err(
            "access: roles have no effect under preset \"solo\" (everyone sees everything); \
             set preset = \"team\" or \"regulated\""
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;

/// The account directory over the daemon's store.
pub struct RepoDirectory(pub Arc<dyn crate::db::AllRepos>);

#[async_trait]
impl Directory for RepoDirectory {
    async fn subject(&self, account: Uuid) -> crate::Result<Option<Subject>> {
        let Some(a) = crate::db::AccountRepo::by_id(&*self.0, account).await? else {
            return Ok(None);
        };
        let groups = crate::db::AccessRepo::groups(&*self.0, account).await?;
        Ok(Some(Subject { account, email: a.email, groups }))
    }

    async fn elevations(&self, account: Uuid) -> crate::Result<Vec<Elevation>> {
        crate::db::AccessRepo::elevations_for(&*self.0, account).await
    }
}
