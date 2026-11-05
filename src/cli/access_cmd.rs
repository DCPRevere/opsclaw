//! `opsclaw-cli access`: inspect and explain the access rules
//! (`crate::access`). Local: reads the config and the daemon's database.

use std::path::Path;
use std::sync::Arc;

use crate::Result;
use crate::access::{Access, RepoDirectory, Via};
use crate::config::Config;
use crate::db::{AccountRepo, Db};
use crate::domain::Principal;

fn engine(cfg: &Config, home: &Path, db: &Db) -> Result<Access> {
    let access = Access::new(&cfg.access, home)?;
    access.set_directory(Arc::new(RepoDirectory(db.repos())));
    Ok(access)
}

/// The Cedar policies in force: built-ins, compiled roles, custom file.
pub fn policies(cfg: &Config, home: &Path) -> Result<String> {
    Ok(Access::new(&cfg.access, home)?.source().to_string())
}

/// Every account and the roles it holds.
pub async fn who(cfg: &Config, home: &Path, db: &Db) -> Result<Vec<String>> {
    let access = engine(cfg, home, db)?;
    let mut out = vec![format!("preset: {:?}", cfg.access.preset).to_lowercase()];
    for a in AccountRepo::list(&*db.repos()).await? {
        let groups = db.repos().groups(a.id).await?;
        let subject = crate::access::Subject {
            account: a.id,
            email: a.email.clone(),
            groups: groups.clone(),
        };
        let roles = access.roles_of(&subject);
        out.push(format!(
            "{}  roles: {}  groups: {}",
            a.email,
            if roles.is_empty() { "(none)".into() } else { roles.join(", ") },
            if groups.is_empty() { "(none)".into() } else { groups.join(", ") },
        ));
    }
    Ok(out)
}

/// Why `email` may or may not do `action` on `target`.
pub async fn explain(
    cfg: &Config,
    home: &Path,
    db: &Db,
    email: &str,
    action: &str,
    target: &str,
    class: &str,
    via: Via,
) -> Result<Vec<String>> {
    let access = engine(cfg, home, db)?;
    let account = db
        .repos()
        .by_email(&email.trim().to_ascii_lowercase())
        .await?
        .ok_or_else(|| crate::Error::NotFound(format!("account {email}")))?;
    Ok(access
        .explain(&Principal::Operator { account: account.id }, via, action, target, class)
        .await)
}

/// Restrict an incident to named people or groups, or lift it.
pub async fn restrict(db: &Db, incident: uuid::Uuid, to: &[String]) -> Result<()> {
    crate::db::IncidentRepo::get(&*db.repos(), incident)
        .await?
        .ok_or_else(|| crate::Error::NotFound(format!("incident {incident}")))?;
    let to = (!to.is_empty()).then_some(to);
    db.repos().set_restricted("incident", &incident.to_string(), to).await
}

/// Every elevation, newest first.
pub async fn elevations(db: &Db) -> Result<Vec<String>> {
    let now = chrono::Utc::now();
    let mut out = Vec::new();
    for e in db.repos().list_elevations().await? {
        let who = AccountRepo::by_id(&*db.repos(), e.account)
            .await?
            .map(|a| a.email)
            .unwrap_or_else(|| e.account.to_string());
        out.push(format!(
            "{}  {}  raw {} on {}  {}  until {}  ({})",
            e.id,
            who,
            e.class,
            e.scope,
            if e.live(now) { "LIVE".to_string() } else { e.state.as_str().to_string() },
            e.expires_at.format("%Y-%m-%d %H:%M UTC"),
            e.reason
        ));
    }
    Ok(out)
}
