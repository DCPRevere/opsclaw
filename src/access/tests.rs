use std::collections::HashMap;
use std::sync::Mutex;

use super::*;

#[derive(Default)]
struct Dir {
    people: HashMap<Uuid, Subject>,
    elevations: Mutex<Vec<Elevation>>,
}

#[async_trait]
impl Directory for Dir {
    async fn subject(&self, account: Uuid) -> crate::Result<Option<Subject>> {
        Ok(self.people.get(&account).cloned())
    }
    async fn elevations(&self, account: Uuid) -> crate::Result<Vec<Elevation>> {
        Ok(self
            .elevations
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.account == account)
            .cloned()
            .collect())
    }
}

const TEAM: &str = r#"
preset = "team"

[[role]]
name = "readers"
idp_groups = ["opsclaw-sandbox-readers"]
where = ["example::sandbox"]
data = ["state", "metrics"]
findings = "summary"

[[role]]
name = "oncall"
members = ["bob@example.com"]
where = ["example::sandbox", "example::dev"]
data = ["state", "metrics", "logs"]
findings = "full"
actions = "request"

[[role]]
name = "investigators"
idp_groups = ["investigators"]
where = ["example::sandbox"]
data = ["logs:raw"]
elevation = "self"

[[role]]
name = "leads"
idp_groups = ["leads"]
where = ["*"]
data = ["state"]
actions = "approve"
"#;

struct World {
    access: Access,
    dir: Arc<Dir>,
    alice: Principal,
    bob: Principal,
    ivy: Principal,
    lee: Principal,
    nobody: Principal,
}

fn person(dir: &mut Dir, email: &str, groups: &[&str]) -> Principal {
    let account = Uuid::new_v4();
    dir.people.insert(
        account,
        Subject {
            account,
            email: email.into(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
        },
    );
    Principal::Operator { account }
}

fn world(src: &str) -> World {
    let cfg: AccessCfg = toml::from_str(src).unwrap();
    let access = Access::new(&cfg, Path::new(".")).unwrap();
    let mut dir = Dir::default();
    let alice = person(&mut dir, "alice@example.com", &["opsclaw-sandbox-readers"]);
    let bob = person(&mut dir, "Bob@Example.com", &[]);
    let ivy = person(&mut dir, "ivy@example.com", &["investigators"]);
    let lee = person(&mut dir, "lee@example.com", &["leads"]);
    let nobody = person(&mut dir, "eve@example.com", &["other"]);
    let dir = Arc::new(dir);
    access.set_directory(dir.clone());
    World { access, dir, alice, bob, ivy, lee, nobody }
}

const SB: &str = "example::sandbox::aks";
const ES: &str = "example::sandbox::aks::elasticsearch::logs";

#[tokio::test]
async fn solo_allows_everything_but_secrets() {
    let access = Access::solo();
    let op = Principal::Operator { account: Uuid::new_v4() };
    assert_eq!(access.read(&op, Via::Web, SB, "logs").await, Ok(Exposure::Raw));
    assert!(access.request(&op, Via::Web, SB).await.is_ok());
    assert_eq!(access.findings(&op, Via::Web, SB).await, FindingsLevel::Full);
    assert!(access.read(&op, Via::Web, SB, "secrets").await.is_err());
    // The agent is OpsClaw's own ceiling.
    let agent = Principal::Agent { job: None };
    assert_eq!(access.read(&agent, Via::Internal, SB, "secrets").await, Ok(Exposure::Raw));
}

#[tokio::test]
async fn roles_scope_classes_and_targets() {
    let w = world(TEAM);
    let a = &w.access;
    assert_eq!(a.read(&w.alice, Via::Web, SB, "state").await, Ok(Exposure::Raw));
    assert_eq!(a.read(&w.alice, Via::Web, SB, "metrics").await, Ok(Exposure::Raw));
    assert!(a.read(&w.alice, Via::Web, ES, "logs").await.is_err());
    assert!(a.read(&w.alice, Via::Web, "example::dev::aks", "state").await.is_err());
    assert!(a.read(&w.alice, Via::Web, "example::sandboxed::x", "state").await.is_err());
    assert!(a.request(&w.alice, Via::Web, SB).await.is_err());
    // Members match by email, case-insensitively; logs come redacted.
    assert_eq!(a.read(&w.bob, Via::Web, ES, "logs").await, Ok(Exposure::Redacted));
    assert_eq!(a.read(&w.bob, Via::Web, "example::dev::aks", "logs").await, Ok(Exposure::Redacted));
    assert!(a.request(&w.bob, Via::Web, SB).await.is_ok());
    // No role: nothing.
    assert!(a.read(&w.nobody, Via::Web, SB, "state").await.is_err());
    assert_eq!(a.findings(&w.nobody, Via::Web, SB).await, FindingsLevel::None);
    // Secrets never, whatever the role.
    assert!(a.read(&w.lee, Via::Web, SB, "secrets").await.is_err());
}

#[tokio::test]
async fn raw_needs_an_elevation_and_mcp_respects_it() {
    let w = world(TEAM);
    let a = &w.access;
    assert_eq!(a.read(&w.ivy, Via::Web, ES, "logs").await, Ok(Exposure::Redacted));
    assert_eq!(
        a.may_elevate(&w.ivy, "example::sandbox", "logs").await,
        Ok(ElevationMode::SelfService)
    );
    assert!(a.may_elevate(&w.bob, "example::sandbox", "logs").await.is_err());

    let Principal::Operator { account } = w.ivy else { unreachable!() };
    w.dir.elevations.lock().unwrap().push(Elevation {
        id: Uuid::new_v4(),
        account,
        scope: "example::sandbox".into(),
        class: "logs".into(),
        reason: "INC-1".into(),
        requested_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        state: ElevationState::Active,
        decided_by: None,
    });
    assert_eq!(a.read(&w.ivy, Via::Web, ES, "logs").await, Ok(Exposure::Raw));
    assert_eq!(a.read(&w.ivy, Via::Mcp, ES, "logs").await, Ok(Exposure::Raw));
    // Elevations don't spread to other classes.
    assert!(a.read(&w.ivy, Via::Web, ES, "messages").await.is_err());

    // Expired: back to redacted.
    w.dir.elevations.lock().unwrap()[0].expires_at = Utc::now() - chrono::Duration::minutes(1);
    assert_eq!(a.read(&w.ivy, Via::Web, ES, "logs").await, Ok(Exposure::Redacted));
}

#[tokio::test]
async fn mcp_gets_raw_only_with_an_elevation() {
    let src = r#"
        preset = "team"
        [[role]]
        name = "standing"
        members = ["bob@example.com"]
        where = ["*"]
        data = ["logs:raw"]
        elevation = "none"
    "#;
    let w = world(src);
    assert_eq!(w.access.read(&w.bob, Via::Web, ES, "logs").await, Ok(Exposure::Raw));
    assert_eq!(w.access.read(&w.bob, Via::Mcp, ES, "logs").await, Ok(Exposure::Redacted));
}

#[tokio::test]
async fn regulated_needs_an_approved_elevation_even_for_standing_raw() {
    let src = r#"
        preset = "regulated"
        [[role]]
        name = "standing"
        members = ["bob@example.com"]
        where = ["*"]
        data = ["logs:raw"]
        elevation = "self"
    "#;
    let w = world(src);
    let Principal::Operator { account } = w.bob else { unreachable!() };
    assert_eq!(w.access.may_elevate(&w.bob, "*", "logs").await, Ok(ElevationMode::Approval));
    let mut e = Elevation {
        id: Uuid::new_v4(),
        account,
        scope: "*".into(),
        class: "logs".into(),
        reason: "x".into(),
        requested_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        state: ElevationState::Active,
        decided_by: Some(account),
    };
    w.dir.elevations.lock().unwrap().push(e.clone());
    // Approving your own doesn't count.
    assert_eq!(w.access.read(&w.bob, Via::Web, ES, "logs").await, Ok(Exposure::Redacted));
    e.decided_by = Some(Uuid::new_v4());
    *w.dir.elevations.lock().unwrap() = vec![e];
    assert_eq!(w.access.read(&w.bob, Via::Web, ES, "logs").await, Ok(Exposure::Raw));
}

#[tokio::test]
async fn approvals_need_the_role_and_four_eyes() {
    let w = world(TEAM);
    assert!(w.access.approve(&w.lee, Via::Web, SB, &w.bob).await.is_ok());
    assert!(w.access.approve(&w.lee, Via::Web, SB, &w.lee).await.is_err());
    assert!(w.access.approve(&w.bob, Via::Web, SB, &w.alice).await.is_err());
}

#[tokio::test]
async fn finding_views_hide_and_redact_evidence_by_class() {
    let w = world(TEAM);
    let labels = vec![
        Label { target: SB.into(), class: "state".into() },
        Label { target: ES.into(), class: "logs".into() },
    ];
    let alice = w.access.view(&w.alice, Via::Web, SB, &labels).await;
    assert_eq!(alice.level, FindingsLevel::Summary);
    let bob = w.access.view(&w.bob, Via::Web, SB, &labels).await;
    assert_eq!(bob.level, FindingsLevel::Full);
    assert!(bob.hidden.is_empty());
    assert_eq!(bob.redact, vec![labels[1].clone()]);
    let nobody = w.access.view(&w.nobody, Via::Web, SB, &labels).await;
    assert_eq!(nobody.level, FindingsLevel::None);
}

#[tokio::test]
async fn custom_cedar_forbids_override_roles() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("extra.cedar"),
        r#"forbid(principal, action == OpsClaw::Action::"read", resource in OpsClaw::Scope::"example::dev")
           unless { principal in OpsClaw::Group::"dev-team" };"#,
    )
    .unwrap();
    let mut cfg: AccessCfg = toml::from_str(TEAM).unwrap();
    cfg.cedar_policies = Some("extra.cedar".into());
    let access = Access::new(&cfg, dir.path()).unwrap();
    let mut d = Dir::default();
    let bob = person(&mut d, "bob@example.com", &[]);
    access.set_directory(Arc::new(d));
    assert!(access.read(&bob, Via::Web, "example::dev::aks", "logs").await.is_err());
    assert!(access.read(&bob, Via::Web, SB, "logs").await.is_ok());
    // The agent can be fenced too: "this class never goes to the LLM".
    let src = r#"forbid(principal is OpsClaw::Agent, action, resource) when { context.class == "logs" };"#;
    std::fs::write(dir.path().join("extra.cedar"), src).unwrap();
    let access = Access::new(&cfg, dir.path()).unwrap();
    let agent = Principal::Agent { job: None };
    assert!(access.read(&agent, Via::Internal, ES, "logs").await.is_err());
}

#[tokio::test]
async fn fail_closed_without_a_directory() {
    let cfg: AccessCfg = toml::from_str(TEAM).unwrap();
    let access = Access::new(&cfg, Path::new(".")).unwrap();
    let op = Principal::Operator { account: Uuid::new_v4() };
    assert!(access.read(&op, Via::Web, SB, "state").await.is_err());
}

#[test]
fn bad_configs_are_refused() {
    let bad = [
        (
            r#"preset = "team"
            [[role]]
            name = "r"
            members = ["a@b"]
            where = ["*"]
            data = ["secrets"]"#,
            "can never be granted",
        ),
        (
            r#"preset = "team"
            [[role]]
            name = "r"
            members = ["a@b"]
            where = ["*"]
            data = ["nope"]"#,
            "unknown data class",
        ),
        (
            r#"preset = "team"
            [[role]]
            name = "r"
            where = ["*"]"#,
            "nobody holds it",
        ),
        (
            r#"[[role]]
            name = "r"
            members = ["a@b"]
            where = ["*"]"#,
            "no effect under preset",
        ),
        (r#"disable_builtin_redaction = ["nope"]"#, "no built-in pattern"),
    ];
    for (src, want) in bad {
        let cfg: AccessCfg = toml::from_str(src).unwrap();
        let err = Access::new(&cfg, Path::new(".")).err().expect(src).to_string();
        assert!(err.contains(want), "{src}: {err}");
    }
}

#[test]
fn explain_names_the_deciding_policy() {
    let w = world(TEAM);
    let lines = futures_lite(w.access.explain(&w.bob, Via::Web, "read", ES, "logs"));
    assert!(
        lines
            .iter()
            .any(|l| l.contains("read redacted: ALLOW (role:oncall:read:example::sandbox)")),
        "{lines:?}"
    );
}

fn futures_lite<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
}

#[test]
fn scope_cover_is_by_whole_segments() {
    assert!(scope_covers("*", "a::b"));
    assert!(scope_covers("a", "a::b"));
    assert!(scope_covers("a::b", "a::b"));
    assert!(!scope_covers("a::b", "a::bc"));
    assert!(!scope_covers("a::b::c", "a::b"));
}
