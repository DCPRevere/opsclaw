//! `opsclaw-cli approvals list|show|approve|deny` — the queue, locally.
//!
//! The gap this closes was total. `ApprovalRepo::list_pending()` has always
//! existed and `GET /api/approvals` has always used it, but no CLI command
//! did — so `opsclaw-cli approve <id>` required a UUID that nothing local
//! would print. And `approve`/`deny` were remote-ONLY, needing a gateway
//! session, which needs `login`, which is a browser hand-off. On a host
//! whose web UI is not reachable yet, every route to the queue was closed:
//! an operator could watch the agent say "queued for human approval" and
//! have no way to see the request, let alone answer it.
//!
//! So these are LOCAL, against the same SQLite file the daemon uses. Reading
//! is plainly safe. Deciding is safe for a subtler reason: `ApprovalRepo::
//! decide` is an atomic compare-and-set on a PENDING row, so a decision here
//! and a decision through the gateway cannot both land — the second gets
//! `Error::Conflict` rather than executing the command twice.
//!
//! [`approve`] EXECUTES the stored command, verbatim, in this process. That
//! is the same contract the gateway has (`incidents::approvals::approve`
//! takes `ExecuteApproved`, deliberately not `PolicyExecute`, so approving
//! cannot re-enter the autonomy gate and queue a second approval) — but it
//! means the command runs wherever the CLI runs. Under the standard docker
//! install that is the daemon's own container, which is the same network
//! position the daemon would have acted from.

use std::sync::Arc;

use serde::Serialize;
use uuid::Uuid;

use crate::Result;
use crate::db::{AccountRepo, AllRepos, ApprovalRepo};
use crate::domain::{ApprovalRequest, ApprovalState};

/// One queued request, flattened for display. `ApprovalRequest` is already
/// `Serialize`, but its `Principal` and `FqTarget` render as structures;
/// an operator deciding under pressure needs one line per fact.
#[derive(Debug, Serialize)]
pub struct ApprovalView {
    pub id: Uuid,
    pub target: String,
    pub tool: String,
    /// The exact command that runs on approval, verbatim.
    pub command: String,
    pub risk: String,
    pub hypothesis: String,
    pub state: String,
    pub requested_by: String,
    pub requested_at: String,
    pub expires_at: String,
    pub incident: Option<Uuid>,
}

impl From<&ApprovalRequest> for ApprovalView {
    fn from(a: &ApprovalRequest) -> Self {
        ApprovalView {
            id: a.id,
            target: a.target.to_string(),
            tool: a.tool.clone(),
            command: a.command.clone(),
            risk: format!("{:?}", a.risk).to_lowercase(),
            hypothesis: a.hypothesis.clone(),
            state: format!("{:?}", a.state).to_lowercase(),
            requested_by: format!("{:?}", a.requested_by),
            requested_at: a.requested_at.to_rfc3339(),
            expires_at: a.expires_at.to_rfc3339(),
            incident: a.incident,
        }
    }
}

/// Every request still awaiting a decision.
pub async fn list(repos: &Arc<dyn AllRepos>) -> Result<Vec<ApprovalView>> {
    let pending = ApprovalRepo::list_pending(&**repos).await?;
    Ok(pending.iter().map(ApprovalView::from).collect())
}

/// One request by id, pending or already decided — `show` must work after
/// the fact, because "what did we approve, and who approved it?" is a
/// post-incident question.
pub async fn show(repos: &Arc<dyn AllRepos>, id: Uuid) -> Result<ApprovalView> {
    ApprovalRepo::get(&**repos, id)
        .await?
        .as_ref()
        .map(ApprovalView::from)
        .ok_or_else(|| crate::Error::Config(format!("no approval with id {id}")))
}

/// Render the queue for a human.
///
/// The command is printed VERBATIM and on its own line. It is the thing
/// being consented to, and an operator who cannot see exactly what will run
/// is not really approving anything.
pub fn render(views: &[ApprovalView]) -> String {
    if views.is_empty() {
        return "no pending approvals.\n".to_string();
    }
    let mut out = String::new();
    for a in views {
        out.push_str(&format!("{}  [{}]  {}\n", a.id, a.risk, a.target));
        out.push_str(&format!("  tool        {}\n", a.tool));
        out.push_str(&format!("  command     {}\n", a.command));
        out.push_str(&format!("  because     {}\n", a.hypothesis));
        out.push_str(&format!("  requested   {} by {}\n", a.requested_at, a.requested_by));
        out.push_str(&format!("  expires     {}\n", a.expires_at));
        if let Some(i) = a.incident {
            out.push_str(&format!("  incident    {i}\n"));
        }
        if a.state != "pending" {
            out.push_str(&format!("  state       {}\n", a.state));
        }
        out.push('\n');
    }
    out.push_str("decide with `opsclaw-cli approvals approve <id>` or `... deny <id>`.\n");
    out
}

/// Which operator a local decision is attributed to.
///
/// The audit chain records `decided_by`, and a local invocation has no
/// session to read it from. Rather than invent an id — which would put a
/// name on a decision nobody made — this resolves an explicit `--as <email>`
/// or, when the deployment has exactly ONE operator account, that account:
/// unambiguous, and the overwhelmingly common shape. With several accounts
/// and no `--as`, it refuses and lists them, because guessing here forges an
/// attribution in an append-only log.
pub async fn resolve_operator(repos: &Arc<dyn AllRepos>, as_email: Option<&str>) -> Result<Uuid> {
    let accounts = AccountRepo::list(&**repos).await?;
    if let Some(email) = as_email {
        return accounts
            .iter()
            .find(|a| a.email.eq_ignore_ascii_case(email))
            .map(|a| a.id)
            .ok_or_else(|| {
                crate::Error::Config(format!(
                    "no operator account {email:?}. Known: {}",
                    accounts.iter().map(|a| a.email.as_str()).collect::<Vec<_>>().join(", ")
                ))
            });
    }
    match accounts.as_slice() {
        [] => Err(crate::Error::Config(
            "no operator accounts exist — create one with `opsclaw-cli account create <email>` \
             so the decision can be attributed"
                .into(),
        )),
        [only] => Ok(only.id),
        many => Err(crate::Error::Config(format!(
            "several operator accounts exist, so who is deciding cannot be inferred — pass --as \
             <email>. Known: {}",
            many.iter().map(|a| a.email.as_str()).collect::<Vec<_>>().join(", ")
        ))),
    }
}

/// The confirmation preview for a decision: the verbatim command, because
/// approving is consenting to exactly that string running.
pub fn decision_preview(view: &ApprovalView, approving: bool) -> String {
    if approving {
        format!(
            "will APPROVE and immediately RUN this command on {}:\n\n  {}\n\nrisk: {}   because: \
             {}",
            view.target, view.command, view.risk, view.hypothesis
        )
    } else {
        format!(
            "will DENY this request on {}:\n\n  {}\n\nthe command will not run.",
            view.target, view.command
        )
    }
}

/// Whether a request can still be decided. Checked before prompting so the
/// operator is not asked to confirm something that will then fail.
pub fn is_pending(view: &ApprovalView) -> bool {
    view.state == format!("{:?}", ApprovalState::Pending).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::domain::{FqTarget, Principal, RiskClass};
    use chrono::{Duration, Utc};

    async fn db() -> Db {
        Db::connect("sqlite::memory:").await.unwrap()
    }

    fn request(command: &str) -> ApprovalRequest {
        ApprovalRequest {
            id: Uuid::new_v4(),
            incident: None,
            requested_by: Principal::Agent { job: None },
            target: FqTarget::parse("example::prod::web-1").unwrap(),
            tool: "shell".into(),
            command: command.into(),
            risk: RiskClass::High,
            hypothesis: "disk is full".into(),
            state: ApprovalState::Pending,
            requested_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            decided_at: None,
            decided_by: None,
        }
    }

    #[tokio::test]
    async fn list_surfaces_the_id_that_approve_needs() {
        // The whole point: `approve <id>` was unusable because no local
        // command would print an id.
        let db = db().await;
        let repos = db.repos();
        let req = request("rm -rf /var/log/old");
        ApprovalRepo::insert(&*repos, &req).await.unwrap();

        let views = list(&repos).await.unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].id, req.id);

        let text = render(&views);
        assert!(text.contains(&req.id.to_string()), "the id must be copy-pasteable: {text}");
        assert!(
            text.contains("rm -rf /var/log/old"),
            "the VERBATIM command is the thing being consented to: {text}"
        );
        assert!(text.contains("disk is full"), "and why: {text}");
    }

    #[tokio::test]
    async fn show_still_works_after_a_decision() {
        // "What did we approve, and who approved it?" is a post-incident
        // question, so show must not be restricted to pending rows.
        let db = db().await;
        let repos = db.repos();
        let req = request("systemctl restart nginx");
        ApprovalRepo::insert(&*repos, &req).await.unwrap();
        let operator = Uuid::new_v4();
        ApprovalRepo::decide(&*repos, req.id, ApprovalState::Denied, operator).await.unwrap();

        let view = show(&repos, req.id).await.unwrap();
        assert_eq!(view.state, "denied");
        assert!(!is_pending(&view));
        assert!(list(&repos).await.unwrap().is_empty(), "and it leaves the pending queue");
    }

    #[tokio::test]
    async fn an_unknown_id_is_an_error_not_an_empty_success() {
        let db = db().await;
        assert!(show(&db.repos(), Uuid::new_v4()).await.is_err());
    }

    #[tokio::test]
    async fn the_deciding_operator_is_resolved_never_invented() {
        // decided_by lands in an append-only audit chain. Guessing it would
        // put a name on a decision that person did not make.
        let db = db().await;
        let repos = db.repos();

        let err = resolve_operator(&repos, None).await.unwrap_err().to_string();
        assert!(err.contains("account create"), "no accounts: say how to fix it: {err}");

        let a = crate::cli::account_cmd::create(
            &db,
            "solo@example.com",
            "Solo",
            crate::cli::account_cmd::Credential::Password("a-long-enough-password"),
        )
        .await
        .unwrap();
        assert_eq!(
            resolve_operator(&repos, None).await.unwrap(),
            a.id,
            "one account is unambiguous"
        );

        crate::cli::account_cmd::create(
            &db,
            "second@example.com",
            "Second",
            crate::cli::account_cmd::Credential::Password("another-long-password"),
        )
        .await
        .unwrap();
        let err = resolve_operator(&repos, None).await.unwrap_err().to_string();
        assert!(err.contains("--as"), "two accounts: refuse and say how: {err}");
        assert!(err.contains("solo@example.com"), "listing them: {err}");

        assert_eq!(
            resolve_operator(&repos, Some("SOLO@example.com")).await.unwrap(),
            a.id,
            "email match is case-insensitive — an operator typing their own address"
        );
        assert!(resolve_operator(&repos, Some("nobody@example.com")).await.is_err());
    }

    #[test]
    fn the_approve_preview_shows_the_command_that_will_run() {
        let view = ApprovalView::from(&request("kubectl delete pod web-1"));
        let approve = decision_preview(&view, true);
        assert!(approve.contains("kubectl delete pod web-1"), "{approve}");
        assert!(approve.contains("RUN"), "approving is consenting to it running: {approve}");

        let deny = decision_preview(&view, false);
        assert!(deny.contains("will not run"), "{deny}");
    }

    #[test]
    fn an_empty_queue_says_so() {
        assert!(render(&[]).contains("no pending approvals"));
    }
}
