//! DoD #5 end-to-end (brief §13.5): "an operator at `suggest` autonomy can
//! approve a remediation from a chat message and see it executed and
//! audited." Same spine as `tests/e2e_flow.rs` — a REAL bound HTTP server,
//! real auth, real requests via `reqwest` — but with the policy engine wired
//! to an observable [`FakeExecutor`] instead of the fakes spine's empty
//! executor map, and (for the chat-driven test) the REAL agent dispatch
//! (`agent::dispatch::ChatTurn`) over a [`ScriptedLlm`] so the mutation
//! arrives the way it does in production: the operator says something in
//! chat, the model composes a tool call, and policy queues it.
//!
//! The load-bearing end-to-end claim: approve-over-HTTP executes the STORED
//! command verbatim (never a fresh interpretation of "yes, do it") and every
//! hop is on the audit chain — `ApprovalQueued` when the gate queues it,
//! `Begun` + `Executed` when the human decision releases it — with both
//! identities durably recorded (the requesting principal on the audit
//! records, the approving operator on the approval row's `decided_by`).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use opsclaw::agent::dispatch::{ChatTurn, DispatchDeps};
use opsclaw::audit::{AuditOutcome, AuditWriter};
use opsclaw::config::{Config, SecretStore};
use opsclaw::db::memory::InMemoryDb;
use opsclaw::db::{Account, AccountRepo, ApprovalRepo, AuditRepo};
use opsclaw::domain::{ApprovalState, FqTarget, Principal, RiskClass};
use opsclaw::http::AppState;
use opsclaw::llm::ScriptedLlm;
use opsclaw::memory::Memory;
use opsclaw::policy::{CommandRequest, EStop, Policy, PolicyOutcome, Scrubber};
use opsclaw::targets::{Command, ExecOutput, ProbeReport, TargetExecutor};
use uuid::Uuid;

/// Bind `state`'s router on an ephemeral port and serve it on a background
/// task for the life of the test (same helper as `tests/e2e_flow.rs` —
/// integration tests are separate crates, so it can't be imported).
async fn spawn_server(state: AppState) -> String {
    let router = opsclaw::http::routes::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}")
}

/// The single-cookie session jar from `tests/e2e_flow.rs`, trimmed to what
/// these tests use.
struct SessionClient {
    client: reqwest::Client,
    cookie: std::sync::Mutex<Option<String>>,
}

impl SessionClient {
    fn new() -> Self {
        SessionClient { client: reqwest::Client::new(), cookie: std::sync::Mutex::new(None) }
    }

    fn capture(&self, resp: &reqwest::Response) {
        if let Some(v) = resp.headers().get(reqwest::header::SET_COOKIE)
            && let Ok(s) = v.to_str()
        {
            let kv = s.split(';').next().unwrap_or(s).to_string();
            *self.cookie.lock().unwrap() = Some(kv);
        }
    }

    fn attach(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(c) = self.cookie.lock().unwrap().clone() {
            req = req.header(reqwest::header::COOKIE, c);
        }
        req
    }

    async fn get(&self, url: &str) -> reqwest::Response {
        let resp = self.attach(self.client.get(url)).send().await.unwrap();
        self.capture(&resp);
        resp
    }

    async fn post_json(&self, url: &str, body: &serde_json::Value) -> reqwest::Response {
        let resp = self.attach(self.client.post(url).json(body)).send().await.unwrap();
        self.capture(&resp);
        resp
    }

    async fn post(&self, url: &str) -> reqwest::Response {
        let resp = self.attach(self.client.post(url)).send().await.unwrap();
        self.capture(&resp);
        resp
    }
}

/// Seed one operator account directly via the repo — the same bootstrap seam
/// `tests/e2e_flow.rs` uses (`opsclaw onboard`'s path; bootstrap has no HTTP
/// route by design).
async fn seed_account(state: &AppState, email: &str, password: &str) -> Uuid {
    let id = Uuid::new_v4();
    let account = Account {
        id,
        email: email.into(),
        display_name: "Approving Operator".into(),
        password_hash: opsclaw::http::auth::hash_password(password).unwrap(),
        token_version: 0,
        created_at: chrono::Utc::now(),
        auth_provider: "local".into(),
        external_subject: None,
    };
    AccountRepo::insert(&*state.repos, &account).await.unwrap();
    id
}

/// Observable executor: records every command line it is asked to run and
/// returns a fixed success — the same shape as `policy::mod`'s own test
/// `FakeExecutor` (that one is `#[cfg(test)]`, invisible to an integration
/// test binary).
struct FakeExecutor {
    output: ExecOutput,
    ran: std::sync::Mutex<Vec<String>>,
}

impl FakeExecutor {
    fn ok(stdout: &str) -> Arc<Self> {
        Arc::new(FakeExecutor {
            output: ExecOutput {
                exit_code: 0,
                stdout: stdout.into(),
                stderr: String::new(),
                duration_ms: 1,
            },
            ran: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn ran(&self) -> Vec<String> {
        self.ran.lock().unwrap().clone()
    }
}

#[async_trait]
impl TargetExecutor for FakeExecutor {
    async fn run(
        &self,
        cmd: &Command,
        _timeout: std::time::Duration,
    ) -> opsclaw::Result<ExecOutput> {
        self.ran.lock().unwrap().push(cmd.line.clone());
        Ok(self.output.clone())
    }
    async fn probe(&self) -> opsclaw::Result<ProbeReport> {
        Ok(ProbeReport { reachable: true, detail: "fake".into() })
    }
}

const FQ: &str = "remundo::prod::web-1";
const REMEDIATION: &str = "systemctl restart nginx";

/// One project/env/target at `suggest` autonomy — the DoD's stated level:
/// reads auto-execute, mutations become approval requests.
fn suggest_config(home: &std::path::Path) -> Config {
    let toml = r#"
        [[project]]
        name = "remundo"
        autonomy = "suggest"
        [[project.env]]
        name = "prod"
        [[project.env.target]]
        name = "web-1"
        kind = "local"
    "#;
    let mut config: Config = toml::from_str(toml).expect("test config parses");
    // Never the real machine's ~/.opsclaw/runbooks (same isolation
    // discipline as e2e_flow's IsolatedOpsclawHome, without the env var).
    config.daemon.runbooks_dir = home.join("runbooks");
    config
}

/// The wired test daemon: `AppState::fake_with_config`'s spine with the
/// repos AND the policy engine rebuilt over ONE shared [`InMemoryDb`] so
/// the HTTP handlers, the policy's approval queue, and the audit chain all
/// see the same store — plus the observable executor registered for [`FQ`].
struct Rig {
    state: AppState,
    db: Arc<InMemoryDb>,
    executor: Arc<FakeExecutor>,
    policy: Arc<Policy>,
    config: Arc<Config>,
    home: tempfile::TempDir,
}

fn rig() -> Rig {
    let home = tempfile::tempdir().expect("tempdir");
    let config = suggest_config(home.path());
    let db = Arc::new(InMemoryDb::new());
    let estop = Arc::new(EStop::new(home.path().join("ESTOP"), db.clone()));
    let executor = FakeExecutor::ok("nginx restarted");
    let mut executors: HashMap<String, Arc<dyn TargetExecutor>> = HashMap::new();
    executors.insert(FQ.into(), executor.clone());
    let config_arc = Arc::new(config.clone());
    let policy = Arc::new(Policy::new(
        config_arc.clone(),
        executors,
        Arc::new(AuditWriter::new(db.clone())),
        estop.clone(),
        db.clone(),
        Arc::new(Scrubber::new()),
    ));
    let mut state = AppState::fake_with_config(config);
    state.repos = db.clone();
    state.policy = policy.clone();
    state.approved = policy.clone();
    state.estop = estop;
    Rig { state, db, executor, policy, config: config_arc, home }
}

/// Wire the REAL chat dispatch (`agent::dispatch::ChatTurn`) over a
/// [`ScriptedLlm`] whose one deterministic turn proposes [`REMEDIATION`]
/// via the `shell` tool — the exact production path from an operator's chat
/// message to a queued approval, minus only the nondeterministic model.
fn wire_scripted_chat(rig: &mut Rig) {
    let store = SecretStore::open(rig.home.path()).expect("secret store");
    let mut llm = ScriptedLlm::new();
    llm.push_tool_call(
        "shell",
        serde_json::json!({
            "target": FQ,
            "command": REMEDIATION,
            "hypothesis": "nginx workers wedged after the deploy; a restart clears it",
        }),
    );
    llm.push_text("Queued the nginx restart for approval — it has not run yet.");
    let deps = DispatchDeps::assemble(
        rig.config.clone(),
        &store,
        rig.policy.clone(),
        rig.db.clone(),
        rig.db.clone(),
        rig.db.clone(),
        Arc::new(Memory::disabled()),
        Arc::new(llm),
    )
    .expect("assemble dispatch deps");
    rig.state.chat = Arc::new(ChatTurn::new(deps));
}

/// Audit outcomes in chain order, straight off the shared store.
async fn audit_outcomes(db: &InMemoryDb) -> Vec<AuditOutcome> {
    db.range(1, 100).await.unwrap().iter().map(|r| r.outcome).collect()
}

/// The DoD #5 journey, end to end over real HTTP:
///
/// (a) an authenticated operator sends a chat message; the (scripted) model
///     proposes a mutation, which `suggest` autonomy queues for approval;
/// (b) the operator lists the pending queue and sees the full decision
///     context (verbatim command, target, risk, hypothesis);
/// (c) the operator approves over HTTP;
/// (d) the STORED command executes verbatim on the target's executor, the
///     audit chain carries ApprovalQueued → Begun → Executed and verifies
///     over HTTP, and both identities are durable on the record.
#[tokio::test]
async fn operator_at_suggest_approves_a_chat_remediation_and_it_executes_audited() {
    let mut rig = rig();
    wire_scripted_chat(&mut rig);
    let operator_id = seed_account(&rig.state, "approver@example.com", "some-password-123").await;
    let base = spawn_server(rig.state.clone()).await;
    let client = SessionClient::new();
    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "approver@example.com", "password": "some-password-123" }),
        )
        .await;

    // (a) The chat message that leads to the mutation.
    let chat = client
        .post_json(
            &format!("{base}/api/chat"),
            &serde_json::json!({ "message": "nginx on web-1 looks wedged — restart it" }),
        )
        .await;
    assert_eq!(chat.status(), reqwest::StatusCode::OK);
    let chat_body: serde_json::Value = chat.json().await.unwrap();
    assert_eq!(chat_body["reply"], "Queued the nginx restart for approval — it has not run yet.");

    // Suggest autonomy queued it — NOTHING has touched the executor yet.
    assert!(rig.executor.ran().is_empty(), "no command may run before approval");

    // (b) The pending queue carries the full decision context.
    let approvals: serde_json::Value =
        client.get(&format!("{base}/api/approvals")).await.json().await.unwrap();
    let pending = approvals["approvals"].as_array().unwrap();
    assert_eq!(pending.len(), 1, "exactly one queued approval: {approvals}");
    let row = &pending[0];
    assert_eq!(row["command"], REMEDIATION, "the stored command is the verbatim proposal");
    assert_eq!(row["target"], FQ);
    assert_eq!(row["state"], "pending");
    // The CLASSIFIER's verdict, not the tool's declared Medium: `systemctl
    // restart` matches classify.rs's "systemctl-disrupt" rule (High), and
    // the classifier may raise, never lower — the queue shows the human the
    // raised class.
    assert_eq!(row["risk"], "high", "systemctl restart classifies as High (systemctl-disrupt)");
    assert!(
        row["hypothesis"].as_str().unwrap().contains("wedged"),
        "the hypothesis reaches the deciding human: {row}"
    );
    let id = row["id"].as_str().unwrap().to_string();

    // (c) Approve over HTTP as the signed-in operator.
    let approved: serde_json::Value =
        client.post(&format!("{base}/api/approvals/{id}/approve")).await.json().await.unwrap();
    assert_eq!(approved["decision"], "approved", "{approved}");
    assert_eq!(approved["status"], "executed", "{approved}");
    assert_eq!(approved["detail"]["exit_code"], 0);
    assert_eq!(approved["detail"]["stdout"], "nginx restarted");

    // (d) The STORED command ran verbatim, exactly once.
    assert_eq!(rig.executor.ran(), vec![REMEDIATION.to_string()]);

    // The approval row tells the truth durably: Executed, decided by THIS
    // operator, requested by the operator-principal chat turn.
    let stored = ApprovalRepo::get(&*rig.db, id.parse().unwrap()).await.unwrap().unwrap();
    assert_eq!(stored.state, ApprovalState::Executed);
    assert_eq!(stored.decided_by, Some(operator_id), "the approving operator is on record");
    assert!(
        matches!(&stored.requested_by, Principal::Operator { account } if *account == operator_id),
        "the requesting principal is on record: {:?}",
        stored.requested_by
    );

    // The audit chain carries the whole story, in order, and every record
    // names the fully-qualified target and the exact command.
    assert_eq!(
        audit_outcomes(&rig.db).await,
        vec![AuditOutcome::ApprovalQueued, AuditOutcome::Begun, AuditOutcome::Executed]
    );
    for record in rig.db.range(1, 100).await.unwrap() {
        assert_eq!(record.fq_target, FQ);
        assert_eq!(record.command, REMEDIATION);
        assert!(
            matches!(&record.principal, Principal::Operator { account } if *account == operator_id)
        );
    }
    let verify: serde_json::Value =
        client.get(&format!("{base}/api/audit/verify")).await.json().await.unwrap();
    assert_eq!(verify["ok"], true, "{verify}");
    assert_eq!(verify["records_verified"], 3);

    // A second approve of the same request is a 409, not a re-execution
    // (the double-tap guard, now proven over HTTP).
    let replay = client.post(&format!("{base}/api/approvals/{id}/approve")).await;
    assert_eq!(replay.status(), reqwest::StatusCode::CONFLICT);
    assert_eq!(rig.executor.ran().len(), 1, "a replayed approve must not re-run the command");

    // And the queue is empty again — the row is no longer pending.
    let after: serde_json::Value =
        client.get(&format!("{base}/api/approvals")).await.json().await.unwrap();
    assert!(after["approvals"].as_array().unwrap().is_empty());
}

/// The negative half of the same claim: deny over HTTP never executes, and
/// the audit chain shows the queued request and nothing else. The queue is
/// driven through `PolicyExecute` here (the exact seam tool dispatch hands
/// every command to) rather than a second scripted chat turn — what's under
/// test is the HTTP decision surface, not the chat plumbing again.
#[tokio::test]
async fn deny_over_http_records_the_decision_and_never_executes() {
    let rig = rig();
    let operator_id = seed_account(&rig.state, "denier@example.com", "some-password-123").await;

    let outcome = rig
        .state
        .policy
        .execute(CommandRequest {
            principal: Principal::Agent { job: None },
            tool: "shell".into(),
            target: FqTarget::new("remundo", "prod", "web-1"),
            command: REMEDIATION.into(),
            declared_risk: RiskClass::Medium,
            hypothesis: Some("heartbeat scan thinks nginx is wedged".into()),
            runbook: None,
        })
        .await
        .unwrap();
    let id = match outcome {
        PolicyOutcome::NeedsApproval(id) => id,
        other => panic!("suggest must queue the mutation, got {other:?}"),
    };

    let base = spawn_server(rig.state.clone()).await;
    let client = SessionClient::new();
    client
        .post_json(
            &format!("{base}/api/login"),
            &serde_json::json!({ "email": "denier@example.com", "password": "some-password-123" }),
        )
        .await;

    let denied: serde_json::Value =
        client.post(&format!("{base}/api/approvals/{id}/deny")).await.json().await.unwrap();
    assert_eq!(denied["decision"], "denied", "{denied}");

    assert!(rig.executor.ran().is_empty(), "a denied command must never execute");
    let stored = ApprovalRepo::get(&*rig.db, id).await.unwrap().unwrap();
    assert_eq!(stored.state, ApprovalState::Denied);
    assert_eq!(stored.decided_by, Some(operator_id));
    // Only the queueing is on the chain — no Begun, no Executed.
    assert_eq!(audit_outcomes(&rig.db).await, vec![AuditOutcome::ApprovalQueued]);
}
