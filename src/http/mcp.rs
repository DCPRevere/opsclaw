//! OpsClaw's tools over MCP (streamable HTTP at `/mcp`), for people who
//! bring their own agent (docs/plans/ACCESS.md §6, MCP.md part A).
//!
//! - **Who:** the caller presents an `ops_` CLI token (minted by
//!   `opsclaw-cli login`, which signs in through the configured provider,
//!   SSO included). Under SSO those tokens expire.
//! - **What they see:** `tools/list` shows only the tools whose data class
//!   the person may read on at least one target, and tool calls see only
//!   those targets.
//! - **What they get:** every call goes through `policy::execute` as the
//!   person, with `via = mcp`: the access rules decide, results of
//!   redacted classes come back redacted unless the person holds a live
//!   elevation, and mutations always queue for approval.
//! - **Off by default:** `[access.mcp] enabled = true` mounts it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rmcp::ErrorData;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::{RequestContext, RoleServer};

use crate::access::Via;
use crate::agent::dispatch::{DispatchDeps, build_tool_ctx};
use crate::domain::Principal;
use crate::http::state::AppState;
use crate::tools::{Ops, Tool, ToolCtx};

/// Tools never offered over MCP: they write OpsClaw's own state (incidents,
/// memory, config) or fetch arbitrary URLs from the daemon's network.
const NEVER: &[&str] = &[
    "opsclaw_notify",
    "store_memory",
    "forget_memory",
    "recall_memory",
    "opsclaw_config",
    "web_fetch",
    "file_write",
];

/// A command that stands for what a tool usually returns, to decide which
/// class gates its listing.
fn probe(tool: &str) -> &'static str {
    match tool {
        "kubernetes" => "kubectl get pods",
        "systemd" => "systemctl status",
        "docker" => "docker ps",
        _ => "",
    }
}

struct Caller {
    principal: Principal,
    client: String,
}

#[derive(Clone)]
pub struct OpsMcp {
    state: AppState,
    deps: DispatchDeps,
    /// Calls in the current minute per account.
    window: Arc<Mutex<HashMap<uuid::Uuid, (Instant, u32)>>>,
}

impl OpsMcp {
    pub fn new(state: AppState, deps: DispatchDeps) -> Self {
        OpsMcp { state, deps, window: Arc::new(Mutex::new(HashMap::new())) }
    }

    async fn caller(&self, context: &RequestContext<RoleServer>) -> Result<Caller, ErrorData> {
        let parts = context
            .extensions
            .get::<axum::http::request::Parts>()
            .ok_or_else(|| ErrorData::internal_error("no HTTP request", None))?;
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|t| t.starts_with(crate::http::cli_auth::TOKEN_PREFIX))
            .ok_or_else(|| {
                ErrorData::invalid_request(
                    "sign in with `opsclaw-cli login` and send its token as a Bearer header",
                    None,
                )
            })?;
        let (token_id, account) = self
            .state
            .repos
            .find_cli_token(&crate::http::cli_auth::token_hash(token))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?
            .ok_or_else(|| {
                ErrorData::invalid_request("token revoked — run `opsclaw-cli login`", None)
            })?;
        crate::http::cli_auth::check_token_age(&self.state, token_id, account)
            .await
            .map_err(|e| ErrorData::invalid_request(e.to_string(), None))?;
        let client = context
            .peer
            .peer_info()
            .map(|i| i.client_info.name.clone())
            .unwrap_or_else(|| "unknown".into());
        if !self.state.access.mcp_client_allowed(&client) {
            return Err(ErrorData::invalid_request(
                format!("MCP client {client:?} is not allowed here"),
                None,
            ));
        }
        Ok(Caller { principal: Principal::Operator { account }, client })
    }

    fn rate_ok(&self, account: uuid::Uuid) -> bool {
        let cap = self.state.access.config().mcp.calls_per_minute;
        if cap == 0 {
            return true;
        }
        let mut w = self.window.lock().unwrap_or_else(|p| p.into_inner());
        let entry = w.entry(account).or_insert((Instant::now(), 0));
        if entry.0.elapsed().as_secs() >= 60 {
            *entry = (Instant::now(), 0);
        }
        entry.1 += 1;
        entry.1 <= cap
    }

    /// The person's tool context: their principal, `via = mcp`, and only
    /// the targets they can read anything on.
    async fn ctx_for(&self, caller: &Caller) -> ToolCtx {
        let mut ctx = build_tool_ctx(&self.deps, caller.principal.clone());
        ctx.call.via = Via::Mcp;
        // MCP answers aren't stored as findings.
        ctx.call.labels = None;
        let access = &self.state.access;
        let mut keep = Vec::new();
        for t in &ctx.known_targets {
            let path = t.to_string();
            for class in crate::access::classes::BUILT_IN
                .iter()
                .map(|(n, _)| *n)
                .chain(access.config().classes.iter().map(|c| c.name.as_str()))
            {
                if access.read(&caller.principal, Via::Mcp, &path, class).await.is_ok() {
                    keep.push(t.clone());
                    break;
                }
            }
        }
        ctx.known_targets = keep;
        ctx
    }

    async fn tools_for(&self, caller: &Caller, ctx: &ToolCtx) -> Vec<Box<dyn Tool>> {
        let access = &self.state.access;
        let mut out = Vec::new();
        for tool in crate::tools::registry(ctx, false) {
            if NEVER.contains(&tool.name()) {
                continue;
            }
            if tool.name() == "list_incidents" || tool.name().starts_with("runbook_") {
                out.push(tool);
                continue;
            }
            let mut visible = false;
            for t in &ctx.known_targets {
                let path = t.to_string();
                let class = access.classify(tool.name(), &path, probe(tool.name()));
                if access.read(&caller.principal, Via::Mcp, &path, &class).await.is_ok() {
                    visible = true;
                    break;
                }
            }
            if visible {
                out.push(tool);
            }
        }
        out
    }
}

impl rmcp::ServerHandler for OpsMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "OpsClaw: read-only access to infrastructure the signed-in person may see. Every \
             call is checked and audited as that person; personal data in logs and messages \
             comes back redacted unless they hold a live elevation. Mutations are queued for \
             human approval, never run directly.",
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let caller = self.caller(&context).await?;
        let ctx = self.ctx_for(&caller).await;
        let tools = self.tools_for(&caller, &ctx).await;
        Ok(ListToolsResult::with_all_items(
            tools.iter().map(|t| dcpr_agent::mcp::mcp_definition::<Ops>(t)).collect(),
        ))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let caller = self.caller(&context).await?;
        let Principal::Operator { account } = caller.principal else { unreachable!() };
        if !self.rate_ok(account) {
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                "rate limit: too many OpsClaw calls this minute; wait and retry",
            )])
            .into());
        }
        let ctx = self.ctx_for(&caller).await;
        let tools = self.tools_for(&caller, &ctx).await;
        let Some(tool) = tools.iter().find(|t| t.name() == request.name) else {
            return Err(ErrorData::invalid_params(format!("unknown tool: {}", request.name), None));
        };
        tracing::info!(%account, client = %caller.client, tool = %request.name, "mcp call");
        let args = match dcpr_agent::Tool::<Ops>::prepare_arguments(
            tool,
            serde_json::Value::Object(request.arguments.unwrap_or_default()),
        ) {
            Ok(args) => args,
            Err(error) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(
                    error.for_model(&request.name),
                )])
                .into());
            }
        };
        let outcome = tokio::select! {
            outcome = dcpr_agent::Tool::<Ops>::call(tool, &ctx, args) => outcome,
            () = context.ct.cancelled() => {
                return Err(ErrorData::internal_error("request cancelled", None));
            }
        };
        Ok(match outcome {
            Ok(result) => dcpr_agent::mcp::mcp_result(&result),
            Err(error) => CallToolResult::error(vec![ContentBlock::text(format!(
                "{} failed: {error}",
                request.name
            ))]),
        }
        .into())
    }
}

/// The `/mcp` service, when enabled.
pub fn service(
    state: AppState,
    deps: DispatchDeps,
) -> rmcp::transport::streamable_http_server::StreamableHttpService<
    OpsMcp,
    rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
> {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    };
    let mut config =
        StreamableHttpServerConfig::default().with_cancellation_token(state.shutdown.child_token());
    let extra = &state.access.config().mcp.allowed_hosts;
    if !extra.is_empty() {
        let mut hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
        hosts.extend(extra.iter().cloned());
        config = config.with_allowed_hosts(hosts);
    }
    let handler = OpsMcp::new(state, deps);
    StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::{Value, json};

    use crate::db::{Account, AccountRepo, CliToken};
    use crate::http::state::AppState;

    const CONFIG: &str = r#"
        [[project]]
        name = "acme"
        autonomy = "auto"
        [[project.env]]
        name = "prod"
        [[project.env.target]]
        name = "box"
        kind = "local"

        [access]
        preset = "team"
        [access.mcp]
        enabled = true
        [[access.role]]
        name = "ops"
        members = ["ops@acme.com"]
        where = ["acme::prod"]
        data = ["host"]
        actions = "request"
    "#;

    async fn person(state: &AppState, email: &str) -> String {
        let id = uuid::Uuid::new_v4();
        AccountRepo::insert(
            &*state.repos,
            &Account {
                id,
                email: email.into(),
                display_name: email.into(),
                password_hash: "x".into(),
                token_version: 0,
                created_at: chrono::Utc::now(),
                auth_provider: "local".into(),
                external_subject: None,
            },
        )
        .await
        .unwrap();
        let token = crate::http::cli_auth::generate_token();
        let row = CliToken {
            id: uuid::Uuid::new_v4(),
            account: id,
            name: "test".into(),
            created_at: chrono::Utc::now(),
            last_used_at: None,
        };
        state
            .repos
            .create_cli_token(row, &crate::http::cli_auth::token_hash(&token))
            .await
            .unwrap();
        token
    }

    async fn daemon() -> (String, AppState, tempfile::TempDir) {
        let config: crate::config::Config = toml::from_str(CONFIG).unwrap();
        let mut state = AppState::fake_with_config(config.clone());
        let access = Arc::new(
            crate::access::Access::new(&config.access, std::path::Path::new(".")).unwrap(),
        );
        access.set_directory(Arc::new(crate::access::RepoDirectory(state.repos.clone())));
        state.access = access.clone();
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::SecretStore::open(dir.path()).unwrap();
        let executors = crate::targets::wiring::build_executors(
            &config,
            &store,
            &crate::policy::Scrubber::new(),
        )
        .unwrap()
        .0;
        let policy = Arc::new(
            crate::policy::Policy::new(
                Arc::new(config.clone()),
                executors,
                Arc::new(crate::audit::AuditWriter::new(state.repos.clone())),
                Arc::new(crate::policy::EStop::new(dir.path().join("ESTOP"), state.repos.clone())),
                state.repos.clone(),
                Arc::new(crate::policy::Scrubber::new()),
            )
            .with_access(access.clone()),
        );
        let deps = crate::agent::dispatch::DispatchDeps::assemble(
            Arc::new(config),
            &store,
            policy,
            state.repos.clone(),
            state.repos.clone(),
            state.repos.clone(),
            Arc::new(crate::memory::Memory::disabled()),
            Arc::new(crate::llm::fakes::FakeLlm::new()),
        )
        .unwrap()
        .with_access(access, state.repos.clone());
        state.dispatch = Some(deps);
        let app = crate::http::routes::router(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://127.0.0.1:{}/mcp", addr.port()), state, dir)
    }

    /// One MCP session: initialize, then the given request.
    async fn rpc(url: &str, token: &str, method: &str, params: Value) -> Value {
        let http = reqwest::Client::new();
        let post = |body: Value, session: Option<String>| {
            let mut r = http
                .post(url)
                .bearer_auth(token)
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json")
                .json(&body);
            if let Some(s) = session {
                r = r.header("mcp-session-id", s);
            }
            r.send()
        };
        let init = post(
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":"test-agent","version":"1"}}}),
            None,
        )
        .await
        .unwrap();
        assert!(init.status().is_success(), "initialize: {}", init.status());
        let session = init.headers().get("mcp-session-id").map(|v| v.to_str().unwrap().to_string());
        let _ = init.text().await;
        post(json!({"jsonrpc":"2.0","method":"notifications/initialized"}), session.clone())
            .await
            .unwrap();
        let resp = post(json!({"jsonrpc":"2.0","id":2,"method":method,"params":params}), session)
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let data = resp
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .find(|d| d.contains("\"id\":2"))
            .unwrap_or_else(|| panic!("no response in {resp}"));
        serde_json::from_str(data).unwrap()
    }

    fn names(list: &Value) -> Vec<String> {
        list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn each_caller_sees_only_their_tools_and_never_acts_directly() {
        let (url, state, _dir) = daemon().await;
        let ops = person(&state, "ops@acme.com").await;
        let eve = person(&state, "eve@acme.com").await;

        let ops_tools = names(&rpc(&url, &ops, "tools/list", json!({})).await);
        assert!(ops_tools.contains(&"shell".to_string()), "{ops_tools:?}");
        assert!(!ops_tools.contains(&"opsclaw_notify".to_string()), "{ops_tools:?}");
        let eve_tools = names(&rpc(&url, &eve, "tools/list", json!({})).await);
        assert!(!eve_tools.contains(&"shell".to_string()), "{eve_tools:?}");

        // The shell tool is a mutation-class tool: over MCP it always queues
        // for a human, even at autonomy auto. (Redaction of reads over MCP
        // is covered in `access::tests` and `policy::tests`.)
        let out = rpc(
            &url,
            &ops,
            "tools/call",
            json!({"name":"shell","arguments":{"target":"acme::prod::box","command":"uptime"}}),
        )
        .await;
        let text = out["result"]["content"][0]["text"].as_str().unwrap_or_default();
        assert!(text.contains("queued for human approval"), "{out}");

        // Eve can't call what she can't see.
        let out = rpc(
            &url,
            &eve,
            "tools/call",
            json!({"name":"shell","arguments":{"target":"acme::prod::box","command":"echo hi"}}),
        )
        .await;
        assert!(out["error"].is_object(), "{out}");
    }

    #[tokio::test]
    async fn no_token_no_service() {
        let (url, _state, _dir) = daemon().await;
        let out = rpc(&url, "ops_not-a-real-token", "tools/list", json!({})).await;
        assert!(out["error"]["message"].as_str().unwrap().contains("revoked"), "{out}");
    }
}
