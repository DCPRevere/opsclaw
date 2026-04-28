//! GitHub tool. One tool, one token, many actions:
//! issues, PRs, workflow runs, deployments, releases, commits.
//!
//! Writes (comment, create, rerun, cancel) are gated by autonomy and
//! audit-logged.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use zeroclaw::tools::traits::{Tool, ToolResult};

use crate::ops_config::OpsClawAutonomy;
use crate::tools::ssh_tool::write_audit_entry;

const MAX_OUTPUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct GithubToolConfig {
    pub token: String,
    pub default_owner: Option<String>,
    pub default_repo: Option<String>,
    pub autonomy: OpsClawAutonomy,
    pub api_base: String,
}

impl GithubToolConfig {
    pub fn new(token: String) -> Self {
        Self {
            token,
            default_owner: None,
            default_repo: None,
            autonomy: OpsClawAutonomy::default(),
            api_base: "https://api.github.com".into(),
        }
    }
}

pub struct GithubTool {
    config: GithubToolConfig,
    client: reqwest::Client,
    audit_dir: Option<PathBuf>,
}

impl GithubTool {
    pub fn new(config: GithubToolConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("opsclaw/0.6")
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            audit_dir: None,
        }
    }

    pub fn with_audit_dir(mut self, dir: PathBuf) -> Self {
        self.audit_dir = Some(dir);
        self
    }

    fn owner_repo(&self, args: &Value) -> Result<(String, String), String> {
        let owner = args
            .get("owner")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| self.config.default_owner.clone())
            .ok_or_else(|| "missing 'owner' (no default_owner in config)".to_string())?;
        let repo = args
            .get("repo")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| self.config.default_repo.clone())
            .ok_or_else(|| "missing 'repo' (no default_repo in config)".to_string())?;
        Ok((owner, repo))
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}/{}", self.config.api_base.trim_end_matches('/'), path);
        self.client
            .request(method, &url)
            .header("Authorization", format!("Bearer {}", self.config.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    fn audit(&self, action: &str, detail: &str, duration_ms: u128, exit: i32) {
        let _ = write_audit_entry(
            "github",
            &format!("{action} {detail}"),
            exit,
            duration_ms,
            self.audit_dir.as_ref(),
        );
    }

    fn is_dry_run(&self) -> bool {
        self.config.autonomy == OpsClawAutonomy::DryRun
    }
}

#[async_trait]
impl Tool for GithubTool {
    fn name(&self) -> &str {
        "github"
    }

    fn description(&self) -> &str {
        "GitHub API tool. Reads: list_issues, get_issue, list_prs, get_pr, \
         list_pr_comments, list_runs, get_run, get_run_logs_url, \
         list_deployments, list_releases, list_commits. Writes: \
         create_issue, comment_issue, comment_pr, rerun_run, cancel_run. \
         Writes respect autonomy (DryRun returns 'would do X') and are \
         audit-logged."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "issue_number": {"type": "integer"},
                "pr_number": {"type": "integer"},
                "run_id": {"type": "integer"},
                "deployment_id": {"type": "integer"},
                "release_id": {"type": "integer"},
                "branch": {"type": "string"},
                "state": {"type": "string", "enum": ["open", "closed", "all"]},
                "status": {"type": "string"},
                "title": {"type": "string"},
                "body": {"type": "string"},
                "labels": {"type": "array", "items": {"type": "string"}},
                "per_page": {"type": "integer", "default": 30}
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let action = match args.get("action").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("missing 'action'".into()),
                });
            }
        };
        let start = std::time::Instant::now();
        let result = self.dispatch(&action, &args).await;
        let elapsed = start.elapsed().as_millis();
        let exit = match &result {
            Ok(r) if r.success => 0,
            _ => 1,
        };
        let detail = args
            .get("issue_number")
            .or_else(|| args.get("pr_number"))
            .or_else(|| args.get("run_id"))
            .map(|v| v.to_string())
            .unwrap_or_default();
        self.audit(&action, &detail, elapsed, exit);
        result
    }
}

impl GithubTool {
    async fn dispatch(&self, action: &str, args: &Value) -> anyhow::Result<ToolResult> {
        match action {
            "list_issues" => self.list_issues(args).await,
            "get_issue" => self.get_issue(args).await,
            "list_prs" => self.list_prs(args).await,
            "get_pr" => self.get_pr(args).await,
            "list_pr_comments" => self.list_pr_comments(args).await,
            "list_runs" => self.list_runs(args).await,
            "get_run" => self.get_run(args).await,
            "get_run_logs_url" => self.get_run_logs_url(args).await,
            "list_deployments" => self.list_deployments(args).await,
            "list_releases" => self.list_releases(args).await,
            "list_commits" => self.list_commits(args).await,
            "create_issue" => self.create_issue(args).await,
            "comment_issue" => self.comment(args, /*is_pr=*/ false).await,
            "comment_pr" => self.comment(args, true).await,
            "rerun_run" => self.run_mutation(args, "rerun").await,
            "cancel_run" => self.run_mutation(args, "cancel").await,
            other => Ok(err(format!("unknown action '{other}'"))),
        }
    }

    async fn list_issues(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let state = args.get("state").and_then(|v| v.as_str()).unwrap_or("open");
        let per_page = args
            .get("per_page")
            .and_then(|v| v.as_u64())
            .unwrap_or(30)
            .min(100);
        let path = format!("repos/{owner}/{repo}/issues");
        let resp = self
            .req(reqwest::Method::GET, &path)
            .query(&[("state", state), ("per_page", &per_page.to_string())])
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let arr: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(a) = arr.as_array() {
            writeln!(out, "count: {}", a.len()).ok();
            for i in a {
                // Skip pull requests (issues API returns both).
                if i.get("pull_request").is_some() {
                    continue;
                }
                let num = i.get("number").and_then(|v| v.as_u64()).unwrap_or(0);
                let st = i.get("state").and_then(|v| v.as_str()).unwrap_or("");
                let title = i.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let user = i
                    .get("user")
                    .and_then(|v| v.get("login"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                writeln!(out, "  #{num} [{st}] @{user} — {title}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn get_issue(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let n = match args.get("issue_number").and_then(|v| v.as_u64()) {
            Some(n) => n,
            None => return Ok(err("missing 'issue_number'")),
        };
        let path = format!("repos/{owner}/{repo}/issues/{n}");
        let resp = self.req(reqwest::Method::GET, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        Ok(ok_res(format_issue(&v)))
    }

    async fn list_prs(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let state = args.get("state").and_then(|v| v.as_str()).unwrap_or("open");
        let per_page = args
            .get("per_page")
            .and_then(|v| v.as_u64())
            .unwrap_or(30)
            .min(100);
        let path = format!("repos/{owner}/{repo}/pulls");
        let resp = self
            .req(reqwest::Method::GET, &path)
            .query(&[("state", state), ("per_page", &per_page.to_string())])
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let arr: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(a) = arr.as_array() {
            writeln!(out, "count: {}", a.len()).ok();
            for p in a {
                let num = p.get("number").and_then(|v| v.as_u64()).unwrap_or(0);
                let st = p.get("state").and_then(|v| v.as_str()).unwrap_or("");
                let title = p.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let user = p
                    .get("user")
                    .and_then(|v| v.get("login"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                writeln!(out, "  #{num} [{st}] @{user} — {title}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn get_pr(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let n = match args.get("pr_number").and_then(|v| v.as_u64()) {
            Some(n) => n,
            None => return Ok(err("missing 'pr_number'")),
        };
        let path = format!("repos/{owner}/{repo}/pulls/{n}");
        let resp = self.req(reqwest::Method::GET, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = format_issue(&v);
        if let Some(merged) = v.get("merged").and_then(|v| v.as_bool()) {
            writeln!(out, "merged: {merged}").ok();
        }
        if let Some(head) = v
            .get("head")
            .and_then(|v| v.get("ref"))
            .and_then(|v| v.as_str())
        {
            writeln!(out, "head: {head}").ok();
        }
        Ok(ok_res(out))
    }

    async fn list_pr_comments(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let n = match args.get("pr_number").and_then(|v| v.as_u64()) {
            Some(n) => n,
            None => return Ok(err("missing 'pr_number'")),
        };
        let path = format!("repos/{owner}/{repo}/pulls/{n}/comments");
        let resp = self.req(reqwest::Method::GET, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let arr: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(a) = arr.as_array() {
            for c in a {
                let user = c
                    .get("user")
                    .and_then(|v| v.get("login"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let created = c.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
                let body_text = c.get("body").and_then(|v| v.as_str()).unwrap_or("");
                let first_line = body_text.lines().next().unwrap_or("");
                writeln!(out, "  {created} @{user}: {first_line}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn list_runs(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(s) = args.get("status").and_then(|v| v.as_str()) {
            params.push(("status", s.to_string()));
        }
        if let Some(b) = args.get("branch").and_then(|v| v.as_str()) {
            params.push(("branch", b.to_string()));
        }
        let per_page = args
            .get("per_page")
            .and_then(|v| v.as_u64())
            .unwrap_or(30)
            .min(100);
        params.push(("per_page", per_page.to_string()));
        let path = format!("repos/{owner}/{repo}/actions/runs");
        let resp = self
            .req(reqwest::Method::GET, &path)
            .query(&params)
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(runs) = v.get("workflow_runs").and_then(|x| x.as_array()) {
            writeln!(out, "count: {}", runs.len()).ok();
            for r in runs {
                let id = r.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let st = r.get("status").and_then(|v| v.as_str()).unwrap_or("");
                let concl = r.get("conclusion").and_then(|v| v.as_str()).unwrap_or("-");
                let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let branch = r.get("head_branch").and_then(|v| v.as_str()).unwrap_or("");
                let created = r.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
                writeln!(out, "  {id} [{st}/{concl}] {branch} {created} — {name}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn get_run(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let id = match args.get("run_id").and_then(|v| v.as_u64()) {
            Some(n) => n,
            None => return Ok(err("missing 'run_id'")),
        };
        let path = format!("repos/{owner}/{repo}/actions/runs/{id}");
        let resp = self.req(reqwest::Method::GET, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        for k in [
            "id",
            "name",
            "status",
            "conclusion",
            "head_branch",
            "head_sha",
            "created_at",
            "html_url",
        ] {
            if let Some(val) = v.get(k) {
                writeln!(out, "{k}: {val}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn get_run_logs_url(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let id = match args.get("run_id").and_then(|v| v.as_u64()) {
            Some(n) => n,
            None => return Ok(err("missing 'run_id'")),
        };
        // GitHub returns 302 to a signed S3 URL. We don't follow it — the agent just needs the URL.
        let path = format!("repos/{owner}/{repo}/actions/runs/{id}/logs");
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .user_agent("opsclaw/0.6")
            .build()?;
        let url = format!("{}/{}", self.config.api_base.trim_end_matches('/'), path);
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await?;
        let status = resp.status();
        if status.as_u16() == 302 || status == reqwest::StatusCode::FOUND {
            if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
                return Ok(ok_res(format!("logs_url: {loc}")));
            }
        }
        let body = resp.text().await.unwrap_or_default();
        if status.is_success() {
            return Ok(ok_res(format!(
                "status: {status} (no redirect; logs inline, {} bytes)",
                body.len()
            )));
        }
        Ok(err(format!("{status}: {}", snippet(&body))))
    }

    async fn list_deployments(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let per_page = args
            .get("per_page")
            .and_then(|v| v.as_u64())
            .unwrap_or(30)
            .min(100);
        let path = format!("repos/{owner}/{repo}/deployments");
        let resp = self
            .req(reqwest::Method::GET, &path)
            .query(&[("per_page", per_page.to_string())])
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let arr: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(a) = arr.as_array() {
            writeln!(out, "count: {}", a.len()).ok();
            for d in a {
                let id = d.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let env = d.get("environment").and_then(|v| v.as_str()).unwrap_or("");
                let sha = d.get("sha").and_then(|v| v.as_str()).unwrap_or("");
                let created = d.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
                writeln!(out, "  {id} [{env}] {sha} {created}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn list_releases(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let path = format!("repos/{owner}/{repo}/releases");
        let per_page = args
            .get("per_page")
            .and_then(|v| v.as_u64())
            .unwrap_or(30)
            .min(100);
        let resp = self
            .req(reqwest::Method::GET, &path)
            .query(&[("per_page", per_page.to_string())])
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let arr: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(a) = arr.as_array() {
            writeln!(out, "count: {}", a.len()).ok();
            for r in a {
                let tag = r.get("tag_name").and_then(|v| v.as_str()).unwrap_or("");
                let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let published = r.get("published_at").and_then(|v| v.as_str()).unwrap_or("");
                writeln!(out, "  {tag} {published} — {name}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn list_commits(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let branch = args.get("branch").and_then(|v| v.as_str());
        let per_page = args
            .get("per_page")
            .and_then(|v| v.as_u64())
            .unwrap_or(20)
            .min(100);
        let path = format!("repos/{owner}/{repo}/commits");
        let mut params: Vec<(&str, String)> = vec![("per_page", per_page.to_string())];
        if let Some(b) = branch {
            params.push(("sha", b.to_string()));
        }
        let resp = self
            .req(reqwest::Method::GET, &path)
            .query(&params)
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let arr: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let mut out = String::new();
        if let Some(a) = arr.as_array() {
            for c in a {
                let sha = c.get("sha").and_then(|v| v.as_str()).unwrap_or("");
                let sha_short: String = sha.chars().take(8).collect();
                let msg = c
                    .get("commit")
                    .and_then(|v| v.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let first = msg.lines().next().unwrap_or("");
                let author = c
                    .get("commit")
                    .and_then(|v| v.get("author"))
                    .and_then(|v| v.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let date = c
                    .get("commit")
                    .and_then(|v| v.get("author"))
                    .and_then(|v| v.get("date"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                writeln!(out, "  {sha_short} {date} {author}: {first}").ok();
            }
        }
        Ok(ok_res(out))
    }

    async fn create_issue(&self, args: &Value) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let title = match args.get("title").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Ok(err("missing 'title'")),
        };
        let body = args
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let labels = args
            .get("labels")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if self.is_dry_run() {
            return Ok(ok_res(format!(
                "[dry-run] would create issue in {owner}/{repo}: {title}"
            )));
        }

        let payload = json!({"title": title, "body": body, "labels": labels});
        let path = format!("repos/{owner}/{repo}/issues");
        let resp = self
            .req(reqwest::Method::POST, &path)
            .json(&payload)
            .send()
            .await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let num = v.get("number").and_then(|v| v.as_u64()).unwrap_or(0);
        let url = v.get("html_url").and_then(|v| v.as_str()).unwrap_or("");
        Ok(ok_res(format!("created issue #{num}: {url}")))
    }

    async fn comment(&self, args: &Value, _is_pr: bool) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        // PR comments use the same /issues/{n}/comments endpoint.
        let n = args
            .get("pr_number")
            .and_then(|v| v.as_u64())
            .or_else(|| args.get("issue_number").and_then(|v| v.as_u64()));
        let n = match n {
            Some(n) => n,
            None => return Ok(err("missing 'issue_number' or 'pr_number'")),
        };
        let body = match args.get("body").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Ok(err("missing 'body'")),
        };
        if self.is_dry_run() {
            return Ok(ok_res(format!(
                "[dry-run] would comment on {owner}/{repo}#{n}: {body}"
            )));
        }
        let path = format!("repos/{owner}/{repo}/issues/{n}/comments");
        let resp = self
            .req(reqwest::Method::POST, &path)
            .json(&json!({"body": body}))
            .send()
            .await?;
        let (ok, status, resp_body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&resp_body))));
        }
        Ok(ok_res(format!("comment added to {owner}/{repo}#{n}")))
    }

    async fn run_mutation(&self, args: &Value, op: &str) -> anyhow::Result<ToolResult> {
        let (owner, repo) = match self.owner_repo(args) {
            Ok(p) => p,
            Err(e) => return Ok(err(e)),
        };
        let id = match args.get("run_id").and_then(|v| v.as_u64()) {
            Some(n) => n,
            None => return Ok(err("missing 'run_id'")),
        };
        if self.is_dry_run() {
            return Ok(ok_res(format!(
                "[dry-run] would {op} run {id} in {owner}/{repo}"
            )));
        }
        let suffix = if op == "rerun" { "rerun" } else { "cancel" };
        let path = format!("repos/{owner}/{repo}/actions/runs/{id}/{suffix}");
        let resp = self.req(reqwest::Method::POST, &path).send().await?;
        let (ok, status, body) = consume(resp).await;
        if !ok {
            return Ok(err(format!("{status}: {}", snippet(&body))));
        }
        Ok(ok_res(format!("{op} requested for run {id}")))
    }
}

async fn consume(resp: reqwest::Response) -> (bool, reqwest::StatusCode, String) {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    (status.is_success(), status, text)
}

fn snippet(s: &str) -> &str {
    &s[..s.len().min(500)]
}

fn err<S: Into<String>>(msg: S) -> ToolResult {
    ToolResult {
        success: false,
        output: String::new(),
        error: Some(msg.into()),
    }
}

fn ok_res(mut s: String) -> ToolResult {
    if s.len() > MAX_OUTPUT_BYTES {
        let mut cut = MAX_OUTPUT_BYTES;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("\n... [truncated]");
    }
    ToolResult {
        success: true,
        output: s,
        error: None,
    }
}

fn format_issue(v: &Value) -> String {
    let mut out = String::new();
    for k in [
        "number",
        "state",
        "title",
        "created_at",
        "updated_at",
        "html_url",
    ] {
        if let Some(val) = v.get(k) {
            writeln!(out, "{k}: {val}").ok();
        }
    }
    if let Some(user) = v
        .get("user")
        .and_then(|v| v.get("login"))
        .and_then(|v| v.as_str())
    {
        writeln!(out, "user: {user}").ok();
    }
    if let Some(body) = v.get("body").and_then(|v| v.as_str()) {
        let first: String = body.chars().take(1000).collect();
        writeln!(out, "body:\n{first}").ok();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn tool(server: &MockServer, autonomy: OpsClawAutonomy) -> GithubTool {
        let dir = tempfile::tempdir().unwrap();
        GithubTool::new(GithubToolConfig {
            token: "ghp_xxx".into(),
            default_owner: Some("acme".into()),
            default_repo: Some("widgets".into()),
            autonomy,
            api_base: server.uri(),
        })
        .with_audit_dir(dir.keep())
    }

    #[tokio::test]
    async fn list_issues_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues"))
            .and(header("authorization", "Bearer ghp_xxx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"number": 1, "state": "open", "title": "t1", "user": {"login": "u1"}}
            ])))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "list_issues"})).await.unwrap();
        assert!(r.success, "{:?}", r.error);
        assert!(r.output.contains("#1"));
        assert!(r.output.contains("t1"));
    }

    #[tokio::test]
    async fn get_run_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/actions/runs/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 42, "status": "completed", "conclusion": "success",
                "head_branch": "main"
            })))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({"action": "get_run", "run_id": 42}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.contains("conclusion: \"success\""));
    }

    #[tokio::test]
    async fn create_issue_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/issues"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "number": 99, "html_url": "https://github.com/acme/widgets/issues/99"
            })))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({"action": "create_issue", "title": "fire", "body": "down"}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.contains("#99"));
    }

    #[tokio::test]
    async fn create_issue_dry_run_skips_http() {
        let server = MockServer::start().await;
        let t = tool(&server, OpsClawAutonomy::DryRun);
        let r = t
            .execute(json!({"action": "create_issue", "title": "fire"}))
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.output.starts_with("[dry-run]"));
    }

    #[tokio::test]
    async fn rerun_run_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/actions/runs/7/rerun"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t
            .execute(json!({"action": "rerun_run", "run_id": 7}))
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.error);
    }

    #[tokio::test]
    async fn missing_owner_surfaces_error() {
        let server = MockServer::start().await;
        let t = GithubTool::new(GithubToolConfig {
            token: "x".into(),
            default_owner: None,
            default_repo: None,
            autonomy: OpsClawAutonomy::Auto,
            api_base: server.uri(),
        });
        let r = t.execute(json!({"action": "list_issues"})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("owner"));
    }

    #[tokio::test]
    async fn auth_failure_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "Bad creds"})))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "list_issues"})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("401"));
    }

    #[tokio::test]
    async fn server_500_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "list_issues"})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("500"));
    }

    #[tokio::test]
    async fn unknown_action_rejected() {
        let server = MockServer::start().await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({"action": "nuke_repo"})).await.unwrap();
        assert!(!r.success);
    }

    #[tokio::test]
    async fn missing_action_rejected() {
        let server = MockServer::start().await;
        let t = tool(&server, OpsClawAutonomy::Auto);
        let r = t.execute(json!({})).await.unwrap();
        assert!(!r.success);
    }
}
