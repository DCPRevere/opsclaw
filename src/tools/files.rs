//! `file_read`/`file_write` — daemon-local, WORKSPACE-BOUNDED file ops
//! (brief §10 "Generic: ... file read/write (workspace-bounded)", §5's
//! "workspace-only file ops" policy bound). The agent gets a scratch area
//! for notes, draft runbooks, and gathered evidence — bounded to
//! `daemon.workspace_dir` (default `<opsclaw_home>/workspace`,
//! [`crate::config::DaemonCfg::workspace_root`]) so a tool call can never
//! read `/etc/shadow` or overwrite the daemon's own config file.
//!
//! Bounding is enforced by CANONICALIZATION, not string prefixing: after a
//! lexical pre-check (relative paths only, no `..` components — rejected
//! with a precise message before touching the filesystem), the resolved
//! path is `fs::canonicalize`d and must sit under the canonicalized
//! workspace root. For writes the PARENT directory is canonicalized (the
//! file itself may not exist yet), and a pre-existing destination is
//! canonicalized too — so a symlink planted inside the workspace pointing
//! out of it can't smuggle a read or a write past the boundary.
//!
//! Both tools are daemon-local (no remote side effect), so like
//! [`crate::tools::notify`] they never round-trip through `ctx.policy` —
//! there is no target and no command to classify. `file_write` still
//! declares `is_action` (it writes state) and is NOT offered in heartbeat
//! runs: an unattended scan gathers evidence and escalates, it doesn't
//! accrete workspace state nobody asked for.

use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::RiskClass;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

/// Read cap: enough for any note or runbook draft; an honest truncation
/// marker (never a silent cut) when a file exceeds it, so the model knows
/// it saw a prefix.
const MAX_READ_BYTES: usize = 64 * 1024;

pub struct FileReadTool;
pub struct FileWriteTool;

/// The workspace root from config — both tools' single source of the
/// boundary. `Internal` when config isn't wired: the registry only offers
/// these tools when `ctx.config` exists, so a miss is a wiring bug, not a
/// model mistake.
fn workspace_root(ctx: &ToolCtx) -> Result<PathBuf, ToolError> {
    let config = ctx
        .config
        .as_ref()
        .ok_or_else(|| ToolError::Internal("file tool called with no config wired".to_string()))?;
    Ok(config.daemon.workspace_root())
}

/// Lexical pre-check shared by read and write: the model must give a
/// non-empty RELATIVE path with no `..` components. Rejected before any
/// filesystem access so the error names the actual rule (canonicalization
/// alone would report a confusing "no such file" for a `../` escape that
/// happens not to exist).
fn checked_relative(path: &str) -> Result<&Path, ToolError> {
    if path.is_empty() {
        return Err(ToolError::UserFacing("\"path\" must not be empty".to_string()));
    }
    let p = Path::new(path);
    if p.is_absolute() {
        return Err(ToolError::UserFacing(format!(
            "absolute path {path:?} is not allowed — give a path relative to the workspace \
             root, e.g. \"notes/scan.md\""
        )));
    }
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(ToolError::UserFacing(format!(
            "path {path:?} contains \"..\" — paths must stay inside the workspace"
        )));
    }
    Ok(p)
}

/// The boundary check both tools end on: a canonicalized path must sit
/// under the canonicalized root, or the call is refused naming why.
fn ensure_inside(canonical: &Path, root: &Path, path: &str) -> Result<(), ToolError> {
    if canonical.starts_with(root) {
        Ok(())
    } else {
        Err(ToolError::UserFacing(format!(
            "path {path:?} escapes the workspace (it resolves outside the workspace root, \
             e.g. via a symlink) — refusing"
        )))
    }
}

#[async_trait]
impl Tool for FileReadTool {
    fn name(&self) -> &'static str {
        "file_read"
    }

    fn description(&self) -> &str {
        "Read a file from the daemon's workspace — the scratch area where file_write puts \
         notes, drafts, and gathered evidence. Paths are relative to the workspace root \
         (e.g. \"notes/scan.md\"); nothing outside the workspace is reachable. Output is \
         capped at 64KB with a truncation marker. To read a file ON a target, use ssh/shell \
         instead."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "workspace-relative path, e.g. notes/scan.md"}
            },
            "required": ["path"]
        })
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

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let path = args["path"].as_str().ok_or_else(|| {
            ToolError::UserFacing("file_read requires a \"path\" argument".to_string())
        })?;
        let rel = checked_relative(path)?;
        let root = workspace_root(ctx)?.canonicalize().map_err(|_| {
            ToolError::UserFacing(
                "the workspace directory does not exist yet — nothing has been written to it"
                    .to_string(),
            )
        })?;
        let canonical = root.join(rel).canonicalize().map_err(|_| {
            ToolError::UserFacing(format!("no such file in the workspace: {path:?}"))
        })?;
        ensure_inside(&canonical, &root, path)?;

        let bytes = std::fs::read(&canonical)
            .map_err(|e| ToolError::UserFacing(format!("cannot read {path:?}: {e}")))?;
        if bytes.is_empty() {
            return Ok(ToolResult { output: "(empty file)".to_string() });
        }
        let shown = bytes.len().min(MAX_READ_BYTES);
        let mut output = String::from_utf8_lossy(&bytes[..shown]).into_owned();
        if bytes.len() > MAX_READ_BYTES {
            output.push_str(&format!(
                "\n[truncated: showing the first {MAX_READ_BYTES} bytes of {} total]",
                bytes.len()
            ));
        }
        Ok(ToolResult { output })
    }
}

#[async_trait]
impl Tool for FileWriteTool {
    fn name(&self) -> &'static str {
        "file_write"
    }

    fn description(&self) -> &str {
        "Write (create or overwrite) a file in the daemon's workspace — for notes, draft \
         runbooks, and evidence you want to keep across steps. Paths are relative to the \
         workspace root (e.g. \"notes/scan.md\"); missing directories are created; nothing \
         outside the workspace can be touched. To change a file ON a target, use ssh/shell \
         (gated by policy) instead."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "workspace-relative path, e.g. notes/scan.md"},
                "content": {"type": "string", "description": "the full new file content (overwrites any existing content)"}
            },
            "required": ["path", "content"]
        })
    }

    fn risk(&self) -> RiskClass {
        // Writes daemon-local state only — nothing runs against a target,
        // so like `opsclaw_notify` this is never autonomy-gated; the
        // workspace bound above is its whole policy.
        RiskClass::Read
    }

    fn is_action(&self) -> bool {
        // Still an ACTION (it writes state) even though it carries no
        // policy risk — mirrors `opsclaw_notify`.
        true
    }

    fn allowed_in_heartbeat(&self) -> bool {
        // See the module doc: unattended runs observe and escalate; they
        // don't accrete workspace state.
        false
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let path = args["path"].as_str().ok_or_else(|| {
            ToolError::UserFacing("file_write requires a \"path\" argument".to_string())
        })?;
        let content = args["content"].as_str().ok_or_else(|| {
            ToolError::UserFacing("file_write requires a \"content\" argument".to_string())
        })?;
        let rel = checked_relative(path)?;

        let configured_root = workspace_root(ctx)?;
        std::fs::create_dir_all(&configured_root).map_err(|e| {
            ToolError::Internal(format!("cannot create workspace {configured_root:?}: {e}"))
        })?;
        let root = configured_root
            .canonicalize()
            .map_err(|e| ToolError::Internal(format!("cannot resolve workspace root: {e}")))?;

        let full = root.join(rel);
        // Canonicalize the PARENT (the file itself may not exist yet):
        // creating it first is safe — `rel` is lexically confined, so the
        // only way the created chain could leave the workspace is a
        // pre-existing symlink along it, which the canonicalize catches.
        let parent = full.parent().unwrap_or(&root);
        std::fs::create_dir_all(parent)
            .map_err(|e| ToolError::UserFacing(format!("cannot create directories: {e}")))?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|e| ToolError::Internal(format!("cannot resolve {parent:?}: {e}")))?;
        ensure_inside(&canonical_parent, &root, path)?;

        let file_name = full
            .file_name()
            .ok_or_else(|| ToolError::UserFacing(format!("path {path:?} must name a file")))?;
        let dest = canonical_parent.join(file_name);
        // The destination itself may pre-exist as a symlink pointing out of
        // the workspace — `fs::write` would follow it, so check where it
        // actually resolves before writing.
        if let Ok(existing) = dest.canonicalize() {
            ensure_inside(&existing, &root, path)?;
        }
        std::fs::write(&dest, content)
            .map_err(|e| ToolError::UserFacing(format!("cannot write {path:?}: {e}")))?;

        Ok(ToolResult {
            output: format!("wrote {} bytes to workspace file {path:?}", content.len()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
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

    /// A ctx whose workspace root is a fresh tempdir. The tempdir guard is
    /// returned too — dropping it deletes the workspace.
    fn ctx_with_workspace() -> (ToolCtx, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.daemon.workspace_dir = Some(dir.path().join("workspace"));
        let mut ctx = ToolCtx::for_tests(Principal::Agent { job: None }, Arc::new(NoopPolicy));
        ctx.config = Some(Arc::new(config));
        (ctx, dir)
    }

    #[tokio::test]
    async fn write_then_read_roundtrips() {
        let (ctx, _dir) = ctx_with_workspace();
        let w = FileWriteTool
            .call(&ctx, json!({"path": "notes/scan.md", "content": "cpu was fine"}))
            .await
            .unwrap();
        assert!(w.output.contains("wrote 12 bytes"), "{}", w.output);

        let r = FileReadTool.call(&ctx, json!({"path": "notes/scan.md"})).await.unwrap();
        assert_eq!(r.output, "cpu was fine");
    }

    #[tokio::test]
    async fn overwrite_replaces_content() {
        let (ctx, _dir) = ctx_with_workspace();
        FileWriteTool.call(&ctx, json!({"path": "a.txt", "content": "one"})).await.unwrap();
        FileWriteTool.call(&ctx, json!({"path": "a.txt", "content": "two"})).await.unwrap();
        let r = FileReadTool.call(&ctx, json!({"path": "a.txt"})).await.unwrap();
        assert_eq!(r.output, "two");
    }

    #[tokio::test]
    async fn dotdot_paths_are_rejected_lexically() {
        let (ctx, dir) = ctx_with_workspace();
        for tool_call in [
            FileReadTool.call(&ctx, json!({"path": "../outside.txt"})).await,
            FileWriteTool.call(&ctx, json!({"path": "../outside.txt", "content": "x"})).await,
            FileWriteTool.call(&ctx, json!({"path": "a/../../outside.txt", "content": "x"})).await,
        ] {
            let err = tool_call.unwrap_err();
            match err {
                ToolError::UserFacing(msg) => assert!(msg.contains(".."), "{msg}"),
                other => panic!("expected UserFacing, got {other:?}"),
            }
        }
        assert!(!dir.path().join("outside.txt").exists(), "nothing may land outside");
    }

    #[tokio::test]
    async fn absolute_paths_are_rejected() {
        let (ctx, _dir) = ctx_with_workspace();
        let err = FileReadTool.call(&ctx, json!({"path": "/etc/passwd"})).await.unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        let err = FileWriteTool
            .call(&ctx, json!({"path": "/tmp/pwned.txt", "content": "x"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_file_pointing_outside_is_refused_on_read() {
        let (ctx, dir) = ctx_with_workspace();
        // Materialize the workspace, plant a secret OUTSIDE it, and a link
        // INSIDE it pointing at the secret.
        FileWriteTool.call(&ctx, json!({"path": "seed.txt", "content": ""})).await.unwrap();
        let outside = dir.path().join("secret.txt");
        std::fs::write(&outside, "credentials").unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join("workspace/link.txt")).unwrap();

        let err = FileReadTool.call(&ctx, json!({"path": "link.txt"})).await.unwrap_err();
        match err {
            ToolError::UserFacing(msg) => assert!(msg.contains("escapes"), "{msg}"),
            other => panic!("expected UserFacing, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_directory_pointing_outside_is_refused_on_write() {
        let (ctx, dir) = ctx_with_workspace();
        FileWriteTool.call(&ctx, json!({"path": "seed.txt", "content": ""})).await.unwrap();
        let outside_dir = dir.path().join("elsewhere");
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::os::unix::fs::symlink(&outside_dir, dir.path().join("workspace/linkdir")).unwrap();

        let err = FileWriteTool
            .call(&ctx, json!({"path": "linkdir/pwned.txt", "content": "x"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert!(!outside_dir.join("pwned.txt").exists(), "the write must not have landed");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_file_pointing_outside_is_refused_on_write() {
        let (ctx, dir) = ctx_with_workspace();
        FileWriteTool.call(&ctx, json!({"path": "seed.txt", "content": ""})).await.unwrap();
        let outside = dir.path().join("victim.txt");
        std::fs::write(&outside, "original").unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join("workspace/evil.txt")).unwrap();

        let err = FileWriteTool
            .call(&ctx, json!({"path": "evil.txt", "content": "overwritten"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "original", "must be untouched");
    }

    #[tokio::test]
    async fn oversized_read_is_truncated_with_an_honest_marker() {
        let (ctx, _dir) = ctx_with_workspace();
        let big = "x".repeat(MAX_READ_BYTES + 1000);
        FileWriteTool.call(&ctx, json!({"path": "big.txt", "content": big})).await.unwrap();
        let r = FileReadTool.call(&ctx, json!({"path": "big.txt"})).await.unwrap();
        assert!(r.output.contains("[truncated: showing the first"), "{}", &r.output[..80]);
        assert!(r.output.len() < MAX_READ_BYTES + 200, "output must be capped");
    }

    #[tokio::test]
    async fn reading_a_missing_file_is_user_facing() {
        let (ctx, _dir) = ctx_with_workspace();
        FileWriteTool.call(&ctx, json!({"path": "seed.txt", "content": ""})).await.unwrap();
        let err = FileReadTool.call(&ctx, json!({"path": "nope.txt"})).await.unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[tokio::test]
    async fn missing_config_is_an_internal_fault() {
        let ctx = ToolCtx::for_tests(Principal::Agent { job: None }, Arc::new(NoopPolicy));
        let err = FileReadTool.call(&ctx, json!({"path": "a.txt"})).await.unwrap_err();
        assert!(matches!(err, ToolError::Internal(_)));
        let err = FileWriteTool.call(&ctx, json!({"path": "a.txt", "content": ""})).await;
        assert!(matches!(err.unwrap_err(), ToolError::Internal(_)));
    }

    #[test]
    fn capability_declarations() {
        assert!(!FileReadTool.is_action());
        assert!(FileReadTool.allowed_in_heartbeat());
        assert!(FileWriteTool.is_action());
        assert!(!FileWriteTool.allowed_in_heartbeat(), "no unattended workspace writes");
    }
}
