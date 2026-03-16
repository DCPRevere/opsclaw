//! SshTool component tests (Phase 1c).
//!
//! Tests the SshTool's Tool trait implementation in isolation — argument
//! validation, credential handling, autonomy enforcement, and output format.
//! Does NOT require an actual SSH server; uses mock/stub internals.

use serde_json::json;
use zeroclaw::tools::{Tool, ToolResult};

// These tests import the SshTool once it exists. They define the contract.
use zeroclaw::tools::ssh::SshTool;

// ─────────────────────────────────────────────────────────────────────────────
// Tool trait basics
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ssh_tool_name() {
    let tool = SshTool::new_for_test();
    assert_eq!(tool.name(), "ssh");
}

#[test]
fn ssh_tool_description_mentions_remote() {
    let tool = SshTool::new_for_test();
    let desc = tool.description();
    assert!(
        desc.to_lowercase().contains("remote")
            || desc.to_lowercase().contains("ssh")
            || desc.to_lowercase().contains("command"),
        "description should mention remote command execution"
    );
}

#[test]
fn ssh_tool_schema_requires_target_and_command() {
    let tool = SshTool::new_for_test();
    let schema = tool.parameters_schema();
    let required = schema["required"]
        .as_array()
        .expect("schema should have required fields");
    let required_names: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        required_names.contains(&"target"),
        "schema should require 'target'"
    );
    assert!(
        required_names.contains(&"command"),
        "schema should require 'command'"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument validation
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ssh_tool_rejects_missing_target() {
    let tool = SshTool::new_for_test();
    let result = tool
        .execute(json!({"command": "uptime"}))
        .await
        .expect("should return ToolResult, not error");
    assert!(!result.success, "should fail without target");
    assert!(
        result.error.as_deref().unwrap_or("").contains("target"),
        "error should mention missing target"
    );
}

#[tokio::test]
async fn ssh_tool_rejects_missing_command() {
    let tool = SshTool::new_for_test();
    let result = tool
        .execute(json!({"target": "prod-web-1"}))
        .await
        .expect("should return ToolResult, not error");
    assert!(!result.success, "should fail without command");
    assert!(
        result.error.as_deref().unwrap_or("").contains("command"),
        "error should mention missing command"
    );
}

#[tokio::test]
async fn ssh_tool_rejects_unknown_target() {
    let tool = SshTool::new_for_test();
    let result = tool
        .execute(json!({"target": "nonexistent", "command": "uptime"}))
        .await
        .expect("should return ToolResult, not error");
    assert!(!result.success);
    assert!(
        result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("not found")
            || result.error.as_deref().unwrap_or("").contains("unknown"),
        "error should indicate target not found"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Credential safety
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ssh_tool_output_never_contains_key_material() {
    // Even on connection failure, the error message must not leak the SSH key.
    let tool = SshTool::new_for_test();
    let result = tool
        .execute(json!({"target": "test-target", "command": "uptime"}))
        .await
        .expect("should return ToolResult");

    let output = format!(
        "{} {}",
        result.output,
        result.error.as_deref().unwrap_or("")
    );
    assert!(
        !output.contains("BEGIN"),
        "output must not contain key material"
    );
    assert!(
        !output.contains("PRIVATE KEY"),
        "output must not contain key material"
    );
    assert!(
        !output.contains("ssh-ed25519"),
        "output must not contain public key"
    );
}

#[test]
fn ssh_tool_schema_does_not_expose_key_parameter() {
    let tool = SshTool::new_for_test();
    let schema = tool.parameters_schema();
    let props = schema["properties"].as_object().expect("should have properties");
    assert!(
        !props.contains_key("key"),
        "schema must not expose SSH key as a parameter"
    );
    assert!(
        !props.contains_key("ssh_key"),
        "schema must not expose SSH key as a parameter"
    );
    assert!(
        !props.contains_key("password"),
        "schema must not expose password as a parameter"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Autonomy enforcement
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ssh_tool_observe_mode_blocks_write_commands() {
    // At observe level, commands that modify state should be rejected.
    let tool = SshTool::new_for_test_with_autonomy("observe");
    let write_commands = vec![
        "rm -rf /tmp/test",
        "systemctl restart nginx",
        "docker stop webapp",
        "kill -9 1234",
        "reboot",
    ];
    for cmd in write_commands {
        let result = tool
            .execute(json!({"target": "test-target", "command": cmd}))
            .await
            .expect("should return ToolResult");
        assert!(
            !result.success,
            "observe mode should block write command: {cmd}"
        );
    }
}

#[tokio::test]
async fn ssh_tool_observe_mode_allows_read_commands() {
    // At observe level, read-only commands should be allowed through to execution.
    let tool = SshTool::new_for_test_with_autonomy("observe");
    let read_commands = vec![
        "uptime",
        "ps aux",
        "df -h",
        "cat /etc/os-release",
        "docker ps",
        "ss -tlnp",
    ];
    for cmd in read_commands {
        let result = tool
            .execute(json!({"target": "test-target", "command": cmd}))
            .await
            .expect("should return ToolResult");
        // The command might fail (no SSH server) but it should not be
        // blocked by autonomy. Check that the error is NOT about autonomy.
        if !result.success {
            let err = result.error.as_deref().unwrap_or("");
            assert!(
                !err.contains("autonomy") && !err.contains("blocked") && !err.contains("denied"),
                "read command '{cmd}' should not be blocked by autonomy, got: {err}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Output format
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ssh_tool_result_includes_exit_code() {
    // On successful execution the output should include the exit code
    // so the LLM can reason about command success/failure.
    let tool = SshTool::new_for_test_connected();
    let result = tool
        .execute(json!({"target": "test-target", "command": "true"}))
        .await
        .expect("should return ToolResult");
    assert!(result.success);
    assert!(
        result.output.contains("exit_code")
            || result.output.contains("exit code")
            || result.output.contains("status"),
        "output should include exit code information"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Timeout
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ssh_tool_accepts_optional_timeout() {
    let tool = SshTool::new_for_test();
    let schema = tool.parameters_schema();
    let props = schema["properties"]
        .as_object()
        .expect("should have properties");
    assert!(
        props.contains_key("timeout_secs"),
        "schema should accept an optional timeout parameter"
    );
}
