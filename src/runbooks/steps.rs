//! Body parsing: prose steps, each optionally carrying a fenced `sh` command
//! and a failure-handling marker.
//!
//! Deliberately NOT a general markdown parser (no `pulldown-cmark` dep, by
//! design — see `src/runbooks/mod.rs`). The body grammar recognized is:
//!
//! - A **step** starts at a top-level list item: a line beginning with `-`,
//!   `*`, or `N.` (after optional leading whitespace, list nesting is not
//!   modelled — nested content is folded into the parent step's text).
//! - Lines between one step marker and the next belong to that step: prose is
//!   appended to `text`; a fenced ` ```sh ` … ` ``` ` block anywhere in that
//!   span becomes the step's `command` (first one wins — a step composes one
//!   command).
//! - An inline marker `(on-fail: abort|continue|retry)` anywhere in the
//!   step's own text (not inside the command block) sets [`Step::on_fail`];
//!   absent → [`OnFail::Abort`]. The marker text is stripped from `text`.
//! - `{name}` in the command is a placeholder slot, collected into
//!   [`Step::placeholders`] in first-seen order (see `super::render`).
//! - Prose before the first list item (if any) is ignored for stepping
//!   purposes — callers that want it can read the raw body themselves.

use std::sync::LazyLock;

use regex::Regex;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnFail {
    #[default]
    Abort,
    Continue,
    Retry,
}

impl std::str::FromStr for OnFail {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "abort" => Ok(OnFail::Abort),
            "continue" => Ok(OnFail::Continue),
            "retry" => Ok(OnFail::Retry),
            other => Err(Error::Config(format!(
                "unknown on-fail marker {other:?} (expected abort|continue|retry)"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Step {
    /// The step's prose (list-item text plus any continuation lines), with
    /// the `(on-fail: ...)` marker and any fenced command block stripped.
    pub text: String,
    /// A fenced ` ```sh ` command block belonging to this step, if any.
    pub command: Option<String>,
    /// `{placeholder}` names found in `command`, first-seen order, deduped.
    pub placeholders: Vec<String>,
    pub on_fail: OnFail,
}

static LIST_ITEM: LazyLock<Regex> = LazyLock::new(|| {
    // `-`, `*`, or `1.` / `2)` list markers, optionally indented.
    Regex::new(r"^\s*(?:[-*]|\d+[.)])\s+(.*)$").expect("static regex")
});

// Captures the verb permissively (word chars/hyphens) so a malformed verb
// like `retry-forever` is still recognized AS a marker and rejected by
// `OnFail::from_str` with a clear error — rather than silently failing to
// match the marker at all and defaulting to `Abort`.
static ON_FAIL_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\(on-fail:\s*([a-zA-Z][a-zA-Z-]*)\s*\)").expect("static regex")
});

static PLACEHOLDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{([A-Za-z_][A-Za-z0-9_]*)\}").expect("static regex"));

/// Extract `{name}` placeholders from a command body, first-seen order,
/// deduped.
pub fn extract_placeholders(command: &str) -> Vec<String> {
    let mut seen = Vec::new();
    for cap in PLACEHOLDER.captures_iter(command) {
        let name = cap[1].to_string();
        if !seen.contains(&name) {
            seen.push(name);
        }
    }
    seen
}

/// Parse the runbook body into steps. Errors on a malformed on-fail marker
/// (an unknown verb) so a typo doesn't silently downgrade a step's failure
/// handling to the default.
pub fn parse_steps(body: &str) -> Result<Vec<Step>> {
    let lines: Vec<&str> = body.lines().collect();
    let mut steps = Vec::new();
    let mut current: Option<RawStep> = None;

    for line in lines {
        if let Some(caps) = LIST_ITEM.captures(line) {
            if let Some(raw) = current.take() {
                steps.push(raw.finish()?);
            }
            current = Some(RawStep::new(caps[1].to_string()));
            continue;
        }
        if let Some(raw) = current.as_mut() {
            raw.push_line(line);
        }
        // Lines before the first list item are ignored (module doc).
    }
    if let Some(raw) = current.take() {
        steps.push(raw.finish()?);
    }
    Ok(steps)
}

/// Accumulator for one step while scanning lines.
struct RawStep {
    text_lines: Vec<String>,
    in_fence: bool,
    fence_lang_is_sh: bool,
    command_lines: Vec<String>,
    command: Option<String>,
}

impl RawStep {
    fn new(first_line: String) -> Self {
        RawStep {
            text_lines: vec![first_line],
            in_fence: false,
            fence_lang_is_sh: false,
            command_lines: Vec::new(),
            command: None,
        }
    }

    fn push_line(&mut self, line: &str) {
        let trimmed = line.trim_start();
        if let Some(lang) = trimmed.strip_prefix("```") {
            if !self.in_fence {
                self.in_fence = true;
                self.fence_lang_is_sh = matches!(lang.trim(), "sh" | "bash" | "shell");
                self.command_lines.clear();
                return;
            } else {
                self.in_fence = false;
                if self.fence_lang_is_sh && self.command.is_none() {
                    self.command = Some(self.command_lines.join("\n"));
                }
                return;
            }
        }
        if self.in_fence {
            if self.fence_lang_is_sh {
                self.command_lines.push(line.to_string());
            }
            // Non-sh fenced blocks (e.g. a step author quoting output) are
            // dropped from `text` entirely rather than folded in verbatim —
            // keeps `text` to prose.
            return;
        }
        // A new list item at the SAME or shallower indentation would already
        // have been caught by the caller's LIST_ITEM check before reaching
        // here; anything else (continuation prose, nested sub-bullets) is
        // folded into this step's text.
        if !line.trim().is_empty() {
            self.text_lines.push(line.trim().to_string());
        }
    }

    fn finish(self) -> Result<Step> {
        let joined = self.text_lines.join(" ");
        let (text, on_fail) = extract_on_fail(&joined)?;
        let placeholders = self.command.as_deref().map(extract_placeholders).unwrap_or_default();
        Ok(Step { text, command: self.command, placeholders, on_fail })
    }
}

/// Pull the `(on-fail: ...)` marker out of step text, returning the cleaned
/// text and the parsed [`OnFail`] (default `Abort` if absent).
fn extract_on_fail(text: &str) -> Result<(String, OnFail)> {
    match ON_FAIL_MARKER.captures(text) {
        None => Ok((text.trim().to_string(), OnFail::Abort)),
        Some(caps) => {
            let verb = caps[1].to_ascii_lowercase();
            let on_fail: OnFail = verb.parse()?;
            let cleaned = ON_FAIL_MARKER.replace(text, "").trim().to_string();
            // Collapse the double space left where the marker was removed
            // mid-sentence.
            let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
            Ok((cleaned, on_fail))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_prose_steps() {
        let body = "- Check the queue depth\n- Peek the DLQ\n";
        let steps = parse_steps(body).unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].text, "Check the queue depth");
        assert_eq!(steps[1].text, "Peek the DLQ");
        assert!(steps[0].command.is_none());
        assert_eq!(steps[0].on_fail, OnFail::Abort);
    }

    #[test]
    fn numbered_list_markers_work() {
        let body = "1. First step\n2) Second step\n";
        let steps = parse_steps(body).unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].text, "First step");
        assert_eq!(steps[1].text, "Second step");
    }

    #[test]
    fn parses_command_block() {
        let body = "- Restart the deployment\n  ```sh\n  kubectl rollout restart deploy/{service} -n {namespace}\n  ```\n";
        let steps = parse_steps(body).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(
            steps[0].command.as_deref(),
            Some("  kubectl rollout restart deploy/{service} -n {namespace}")
        );
        assert_eq!(steps[0].placeholders, vec!["service", "namespace"]);
    }

    #[test]
    fn on_fail_marker_parsed_and_stripped() {
        let body =
            "- Restart the pod (on-fail: retry)\n  ```sh\n  kubectl delete pod {pod}\n  ```\n";
        let steps = parse_steps(body).unwrap();
        assert_eq!(steps[0].on_fail, OnFail::Retry);
        assert_eq!(steps[0].text, "Restart the pod");
    }

    #[test]
    fn on_fail_continue_and_default_abort() {
        let body = "- Log the event (on-fail: continue)\n- Verify success\n";
        let steps = parse_steps(body).unwrap();
        assert_eq!(steps[0].on_fail, OnFail::Continue);
        assert_eq!(steps[1].on_fail, OnFail::Abort);
    }

    #[test]
    fn unknown_on_fail_verb_errors() {
        let body = "- Do the thing (on-fail: retry-forever)\n";
        let err = parse_steps(body).unwrap_err();
        assert!(format!("{err}").contains("unknown on-fail marker"), "{err}");
    }

    #[test]
    fn on_fail_marker_is_case_insensitive() {
        let body = "- Restart (ON-FAIL: RETRY)\n";
        let steps = parse_steps(body).unwrap();
        assert_eq!(steps[0].on_fail, OnFail::Retry);
    }

    #[test]
    fn continuation_lines_fold_into_step_text() {
        let body = "- First line of the step\n  more detail on the same step\n- Next step\n";
        let steps = parse_steps(body).unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].text, "First line of the step more detail on the same step");
    }

    #[test]
    fn non_sh_fence_is_dropped_from_text_not_treated_as_command() {
        let body = "- Inspect output\n  ```text\n  some sample output\n  ```\n";
        let steps = parse_steps(body).unwrap();
        assert!(steps[0].command.is_none());
    }

    #[test]
    fn first_sh_fence_wins_when_multiple_present() {
        let body = "- Two commands\n  ```sh\n  echo one\n  ```\n  ```sh\n  echo two\n  ```\n";
        let steps = parse_steps(body).unwrap();
        assert_eq!(steps[0].command.as_deref(), Some("  echo one"));
    }

    #[test]
    fn placeholders_dedup_and_preserve_order() {
        let cmd = "kubectl exec {target} -n {namespace} -- check {target}";
        assert_eq!(extract_placeholders(cmd), vec!["target", "namespace"]);
    }

    #[test]
    fn empty_body_yields_no_steps() {
        assert!(parse_steps("").unwrap().is_empty());
        assert!(parse_steps("just prose, no list items\n").unwrap().is_empty());
    }
}
