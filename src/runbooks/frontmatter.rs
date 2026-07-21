//! TOML front matter: the `trigger`/`title`/`default_vars` block that heads
//! every runbook file.
//!
//! ## Front matter convention (documented here, the single source of truth)
//!
//! A runbook file opens with a `+++`-fenced TOML block, gianna-doc style
//! (chosen over a ```toml fence because `+++` cannot collide with a fenced
//! *command* block inside the body — a body step is free to use ```toml for
//! its own purposes without breaking the parser):
//!
//! ```text
//! +++
//! title = "DLQ backlog triage"
//!
//! [trigger]
//! alert_categories = ["dlq_backlog"]
//! keywords = ["dlq", "poison", "reprocessor"]
//! target_glob = "remundo::*::*"
//!
//! [default_vars]
//! queue = "orders-dlq"
//! +++
//!
//! Body markdown starts here...
//! ```
//!
//! The block must start at byte 0 of the file (no leading blank lines) and be
//! closed by a line that is exactly `+++`. Everything after the closing fence
//! is the body (parsed by [`super::steps`]).

use serde::Deserialize;

use crate::error::{Error, Result};

const FENCE: &str = "+++";

/// The parsed `[trigger]` table.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct Trigger {
    #[serde(default)]
    pub alert_categories: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    /// `project::env::target` with `*` wildcard segments, e.g. `remundo::*::*`.
    /// `None` means this runbook never target-glob-matches (category/keyword
    /// only).
    #[serde(default)]
    pub target_glob: Option<String>,
}

/// The parsed front-matter block.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct FrontMatter {
    pub title: String,
    #[serde(default)]
    pub trigger: Trigger,
    #[serde(default)]
    pub default_vars: std::collections::BTreeMap<String, String>,
}

/// Split a runbook file into `(front_matter_toml, body_markdown)`. Does not
/// parse the TOML — that's [`FrontMatter::parse`] — so callers that only need
/// the body (unlikely, but keeps the two concerns separable) can skip it.
pub fn split(input: &str) -> Result<(&str, &str)> {
    let rest = input.strip_prefix(FENCE).ok_or_else(|| {
        Error::Config(format!(
            "runbook front matter must open with `{FENCE}` on the file's first line"
        ))
    })?;
    // Fence line must be followed by a newline (not `+++more` on the same line).
    let rest = rest.strip_prefix('\n').or_else(|| rest.strip_prefix("\r\n")).ok_or_else(|| {
        Error::Config(format!("`{FENCE}` opening fence must be alone on its line"))
    })?;
    // Find the closing fence: a line that is exactly `+++`.
    let mut search_from = 0usize;
    loop {
        let Some(rel) = rest[search_from..].find(FENCE) else {
            return Err(Error::Config(format!(
                "runbook front matter opened with `{FENCE}` but no closing `{FENCE}` fence found"
            )));
        };
        let idx = search_from + rel;
        let at_line_start = idx == 0 || rest.as_bytes()[idx - 1] == b'\n';
        let after = &rest[idx + FENCE.len()..];
        let line_ends_cleanly =
            after.is_empty() || after.starts_with('\n') || after.starts_with("\r\n");
        if at_line_start && line_ends_cleanly {
            let toml_src = &rest[..idx];
            let body = after.strip_prefix('\n').or_else(|| after.strip_prefix("\r\n"));
            let body = body.unwrap_or(after);
            return Ok((toml_src, body));
        }
        // Not a real fence line (e.g. `+++` appearing mid-line elsewhere in
        // the TOML block, which shouldn't happen but don't infinite-loop).
        search_from = idx + FENCE.len();
    }
}

impl FrontMatter {
    /// Parse a whole runbook file's leading `+++` block. Malformed TOML
    /// surfaces the underlying `toml` error message so authors can find the
    /// exact line.
    pub fn parse(input: &str) -> Result<(FrontMatter, &str)> {
        let (toml_src, body) = split(input)?;
        let fm: FrontMatter = toml::from_str(toml_src)
            .map_err(|e| Error::Config(format!("runbook front matter: {e}")))?;
        if fm.title.trim().is_empty() {
            return Err(Error::Config("runbook front matter: `title` must not be empty".into()));
        }
        Ok((fm, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_fence_and_body() {
        let input = "+++\ntitle = \"x\"\n+++\n# Body\nstep one\n";
        let (toml_src, body) = split(input).unwrap();
        assert_eq!(toml_src, "title = \"x\"\n");
        assert_eq!(body, "# Body\nstep one\n");
    }

    #[test]
    fn missing_opening_fence_errors() {
        let err = split("title = \"x\"\n+++\nbody").unwrap_err();
        assert!(format!("{err}").contains("must open with"), "{err}");
    }

    #[test]
    fn missing_closing_fence_errors() {
        let err = split("+++\ntitle = \"x\"\nno closer here").unwrap_err();
        assert!(format!("{err}").contains("no closing"), "{err}");
    }

    #[test]
    fn parses_full_front_matter() {
        let input = r#"+++
title = "DLQ backlog triage"

[trigger]
alert_categories = ["dlq_backlog"]
keywords = ["dlq", "poison"]
target_glob = "remundo::*::*"

[default_vars]
queue = "orders-dlq"
+++
Body text.
"#;
        let (fm, body) = FrontMatter::parse(input).unwrap();
        assert_eq!(fm.title, "DLQ backlog triage");
        assert_eq!(fm.trigger.alert_categories, vec!["dlq_backlog"]);
        assert_eq!(fm.trigger.keywords, vec!["dlq", "poison"]);
        assert_eq!(fm.trigger.target_glob.as_deref(), Some("remundo::*::*"));
        assert_eq!(fm.default_vars.get("queue"), Some(&"orders-dlq".to_string()));
        assert_eq!(body, "Body text.\n");
    }

    #[test]
    fn trigger_and_default_vars_are_optional() {
        let input = "+++\ntitle = \"Minimal\"\n+++\nBody\n";
        let (fm, _) = FrontMatter::parse(input).unwrap();
        assert_eq!(fm.trigger, Trigger::default());
        assert!(fm.default_vars.is_empty());
    }

    #[test]
    fn empty_title_errors() {
        let input = "+++\ntitle = \"\"\n+++\nBody\n";
        let err = FrontMatter::parse(input).unwrap_err();
        assert!(format!("{err}").contains("title"), "{err}");
    }

    #[test]
    fn malformed_toml_gives_clear_error() {
        let input = "+++\ntitle = \"unterminated\n+++\nBody\n";
        let err = FrontMatter::parse(input).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("runbook front matter"), "{msg}");
    }

    #[test]
    fn missing_title_key_errors() {
        let input = "+++\n[trigger]\nkeywords = [\"x\"]\n+++\nBody\n";
        let err = FrontMatter::parse(input).unwrap_err();
        assert!(format!("{err}").contains("runbook front matter"), "{err}");
    }
}
