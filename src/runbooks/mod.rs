//! Runbooks (brief §7, DESIGN.md §4 "Runbooks"): markdown files with TOML
//! front matter describing a trigger and prose/command steps. A runbook
//! match is the pre-approval that unlocks `act_on_known` in the policy gate —
//! the mechanism by which human knowledge becomes bounded automation.
//!
//! This module is pure parsing/matching/templating: no DB, no network, no
//! executor. Persisting [`history::RunbookRun`] and actually running a
//! runbook's steps through `policy::execute` belong to later waves (the DB
//! wave's `RunbookRunRepo`, and an execution engine respectively) — this
//! module hands them well-typed inputs to work from.
//!
//! ## Front-matter convention
//!
//! Documented in full in [`frontmatter`]: a `+++`-fenced TOML block (chosen
//! over a ```toml fence — see that module for why) containing `title`, an
//! optional `[trigger]` table (`alert_categories`, `keywords`,
//! `target_glob`), and optional `[default_vars]`.
//!
//! ## Submodules
//!
//! - [`frontmatter`] — the TOML front-matter grammar and its parser.
//! - [`steps`] — body parsing into [`steps::Step`]s (list items, fenced `sh`
//!   command blocks, `(on-fail: ...)` markers, `{placeholder}` extraction).
//! - [`matching`] — [`matching::MatchContext`], `target_glob` wildcard
//!   matching, [`Runbook::matches`] and [`matching::best_match`].
//! - [`render`] — `{placeholder}` substitution with clear missing-value
//!   errors.
//! - [`history`] — [`history::RunbookRun`] / [`history::StepOutcome`] and the
//!   `success_rate` / `low_success` helpers.
//! - [`template`] — the `runbook init` starter markdown.

pub mod frontmatter;
pub mod history;
pub mod matching;
pub mod render;
pub mod steps;
pub mod template;

use std::collections::BTreeMap;

use crate::domain::FqTarget;
use crate::error::Result;

pub use frontmatter::{FrontMatter, Trigger};
pub use history::{RunbookRun, StepOutcome, StepStatus, low_success, success_rate};
pub use matching::{MatchContext, best_match, glob_matches};
pub use steps::{OnFail, Step};
pub use template::INIT_TEMPLATE;

/// A fully-parsed runbook: front matter plus its steps.
#[derive(Debug, Clone, PartialEq)]
pub struct Runbook {
    pub front_matter: FrontMatter,
    pub steps: Vec<Step>,
}

impl Runbook {
    /// Parse a whole runbook file (front matter + body).
    pub fn parse(input: &str) -> Result<Runbook> {
        let (front_matter, body) = FrontMatter::parse(input)?;
        let steps = steps::parse_steps(body)?;
        Ok(Runbook { front_matter, steps })
    }

    pub fn title(&self) -> &str {
        &self.front_matter.title
    }

    /// Render every step's command against a vars map built from CLI
    /// `--var`s, this runbook's `default_vars`, and target-derived auto vars.
    /// Returns `(step, rendered_command_or_none)` pairs in step order; errors
    /// on the first missing placeholder (naming it) rather than collecting
    /// partial output — a runbook that's half-renderable is not safe to run.
    pub fn render_all(
        &self,
        target: Option<&FqTarget>,
        cli_vars: &BTreeMap<String, String>,
    ) -> Result<Vec<(Step, Option<String>)>> {
        let vars = render::build_vars(target, &self.front_matter.default_vars, cli_vars);
        self.steps
            .iter()
            .map(|step| render::render_step(step, &vars).map(|cmd| (step.clone(), cmd)))
            .collect()
    }
}

/// The three fixture runbooks (REMUNDO.md "Runbook candidates"), embedded at
/// compile time so tests (and, later, `runbook list`'s doc examples) don't
/// depend on a filesystem layout at runtime.
pub const FIXTURE_DLQ_BACKLOG: &str = include_str!("fixtures/dlq_backlog.md");
pub const FIXTURE_SYNCHRONISER_LAG: &str = include_str!("fixtures/synchroniser_lag.md");
pub const FIXTURE_SANDBOX_IS_DOWN: &str = include_str!("fixtures/sandbox_is_down.md");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_fixtures_parse() {
        for src in [FIXTURE_DLQ_BACKLOG, FIXTURE_SYNCHRONISER_LAG, FIXTURE_SANDBOX_IS_DOWN] {
            let rb = Runbook::parse(src).expect("fixture must parse");
            assert!(!rb.steps.is_empty());
        }
    }

    #[test]
    fn dlq_fixture_matches_dlq_signal() {
        let rb = Runbook::parse(FIXTURE_DLQ_BACKLOG).unwrap();
        let ctx = MatchContext::new().with_category("dlq_backlog").with_target(FqTarget::new(
            "remundo",
            "prod",
            "sb-worker",
        ));
        assert!(rb.matches(&ctx));
    }

    #[test]
    fn dlq_fixture_does_not_match_unrelated_project() {
        let rb = Runbook::parse(FIXTURE_DLQ_BACKLOG).unwrap();
        let ctx = MatchContext::new().with_category("dlq_backlog").with_target(FqTarget::new(
            "other-project",
            "prod",
            "sb-worker",
        ));
        assert!(!rb.matches(&ctx));
    }

    #[test]
    fn synchroniser_fixture_matches_lag_keyword() {
        let rb = Runbook::parse(FIXTURE_SYNCHRONISER_LAG).unwrap();
        let ctx = MatchContext::new()
            .with_text("Synchroniser lag detected on read models")
            .with_target(FqTarget::new("remundo", "prod", "es-cluster"));
        assert!(rb.matches(&ctx));
    }

    #[test]
    fn sandbox_fixture_scoped_to_sandbox_env_only() {
        let rb = Runbook::parse(FIXTURE_SANDBOX_IS_DOWN).unwrap();
        let sandbox_ctx = MatchContext::new()
            .with_category("target_unreachable")
            .with_target(FqTarget::new("remundo", "sandbox", "aks-sandbox"));
        let prod_ctx = MatchContext::new()
            .with_category("target_unreachable")
            .with_target(FqTarget::new("remundo", "prod", "aks-prod"));
        assert!(rb.matches(&sandbox_ctx));
        assert!(!rb.matches(&prod_ctx), "must not fire for prod — that would be a real outage");
    }

    #[test]
    fn best_match_picks_the_right_fixture_among_all_three() {
        let runbooks = vec![
            Runbook::parse(FIXTURE_DLQ_BACKLOG).unwrap(),
            Runbook::parse(FIXTURE_SYNCHRONISER_LAG).unwrap(),
            Runbook::parse(FIXTURE_SANDBOX_IS_DOWN).unwrap(),
        ];
        let ctx = MatchContext::new()
            .with_text("synchroniser projection is stale")
            .with_target(FqTarget::new("remundo", "prod", "es-cluster"));
        let picked = best_match(&runbooks, &ctx).unwrap();
        assert_eq!(picked.title(), "Synchroniser lag");
    }

    #[test]
    fn render_all_fills_target_and_default_vars() {
        let rb = Runbook::parse(FIXTURE_DLQ_BACKLOG).unwrap();
        let target = FqTarget::new("remundo", "prod", "sb-worker");
        let rendered = rb.render_all(Some(&target), &BTreeMap::new()).unwrap();
        let peek_step = rendered.iter().find(|(s, _)| s.text.starts_with("Peek")).unwrap();
        let cmd = peek_step.1.as_deref().unwrap();
        assert!(cmd.contains("--queue orders-dlq"), "{cmd}");
        assert!(cmd.contains("--target sb-worker"), "{cmd}");
    }

    #[test]
    fn render_all_cli_var_overrides_default() {
        let rb = Runbook::parse(FIXTURE_DLQ_BACKLOG).unwrap();
        let target = FqTarget::new("remundo", "prod", "sb-worker");
        let mut cli_vars = BTreeMap::new();
        cli_vars.insert("queue".to_string(), "payments-dlq".to_string());
        let rendered = rb.render_all(Some(&target), &cli_vars).unwrap();
        let peek_step = rendered.iter().find(|(s, _)| s.text.starts_with("Peek")).unwrap();
        assert!(peek_step.1.as_deref().unwrap().contains("--queue payments-dlq"));
    }

    #[test]
    fn render_all_errors_on_missing_placeholder_with_no_target() {
        let rb = Runbook::parse(FIXTURE_DLQ_BACKLOG).unwrap();
        // No target supplied -> {target}/{namespace} unresolved -> error.
        let err = rb.render_all(None, &BTreeMap::new()).unwrap_err();
        assert!(format!("{err}").contains("missing value for placeholder"));
    }

    #[test]
    fn on_fail_markers_present_on_fixture_steps() {
        let rb = Runbook::parse(FIXTURE_DLQ_BACKLOG).unwrap();
        assert!(rb.steps.iter().any(|s| s.on_fail == OnFail::Continue));
        assert!(rb.steps.iter().any(|s| s.on_fail == OnFail::Retry));
        assert!(rb.steps.iter().any(|s| s.on_fail == OnFail::Abort));
    }
}
