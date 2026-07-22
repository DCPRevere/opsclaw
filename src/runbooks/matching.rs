//! Trigger matching: does an incoming signal (alert categories, free-text
//! keywords, an [`FqTarget`]) fire a runbook? A match is the pre-approval
//! that unlocks `act_on_known` (brief §7) — false positives here are a safety
//! issue, not just a UX one, so matching is intentionally conservative: an
//! empty trigger (no categories, no keywords, no glob) never matches
//! anything.

use crate::domain::FqTarget;

use super::Runbook;

/// What we know about an incoming signal, to test against a runbook's
/// trigger.
#[derive(Debug, Clone, Default)]
pub struct MatchContext {
    /// Alert category tags, e.g. from an Alertmanager label.
    pub alert_categories: Vec<String>,
    /// Free text to keyword-search (alert summary, chat message, log line).
    pub text: String,
    /// The target the signal concerns, if known.
    pub target: Option<FqTarget>,
}

impl MatchContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.alert_categories.push(category.into());
        self
    }

    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = text.into();
        self
    }

    pub fn with_target(mut self, target: FqTarget) -> Self {
        self.target = Some(target);
        self
    }
}

/// Score of a single trigger dimension: how specifically it matched, used to
/// rank multiple matching runbooks in [`best_match`]. Higher is more
/// specific. Kept private to this module — callers see only `matches` (bool)
/// and `best_match` (picks the winner); the exact weights are an
/// implementation detail, not a contract.
fn score(runbook: &Runbook, ctx: &MatchContext) -> Option<u32> {
    let trigger = &runbook.front_matter.trigger;
    let mut total = 0u32;
    let mut hit = false;

    if let Some(glob) = &trigger.target_glob {
        if let Some(target) = &ctx.target {
            if glob_matches(glob, &target_path(target)) {
                hit = true;
                // Reward specificity: fewer wildcard segments = a tighter
                // match, so `remundo::prod::web-1` outranks `remundo::*::*`.
                let wildcard_segments = glob.split("::").filter(|seg| *seg == "*").count() as u32;
                let segments = glob.split("::").count() as u32;
                total += 100 + (segments.saturating_sub(wildcard_segments)) * 10;
            } else {
                // An explicit glob that does NOT match the target is a hard
                // miss for this runbook regardless of keyword/category hits —
                // a DLQ runbook scoped to `remundo::*::*` must not fire for
                // `other-project::prod::db`.
                return None;
            }
        }
    }

    if !trigger.alert_categories.is_empty() {
        let hits = ctx
            .alert_categories
            .iter()
            .filter(|c| trigger.alert_categories.iter().any(|tc| tc.eq_ignore_ascii_case(c)))
            .count() as u32;
        if hits > 0 {
            hit = true;
            total += hits * 20;
        }
    }

    if !trigger.keywords.is_empty() && !ctx.text.is_empty() {
        let haystack = ctx.text.to_ascii_lowercase();
        let hits = trigger
            .keywords
            .iter()
            .filter(|kw| haystack.contains(&kw.to_ascii_lowercase()))
            .count() as u32;
        if hits > 0 {
            hit = true;
            total += hits * 5;
        }
    }

    if hit { Some(total) } else { None }
}

fn target_path(target: &FqTarget) -> String {
    format!("{}::{}::{}", target.project, target.env, target.target)
}

/// `*` matches exactly one `::`-delimited segment (not a substring, not
/// multiple segments — keeps the grammar simple and the match total
/// predictable). Segment counts must match: `a::*` never matches `a::b::c`.
pub fn glob_matches(glob: &str, path: &str) -> bool {
    let glob_segs: Vec<&str> = glob.split("::").collect();
    let path_segs: Vec<&str> = path.split("::").collect();
    if glob_segs.len() != path_segs.len() {
        return false;
    }
    glob_segs.iter().zip(path_segs.iter()).all(|(g, p)| *g == "*" || *g == *p)
}

impl Runbook {
    /// Does this runbook's trigger fire for `ctx`? An empty trigger (no
    /// categories, keywords, or glob configured) never matches.
    pub fn matches(&self, ctx: &MatchContext) -> bool {
        score(self, ctx).is_some()
    }
}

/// Pick the highest-scoring matching runbook, if any. Ties break on first
/// occurrence (stable) rather than an arbitrary order.
pub fn best_match<'a>(runbooks: &'a [Runbook], ctx: &MatchContext) -> Option<&'a Runbook> {
    runbooks
        .iter()
        .filter_map(|rb| score(rb, ctx).map(|s| (s, rb)))
        .max_by_key(|(s, _)| *s)
        .map(|(_, rb)| rb)
}

/// Command-path scoring — the AGENT side of "a runbook match is the
/// pre-approval that unlocks `act_on_known`" (DESIGN §4 Runbooks, brief §5).
/// Distinct from [`score`] above, which rates an incoming SIGNAL (alert
/// categories, free text) and accepts a hit on any single dimension: a
/// command match GRANTS execution rights in the policy gate, so it is
/// strictly conjunctive and fail-closed —
///
/// - the runbook must declare a `target_glob` AND it must match the
///   command's resolved target (a globless runbook never pre-approves:
///   operator knowledge about one system must not silently apply to every
///   system);
/// - the runbook must declare at least one non-empty keyword AND at least
///   one must appear in the composed command line (case-insensitive
///   substring) — a keywordless runbook must not blanket-pre-approve every
///   command that happens to land on its targets.
///
/// Alert categories deliberately do NOT count here: they describe signals,
/// not commands, and a category hit says nothing about whether THIS command
/// is the remediation the runbook's author pre-approved.
///
/// SECURITY INVARIANT: callers compute this from the loaded store plus the
/// code-composed command and the dispatcher-resolved target — never from
/// model output, which could otherwise grant itself pre-approval by naming
/// a runbook (see `tools::executor::run_command`).
fn command_score(runbook: &Runbook, command: &str, target_path: &str) -> Option<u32> {
    let trigger = &runbook.front_matter.trigger;
    // Fail closed: no glob → no pre-approval, ever.
    let glob = trigger.target_glob.as_deref()?;
    if !glob_matches(glob, target_path) {
        return None;
    }
    // Only non-empty keywords count — `haystack.contains("")` is always
    // true, so a stray `""` in the keyword list would otherwise match every
    // command (the blanket-pre-approval this matcher exists to refuse).
    let haystack = command.to_ascii_lowercase();
    let hits = trigger
        .keywords
        .iter()
        .filter(|kw| !kw.trim().is_empty())
        .filter(|kw| haystack.contains(&kw.to_ascii_lowercase()))
        .count() as u32;
    if hits == 0 {
        // Covers both "no keywords declared" and "none matched" — fail
        // closed either way.
        return None;
    }
    // Same specificity ranking as `score`: a tighter glob outranks a
    // broader one, more keyword hits outrank fewer.
    let wildcard_segments = glob.split("::").filter(|seg| *seg == "*").count() as u32;
    let segments = glob.split("::").count() as u32;
    Some(100 + (segments.saturating_sub(wildcard_segments)) * 10 + hits * 5)
}

/// Pick the best pre-approving runbook for a composed command against a
/// resolved target, per [`command_score`]'s conjunctive fail-closed rule.
/// `None` when nothing pre-approves — at `act_on_known` that means the
/// command queues for a human instead of executing, which is the safe
/// default this whole module is built around.
pub fn best_command_match<'a>(
    runbooks: &'a [Runbook],
    command: &str,
    target: &FqTarget,
) -> Option<&'a Runbook> {
    let path = target_path(target);
    runbooks
        .iter()
        .filter_map(|rb| command_score(rb, command, &path).map(|s| (s, rb)))
        .max_by_key(|(s, _)| *s)
        .map(|(_, rb)| rb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runbooks::Runbook;

    fn runbook(toml_trigger: &str) -> Runbook {
        let src = format!("+++\ntitle = \"t\"\n\n{toml_trigger}\n+++\n- step one\n");
        Runbook::parse(&src).unwrap()
    }

    #[test]
    fn glob_wildcard_matches_segment() {
        assert!(glob_matches("remundo::*::*", "remundo::prod::web-1"));
        assert!(glob_matches("remundo::prod::*", "remundo::prod::web-1"));
        assert!(!glob_matches("remundo::prod::*", "remundo::staging::web-1"));
    }

    #[test]
    fn glob_segment_count_must_match() {
        assert!(!glob_matches("remundo::*", "remundo::prod::web-1"));
        assert!(!glob_matches("remundo::*::*::extra", "remundo::prod::web-1"));
    }

    #[test]
    fn glob_exact_segment_must_equal() {
        assert!(glob_matches("remundo::prod::web-1", "remundo::prod::web-1"));
        assert!(!glob_matches("remundo::prod::web-2", "remundo::prod::web-1"));
    }

    #[test]
    fn empty_trigger_never_matches() {
        let rb = runbook("[trigger]");
        let ctx = MatchContext::new()
            .with_category("dlq_backlog")
            .with_text("dlq is backed up")
            .with_target(FqTarget::new("remundo", "prod", "web-1"));
        assert!(!rb.matches(&ctx));
    }

    #[test]
    fn category_match() {
        let rb = runbook("[trigger]\nalert_categories = [\"dlq_backlog\"]");
        assert!(rb.matches(&MatchContext::new().with_category("dlq_backlog")));
        assert!(!rb.matches(&MatchContext::new().with_category("other")));
    }

    #[test]
    fn category_match_is_case_insensitive() {
        let rb = runbook("[trigger]\nalert_categories = [\"DLQ_Backlog\"]");
        assert!(rb.matches(&MatchContext::new().with_category("dlq_backlog")));
    }

    #[test]
    fn keyword_match_is_substring_case_insensitive() {
        let rb = runbook("[trigger]\nkeywords = [\"dlq\", \"poison\"]");
        assert!(rb.matches(&MatchContext::new().with_text("The DLQ depth is climbing")));
        assert!(rb.matches(&MatchContext::new().with_text("poison messages piling up")));
        assert!(!rb.matches(&MatchContext::new().with_text("cpu is high")));
    }

    #[test]
    fn target_glob_match() {
        let rb = runbook("[trigger]\ntarget_glob = \"remundo::*::*\"");
        assert!(
            rb.matches(&MatchContext::new().with_target(FqTarget::new("remundo", "prod", "web-1")))
        );
        assert!(
            !rb.matches(&MatchContext::new().with_target(FqTarget::new("other", "prod", "web-1")))
        );
    }

    #[test]
    fn target_glob_present_but_no_target_in_context_is_not_a_match_on_its_own() {
        let rb = runbook("[trigger]\ntarget_glob = \"remundo::*::*\"");
        // No target supplied and no other dimension hits -> no match.
        assert!(!rb.matches(&MatchContext::new()));
    }

    #[test]
    fn glob_mismatch_vetoes_even_with_keyword_hit() {
        let rb = runbook("[trigger]\nkeywords = [\"dlq\"]\ntarget_glob = \"remundo::*::*\"");
        let ctx = MatchContext::new().with_text("dlq backlog").with_target(FqTarget::new(
            "other-project",
            "prod",
            "web-1",
        ));
        assert!(!rb.matches(&ctx), "glob mismatch must veto even with a keyword hit");
    }

    #[test]
    fn best_match_prefers_more_specific_glob() {
        let broad = runbook("[trigger]\ntarget_glob = \"remundo::*::*\"");
        let narrow = runbook("[trigger]\ntarget_glob = \"remundo::prod::web-1\"");
        let ctx = MatchContext::new().with_target(FqTarget::new("remundo", "prod", "web-1"));
        let candidates = [broad.clone(), narrow.clone()];
        let picked = best_match(&candidates, &ctx).unwrap();
        assert_eq!(
            picked.front_matter.trigger.target_glob,
            narrow.front_matter.trigger.target_glob
        );
    }

    #[test]
    fn best_match_none_when_nothing_matches() {
        let rb = runbook("[trigger]\nkeywords = [\"dlq\"]");
        assert!(best_match(&[rb], &MatchContext::new().with_text("unrelated")).is_none());
    }

    #[test]
    fn best_match_sums_multiple_keyword_hits() {
        let rb = runbook("[trigger]\nkeywords = [\"dlq\", \"poison\", \"reprocessor\"]");
        let one_hit = runbook("[trigger]\nkeywords = [\"dlq\"]");
        let ctx = MatchContext::new().with_text("dlq poison reprocessor backlog");
        let candidates = [one_hit, rb.clone()];
        let picked = best_match(&candidates, &ctx).unwrap();
        assert_eq!(picked.front_matter.title, rb.front_matter.title);
    }

    // ---- the command-path (pre-approval) matcher --------------------------

    fn titled_runbook(title: &str, toml_trigger: &str) -> Runbook {
        let src = format!("+++\ntitle = \"{title}\"\n\n{toml_trigger}\n+++\n- step one\n");
        Runbook::parse(&src).unwrap()
    }

    fn prod_target() -> FqTarget {
        FqTarget::new("remundo", "prod", "web-1")
    }

    #[test]
    fn command_match_requires_glob_and_keyword_together() {
        let rb =
            runbook("[trigger]\nkeywords = [\"nginx\"]\ntarget_glob = \"remundo::prod::web-1\"");
        let hit = best_command_match(
            std::slice::from_ref(&rb),
            "systemctl restart nginx",
            &prod_target(),
        );
        assert!(hit.is_some());
    }

    #[test]
    fn command_match_glob_mismatch_vetoes_despite_keyword_hit() {
        let rb = runbook("[trigger]\nkeywords = [\"nginx\"]\ntarget_glob = \"remundo::prod::*\"");
        let other = FqTarget::new("remundo", "staging", "web-1");
        assert!(
            best_command_match(std::slice::from_ref(&rb), "systemctl restart nginx", &other)
                .is_none()
        );
    }

    #[test]
    fn command_match_keyword_miss_vetoes_despite_glob_hit() {
        let rb = runbook("[trigger]\nkeywords = [\"nginx\"]\ntarget_glob = \"remundo::*::*\"");
        assert!(
            best_command_match(
                std::slice::from_ref(&rb),
                "systemctl restart postgres",
                &prod_target()
            )
            .is_none()
        );
    }

    #[test]
    fn command_match_fails_closed_without_a_glob() {
        // A globless runbook must never pre-approve, even on a keyword hit —
        // operator knowledge about one system must not apply to every system.
        let rb = runbook("[trigger]\nkeywords = [\"nginx\"]");
        assert!(
            best_command_match(
                std::slice::from_ref(&rb),
                "systemctl restart nginx",
                &prod_target()
            )
            .is_none()
        );
    }

    #[test]
    fn command_match_fails_closed_without_keywords() {
        // A keywordless runbook must not blanket-pre-approve every command
        // that lands on its targets.
        let rb = runbook("[trigger]\ntarget_glob = \"remundo::*::*\"");
        assert!(
            best_command_match(
                std::slice::from_ref(&rb),
                "systemctl restart nginx",
                &prod_target()
            )
            .is_none()
        );
    }

    #[test]
    fn command_match_empty_keyword_string_is_not_a_blanket_match() {
        // `haystack.contains("")` is always true — a stray empty keyword
        // must not turn into "pre-approve everything on these targets".
        let rb = runbook("[trigger]\nkeywords = [\"\"]\ntarget_glob = \"remundo::*::*\"");
        assert!(
            best_command_match(
                std::slice::from_ref(&rb),
                "systemctl restart nginx",
                &prod_target()
            )
            .is_none()
        );
    }

    #[test]
    fn command_match_categories_alone_never_pre_approve() {
        // Categories describe signals, not commands — a category-only
        // trigger can fire the SIGNAL matcher but never the command matcher.
        let rb = runbook(
            "[trigger]\nalert_categories = [\"dlq_backlog\"]\ntarget_glob = \"remundo::*::*\"",
        );
        assert!(
            best_command_match(
                std::slice::from_ref(&rb),
                "restart the dlq reprocessor",
                &prod_target()
            )
            .is_none()
        );
    }

    #[test]
    fn command_match_keyword_is_case_insensitive() {
        let rb = runbook("[trigger]\nkeywords = [\"NGINX\"]\ntarget_glob = \"remundo::*::*\"");
        assert!(
            best_command_match(
                std::slice::from_ref(&rb),
                "systemctl restart nginx",
                &prod_target()
            )
            .is_some()
        );
    }

    #[test]
    fn command_match_prefers_more_specific_glob() {
        let broad = titled_runbook(
            "broad",
            "[trigger]\nkeywords = [\"nginx\"]\ntarget_glob = \"remundo::*::*\"",
        );
        let narrow = titled_runbook(
            "narrow",
            "[trigger]\nkeywords = [\"nginx\"]\ntarget_glob = \"remundo::prod::web-1\"",
        );
        let candidates = [broad, narrow];
        let picked =
            best_command_match(&candidates, "systemctl restart nginx", &prod_target()).unwrap();
        assert_eq!(picked.title(), "narrow");
    }

    #[test]
    fn command_match_more_keyword_hits_outrank_fewer() {
        let one = titled_runbook(
            "one-hit",
            "[trigger]\nkeywords = [\"nginx\"]\ntarget_glob = \"remundo::*::*\"",
        );
        let two = titled_runbook(
            "two-hits",
            "[trigger]\nkeywords = [\"nginx\", \"restart\"]\ntarget_glob = \"remundo::*::*\"",
        );
        let candidates = [one, two];
        let picked =
            best_command_match(&candidates, "systemctl restart nginx", &prod_target()).unwrap();
        assert_eq!(picked.title(), "two-hits");
    }

    #[test]
    fn command_match_resource_qualified_target_matches_on_base_path() {
        // Endpoint mutations (e.g. an argocd rollback) carry a resource-
        // qualified target; the glob grammar addresses the base
        // project::env::target path, same as the signal matcher.
        let rb =
            runbook("[trigger]\nkeywords = [\"rollback\"]\ntarget_glob = \"remundo::prod::*\"");
        let mut target = prod_target();
        target.resource = Some((crate::domain::ResourceType::Argocd, "main".into()));
        assert!(
            best_command_match(
                std::slice::from_ref(&rb),
                "argocd app rollback guestbook 7",
                &target
            )
            .is_some()
        );
    }
}
