//! Token-budgeted history management for the tool loop.
//!
//! Ported from gianna's `src/agent/replay.rs`, simplified for opsclaw's flat
//! `llm::Turn` shape: gianna's `ToolTurn` split an assistant tool-call turn
//! from its results into two separate variants that had to stay paired
//! (`AssistantToolCalls` + `ToolResults`), so its replay logic did a whole
//! call/result pairing dance to avoid ever emitting an orphan. Opsclaw's
//! `Turn::Assistant` already bundles its own `tool_calls`, and
//! `Turn::ToolResult` is one row per call rather than a batch — so there is
//! no pairing to preserve and no "orphan leading tool row" hazard to guard
//! against. What's kept: the token-budget estimate, capping an oversized
//! verbatim tool result, and shrinking a live history on a context-overflow
//! recovery.
//!
//! Opsclaw has no cross-restart chat history store (unlike gianna's
//! `MessageRepo`) — DESIGN.md's replay window is scoped to ONE tool-loop
//! call's own growing `history: Vec<Turn>`, not stored turns replayed back
//! in from a prior conversation. So this module has no `assemble_replay`
//! counterpart; it only manages the in-flight history within a turn.

use crate::llm::Turn;

/// Cheap token estimate (no tokenizer needed for a loose budget): ~4
/// chars/token.
fn est_tokens(s: &str) -> usize {
    s.len().div_ceil(4)
}

/// Max chars kept from a single verbatim tool result. A large payload (a
/// command's full stdout, a big `kubectl get` dump) need not stay
/// full-length once several more steps have happened after it — cap it and
/// mark the cut so the model knows the tail was elided.
const TOOL_RESULT_CHARS_MAX: usize = 1_200;

/// Cap one tool result's output text if it's over [`TOOL_RESULT_CHARS_MAX`].
/// No-op on any other turn variant.
fn cap_tool_result(t: Turn) -> Turn {
    match t {
        Turn::ToolResult { call_id, name, output } if output.chars().count() > TOOL_RESULT_CHARS_MAX => {
            let mut kept: String = output.chars().take(TOOL_RESULT_CHARS_MAX).collect();
            kept.push_str("…[truncated]");
            Turn::ToolResult { call_id, name, output: kept }
        }
        other => other,
    }
}

/// Token estimate for one history turn.
fn turn_tokens(t: &Turn) -> usize {
    match t {
        Turn::User { content } => est_tokens(content),
        Turn::Assistant { content, tool_calls } => {
            est_tokens(content)
                + tool_calls.iter().map(|c| est_tokens(&c.name) + est_tokens(&c.args.to_string())).sum::<usize>()
        }
        Turn::ToolResult { output, .. } => est_tokens(output),
    }
}

/// Approximate token count of an assembled history (~chars/4). Cheap, no
/// tokenizer — for the loop's observability guard and shrink decisions, not
/// a hard gate (the provider stays the authority on what actually fits).
pub(crate) fn estimate_history_tokens(history: &[Turn]) -> usize {
    history.iter().map(turn_tokens).sum()
}

/// Shrink a LIVE running history in place — the token-budgeted fold DESIGN.md
/// §3 calls for: (1) cap oversized verbatim tool results (a command's full
/// output the model already consumed when it ran); (2) collapse STALE tool
/// exchanges (an `Assistant` turn carrying tool calls, immediately followed
/// by their `ToolResult` turns) older than the most recent `keep_tool_turns`
/// into one-line `[used tool → outcome]` markers — the fact that a tool ran
/// and its outcome survives, the raw argument/output payload doesn't; (3) if
/// still over the turn-count ceiling after folding, drop the OLDEST turns
/// until at most `keep_recent` remain. The tail (most recent turns,
/// including the current user message) is always preserved. Returns `true`
/// if it actually changed anything, so the caller can tell a real shrink
/// from a no-op (a history already minimal, where retrying the identical
/// call is pointless).
///
/// Deliberately blunt — the goal is to get under budget, not to optimise
/// what's kept; the caller's honest fallback covers the case where even the
/// minimum still overflows.
pub(crate) fn shrink_history(history: &mut Vec<Turn>, keep_recent: usize) -> bool {
    let before_len = history.len();
    let before_tokens = estimate_history_tokens(history);

    for t in history.iter_mut() {
        let capped = cap_tool_result(std::mem::replace(t, Turn::User { content: String::new() }));
        *t = capped;
    }

    collapse_stale_tool_exchanges(history, KEEP_TOOL_EXCHANGES_VERBATIM);

    let keep = keep_recent.max(1).min(history.len());
    if history.len() > keep {
        let drop = history.len() - keep;
        history.drain(0..drop);
    }

    let after_tokens = estimate_history_tokens(history);
    history.len() != before_len || after_tokens < before_tokens
}

/// Most-recent tool exchanges kept VERBATIM (full call args + full result)
/// by [`collapse_stale_tool_exchanges`]; older ones fold to a marker.
const KEEP_TOOL_EXCHANGES_VERBATIM: usize = 3;

/// Fold tool exchanges older than the last `keep` into one-line markers.
/// A "tool exchange" here is an `Assistant` turn whose `tool_calls` is
/// non-empty, together with the `ToolResult` turn(s) that immediately
/// follow it (the shape [`crate::agent::run_turn`] always builds: one
/// `Assistant{tool_calls: [call]}` immediately followed by one matching
/// `ToolResult`). Walking newest-first and counting exchanges from the end
/// means the most recent `keep` survive verbatim regardless of how many
/// total exchanges there are.
fn collapse_stale_tool_exchanges(history: &mut Vec<Turn>, keep: usize) {
    // Identify exchange START indices (an Assistant turn with tool_calls),
    // newest-first, so we know which ones are "recent enough" to keep.
    let exchange_starts: Vec<usize> = history
        .iter()
        .enumerate()
        .filter(|(_, t)| matches!(t, Turn::Assistant { tool_calls, .. } if !tool_calls.is_empty()))
        .map(|(i, _)| i)
        .collect();
    if exchange_starts.len() <= keep {
        return; // nothing is stale yet
    }
    let stale_starts = &exchange_starts[..exchange_starts.len() - keep];

    let mut out: Vec<Turn> = Vec::with_capacity(history.len());
    let mut i = 0;
    while i < history.len() {
        let is_stale_start = stale_starts.contains(&i);
        match (&history[i], is_stale_start) {
            (Turn::Assistant { tool_calls, .. }, true) if !tool_calls.is_empty() => {
                // Fold this call plus every immediately-following ToolResult
                // into one marker per call (matches by position: `run_turn`
                // always pushes exactly one ToolResult per single-call
                // Assistant turn, in order).
                let call = &tool_calls[0];
                let mut j = i + 1;
                let mut outcome = String::new();
                if let Some(Turn::ToolResult { output, .. }) = history.get(j) {
                    outcome = output.clone();
                    j += 1;
                }
                out.push(Turn::Assistant {
                    content: collapse_marker(&call.name, &outcome),
                    tool_calls: Vec::new(),
                });
                i = j;
            }
            _ => {
                out.push(history[i].clone());
                i += 1;
            }
        }
    }
    *history = out;
}

/// Collapse an old tool exchange (a call plus its result, still adjacent in
/// history) into one short assistant-text marker — keeps the FACT that a
/// tool ran and its outcome, drops the raw argument/output payload. Used by
/// the tool loop to fold turns once they're old enough that their full
/// detail no longer earns its context cost, while still telling the model
/// it already acted (so it doesn't repeat the call thinking nothing
/// happened). `name` is the tool; `outcome` is its result text (already
/// capped by the caller if needed).
pub(crate) fn collapse_marker(name: &str, outcome: &str) -> String {
    let outcome = outcome.trim();
    let shown = if outcome.chars().count() > 160 {
        let clipped: String = outcome.chars().take(160).collect();
        format!("{clipped}…")
    } else {
        outcome.to_string()
    };
    if shown.is_empty() {
        format!("[used {name}]")
    } else {
        format!("[used {name} → {shown}]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::ToolCall;

    fn user(s: &str) -> Turn {
        Turn::User { content: s.into() }
    }
    fn asst(s: &str) -> Turn {
        Turn::Assistant { content: s.into(), tool_calls: Vec::new() }
    }
    fn asst_call(id: &str, name: &str) -> Turn {
        Turn::Assistant {
            content: String::new(),
            tool_calls: vec![ToolCall { id: id.into(), name: name.into(), args: serde_json::json!({}) }],
        }
    }
    fn result(id: &str, name: &str, output: &str) -> Turn {
        Turn::ToolResult { call_id: id.into(), name: name.into(), output: output.into() }
    }

    #[test]
    fn estimate_sums_all_turn_kinds() {
        let history = vec![user("hello there"), asst("hi"), result("c1", "ssh", "uptime output")];
        assert!(estimate_history_tokens(&history) > 0);
    }

    #[test]
    fn cap_tool_result_truncates_oversized_output() {
        let big = "x".repeat(5_000);
        let t = result("c1", "ssh", &big);
        let capped = cap_tool_result(t);
        match capped {
            Turn::ToolResult { output, .. } => {
                assert!(output.chars().count() < 2_000);
                assert!(output.ends_with("…[truncated]"));
            }
            _ => panic!("expected ToolResult"),
        }
    }

    #[test]
    fn cap_tool_result_leaves_small_output_untouched() {
        let t = result("c1", "ssh", "uptime: 5 days");
        let capped = cap_tool_result(t.clone());
        assert!(matches!(capped, Turn::ToolResult { output, .. } if output == "uptime: 5 days"));
    }

    #[test]
    fn cap_tool_result_is_a_noop_on_non_tool_turns() {
        let u = user("hi");
        assert!(matches!(cap_tool_result(u), Turn::User { content } if content == "hi"));
    }

    #[test]
    fn shrink_history_drops_oldest_keeps_recent() {
        let mut hist: Vec<Turn> = Vec::new();
        for i in 0..20 {
            hist.push(user(&format!("u{i}")));
            hist.push(asst(&format!("a{i}")));
        }
        let changed = shrink_history(&mut hist, 6);
        assert!(changed);
        assert!(hist.len() <= 6);
        assert!(matches!(hist.last(), Some(Turn::Assistant { content, .. }) if content == "a19"));
    }

    #[test]
    fn shrink_history_caps_oversized_result_even_without_dropping() {
        let big = "y".repeat(12_000);
        let mut hist = vec![user("read it"), asst_call("c1", "ssh"), result("c1", "ssh", &big)];
        let before = estimate_history_tokens(&hist);
        let changed = shrink_history(&mut hist, 100); // keep_recent huge -> no drop
        assert!(changed, "capping counts as a change");
        assert!(estimate_history_tokens(&hist) < before);
        let kept = hist.iter().find_map(|t| match t {
            Turn::ToolResult { output, .. } => Some(output.clone()),
            _ => None,
        });
        assert!(kept.unwrap().ends_with("…[truncated]"));
    }

    #[test]
    fn shrink_history_is_a_noop_on_an_already_minimal_history() {
        let mut hist = vec![user("hi")];
        assert!(!shrink_history(&mut hist, 6));
        assert_eq!(hist.len(), 1);
    }

    #[test]
    fn shrink_history_preserves_the_most_recent_turn() {
        let mut hist: Vec<Turn> = (0..10).map(|i| user(&format!("u{i}"))).collect();
        shrink_history(&mut hist, 3);
        assert!(matches!(hist.last(), Some(Turn::User { content }) if content == "u9"));
    }

    #[test]
    fn collapse_marker_states_tool_ran_and_its_outcome() {
        let m = collapse_marker("ssh", "uptime: 5 days, load 0.3");
        assert!(m.starts_with("[used ssh"));
        assert!(m.contains("uptime: 5 days"));
    }

    #[test]
    fn collapse_marker_handles_empty_outcome() {
        let m = collapse_marker("notify", "");
        assert_eq!(m, "[used notify]");
    }

    #[test]
    fn collapse_marker_clips_long_outcomes() {
        let long = "x".repeat(500);
        let m = collapse_marker("ssh", &long);
        assert!(m.len() < 300, "marker must clip: {} chars", m.len());
        assert!(m.contains('…'), "clipped outcome is marked: {m}");
    }

    fn tool_exchange(n: usize, name: &str) -> Vec<Turn> {
        let id = format!("c{n}");
        vec![
            user(&format!("do thing {n}")),
            asst_call(&id, name),
            result(&id, name, &format!("{name} done: thing {n}")),
        ]
    }

    #[test]
    fn collapse_keeps_the_most_recent_exchanges_verbatim_and_folds_older_ones() {
        let mut hist: Vec<Turn> = Vec::new();
        for i in 0..5 {
            hist.extend(tool_exchange(i, "restart_service"));
        }
        collapse_stale_tool_exchanges(&mut hist, KEEP_TOOL_EXCHANGES_VERBATIM);

        let verbatim_calls = hist
            .iter()
            .filter(|t| matches!(t, Turn::Assistant { tool_calls, .. } if !tool_calls.is_empty()))
            .count();
        assert_eq!(verbatim_calls, KEEP_TOOL_EXCHANGES_VERBATIM, "only the last 3 stay verbatim");

        let markers: Vec<&String> = hist
            .iter()
            .filter_map(|t| match t {
                Turn::Assistant { content, tool_calls } if tool_calls.is_empty() && content.starts_with("[used ") => {
                    Some(content)
                }
                _ => None,
            })
            .collect();
        assert_eq!(markers.len(), 2, "the two oldest exchanges collapse to markers");
        for m in &markers {
            assert!(m.contains("restart_service"), "marker names the tool: {m}");
            assert!(m.contains("done: thing"), "marker carries the outcome: {m}");
        }
    }

    #[test]
    fn collapse_is_a_noop_when_exchange_count_is_within_the_keep_window() {
        let mut hist: Vec<Turn> = Vec::new();
        for i in 0..2 {
            hist.extend(tool_exchange(i, "echo"));
        }
        let before = hist.len();
        collapse_stale_tool_exchanges(&mut hist, KEEP_TOOL_EXCHANGES_VERBATIM);
        assert_eq!(hist.len(), before, "2 exchanges <= keep(3) -> nothing folds");
    }

    #[test]
    fn shrink_history_folds_stale_tool_exchanges_before_dropping_turns() {
        // 5 tool exchanges (15 turns) with a generous keep_recent: the
        // budget/turn-count pressure should be relieved by FOLDING first,
        // not by dropping the early user turns outright.
        let mut hist: Vec<Turn> = Vec::new();
        for i in 0..5 {
            hist.extend(tool_exchange(i, "restart_service"));
        }
        let before_len = hist.len();
        let changed = shrink_history(&mut hist, 100); // huge keep_recent -> folding is the only lever
        assert!(changed);
        assert!(hist.len() < before_len, "folding must shrink turn count");
        // The earliest user turn ("do thing 0") survives — folding drops the
        // raw tool call/result, not the surrounding user turns.
        assert!(hist.iter().any(|t| matches!(t, Turn::User { content } if content == "do thing 0")));
    }
}
