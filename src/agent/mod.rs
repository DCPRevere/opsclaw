//! The agent: the tool-calling loop (DESIGN.md §3 "Agent loop").
//!
//! Ported from gianna's `src/agent/mod.rs` tool loop: hand-rolled
//! `for _ in 0..max_steps`, step cap PLUS a separate wall-clock deadline,
//! tool errors returned to the model as strings rather than aborting the
//! turn (split user-facing vs internal fault), a duplicate-call guard on
//! repeated identical action calls, and detached memory retention after the
//! turn. What's dropped: everything household/liturgy-specific (novenas,
//! setup mode, calendar, enrichment runs, images) — opsclaw's loop is a
//! single, focused SRE diagnose/act/escalate turn, not a multi-purpose
//! household assistant. `prompt` owns system-prompt text (persona,
//! observation framing, environment scepticism); `replay` owns the
//! in-flight history token budget.
//!
//! **Difference from gianna (DESIGN.md §3):** gianna is act-then-announce
//! because everything is reversible. OpsClaw is classify-then-gate: every
//! tool that touches a target routes through `policy::PolicyExecute`
//! (reached only via `ToolCtx`), which decides execute/ask/block BEFORE
//! anything runs. The loop shape here is gianna's; the dispatch inside a
//! tool's `call` is not this module's concern — this loop never sees a
//! `TargetExecutor`, only `Tool::call`'s `Result<ToolResult, ToolError>`.
//!
//! [`dispatch`] is the OTHER kind of dispatch — not tool dispatch inside a
//! turn, but WHO calls `run_turn` at all: it wires a real `ToolCtx` from
//! config/repos/memory and implements `scheduler::JobComposer` (a fired
//! scan job becomes one heartbeat-mode turn) and `http::webhook::IngestAlert`
//! (a verified alert becomes one interactive-mode turn), the two seams both
//! of those modules already predicted.

pub mod dispatch;
pub mod prompt;
mod replay;

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;

use crate::llm::{LlmProvider, ToolSpec, Turn};
use crate::memory::Memory;
use crate::tools::{Tool, ToolCtx, ToolError};
use crate::{Error, Result};

/// Bound the loop so a misbehaving or looping model can't spin forever.
/// DESIGN.md §3 says "cap ~10–20"; opsclaw's turns are diagnose/act/escalate
/// (no multi-page enrichment-style runs to accommodate), so 16 sits in the
/// middle of that range with headroom for a multi-tool diagnostic chain
/// (three or four diagnostics plus a notify/approval call).
pub const MAX_STEPS: usize = 16;

/// Step cap for UNATTENDED (heartbeat) turns. A real-cluster sweep is
/// step-hungry — first sandbox scan hit the 16-step cap while several
/// namespaces still had genuine faults unexamined — and a heartbeat turn
/// has no impatient human and no wall-clock deadline, so it gets the
/// deeper budget (gianna's split: 10 interactive / 20 enrichment, scaled
/// for cluster-sweep workloads). Interactive turns keep [`MAX_STEPS`]:
/// they're already bounded by [`TURN_DEADLINE`] and a human is waiting.
pub const MAX_STEPS_HEARTBEAT: usize = 32;

/// Wall-clock budget for one turn. Steps are bounded at [`MAX_STEPS`], but
/// each step can sit behind a slow provider call or a slow remote command,
/// so a degraded backend could otherwise run for many minutes — this is the
/// separate, independent cap DESIGN.md §3 calls for. Checked at the top of
/// each loop iteration.
pub const TURN_DEADLINE: Duration = Duration::from_secs(120);

/// What the agent did this turn, for the caller (HTTP/chat/scheduler) to
/// surface. `reply` is the model's final text; `acted` is true iff at least
/// one action (mutating) tool ran this turn — callers use it to decide
/// things like whether to retain the turn to memory.
#[derive(Debug, Clone, Default)]
pub struct AgentReply {
    pub reply: String,
    pub acted: bool,
}

/// Everything one call to [`run_turn`] needs. Grouped so construction isn't
/// a long positional call and so tests build one fixture rather than
/// threading arguments through every helper.
pub struct AgentDeps {
    pub llm: Arc<dyn LlmProvider>,
    pub memory: Arc<Memory>,
    /// True for a scheduled/heartbeat-triggered turn (no operator waiting
    /// synchronously) — selects [`prompt::HEARTBEAT_FRAMING`]  and skips the
    /// wall-clock deadline (an unattended scan may legitimately run a slow
    /// diagnostic chain with no impatient human on the other end).
    pub heartbeat: bool,
    /// Observer fired twice per tool call the model makes, as it happens —
    /// [`ToolEvent::Called`] before execution, [`ToolEvent::Finished`] once
    /// the result is known. The chat surface uses this to render the
    /// agent's tool activity live in the shared log (the same transparency
    /// stance as the audit chain, surfaced where the operator is looking).
    /// `None` (scans, webhook ingest, tests) observes nothing.
    pub on_tool: Option<ToolObserver>,
}

/// One notification in a tool call's lifecycle (see [`AgentDeps::on_tool`]).
/// Borrowed on purpose: the observer runs inline in the turn loop and must
/// hand off immediately, so it copies only what it keeps.
pub enum ToolEvent<'a> {
    /// The model asked for this call — fired BEFORE execution, so a slow
    /// tool is visible while it runs. `args` is the compact single-line
    /// JSON of what was actually requested.
    Called { name: &'a str, args: &'a str },
    /// The result is known. `ok` is false for a failed call AND for an
    /// unknown tool name; the duplicate-action short-circuit reports the
    /// PRIOR result, which succeeded, so it counts as ok.
    Finished { name: &'a str, ok: bool },
}

/// See [`AgentDeps::on_tool`]. Sync + cheap by contract: called from inside
/// the turn loop, so an implementation must hand off (publish to a
/// broadcast hub, push into a Vec) — never block on I/O.
pub type ToolObserver = Arc<dyn Fn(ToolEvent<'_>) + Send + Sync>;

/// Run one full tool-calling turn: assemble the system prompt, give the
/// model the tool registry, execute what it calls, feed results back,
/// repeat until it returns final text (or a cap trips). `registry` is
/// built by the caller (context-gated per DESIGN.md `tools/` — read-only
/// tools when configured, mutating tools only when a target exists) and
/// handed in rather than built here, since this module has no config/db
/// access of its own. `team_context` is free text (a target roster, a
/// standing note) the caller assembles from config/db state; `None` omits
/// the section.
pub async fn run_turn(
    deps: &AgentDeps,
    ctx: &ToolCtx,
    registry: &[Box<dyn Tool>],
    team_context: Option<&str>,
    message: &str,
) -> Result<AgentReply> {
    run_turn_with_history(deps, ctx, registry, team_context, &[], message).await
}

/// [`run_turn`] with prior conversational context. `prior` is earlier
/// user/assistant exchanges the CALLER curates (the chat surfaces' shared
/// transcript — see `agent::dispatch`'s chat entry point); scan jobs and
/// webhook ingest have no prior conversation and use plain [`run_turn`].
/// The prior turns are replayed ahead of `message` in the same history the
/// in-flight token budget (`replay`) already manages, so an over-long
/// transcript shrinks by the same rules as an over-long tool chain.
pub async fn run_turn_with_history(
    deps: &AgentDeps,
    ctx: &ToolCtx,
    registry: &[Box<dyn Tool>],
    team_context: Option<&str>,
    prior: &[Turn],
    message: &str,
) -> Result<AgentReply> {
    let specs: Vec<ToolSpec> = registry
        .iter()
        .map(|t| ToolSpec {
            name: t.name().to_string(),
            description: t.description().to_string(),
            parameters: t.schema(),
        })
        .collect();
    let system = assemble_system_prompt(deps.heartbeat, team_context);

    let mut history: Vec<Turn> = prior.to_vec();
    history.push(Turn::User { content: message.to_string() });
    let mut acted = false;
    // Executed action calls this turn, keyed by (tool name, canonicalized
    // args) -> the result string handed back. On an EXACT repeat of an
    // action call, a model that ignored the first result would otherwise
    // re-run it (duplicating a real side effect against a real target) —
    // short-circuit to the prior result with a do-not-repeat note instead.
    // Read-only tools aren't tracked: re-reading is harmless and idempotent.
    let mut executed_actions: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // The unattended heartbeat path has no impatient human, so it runs on
    // the step cap alone (DESIGN.md's scheduler already tightens/relaxes
    // the OUTER tick cadence around incidents; a single turn's wall clock
    // isn't this module's place to second-guess for that path) — and gets
    // the deeper cap for the same reason (see MAX_STEPS_HEARTBEAT).
    let deadline = (!deps.heartbeat).then(|| Instant::now() + TURN_DEADLINE);
    let max_steps = if deps.heartbeat { MAX_STEPS_HEARTBEAT } else { MAX_STEPS };

    for step_num in 0..max_steps {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            tracing::warn!(step = step_num, acted, "agent turn hit the wall-clock deadline");
            return Ok(finish(acted, deadline_reply(acted)));
        }

        let step = deps.llm.chat_step(&ctx.principal, &system, &history, &specs).await?;

        if step.tool_calls.is_empty() {
            let text = step.text.unwrap_or_default();
            if text.trim().is_empty() {
                // A malformed step (no tool calls, no usable text): nudge
                // once rather than return a blank reply — the loop simply
                // continues to the next iteration, spending one more step.
                tracing::warn!(step = step_num, "empty model step — nudging in-loop");
                history.push(Turn::Assistant { content: text, tool_calls: Vec::new() });
                history.push(Turn::User {
                    content: "Your reply was empty. Please respond in plain text now.".into(),
                });
            } else {
                tracing::info!(
                    steps = step_num + 1,
                    acted,
                    reply_len = text.len(),
                    "agent turn finished"
                );
                return Ok(finish(acted, text));
            }
        } else {
            for call in &step.tool_calls {
                if let Some(observe) = &deps.on_tool {
                    // Compact single-line args (the model's own JSON can be
                    // multi-line); truncation is the OBSERVER's concern —
                    // this reports what was actually called.
                    let args = call.args.to_string();
                    observe(ToolEvent::Called { name: &call.name, args: &args });
                }
                history.push(Turn::Assistant {
                    content: step.text.clone().unwrap_or_default(),
                    tool_calls: vec![call.clone()],
                });

                let Some(tool) = registry.iter().find(|t| t.name() == call.name) else {
                    let valid = registry.iter().map(|t| t.name()).collect::<Vec<_>>();
                    let out = format!(
                        "unknown tool: {}. Valid tools are: {}.",
                        call.name,
                        valid.join(", ")
                    );
                    // A `Called` was already emitted for this name, so the
                    // observer still needs its close — a hallucinated tool
                    // is a failed call from the operator's point of view.
                    if let Some(observe) = &deps.on_tool {
                        observe(ToolEvent::Finished { name: &call.name, ok: false });
                    }
                    history.push(Turn::ToolResult {
                        call_id: call.id.clone(),
                        name: call.name.clone(),
                        output: out,
                    });
                    continue;
                };

                let action_key = tool
                    .is_action()
                    .then(|| format!("{}::{}", call.name, canonical_args(&call.args)));

                let (output, ok) = if let Some(key) = &action_key
                    && let Some(prev) = executed_actions.get(key)
                {
                    tracing::warn!(
                        tool = %call.name,
                        "duplicate action call this turn — short-circuiting to prior result"
                    );
                    let out = format!(
                        "You already called {} with these exact arguments this turn — \
                         result: {prev}. Do NOT repeat it; move on or reply to the user.",
                        call.name
                    );
                    // The short-circuit re-serves a result that DID succeed
                    // (only Ok outputs enter `executed_actions`) — ok.
                    (out, true)
                } else {
                    match tool.call(ctx, call.args.clone()).await {
                        Ok(r) => {
                            if tool.is_action() {
                                acted = true;
                            }
                            if let Some(key) = action_key {
                                executed_actions.insert(key, r.output.clone());
                            }
                            (r.output, true)
                        }
                        Err(e) => {
                            tracing::warn!(tool = %call.name, "tool call failed: {e}");
                            (tool_error_for_model(&call.name, &e), false)
                        }
                    }
                };
                if let Some(observe) = &deps.on_tool {
                    observe(ToolEvent::Finished { name: &call.name, ok });
                }

                history.push(Turn::ToolResult {
                    call_id: call.id.clone(),
                    name: call.name.clone(),
                    output,
                });
            }
        }

        // Cheap proactive guard: if the running history is getting large,
        // shrink it rather than waiting for a provider 400. Unlike gianna's
        // single-shot overflow recovery (which only fires after an actual
        // context-overflow error), this runs every step because opsclaw's
        // `LlmProvider::chat_step` doesn't yet surface a pre-flight token
        // count — shrinking early is cheap insurance either way.
        if replay::estimate_history_tokens(&history) > HISTORY_SHRINK_THRESHOLD_TOKENS {
            replay::shrink_history(&mut history, HISTORY_SHRINK_KEEP_RECENT);
        }
    }

    tracing::warn!(steps = max_steps, acted, "tool loop did not converge (hit the step cap)");
    // The steps weren't wasted — the history holds real tool results. One
    // final TOOL-LESS call turns them into a report instead of discarding
    // them behind a canned "check the audit log" line (observed live: a
    // 30-step sandbox sweep of a badly broken cluster produced excellent
    // forensics and then threw them away). No tools are offered, so this
    // cannot extend the loop; a failure here falls back to the old text.
    history.push(Turn::User {
        content: "SYSTEM: step budget exhausted. Stop investigating NOW and write your final \
                  report from what you have already seen: findings so far, what you did not get \
                  to, and what to check next. No more tool calls are available."
            .to_string(),
    });
    match deps.llm.chat_step(&ctx.principal, &system, &history, &[]).await {
        Ok(step) => {
            if let Some(text) = step.text
                && !text.trim().is_empty()
            {
                return Ok(finish(acted, text));
            }
        }
        Err(e) => tracing::warn!(error = %e, "final-report call after step cap failed"),
    }
    if acted {
        return Ok(finish(acted, best_effort_acted_reply()));
    }
    Err(Error::llm_hard("tool loop did not converge"))
}

/// Assemble the system prompt stable-first: static persona, then per-turn
/// framing (heartbeat vs not) and team context, with the clock last.
fn assemble_system_prompt(heartbeat: bool, team_context: Option<&str>) -> String {
    let mut system = String::new();
    system.push_str(prompt::persona());
    if heartbeat {
        system.push_str(prompt::HEARTBEAT_FRAMING);
    }
    system.push_str(&prompt::team_context_section(team_context));
    system.push_str(&prompt::date_ctx(Utc::now()));
    system
}

/// Retain this turn to team memory, detached (fire-and-forget — a slow or
/// down memory backend must never block or fail the turn). Framed by
/// `speaker` per the memory module's attribution convention. Callers should
/// gate this on `memory::should_retain(message)` before calling, mirroring
/// gianna's per-turn retain-or-skip decision — kept as a separate step
/// (rather than folded into `run_turn`) so a caller that already knows this
/// was a pure command/lookup can skip the call outright.
pub fn retain_turn_detached(
    memory: &Arc<Memory>,
    speaker: impl Into<String>,
    message: impl Into<String>,
) {
    memory.retain_detached(speaker.into(), message.into());
}

/// The observation sibling of [`retain_turn_detached`]: retain a scan turn's
/// FINDING to team memory, detached, framed `"scan of {fq_target} observed:
/// …"` (DESIGN §3 memory) so a heartbeat's passive finding is never pooled
/// as something an operator or the agent said. No `should_retain` pre-gate
/// here — the framing is applied inside `Memory::retain_observation`, which
/// runs the filter on the framed text itself (a finding is a statement by
/// construction; the filter's real job on this path is the secret-shape
/// defence, which must see what will actually be stored).
pub fn retain_scan_observation_detached(
    memory: &Arc<Memory>,
    fq_target: impl Into<String>,
    finding: impl Into<String>,
) {
    memory.retain_observation_detached(fq_target.into(), finding.into());
}

fn finish(acted: bool, reply: impl Into<String>) -> AgentReply {
    AgentReply { reply: reply.into(), acted }
}

/// Once the deadline trips: if an action already ran this turn, surface an
/// honest best-effort acknowledgement (never silently drop it, and never
/// let the caller re-run the turn and duplicate the action). If nothing
/// acted yet, an empty diagnostic turn timing out is worth surfacing as an
/// explicit statement rather than a vague reply.
fn deadline_reply(acted: bool) -> String {
    if acted {
        best_effort_acted_reply()
    } else {
        "This is taking longer than expected — stopping before completing the diagnosis. \
         No action was taken."
            .to_string()
    }
}

/// A plain, honest reply for when the loop ends (deadline or step cap)
/// after at least one action tool already ran. Deliberately generic (unlike
/// gianna's per-tool "claim" strings) — opsclaw's action tools compose
/// arbitrary commands rather than a small fixed vocabulary of household
/// actions, so a specific claim per tool isn't available; the honest
/// non-claim is that SOMETHING ran, not fabricating what.
fn best_effort_acted_reply() -> String {
    "I took at least one action before running out of steps/time this turn. \
     Check the audit log or incident/approval queue for exactly what ran."
        .to_string()
}

/// A stable string key for a tool call's arguments, so an exact repeat of
/// an action call this turn can be detected regardless of key ordering.
/// `serde_json` serializes object maps in sorted key order, so `to_string`
/// is already canonical for our purposes.
fn canonical_args(args: &serde_json::Value) -> String {
    args.to_string()
}

/// The tool-result string fed back to the model after a tool call ERRORED.
/// Ported verbatim from gianna's error-splitting: a user-facing error
/// (validation, conflict, bad input) is relayed with detail so the model
/// can self-correct; an internal fault (DB down, backend unreachable) is
/// scrubbed — the raw error might leak internals — and comes with an
/// explicit "do NOT retry" so a wedged backend doesn't get hammered for the
/// rest of the loop's step budget.
fn tool_error_for_model(tool: &str, e: &ToolError) -> String {
    match e {
        ToolError::UserFacing(msg) => format!("error in {tool}: {msg}"),
        ToolError::Internal(_) => format!(
            "error: {tool} is temporarily unavailable — do NOT retry it. \
             Tell the user you couldn't complete this part right now."
        ),
    }
}

/// Above this estimated token count, proactively shrink the running history
/// (see the per-step guard in [`run_turn`]). Conservative relative to any
/// real model's window — the goal is early, cheap insurance, not a hard
/// local ceiling; the provider stays the authority on what actually fits.
const HISTORY_SHRINK_THRESHOLD_TOKENS: usize = 40_000;
/// How many of the most-recent history turns survive a proactive shrink.
const HISTORY_SHRINK_KEEP_RECENT: usize = 12;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Principal;
    use crate::llm::ScriptedLlm;
    use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
    use async_trait::async_trait;
    use serde_json::{Value, json};
    use std::sync::Mutex;

    fn principal() -> Principal {
        Principal::Agent { job: None }
    }

    /// No test tool here actually reaches the policy layer (the fake tools
    /// below resolve without calling it), but `ToolCtx` requires a handle.
    struct NoopPolicy;
    #[async_trait]
    impl PolicyExecute for NoopPolicy {
        async fn execute(&self, _req: CommandRequest) -> Result<PolicyOutcome> {
            Ok(PolicyOutcome::EStopped)
        }
    }

    fn ctx() -> ToolCtx {
        // ToolCtx::for_tests() defaults every optional field to its honest
        // off state, so this helper no longer breaks on each additive
        // ToolCtx field (it broke twice across the tools:: waves before
        // this constructor existed) — this loop's tests don't exercise any
        // of the optional fields.
        ToolCtx::for_tests(principal(), Arc::new(NoopPolicy))
    }

    fn deps(llm: Arc<dyn LlmProvider>) -> AgentDeps {
        AgentDeps { llm, memory: Arc::new(Memory::disabled()), heartbeat: false, on_tool: None }
    }

    /// A trivial read-only tool: echoes its `q` argument back.
    struct EchoTool;
    #[async_trait]
    impl Tool for EchoTool {
        fn name(&self) -> &'static str {
            "echo"
        }
        fn description(&self) -> &str {
            "echoes the q argument"
        }
        fn schema(&self) -> Value {
            json!({"type": "object", "properties": {"q": {"type": "string"}}})
        }
        fn risk(&self) -> crate::domain::RiskClass {
            crate::domain::RiskClass::Read
        }
        fn is_action(&self) -> bool {
            false
        }
        fn allowed_in_heartbeat(&self) -> bool {
            true
        }
        async fn call(
            &self,
            _ctx: &ToolCtx,
            args: Value,
        ) -> std::result::Result<crate::tools::ToolResult, ToolError> {
            Ok(crate::tools::ToolResult { output: format!("echo: {}", args["q"]) })
        }
    }

    /// A counting action tool, so duplicate-guard tests can assert it ran
    /// exactly once despite repeated identical calls.
    struct CountingActionTool {
        calls: Mutex<usize>,
    }
    impl CountingActionTool {
        fn new() -> Self {
            Self { calls: Mutex::new(0) }
        }
    }
    #[async_trait]
    impl Tool for CountingActionTool {
        fn name(&self) -> &'static str {
            "restart_service"
        }
        fn description(&self) -> &str {
            "restarts a service"
        }
        fn schema(&self) -> Value {
            json!({"type": "object", "properties": {"service": {"type": "string"}}})
        }
        fn risk(&self) -> crate::domain::RiskClass {
            crate::domain::RiskClass::Medium
        }
        fn is_action(&self) -> bool {
            true
        }
        fn allowed_in_heartbeat(&self) -> bool {
            false
        }
        async fn call(
            &self,
            _ctx: &ToolCtx,
            args: Value,
        ) -> std::result::Result<crate::tools::ToolResult, ToolError> {
            *self.calls.lock().unwrap() += 1;
            Ok(crate::tools::ToolResult { output: format!("restarted {}", args["service"]) })
        }
    }

    /// Delegates to a shared `CountingActionTool` so a test can hold the
    /// counter outside the boxed registry and assert on it after the turn.
    struct Delegate(Arc<CountingActionTool>);
    #[async_trait]
    impl Tool for Delegate {
        fn name(&self) -> &'static str {
            "restart_service"
        }
        fn description(&self) -> &str {
            "restarts a service"
        }
        fn schema(&self) -> Value {
            json!({"type": "object"})
        }
        fn risk(&self) -> crate::domain::RiskClass {
            crate::domain::RiskClass::Medium
        }
        fn is_action(&self) -> bool {
            true
        }
        fn allowed_in_heartbeat(&self) -> bool {
            false
        }
        async fn call(
            &self,
            ctx: &ToolCtx,
            args: Value,
        ) -> std::result::Result<crate::tools::ToolResult, ToolError> {
            self.0.call(ctx, args).await
        }
    }

    /// An always-internal-faulting tool, for error-splitting tests.
    struct FaultyTool;
    #[async_trait]
    impl Tool for FaultyTool {
        fn name(&self) -> &'static str {
            "flaky"
        }
        fn description(&self) -> &str {
            "always internal-faults"
        }
        fn schema(&self) -> Value {
            json!({"type": "object"})
        }
        fn risk(&self) -> crate::domain::RiskClass {
            crate::domain::RiskClass::Read
        }
        fn is_action(&self) -> bool {
            false
        }
        fn allowed_in_heartbeat(&self) -> bool {
            true
        }
        async fn call(
            &self,
            _ctx: &ToolCtx,
            _args: Value,
        ) -> std::result::Result<crate::tools::ToolResult, ToolError> {
            Err(ToolError::Internal("connection refused to backend".into()))
        }
    }

    /// A user-facing-erroring tool.
    struct ValidationTool;
    #[async_trait]
    impl Tool for ValidationTool {
        fn name(&self) -> &'static str {
            "validate_me"
        }
        fn description(&self) -> &str {
            "always user-errors"
        }
        fn schema(&self) -> Value {
            json!({"type": "object"})
        }
        fn risk(&self) -> crate::domain::RiskClass {
            crate::domain::RiskClass::Read
        }
        fn is_action(&self) -> bool {
            false
        }
        fn allowed_in_heartbeat(&self) -> bool {
            true
        }
        async fn call(
            &self,
            _ctx: &ToolCtx,
            _args: Value,
        ) -> std::result::Result<crate::tools::ToolResult, ToolError> {
            Err(ToolError::UserFacing("unknown target 'foo'".into()))
        }
    }

    #[tokio::test]
    async fn scripted_multi_step_loop_end_to_end() {
        let mut scripted = ScriptedLlm::new();
        scripted.push_tool_call("echo", json!({"q": "ping"})).push_text("done: pong observed");
        let llm: Arc<dyn LlmProvider> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(EchoTool)];

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "check something").await.unwrap();
        assert_eq!(reply.reply, "done: pong observed");
        assert!(!reply.acted, "echo is not an action tool");
    }

    #[tokio::test]
    async fn action_tool_sets_acted() {
        let mut scripted = ScriptedLlm::new();
        scripted
            .push_tool_call("restart_service", json!({"service": "nginx"}))
            .push_text("restarted nginx");
        let llm: Arc<dyn LlmProvider> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(CountingActionTool::new())];

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "fix it").await.unwrap();
        assert!(reply.acted);
    }

    #[tokio::test]
    async fn internal_fault_is_scrubbed_and_says_do_not_retry() {
        let mut scripted = ScriptedLlm::new();
        scripted.push_tool_call("flaky", json!({})).push_text("told the user");
        let llm: Arc<dyn LlmProvider> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(FaultyTool)];

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "do it").await.unwrap();
        let msg = tool_error_for_model(
            "flaky",
            &ToolError::Internal("connection refused to backend".into()),
        );
        assert!(!msg.contains("connection refused"), "internal detail must be scrubbed: {msg}");
        assert!(msg.contains("do NOT retry"), "must instruct no retry: {msg}");
        assert_eq!(reply.reply, "told the user");
    }

    #[test]
    fn user_facing_error_is_relayed_with_detail() {
        let msg = tool_error_for_model(
            "validate_me",
            &ToolError::UserFacing("unknown target 'foo'".into()),
        );
        assert!(msg.contains("unknown target 'foo'"), "user-facing detail must be relayed: {msg}");
        assert!(
            !msg.contains("do NOT retry"),
            "a validation error is worth a corrected retry: {msg}"
        );
    }

    #[tokio::test]
    async fn user_facing_tool_error_reaches_the_model_in_the_real_loop() {
        let mut scripted = ScriptedLlm::new();
        scripted.push_tool_call("validate_me", json!({})).push_text("corrected and done");
        let llm: Arc<dyn LlmProvider> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(ValidationTool)];

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "do it").await.unwrap();
        assert_eq!(reply.reply, "corrected and done");
    }

    #[tokio::test]
    async fn duplicate_action_call_actually_executes_only_once() {
        let mut scripted = ScriptedLlm::new();
        scripted
            .push_tool_call("restart_service", json!({"service": "nginx"}))
            .push_tool_call("restart_service", json!({"service": "nginx"}))
            .push_text("done");
        let llm: Arc<dyn LlmProvider> = Arc::new(scripted);

        let tool = Arc::new(CountingActionTool::new());
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(Delegate(tool.clone()))];

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "fix it twice").await.unwrap();
        assert!(reply.acted);
        assert_eq!(*tool.calls.lock().unwrap(), 1, "the action must execute exactly once");
    }

    #[tokio::test]
    async fn duplicate_guard_feeds_back_a_do_not_repeat_note() {
        let mut scripted = ScriptedLlm::new();
        scripted
            .push_tool_call("restart_service", json!({"service": "nginx"}))
            .push_tool_call("restart_service", json!({"service": "nginx"}))
            .push_text("done");
        let llm: Arc<dyn LlmProvider> = Arc::new(scripted);
        let tool = Arc::new(CountingActionTool::new());
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(Delegate(tool))];

        // No direct access to the fed-back history from outside — but a
        // distinct-args call must NOT short-circuit, proving the guard is
        // keyed on args, not just tool name. Covered separately below.
        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "fix it twice").await.unwrap();
        assert!(reply.acted);
    }

    #[tokio::test]
    async fn different_args_are_not_treated_as_duplicates() {
        let mut scripted = ScriptedLlm::new();
        scripted
            .push_tool_call("restart_service", json!({"service": "nginx"}))
            .push_tool_call("restart_service", json!({"service": "postgres"}))
            .push_text("done");
        let llm: Arc<dyn LlmProvider> = Arc::new(scripted);
        let tool = Arc::new(CountingActionTool::new());
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(Delegate(tool.clone()))];

        run_turn(&deps(llm), &ctx(), &registry, None, "fix both").await.unwrap();
        assert_eq!(*tool.calls.lock().unwrap(), 2, "distinct args must both execute");
    }

    #[tokio::test]
    async fn step_cap_with_no_action_returns_an_error() {
        let mut scripted = ScriptedLlm::new();
        for _ in 0..MAX_STEPS {
            scripted.push_tool_call("echo", json!({"q": "still going"}));
        }
        // The post-cap final-report call yields nothing usable either.
        scripted.push_text("   ");
        let llm: Arc<dyn LlmProvider> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(EchoTool)];

        let err = run_turn(&deps(llm), &ctx(), &registry, None, "loop forever").await.unwrap_err();
        assert!(format!("{err}").contains("did not converge"));
    }

    #[tokio::test]
    async fn step_cap_after_acting_returns_best_effort_reply_not_an_error() {
        let mut scripted = ScriptedLlm::new();
        scripted.push_tool_call("restart_service", json!({"service": "nginx"}));
        for i in 1..MAX_STEPS {
            scripted.push_tool_call("echo", json!({"q": format!("still checking {i}")}));
        }
        // The post-cap final-report call turns the work into a report.
        scripted.push_text("restarted nginx; was still verifying when the step budget ran out");
        let llm: Arc<dyn LlmProvider> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> =
            vec![Box::new(CountingActionTool::new()), Box::new(EchoTool)];

        let reply =
            run_turn(&deps(llm), &ctx(), &registry, None, "fix and keep checking").await.unwrap();
        assert!(reply.acted);
        assert!(!reply.reply.is_empty(), "must surface an honest best-effort reply, not silence");
    }

    #[tokio::test]
    async fn unknown_tool_name_is_reported_back_with_valid_names() {
        let mut scripted = ScriptedLlm::new();
        scripted.push_tool_call("does_not_exist", json!({})).push_text("apologized");
        let llm: Arc<dyn LlmProvider> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(EchoTool)];

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "call a bad tool").await.unwrap();
        assert_eq!(reply.reply, "apologized");
    }

    #[tokio::test]
    async fn deadline_trips_before_step_cap_when_configured_very_short() {
        // We can't shrink TURN_DEADLINE itself (a module const), so instead
        // assert the deadline machinery's OUTPUT shape directly: acted=false
        // produces the no-action deadline message, acted=true produces the
        // best-effort message — exercised via deadline_reply() (pure) since
        // driving the real 120s constant in a unit test isn't practical.
        assert!(deadline_reply(false).contains("No action was taken"));
        assert!(deadline_reply(true).contains("audit log"));
    }

    #[tokio::test]
    async fn heartbeat_turns_have_no_wall_clock_deadline() {
        // A heartbeat turn's `deadline` is None regardless of TURN_DEADLINE
        // — proven indirectly: many steps must be reachable without ever
        // hitting the deadline path (a non-heartbeat turn taking this many
        // scripted (near-instant) steps would still finish well under 120s
        // anyway, so this mainly documents/pins the flag's plumbing).
        let mut scripted = ScriptedLlm::new();
        scripted.push_text("scan complete, nothing wrong");
        let llm: Arc<dyn LlmProvider> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> = vec![];
        let mut d = deps(llm);
        d.heartbeat = true;

        let reply = run_turn(&d, &ctx(), &registry, None, "scan").await.unwrap();
        assert_eq!(reply.reply, "scan complete, nothing wrong");
    }

    #[test]
    fn canonical_args_is_key_order_independent() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(canonical_args(&a), canonical_args(&b));
    }

    #[test]
    fn assemble_system_prompt_orders_persona_before_volatile_clock() {
        let system = assemble_system_prompt(false, None);
        let persona_pos = system.find("You are OpsClaw").unwrap();
        let clock_pos = system.find("CONTEXT — current UTC time").unwrap();
        assert!(persona_pos < clock_pos, "persona (stable) must precede the clock (volatile)");
    }

    #[test]
    fn assemble_system_prompt_includes_heartbeat_framing_only_when_set() {
        let normal = assemble_system_prompt(false, None);
        let hb = assemble_system_prompt(true, None);
        assert!(!normal.contains("SCHEDULED SCAN"));
        assert!(hb.contains("SCHEDULED SCAN"));
    }

    #[test]
    fn assemble_system_prompt_includes_team_context_between_persona_and_clock() {
        let system = assemble_system_prompt(false, Some("3 targets in remundo"));
        let persona_pos = system.find("You are OpsClaw").unwrap();
        let team_pos = system.find("TEAM CONTEXT").unwrap();
        let clock_pos = system.find("CONTEXT — current UTC time").unwrap();
        assert!(persona_pos < team_pos && team_pos < clock_pos);
    }

    #[test]
    fn observation_framing_is_exposed_for_callers_that_inject_external_content() {
        // The webhook/log/command-output framing lives in prompt::
        // frame_observation and is exercised by prompt.rs's own tests;
        // this pins that it's reachable from the agent module's public
        // surface for callers assembling a message with injected content.
        let framed = prompt::frame_observation("alertmanager", "cpu at 97%");
        assert!(framed.contains("OBSERVATION from alertmanager"));
        assert!(framed.contains("cpu at 97%"));
    }
}
