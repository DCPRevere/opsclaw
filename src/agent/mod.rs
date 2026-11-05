//! The agent: the tool-calling loop (DESIGN.md §3 "Agent loop").
//!
//! The loop mechanics — step budget, a wall-clock deadline that also
//! abandons a slow model call, the model call itself — are `dcpr-agent`'s
//! [`dcpr_agent::run_turn`]. Every decision is OpsClaw's own, in
//! [`OpsTurn`]'s `TurnPolicy`: the system prompt, which tools are offered,
//! tool errors returned to the model as strings rather than aborting the
//! turn (split user-facing vs internal fault), a duplicate-call guard on
//! repeated identical action calls, the in-flight history budget, and the
//! final report when the budget runs out. Each tool is also a
//! `dcpr_agent::Tool` (see `tools::Ops`): arguments are checked and coerced
//! against its schema before it runs, and consecutive read-only calls in one
//! batch run concurrently while anything that may change state runs alone,
//! in order. Detached memory retention runs
//! after the turn. What's dropped: everything household/liturgy-specific (novenas,
//! setup mode, calendar, enrichment runs, images) — opsclaw's loop is a
//! single, focused SRE diagnose/act/escalate turn, not a multi-purpose
//! household assistant. `prompt` owns system-prompt text (persona,
//! observation framing, environment scepticism).
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
pub(crate) mod turn_gate;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use dcpr_agent::{Flow, StepInfo, StepRequest, TurnLimits, TurnPolicy};

use crate::llm::{Llm, ToolCall, ToolTurn};
use crate::memory::Memory;
use crate::tools::{Ops, Tool, ToolCtx, ToolError};
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
/// separate, independent cap DESIGN.md §3 calls for. No step starts after
/// it, and a model call still running at it is abandoned.
pub const TURN_DEADLINE: Duration = Duration::from_secs(120);

/// Extra time after [`TURN_DEADLINE`] for one tool-free call that turns what
/// the turn already gathered into a report, instead of discarding it.
const DEADLINE_REPORT_GRACE: Duration = Duration::from_secs(60);

/// The instruction for that report.
const DEADLINE_REPORT: &str = "SYSTEM: the time limit for this turn has been reached. Stop \
     investigating NOW and answer from what you have already seen: what you found, what you \
     did not get to, and what to check next. No more tool calls are available.";

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
    pub llm: Arc<Llm>,
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
/// compactor manages, so an over-long transcript shrinks by the same rules as
/// an over-long tool chain, and `message` itself is never dropped.
pub async fn run_turn_with_history(
    deps: &AgentDeps,
    ctx: &ToolCtx,
    registry: &[Box<dyn Tool>],
    team_context: Option<&str>,
    prior: &[ToolTurn],
    message: &str,
) -> Result<AgentReply> {
    let specs = registry
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name(),
                "description": t.description(),
                "parameters": t.schema(),
            })
        })
        .collect();
    let (system, cacheable_prefix_len) = assemble_system_prompt(deps.heartbeat, team_context);

    let mut history: Vec<ToolTurn> = prior.to_vec();
    history.push(ToolTurn::User(message.to_string()));

    // The unattended heartbeat path has no impatient human, so it runs on
    // the step cap alone (DESIGN.md's scheduler already tightens/relaxes
    // the OUTER tick cadence around incidents; a single turn's wall clock
    // isn't this module's place to second-guess for that path) — and gets
    // the deeper cap for the same reason (see MAX_STEPS_HEARTBEAT). One
    // extra step is reserved for the tool-less final report.
    let tool_steps = if deps.heartbeat { MAX_STEPS_HEARTBEAT } else { MAX_STEPS };
    let mut limits = TurnLimits::steps(tool_steps + 1);
    if !deps.heartbeat {
        limits = limits.with_timeout(TURN_DEADLINE);
    }

    let mut policy = OpsTurn {
        deps,
        ctx,
        registry,
        system,
        cacheable_prefix_len,
        specs,
        acted: false,
        executed_actions: HashMap::new(),
        // This turn's message, the last thing pushed above.
        task: Some(history.len() - 1),
    };
    dcpr_agent::run_turn(deps.llm.as_ref(), &ctx.principal, &mut policy, &mut history, limits).await
}

/// The final-step instruction once the tool budget is spent. No tools are
/// offered on that step, so it cannot extend the loop.
const STEP_BUDGET_EXHAUSTED: &str = "SYSTEM: step budget exhausted. Stop investigating NOW and \
     write your final report from what you have already seen: findings so far, what you did \
     not get to, and what to check next. No more tool calls are available.";

/// OpsClaw's decisions around each model step of one turn.
struct OpsTurn<'a> {
    deps: &'a AgentDeps,
    ctx: &'a ToolCtx,
    registry: &'a [Box<dyn Tool>],
    system: String,
    cacheable_prefix_len: usize,
    specs: Vec<serde_json::Value>,
    /// True once any action (mutating) tool succeeded this turn.
    acted: bool,
    /// Executed action calls this turn, keyed by (tool name, canonicalized
    /// args) -> the result string handed back. On an EXACT repeat of an
    /// action call, a model that ignored the first result would otherwise
    /// re-run it (duplicating a real side effect against a real target) —
    /// short-circuit to the prior result with a do-not-repeat note instead.
    /// Read-only tools aren't tracked: re-reading is harmless and idempotent.
    executed_actions: HashMap<String, String>,
    /// Where this turn's request sits in the history. Compaction never drops
    /// it, and reports where it moved.
    task: Option<usize>,
}

/// One call from a model batch: either ready to run, or already answered
/// without running (unknown tool or invalid arguments).
// `&Box<dyn Tool>`, not `&dyn Tool`: the `dcpr_agent::Tool` impl is on the
// box, which is what coerces to `&dyn dcpr_agent::Tool<Ops>` for `call_shared`.
#[allow(clippy::borrowed_box)]
enum Prepared<'r> {
    Answered { output: String, ok: bool },
    Ready { tool: &'r Box<dyn Tool>, args: serde_json::Value, read: bool },
}

impl<'a> OpsTurn<'a> {
    /// Resolve the tool and check the arguments against its schema
    /// (`dcpr-agent` coerces scalar spellings and rejects anything the schema
    /// doesn't allow), before anything runs.
    fn prepare(&self, call: &ToolCall) -> Prepared<'a> {
        let registry: &'a [Box<dyn Tool>] = self.registry;
        let Some(tool) = registry.iter().find(|t| Tool::name(t.as_ref()) == call.name) else {
            let valid = registry.iter().map(|t| Tool::name(t.as_ref())).collect::<Vec<_>>();
            // A hallucinated tool is a failed call from the operator's
            // point of view.
            return Prepared::Answered {
                output: format!(
                    "unknown tool: {}. Valid tools are: {}.",
                    call.name,
                    valid.join(", ")
                ),
                ok: false,
            };
        };
        match dcpr_agent::Tool::<Ops>::prepare_arguments(tool, without_nulls(&call.arguments)) {
            Ok(args) => {
                let read = tool.reads_only(&args);
                Prepared::Ready { tool, args, read }
            }
            Err(e) => {
                tracing::warn!(tool = %call.name, "tool arguments refused: {e}");
                Prepared::Answered {
                    output: format!(
                        "invalid arguments for {}: {e}. Correct them against the tool's schema \
                     and call it again.",
                        call.name
                    ),
                    ok: false,
                }
            }
        }
    }

    fn observe_called(&self, name: &str, args: &serde_json::Value) {
        if let Some(observe) = &self.deps.on_tool {
            // Compact single-line args (the model's own JSON can be
            // multi-line); truncation is the OBSERVER's concern — this
            // reports what was actually called.
            let args = args.to_string();
            observe(ToolEvent::Called { name, args: &args });
        }
    }

    fn observe_finished(&self, name: &str, ok: bool) {
        if let Some(observe) = &self.deps.on_tool {
            observe(ToolEvent::Finished { name, ok });
        }
    }

    /// Run one call that may change something, alone and in order.
    async fn run_action(
        &mut self,
        name: &str,
        tool: &dyn Tool,
        args: serde_json::Value,
    ) -> (String, bool) {
        let key = format!("{name}::{}", canonical_args(&args));
        if let Some(prev) = self.executed_actions.get(&key) {
            tracing::warn!(
                tool = %name,
                "duplicate action call this turn — short-circuiting to prior result"
            );
            // The short-circuit re-serves a result that DID succeed (only Ok
            // outputs enter `executed_actions`) — ok.
            return (
                format!(
                    "You already called {name} with these exact arguments this turn — result: \
                     {prev}. Do NOT repeat it; move on or reply to the user."
                ),
                true,
            );
        }
        match tool.call(self.ctx, args).await {
            Ok(r) => {
                self.acted = true;
                self.executed_actions.insert(key, r.output.clone());
                (r.output, true)
            }
            Err(e) => {
                tracing::warn!(tool = %name, "tool call failed: {e}");
                (tool_error_for_model(name, &e), false)
            }
        }
    }

    /// Run a batch of read-only calls concurrently; results keep their order.
    #[allow(clippy::borrowed_box)] // see `Prepared`
    async fn run_reads(
        &self,
        group: &[(&ToolCall, &'a Box<dyn Tool>, serde_json::Value)],
    ) -> Vec<(String, bool)> {
        for (call, _, args) in group {
            self.observe_called(&call.name, args);
        }
        let shared = group
            .iter()
            .map(|(_, tool, args)| dcpr_agent::SharedCall {
                tool: *tool as &dyn dcpr_agent::Tool<Ops>,
                ctx: self.ctx,
                arguments: args.clone(),
            })
            .collect();
        let results = dcpr_agent::call_shared(shared).await;
        group
            .iter()
            .zip(results)
            .map(|((call, _, _), result)| {
                let (output, ok) = match result {
                    Ok(r) => (r.output, true),
                    Err(e) => {
                        tracing::warn!(tool = %call.name, "tool call failed: {e}");
                        (tool_error_for_model(&call.name, &e), false)
                    }
                };
                self.observe_finished(&call.name, ok);
                (output, ok)
            })
            .collect()
    }

    /// At the deadline: one tool-free call, bounded by
    /// [`DEADLINE_REPORT_GRACE`], that reports from the tool results already
    /// in `history`. `None` when nothing was gathered or the call fails, so
    /// the caller falls back to the fixed reply.
    async fn report_from_gathered(&self, history: &mut Vec<ToolTurn>) -> Option<String> {
        if !history.iter().any(|t| matches!(t, ToolTurn::ToolResults(_))) {
            return None;
        }
        history.push(ToolTurn::User(DEADLINE_REPORT.to_string()));
        let system = crate::llm::SystemPrompt::with_cacheable_prefix(
            &self.system,
            self.cacheable_prefix_len,
        );
        let call = self.deps.llm.chat_step(&self.ctx.principal, system, history, &[]);
        match tokio::time::timeout(DEADLINE_REPORT_GRACE, call).await {
            Ok(Ok(crate::llm::ChatStep::Text(text))) if !text.trim().is_empty() => Some(text),
            Ok(Ok(_)) => None,
            Ok(Err(e)) => {
                tracing::warn!("deadline report call failed: {e}");
                None
            }
            Err(_) => {
                tracing::warn!("deadline report call ran out of time");
                None
            }
        }
    }

    /// The turn ends without a usable final report: if an action already
    /// ran, an honest best-effort reply (never let the caller re-run the
    /// turn and duplicate the action); otherwise the turn failed.
    fn unconverged(&self) -> Result<AgentReply> {
        tracing::warn!(acted = self.acted, "tool loop did not converge (hit the step cap)");
        if self.acted {
            Ok(finish(true, best_effort_acted_reply()))
        } else {
            Err(Error::llm_hard("tool loop did not converge"))
        }
    }
}

#[async_trait]
impl<'a> TurnPolicy<crate::domain::Principal> for OpsTurn<'a> {
    type Output = AgentReply;
    type Error = Error;

    async fn prepare_step(
        &mut self,
        step: StepInfo,
        history: &mut Vec<ToolTurn>,
    ) -> Result<StepRequest> {
        // Cheap proactive guard: if the running history is getting large,
        // compact it rather than waiting for a provider 400. The task stays
        // pinned, recent exchanges stay verbatim, and older ones become
        // evidence notes rather than vanishing.
        let report = dcpr_agent::HistoryCompactor::new(HISTORY_BUDGET_TOKENS)
            .keep_recent_exchanges(HISTORY_KEEP_RECENT_EXCHANGES)
            .compact(history, self.task);
        if report.changed() {
            tracing::info!(
                tokens_before = report.tokens_before,
                tokens_after = report.tokens_after,
                folded_exchanges = report.folded_exchanges,
                digested_turns = report.digested_turns,
                "compacted the turn's history"
            );
            self.task = report.task_index;
        }
        // The tool budget is spent. The steps weren't wasted — the history
        // holds real tool results — so the last step turns them into a
        // report instead of discarding them behind a canned "check the
        // audit log" line (observed live: a 30-step sandbox sweep of a badly
        // broken cluster produced excellent forensics and then threw them
        // away).
        let tools = if step.is_last() {
            history.push(ToolTurn::User(STEP_BUDGET_EXHAUSTED.to_string()));
            Vec::new()
        } else {
            self.specs.clone()
        };
        let mut request = StepRequest::new(self.system.clone(), tools);
        request.cacheable_prefix_len = self.cacheable_prefix_len;
        Ok(request)
    }

    async fn on_text(
        &mut self,
        step: StepInfo,
        text: String,
        history: &mut Vec<ToolTurn>,
    ) -> Result<Flow<AgentReply>> {
        if !text.trim().is_empty() {
            tracing::info!(
                steps = step.number(),
                acted = self.acted,
                reply_len = text.len(),
                "agent turn finished"
            );
            return Ok(Flow::Finish(finish(self.acted, text)));
        }
        if step.is_last() {
            return self.unconverged().map(Flow::Finish);
        }
        // A malformed step (no tool calls, no usable text): nudge rather
        // than return a blank reply — the loop continues to the next step.
        tracing::warn!(step = step.number(), "empty model step — nudging in-loop");
        history
            .push(ToolTurn::User("Your reply was empty. Please respond in plain text now.".into()));
        Ok(Flow::Continue)
    }

    async fn on_tool_calls(
        &mut self,
        step: StepInfo,
        calls: Vec<ToolCall>,
        history: &mut Vec<ToolTurn>,
    ) -> Result<Flow<AgentReply>> {
        if step.is_last() {
            // No tools were offered on the report step; nothing may run.
            return self.unconverged().map(Flow::Finish);
        }
        // Consecutive read-only calls run together; a call that may change
        // something runs alone, so later calls see its effect.
        let mut outputs = Vec::with_capacity(calls.len());
        let prepared: Vec<(Prepared<'a>, &ToolCall)> =
            calls.iter().map(|call| (self.prepare(call), call)).collect();
        let mut pending = prepared.into_iter().peekable();
        while let Some((prepared, call)) = pending.next() {
            match prepared {
                Prepared::Answered { output, ok } => {
                    self.observe_called(&call.name, &call.arguments);
                    self.observe_finished(&call.name, ok);
                    outputs.push(output);
                }
                Prepared::Ready { tool, args, read: false } => {
                    self.observe_called(&call.name, &args);
                    let (output, ok) = self.run_action(&call.name, tool.as_ref(), args).await;
                    self.observe_finished(&call.name, ok);
                    outputs.push(output);
                }
                Prepared::Ready { tool, args, read: true } => {
                    let mut group = vec![(call, tool, args)];
                    while matches!(pending.peek(), Some((Prepared::Ready { read: true, .. }, _))) {
                        if let Some((Prepared::Ready { tool, args, .. }, call)) = pending.next() {
                            group.push((call, tool, args));
                        }
                    }
                    outputs.extend(self.run_reads(&group).await.into_iter().map(|(o, _)| o));
                }
            }
        }
        let results = calls
            .iter()
            .map(|call| call.id.clone())
            .zip(
                outputs
                    .into_iter()
                    .map(|o| dcpr_agent::cap_output(&o, TOOL_OUTPUT_CHARS).into_owned()),
            )
            .collect();
        history.push(ToolTurn::AssistantToolCalls(calls));
        history.push(ToolTurn::ToolResults(results));
        Ok(Flow::Continue)
    }

    async fn on_model_error(
        &mut self,
        step: StepInfo,
        error: dcpr_llm::Error,
        _history: &mut Vec<ToolTurn>,
    ) -> Result<Flow<AgentReply>> {
        if step.is_last() {
            tracing::warn!(error = %error, "final-report call after step cap failed");
            return self.unconverged().map(Flow::Finish);
        }
        Err(error.into())
    }

    async fn on_deadline(
        &mut self,
        step: StepInfo,
        history: &mut Vec<ToolTurn>,
    ) -> Result<AgentReply> {
        tracing::warn!(
            step = step.number(),
            acted = self.acted,
            "agent turn hit the wall-clock deadline"
        );
        let report = self.report_from_gathered(history).await;
        Ok(finish(self.acted, report.unwrap_or_else(|| deadline_reply(self.acted))))
    }

    async fn on_step_limit(&mut self, _history: &mut Vec<ToolTurn>) -> Result<AgentReply> {
        self.unconverged()
    }
}

/// Assemble the system prompt stable-first: static persona, then per-turn
/// framing (heartbeat vs not) and team context, with the clock last.
/// Returns the prompt and the length of its stable prefix (everything
/// before the clock), which providers may cache.
fn assemble_system_prompt(heartbeat: bool, team_context: Option<&str>) -> (String, usize) {
    let mut system = String::new();
    system.push_str(prompt::persona());
    if heartbeat {
        system.push_str(prompt::HEARTBEAT_FRAMING);
    }
    system.push_str(&prompt::team_context_section(team_context));
    let stable_len = system.len();
    system.push_str(&prompt::date_ctx(Utc::now()));
    (system, stable_len)
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
/// `args` without top-level `null`s. Models (OpenAI's especially) send
/// `null` for an optional field they aren't using; it means "not given", and
/// a schema check would otherwise refuse it as the wrong type. A required
/// field sent as `null` is then reported as missing.
fn without_nulls(args: &serde_json::Value) -> serde_json::Value {
    match args {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), v.clone())).collect(),
        ),
        other => other.clone(),
    }
}

fn canonical_args(args: &serde_json::Value) -> String {
    // Sort keys explicitly: serde_json's `preserve_order` is on in this
    // build (cedar-policy enables it), so a map keeps insertion order.
    fn sorted(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                serde_json::Value::Object(
                    keys.into_iter().map(|k| (k.clone(), sorted(&m[k]))).collect(),
                )
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    sorted(args).to_string()
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

/// Above this estimated token count, compact the running history (see
/// `prepare_step`). Conservative relative to any real model's window: early,
/// cheap insurance, not a hard local ceiling. The provider stays the
/// authority on what actually fits.
const HISTORY_BUDGET_TOKENS: usize = 40_000;
/// Tool exchanges (a call batch and its results) kept verbatim by compaction.
const HISTORY_KEEP_RECENT_EXCHANGES: usize = 3;
/// Each tool output is cut to its start and end above this many characters
/// as it comes back, so one `kubectl get pods -A` can't fill the context.
const TOOL_OUTPUT_CHARS: usize = dcpr_agent::DEFAULT_TOOL_OUTPUT_CHARS;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Principal;
    use crate::llm::ScriptedModel;
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

    fn deps(llm: Arc<Llm>) -> AgentDeps {
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
            self.0.schema()
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
        let mut scripted = ScriptedModel::new();
        scripted.push_tool_call("echo", json!({"q": "ping"})).push_text("done: pong observed");
        let llm: Arc<Llm> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(EchoTool)];

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "check something").await.unwrap();
        assert_eq!(reply.reply, "done: pong observed");
        assert!(!reply.acted, "echo is not an action tool");
    }

    #[tokio::test]
    async fn action_tool_sets_acted() {
        let mut scripted = ScriptedModel::new();
        scripted
            .push_tool_call("restart_service", json!({"service": "nginx"}))
            .push_text("restarted nginx");
        let llm: Arc<Llm> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(CountingActionTool::new())];

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "fix it").await.unwrap();
        assert!(reply.acted);
    }

    #[tokio::test]
    async fn internal_fault_is_scrubbed_and_says_do_not_retry() {
        let mut scripted = ScriptedModel::new();
        scripted.push_tool_call("flaky", json!({})).push_text("told the user");
        let llm: Arc<Llm> = Arc::new(scripted);
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
        let mut scripted = ScriptedModel::new();
        scripted.push_tool_call("validate_me", json!({})).push_text("corrected and done");
        let llm: Arc<Llm> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(ValidationTool)];

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "do it").await.unwrap();
        assert_eq!(reply.reply, "corrected and done");
    }

    #[tokio::test]
    async fn duplicate_action_call_actually_executes_only_once() {
        let mut scripted = ScriptedModel::new();
        scripted
            .push_tool_call("restart_service", json!({"service": "nginx"}))
            .push_tool_call("restart_service", json!({"service": "nginx"}))
            .push_text("done");
        let llm: Arc<Llm> = Arc::new(scripted);

        let tool = Arc::new(CountingActionTool::new());
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(Delegate(tool.clone()))];

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "fix it twice").await.unwrap();
        assert!(reply.acted);
        assert_eq!(*tool.calls.lock().unwrap(), 1, "the action must execute exactly once");
    }

    #[tokio::test]
    async fn duplicate_guard_feeds_back_a_do_not_repeat_note() {
        let mut scripted = ScriptedModel::new();
        scripted
            .push_tool_call("restart_service", json!({"service": "nginx"}))
            .push_tool_call("restart_service", json!({"service": "nginx"}))
            .push_text("done");
        let llm: Arc<Llm> = Arc::new(scripted);
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
        let mut scripted = ScriptedModel::new();
        scripted
            .push_tool_call("restart_service", json!({"service": "nginx"}))
            .push_tool_call("restart_service", json!({"service": "postgres"}))
            .push_text("done");
        let llm: Arc<Llm> = Arc::new(scripted);
        let tool = Arc::new(CountingActionTool::new());
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(Delegate(tool.clone()))];

        run_turn(&deps(llm), &ctx(), &registry, None, "fix both").await.unwrap();
        assert_eq!(*tool.calls.lock().unwrap(), 2, "distinct args must both execute");
    }

    #[tokio::test]
    async fn step_cap_with_no_action_returns_an_error() {
        let mut scripted = ScriptedModel::new();
        for _ in 0..MAX_STEPS {
            scripted.push_tool_call("echo", json!({"q": "still going"}));
        }
        // The post-cap final-report call yields nothing usable either.
        scripted.push_text("   ");
        let llm: Arc<Llm> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(EchoTool)];

        let err = run_turn(&deps(llm), &ctx(), &registry, None, "loop forever").await.unwrap_err();
        assert!(format!("{err}").contains("did not converge"));
    }

    #[tokio::test]
    async fn step_cap_after_acting_returns_best_effort_reply_not_an_error() {
        let mut scripted = ScriptedModel::new();
        scripted.push_tool_call("restart_service", json!({"service": "nginx"}));
        for i in 1..MAX_STEPS {
            scripted.push_tool_call("echo", json!({"q": format!("still checking {i}")}));
        }
        // The post-cap final-report call turns the work into a report.
        scripted.push_text("restarted nginx; was still verifying when the step budget ran out");
        let llm: Arc<Llm> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> =
            vec![Box::new(CountingActionTool::new()), Box::new(EchoTool)];

        let reply =
            run_turn(&deps(llm), &ctx(), &registry, None, "fix and keep checking").await.unwrap();
        assert!(reply.acted);
        assert!(!reply.reply.is_empty(), "must surface an honest best-effort reply, not silence");
    }

    #[tokio::test]
    async fn unknown_tool_name_is_reported_back_with_valid_names() {
        let mut scripted = ScriptedModel::new();
        scripted.push_tool_call("does_not_exist", json!({})).push_text("apologized");
        let llm: Arc<Llm> = Arc::new(scripted);
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
        let mut scripted = ScriptedModel::new();
        scripted.push_text("scan complete, nothing wrong");
        let llm: Arc<Llm> = Arc::new(scripted);
        let registry: Vec<Box<dyn Tool>> = vec![];
        let mut d = deps(llm);
        d.heartbeat = true;

        let reply = run_turn(&d, &ctx(), &registry, None, "scan").await.unwrap();
        assert_eq!(reply.reply, "scan complete, nothing wrong");
    }

    #[tokio::test]
    async fn the_report_step_offers_no_tools_and_the_clock_is_outside_the_cached_prefix() {
        let mut scripted = ScriptedModel::new();
        for _ in 0..MAX_STEPS {
            scripted.push_tool_call("echo", json!({"q": "still going"}));
        }
        scripted.push_text("final report");
        let scripted = Arc::new(scripted);
        let llm: Arc<Llm> = scripted.clone();
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(EchoTool)];

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "sweep").await.unwrap();
        assert_eq!(reply.reply, "final report");

        let offered = scripted.tool_names_seen();
        assert_eq!(offered.len(), MAX_STEPS + 1, "every tool step plus the report step");
        assert_eq!(offered[0], vec!["echo".to_string()]);
        assert!(offered.last().unwrap().is_empty(), "the report step must offer no tools");
        let last_history = scripted.histories_seen().pop().unwrap();
        assert!(
            matches!(last_history.last(), Some(ToolTurn::User(m)) if m.contains("step budget exhausted")),
            "the report step is asked for a report"
        );

        let system = &scripted.systems_seen()[0];
        let prefix = scripted.cacheable_prefix_lengths_seen()[0];
        assert!(prefix > 0, "the persona must be marked cacheable");
        assert!(system[..prefix].starts_with("You are OpsClaw"));
        assert!(system[prefix..].contains("current UTC time"), "the clock stays outside");
    }

    #[tokio::test]
    async fn a_batch_of_tool_calls_is_recorded_as_one_exchange() {
        let mut scripted = ScriptedModel::new();
        scripted
            .push_tool_calls(vec![
                ("echo".into(), json!({"q": "a"})),
                ("echo".into(), json!({"q": "b"})),
            ])
            .push_text("both seen");
        let scripted = Arc::new(scripted);
        let llm: Arc<Llm> = scripted.clone();
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(EchoTool)];

        run_turn(&deps(llm), &ctx(), &registry, None, "check both").await.unwrap();
        let history = scripted.histories_seen().pop().unwrap();
        match &history[history.len() - 2..] {
            [ToolTurn::AssistantToolCalls(calls), ToolTurn::ToolResults(results)] => {
                assert_eq!(calls.len(), 2);
                assert_eq!(results[0], ("call_1".to_string(), "echo: \"a\"".to_string()));
                assert_eq!(results[1], ("call_2".to_string(), "echo: \"b\"".to_string()));
            }
            other => panic!("expected one call batch and its results, got {other:?}"),
        }
    }

    #[test]
    fn canonical_args_is_key_order_independent() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(canonical_args(&a), canonical_args(&b));
    }

    #[test]
    fn assemble_system_prompt_orders_persona_before_volatile_clock() {
        let (system, _) = assemble_system_prompt(false, None);
        let persona_pos = system.find("You are OpsClaw").unwrap();
        let clock_pos = system.find("CONTEXT — current UTC time").unwrap();
        assert!(persona_pos < clock_pos, "persona (stable) must precede the clock (volatile)");
    }

    #[test]
    fn assemble_system_prompt_includes_heartbeat_framing_only_when_set() {
        let (normal, _) = assemble_system_prompt(false, None);
        let (hb, _) = assemble_system_prompt(true, None);
        assert!(!normal.contains("SCHEDULED SCAN"));
        assert!(hb.contains("SCHEDULED SCAN"));
    }

    #[test]
    fn assemble_system_prompt_includes_team_context_between_persona_and_clock() {
        let (system, _) = assemble_system_prompt(false, Some("3 targets in example"));
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

    /// A tool that mixes a read verb and a write verb, like `kubernetes`.
    /// It logs each call's start and end; reads can wait on a barrier to
    /// prove they run at the same time.
    struct MixedTool {
        log: CallLog,
        barrier: Option<Arc<tokio::sync::Barrier>>,
    }
    #[async_trait]
    impl Tool for MixedTool {
        fn name(&self) -> &'static str {
            "cluster"
        }
        fn description(&self) -> &str {
            "get reads; restart changes something"
        }
        fn schema(&self) -> Value {
            json!({
                "type": "object",
                "properties": {
                    "verb": {"type": "string", "enum": ["get", "restart"]},
                    "name": {"type": "string"}
                },
                "required": ["verb", "name"]
            })
        }
        fn risk(&self) -> crate::domain::RiskClass {
            crate::domain::RiskClass::Medium
        }
        fn is_action(&self) -> bool {
            true
        }
        fn reads_only(&self, args: &Value) -> bool {
            args["verb"] == "get"
        }
        fn allowed_in_heartbeat(&self) -> bool {
            true
        }
        async fn call(
            &self,
            _ctx: &ToolCtx,
            args: Value,
        ) -> std::result::Result<crate::tools::ToolResult, ToolError> {
            let label =
                format!("{} {}", args["verb"].as_str().unwrap(), args["name"].as_str().unwrap());
            self.log.lock().unwrap().push(format!("start {label}"));
            if let (Some(barrier), true) = (&self.barrier, args["verb"] == "get") {
                tokio::time::timeout(Duration::from_secs(2), barrier.wait())
                    .await
                    .map_err(|_| ToolError::UserFacing("reads ran one at a time".into()))?;
            }
            tokio::task::yield_now().await;
            self.log.lock().unwrap().push(format!("end {label}"));
            Ok(crate::tools::ToolResult { output: format!("ok {label}") })
        }
    }

    type CallLog = Arc<std::sync::Mutex<Vec<String>>>;

    fn mixed(barrier: Option<usize>) -> (Vec<Box<dyn Tool>>, CallLog) {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let tool = MixedTool {
            log: log.clone(),
            barrier: barrier.map(|n| Arc::new(tokio::sync::Barrier::new(n))),
        };
        (vec![Box::new(tool)], log)
    }

    fn get(name: &str) -> (String, Value) {
        ("cluster".to_string(), json!({"verb": "get", "name": name}))
    }

    /// The tool results the model saw on its last step.
    fn last_tool_results(scripted: &ScriptedModel) -> Vec<String> {
        let histories = scripted.histories_seen();
        histories
            .last()
            .unwrap()
            .iter()
            .rev()
            .find_map(|turn| match turn {
                ToolTurn::ToolResults(results) => {
                    Some(results.iter().map(|(_, output)| output.clone()).collect())
                }
                _ => None,
            })
            .unwrap()
    }

    #[tokio::test]
    async fn read_only_calls_in_one_batch_run_concurrently() {
        let mut scripted = ScriptedModel::new();
        scripted.push_tool_calls(vec![get("a"), get("b")]).push_text("done");
        let scripted = Arc::new(scripted);
        let llm: Arc<Llm> = scripted.clone();
        // Each read waits for the other: run one at a time, they time out.
        let (registry, _) = mixed(Some(2));

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "look").await.unwrap();
        assert_eq!(last_tool_results(&scripted), vec!["ok get a", "ok get b"], "in call order");
        assert!(!reply.acted, "reads alone are not acting");
    }

    #[tokio::test]
    async fn an_action_runs_alone_between_the_reads_around_it() {
        let mut scripted = ScriptedModel::new();
        scripted
            .push_tool_calls(vec![
                get("a"),
                ("cluster".to_string(), json!({"verb": "restart", "name": "api"})),
                get("b"),
            ])
            .push_text("done");
        let llm: Arc<Llm> = Arc::new(scripted);
        let (registry, log) = mixed(None);

        let reply = run_turn(&deps(llm), &ctx(), &registry, None, "fix").await.unwrap();
        assert!(reply.acted);
        assert_eq!(
            *log.lock().unwrap(),
            vec![
                "start get a",
                "end get a",
                "start restart api",
                "end restart api",
                "start get b",
                "end get b"
            ]
        );
    }

    #[tokio::test]
    async fn arguments_the_schema_rejects_never_reach_the_tool() {
        let mut scripted = ScriptedModel::new();
        scripted
            .push_tool_call("cluster", json!({"verb": "get", "name": "a", "bogus": true}))
            .push_text("done");
        let scripted = Arc::new(scripted);
        let llm: Arc<Llm> = scripted.clone();
        let (registry, log) = mixed(None);

        run_turn(&deps(llm), &ctx(), &registry, None, "look").await.unwrap();
        assert!(log.lock().unwrap().is_empty(), "the tool must not run");
        let results = last_tool_results(&scripted);
        assert!(results[0].starts_with("invalid arguments for cluster:"), "{results:?}");
    }

    #[tokio::test]
    async fn scalar_spellings_are_coerced_to_the_schema() {
        let mut scripted = ScriptedModel::new();
        scripted.push_tool_call("lookup", json!({"limit": "5"})).push_text("done");
        let scripted = Arc::new(scripted);
        let llm: Arc<Llm> = scripted.clone();
        struct Lookup;
        #[async_trait]
        impl Tool for Lookup {
            fn name(&self) -> &'static str {
                "lookup"
            }
            fn description(&self) -> &str {
                "reads"
            }
            fn schema(&self) -> Value {
                json!({"type": "object", "properties": {"limit": {"type": "integer"}}})
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
                Ok(crate::tools::ToolResult { output: format!("limit={}", args["limit"]) })
            }
        }
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(Lookup)];

        run_turn(&deps(llm), &ctx(), &registry, None, "look").await.unwrap();
        assert_eq!(last_tool_results(&scripted), vec!["limit=5"], "\"5\" became the integer 5");
    }

    /// A read-only tool that returns a large output, like `kubectl get pods -A`.
    struct BigOutputTool;
    #[async_trait]
    impl Tool for BigOutputTool {
        fn name(&self) -> &'static str {
            "big"
        }
        fn description(&self) -> &str {
            "returns a lot of text"
        }
        fn schema(&self) -> Value {
            json!({"type": "object", "properties": {"n": {"type": "integer"}}})
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
            let line = format!("pod-{} Running 0 3d\n", args["n"]);
            Ok(crate::tools::ToolResult { output: line.repeat(1_500) })
        }
    }

    /// The bug `dcpr_agent::HistoryCompactor` replaced: after about nine large
    /// tool results, the old shrink dropped the turn's own request.
    #[tokio::test]
    async fn a_long_turn_with_large_outputs_never_loses_its_task() {
        const TASK: &str = "Scan example::sandbox::aks and report every crashlooping pod.";
        let mut scripted = ScriptedModel::new();
        for n in 0..(MAX_STEPS - 2) {
            scripted.push_tool_call("big", json!({"n": n}));
        }
        scripted.push_text("done");
        let scripted = Arc::new(scripted);
        let llm: Arc<Llm> = scripted.clone();
        let registry: Vec<Box<dyn Tool>> = vec![Box::new(BigOutputTool)];

        run_turn(&deps(llm), &ctx(), &registry, None, TASK).await.unwrap();

        let histories = scripted.histories_seen();
        for (step, history) in histories.iter().enumerate() {
            assert!(
                history.iter().any(|t| matches!(t, ToolTurn::User(m) if m == TASK)),
                "step {step}: the task was dropped"
            );
        }
        let last = histories.last().unwrap();
        assert!(
            dcpr_agent::estimate_tokens(last) <= HISTORY_BUDGET_TOKENS + 8_000,
            "compaction kept the history near its budget"
        );
        let first_output = histories[1]
            .iter()
            .find_map(|t| match t {
                ToolTurn::ToolResults(r) => Some(r[0].1.len()),
                _ => None,
            })
            .unwrap();
        assert!(first_output <= TOOL_OUTPUT_CHARS + 200, "outputs are capped on return");
    }

    #[tokio::test]
    async fn null_for_an_optional_argument_means_not_given() {
        let mut scripted = ScriptedModel::new();
        scripted
            .push_tool_call("cluster", json!({"verb": "get", "name": "a", "bogus": null}))
            .push_tool_call("cluster", json!({"verb": null, "name": "b"}))
            .push_text("done");
        let scripted = Arc::new(scripted);
        let llm: Arc<Llm> = scripted.clone();
        let (registry, log) = mixed(None);

        run_turn(&deps(llm), &ctx(), &registry, None, "look").await.unwrap();
        assert_eq!(*log.lock().unwrap(), vec!["start get a", "end get a"], "the null was dropped");
        let results = last_tool_results(&scripted);
        assert!(results[0].contains("verb"), "a required null is reported missing: {results:?}");
    }

    #[tokio::test]
    async fn the_deadline_turns_gathered_evidence_into_a_report() {
        let mut scripted = ScriptedModel::new();
        scripted.push_text("Found: grafana PVC points at a deleted disk. Not checked: queues.");
        let scripted = Arc::new(scripted);
        let llm: Arc<Llm> = scripted.clone();
        let deps = deps(llm);
        let ctx = ctx();
        let registry: Vec<Box<dyn Tool>> = vec![];
        let mut turn = OpsTurn {
            deps: &deps,
            ctx: &ctx,
            registry: &registry,
            system: "sys".into(),
            cacheable_prefix_len: 0,
            specs: vec![],
            acted: false,
            executed_actions: HashMap::new(),
            task: Some(0),
        };
        let step = StepInfo { index: 3, max_steps: 16 };

        // Nothing gathered yet: the fixed reply, and no model call.
        let mut empty = vec![ToolTurn::User("why is grafana down?".into())];
        let reply = turn.on_deadline(step, &mut empty).await.unwrap();
        assert!(reply.reply.contains("No action was taken"));
        assert_eq!(scripted.histories_seen().len(), 0);

        // Evidence gathered: a report from it, offered no tools.
        let mut history = vec![
            ToolTurn::User("why is grafana down?".into()),
            ToolTurn::AssistantToolCalls(vec![crate::llm::ToolCall {
                id: "c1".into(),
                name: "kubernetes".into(),
                arguments: json!({}),
            }]),
            ToolTurn::ToolResults(vec![("c1".into(), "FailedAttachVolume 404".into())]),
        ];
        let reply = turn.on_deadline(step, &mut history).await.unwrap();
        assert!(reply.reply.starts_with("Found: grafana PVC"), "{}", reply.reply);
        assert_eq!(scripted.tool_names_seen().last().unwrap().len(), 0, "no tools offered");
    }
}
