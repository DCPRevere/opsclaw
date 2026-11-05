# Brief: make dcpr-llm work against OpenAI directly

## Goal

`OpenAiCompat` pointed at `https://api.openai.com/v1` must run a full
tool-calling agent turn with `gpt-6.1-sol`, plus one-shot `complete()` calls.
Today every request fails. OpenRouter behaviour must not change.

The first user is OpsClaw (`~/src/dcprevere/opsclaw`). It calls `chat_step`
with function tools, `complete()` for small helper calls, and sets
`Caller::tool_step_output_tokens` to 16384.

Base: `master` at `v0.2.0` (`a69120b`). An empty branch
`openai-max-completion-tokens` exists in the worktree
`~/src/dcprevere/dcpr-ai-rs-openai`; use it or delete it.

## What was tested against the live OpenAI API (2026-11-04)

- **`max_tokens`:** gpt-5.x and gpt-6.x reject it with a 400: "Unsupported
  parameter: 'max_tokens' … Use 'max_completion_tokens' instead".
  `gpt-4.1-mini` accepts `max_completion_tokens` too.
- **`temperature: 0`:** `gpt-6.1-sol` rejects it ("Only the default (1)
  value is supported"). `gpt-4.1-mini` accepts it.
- **Tools on `/v1/chat/completions`:** `gpt-6.1-sol` rejects function tools
  there: "use /v1/responses or set reasoning_effort to 'none'". But `none`
  and `minimal` are rejected for this model too; the allowed values are low,
  medium, high and xhigh. So tool steps must use the Responses API.
  `gpt-5.5` still allows tools on Chat Completions.
- **The Responses API with `with_responses_api(true)`:**
  - The first tool call works.
  - The step after it fails with "Invalid 'input[1].id': 'call_…'. Expected
    an ID that begins with 'fc'". The cause is `openai_compat/mod.rs:1890`,
    which sets a replayed `function_call` item's `id` to the call id.
  - Sending that item without `id` (keeping `call_id`) is accepted, and the
    model answers from the tool output.
- **Reasoning eating the ceiling:** with `max_completion_tokens: 16` and high
  effort, all 16 tokens went to reasoning. The reply came back with
  `finish_reason: length` and empty content.

## Fix list (most important first)

Line numbers are in `crates/dcpr-llm/src/openai_compat/mod.rs` unless noted.

1. **Token field.** Send `max_completion_tokens` instead of `max_tokens` to
   OpenAI: `completion_body` `:1201`, `chat_step_base` `:1445`.
2. **Temperature.** Omit `temperature` for OpenAI reasoning models (o-series,
   gpt-5+) in `completion_body` `:1202`.
3. **Responses API on OpenAI.** Make it a supported transport for OpenAI
   tool steps. Its doc at `:147` says "OpenRouter only". Decide whether
   OpenAI should default to Responses for tool steps or stay opt-in;
   opt-in is fine, because OpsClaw will turn it on.
4. **Replay id.** Stop sending the call id as the `function_call` item `id`
   (`:1890`). Either omit `id`, or keep the real `fc_…` item id from the
   response and replay that. Check that OpenRouter still accepts whichever
   you choose. Existing tests (e.g. `tests.rs:205`, `:257`, `:1220`) may pin
   the current shape.
5. **Reasoning on OpenAI.** `apply_provider_quirks` (`:438`) only acts on
   OpenRouter. On OpenAI, map the configured effort and budget onto
   `reasoning_effort` (Chat Completions) or `reasoning.effort` (Responses),
   and add reasoning headroom to the output ceiling as the OpenRouter branch
   does. Small helper calls should send the lowest supported effort ("low"
   for gpt-6.1-sol), since none and minimal are rejected.
6. **Carry reasoning between steps.** Ask for `reasoning.encrypted_content`
   and replay it on OpenAI too (`:1119` only does this when a reasoning
   setting exists). `store: false` is already sent; keep it.
7. **Fallback models.** `with_fallback_models` only reaches OpenRouter's
   `models` field (`:506`), so on other hosts it is silently ignored. Either
   fail over client-side or log a warning.
8. **Quota errors.** Treat OpenAI's `429` with code `insufficient_quota` as
   a hard error, not a transient one (`error.rs` around `:167`). This is not
   reproduced.
9. **Batch.** `batch.rs:184` and `:200` reuse the same body builders, so they
   pick up fixes 1, 2 and 5. Tool items for gpt-6.x need the
   `/v1/responses` batch endpoint.
10. **Tool search.** Only add the `openrouter:tool_search` tool (`:1076`) on
    OpenRouter.
11. **Provider detection.** Replace the scattered `contains("openrouter")`
    checks with one provider check, so the OpenAI branches live in one
    place.
12. **Wording.** Errors from OpenAI currently say "OpenRouter Responses …"
    (`:811` and onwards). Fix that, and fix the module docs (`:5`, `:147`).

## Done means

- Wiremock tests for an `api.openai.com` base URL check the request bodies:
  - the token field;
  - no temperature for reasoning models;
  - the reasoning fields;
  - replayed `function_call` items without a `call_…` id;
  - no `provider`, `models` or `openrouter:*` fields.
- The existing OpenRouter tests still pass unchanged, unless one pinned the
  bad replay id (fix 4).
- There is an opt-in live test (env-gated, e.g. `OPENAI_API_KEY` +
  `DCPR_LIVE=1`, which skips with a message when unset). It runs, against
  `gpt-6.1-sol` over Responses:
  - `complete()` with a 64-token ceiling, returning non-empty text;
  - a three-step loop: tool call, then tool result, then a text answer.
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`
  and `cargo test --all-features` all pass.
- A version bump and changelog entry. Don't tag or push until Daniel says
  so.

## Out of scope

Azure OpenAI (`api-key` header, `api-version`), and OpsClaw-side changes
(enabling Responses in `build_chain`, pricing rows); OpsClaw will do those.
