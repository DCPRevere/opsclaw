# dcpr-llm fixes for OpenAI direct — 2026-11-04

Against `v0.2.0` (`a69120b`). Base URL `https://api.openai.com/v1`, models
`gpt-6.1-sol` (target) and `gpt-5.5`. Line numbers are in
`crates/dcpr-llm/src/openai_compat/mod.rs` unless noted.

**Tested** = reproduced against the live API. **Read** = found in the code,
not reproduced.

## Blockers — nothing works without these

1. **`max_tokens` is rejected.** Tested. Every Chat Completions call fails
   with a 400: "Use 'max_completion_tokens' instead". This happens for gpt-5.x
   and gpt-6.x, on both `complete()` and `chat_step`. The field is set at
   `:1201` (`completion_body`) and `:1445` (`chat_step_base`). Fix: send
   `max_completion_tokens` when the base URL is OpenAI. `gpt-4.1` accepts it
   too.

2. **`temperature: 0` is rejected.** Tested. `complete()` sends it at
   `:1202`, and `gpt-6.1-sol` only accepts the default of 1. `gpt-4.1-mini`
   accepts 0. Fix: leave it out for OpenAI reasoning models (o-series,
   gpt-5+).

3. **gpt-6.1-sol cannot call tools on Chat Completions.** Tested. The 400
   says to use `/v1/responses` or set `reasoning_effort: "none"`, but `"none"`
   is itself rejected for this model (only low, medium, high and xhigh are
   allowed). So tool steps must use the Responses API. With the default
   (Chat Completions) transport, the first tool call fails.

4. **The Responses API replay sends the wrong `id`.** Tested. `:1890` sets a
   replayed `function_call` item's `"id"` to the `call_…` id. OpenAI rejects
   it: "Expected an ID that begins with 'fc'". OpenRouter tolerates it.
   Fix: leave `id` out. A function_call with only `call_id` is accepted
   (tested), or you could store the real `fc_…` item id. With this fixed,
   `with_responses_api(true)` runs a full tool round trip on OpenAI: the
   first call already works (tested).

## Will bite soon

5. **Reasoning settings are OpenRouter-only.** Read. `apply_provider_quirks`
   (`:438`) does nothing for other hosts. So:
   - `with_reasoning_effort` and the reasoning budget are silently ignored.
   - The output-ceiling headroom for reasoning is never added.
   - Small helper calls can't be told to keep reasoning low.

   Tested: with a 16-token ceiling and high effort, the model spent all 16
   on reasoning and returned empty content. That's
   `finish_reason: length`, which dcpr reads as a discarded partial reply.
   Fix: on OpenAI send `reasoning_effort` (Chat Completions) or
   `reasoning.effort` (Responses), using "low" for small calls because
   "none" and "minimal" are rejected, and add the same headroom.

6. **Reasoning isn't carried between tool steps.** Read. The Responses
   request asks for `reasoning.encrypted_content` only when a reasoning
   setting exists (`:1119`), and per item 5 none ever exists on OpenAI. The
   model still reasons by default, so each step starts cold. That costs
   quality and tokens, but doesn't cause errors.

7. **Fallback models are ignored.** Read. `with_fallback_models` is only
   sent as OpenRouter's `models` list (`:506`). On OpenAI there is no
   failover, and nothing warns you. Fix: either fail over client-side
   (`Fallback` across one client per model) or warn when fallbacks are set
   for a host that isn't OpenRouter.

8. **An OpenAI `429 insufficient_quota` is retried.** Read. `error.rs`
   treats every 429 as transient (`:167`). OpenAI uses 429 with code
   `insufficient_quota` when the account is out of money, and retrying
   can't fix that. Fix: map it to a hard error, the way OpenRouter's "out of
   credit" 402 already is.

9. **The Batch API has the same bugs.** Read. `batch.rs:184` and `:200`
   build their bodies with `completion_body` and `chat_step_base`, so items 1,
   2 and 3 apply. Batch is OpenAI's API, so `batch` is broken for current
   OpenAI models.

10. **The tool-search entry is OpenRouter-only.** Read. When any tool is
    deferred, `:1076` adds `{"type": "openrouter:tool_search"}`, which
    OpenAI will reject. Fix: add it on OpenRouter only. OpsClaw doesn't
    defer tools, so this doesn't affect it.

## Tidy-ups

11. **Provider detection** is a substring check on the base URL
    (`contains("openrouter")`, in about 6 places). An explicit provider
    setting, or one `is_openrouter()` / `is_openai()` helper, would make
    items 1–10 one branch each.
12. **Error text** says "OpenRouter Responses …" for OpenAI errors (`:811`
    and onwards), which is misleading in logs.
13. **Docs:** `:5` lists OpenAI as supported, and `with_responses_api`
    (`:147`) says "OpenRouter only". Both should match the code once fixed.
14. **No test covers an OpenAI request body.** Add wiremock tests that check
    the request shape for an `api.openai.com` base URL: the token field,
    temperature, reasoning, and the replayed function_call items.

## Not lib work: OpsClaw changes once the lib is fixed

- In `build_chain`, turn on `with_responses_api(true)` for OpenAI (item 3).
- Add a `gpt-6.1-sol` row to `src/llm/pricing.rs`, from OpenAI's published
  prices. It's unknown today, so it gets priced at the expensive default.
- Config: `llm.base_url = "https://api.openai.com/v1"`, the key from
  `env:OPENAI_API_KEY`, and `models = ["gpt-6.1-sol"]`. Set Hindsight's
  `HINDSIGHT_LLM_PROVIDER=openai` with the same key.

## How to re-test

- `/tmp/dcpr-oai` is a scratch binary using the dcpr-llm path dependency at
  `~/src/dcprevere/dcpr-ai-rs-openai`. It runs a three-step tool round trip
  over Responses.
- The OpsClaw live evals now accept any endpoint:
  ```
  OPSCLAW_LIVE_EVALS=1 OPSCLAW_EVAL_BASE_URL=https://api.openai.com/v1 \
    OPSCLAW_EVAL_API_KEY=sk-... OPENROUTER_MODELS=gpt-6.1-sol \
    cargo test --test evals -- --nocapture
  ```
