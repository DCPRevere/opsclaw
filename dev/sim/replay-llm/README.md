# replay-llm — deterministic LLM mock for Tier 2

**Status: scaffold only.** The wire format is correct for opsclaw to talk to it as an OpenAI-compatible provider; the multi-turn tool-call replay logic is not yet implemented. Don't gate CI on this until the gap below is closed.

## Why this exists

Every Tier 2 run currently calls a real LLM (gpt-5.4 by default), at roughly 200k–800k tokens per full run. That:

- costs ~$0.50–$2.00 per run;
- takes ~16 minutes for 9 scenarios;
- is non-deterministic — the same scenario can pass once and fail the next time on a different model phrasing.

A scripted mock fixes all three at once, and unblocks Tier 2 as a CI gate.

## What works today

- `server.py` is a single-file Python `ThreadingHTTPServer` that speaks `/v1/chat/completions` and `/v1/models`.
- Manifests are JSONL: each line is `{"match": {...}, "response": {...}}`.
- The matcher reduces an incoming request to `(model, msg_count, last_role, last_content_head)` and does a first-match-wins linear scan.
- An empty/no-match request gets a loud canned reply ("no manifest entry matched") instead of a silent default — so missing-script bugs surface fast.

## What does not work

The agent loop is a multi-turn conversation:

1. system prompt + first user message → expect `tool_calls` in the response;
2. user message containing the tool result → expect either another `tool_call` or a final `assistant` reply;
3. repeat until the agent decides to stop or call `opsclaw_notify`.

The current matcher is single-shot. It can return one canned response per request, but it has no notion of "which turn of which scenario" we're in. To drive a realistic scenario you need:

- A turn counter keyed on `(scenario_name, conversation_id)`. The scenario name probably has to come from the system prompt or a custom header.
- A response shape that includes `tool_calls` (OpenAI format), not just `content`.
- Streaming support (`stream: true`) — the daemon may use SSE; check `[providers.models.openai].wire_api`.
- Token-usage fields populated so the daemon's accounting doesn't get confused.

## How to extend

1. Capture a real Tier 2 run's HTTP traffic (`mitmproxy` or a tcpdump on port 443 with TLS keys exported) for one passing scenario. Each scenario is one conversation.
2. Convert the captured turns into a JSONL script: one line per `(scenario, turn_index)` pair, with the `match` block keyed on the *outgoing* request's signature and the `response` block being the LLM's reply.
3. Extend `server.py`:
   - Add scenario detection (probably a header set by `slot.sh` when the replay LLM is enabled).
   - Add a turn counter per `(scenario, conversation_id)`.
   - Add `tool_calls` and `usage` to the response.
4. Add a Tier 2 mode (e.g. `dev/test.sh tier2 --replay`) that:
   - Boots `server.py` once on a fixed port.
   - Sets `OPSCLAW_REPLAY_LLM_URL=http://127.0.0.1:18080/v1` for `slot.sh`.
   - Skips the OpenAI key check.

## Running the scaffold standalone

```bash
python3 dev/sim/replay-llm/server.py \
    --port 18080 \
    --manifest dev/sim/replay-llm/scripts/example.jsonl
```

Then point any OpenAI-compatible client at `http://127.0.0.1:18080/v1`.

## Manifest format (current)

```jsonl
{"match": {"model": "gpt-5.4", "msg_count": 1, "last_role": "user"}, "response": {"id": "chatcmpl-1", "object": "chat.completion", "created": 0, "model": "gpt-5.4", "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}}
```

This will need to grow. See above.
