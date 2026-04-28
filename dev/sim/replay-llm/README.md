# replay-llm — deterministic LLM mock for Tier 2

OpenAI-compatible HTTP server that replays scripted multi-turn conversations from a JSONL manifest. Used to make Tier 2 sim runs deterministic and free.

## Status

**Wiring: working.** A Tier 2 run with `--replay` boots the server, swaps the daemon's provider URL, the daemon talks to it instead of OpenAI, scripted responses come back, and the webhook sink correctly captures (or doesn't capture) alerts based on what the script returns.

**Coverage: minimal.** Only `baseline_silent` has a hand-written script today, and it's a single-turn placeholder that just tells the agent "everything's healthy" without scripting a real `monitor → ssh → conclude` flow. To expand, capture real-run traffic and convert it into manifests (see "Adding scenarios" below).

## Usage

```bash
# One scenario under replay (manifest auto-resolves to scripts/<name>.jsonl):
dev/test.sh tier2 --only baseline_silent --bring-up --replay

# Explicit manifest:
dev/test.sh tier2 --replay --replay-manifest path/to/script.jsonl --bring-up

# Standalone server (for ad-hoc poking):
python3 dev/sim/replay-llm/server.py \
    --port 18080 \
    --manifest dev/sim/replay-llm/scripts/baseline_silent.jsonl \
    --log-requests /tmp/replay-requests.jsonl
```

When the server runs under the harness, every incoming request body is captured to `dev/sim/.replay-llm-requests.jsonl` (gitignored) — read it to see what the daemon is actually asking for, which is the foundation for writing new scripts.

## Manifest format

JSONL — one conversation per line. Each line:

```json
{
  "conversation": "baseline_silent",
  "match": {
    "system_prompt_contains": "...",
    "user_prompt_contains": "Heartbeat Task",
    "any_message_contains": "..."
  },
  "turns": [
    {"role": "assistant", "content": "..."},
    {"role": "assistant", "tool_calls": [
      {"id": "call_1", "type": "function",
       "function": {"name": "monitor", "arguments": "{\"project\":\"sim-target\"}"}}
    ]},
    {"role": "assistant", "content": "Final answer."}
  ]
}
```

Match keys are AND-ed. An empty `match` block matches everything (useful as a catch-all at the end of a manifest).

## Routing model

- **Conversation key**: SHA-1 of the *first user message*. Stable across the multi-turn tool-use loop within a single tick, but changes between heartbeat ticks (each tick gets a fresh user message with a unique id), so each tick gets its own turn counter.
- **First match wins** when scanning the manifest top-to-bottom.
- **Script exhausted**: if the agent asks for turn N+1 and the script only has N turns, the server returns `[replay-llm] script for <name> exhausted at turn N` as the assistant content. That's a loud signal — Tier 2 should fail visibly rather than mysteriously.

## Adding scenarios

1. Run the real scenario once with a real API key (no `--replay`), letting `--log-requests` capture every outgoing request:
   ```bash
   ./dev/test.sh tier2 --only memory --bring-up
   # Server isn't running, so the request log won't be populated this way — instead:
   python3 dev/sim/replay-llm/server.py \
       --port 18080 \
       --manifest /dev/null \
       --log-requests /tmp/captured.jsonl &
   OPSCLAW_REPLAY_LLM_URL=... ./dev/test.sh tier2 --only memory --bring-up
   ```
   *(Better tooling for capture is a follow-up — today the workflow is rough.)*
2. Read `/tmp/captured.jsonl` to see the actual sequence of `(messages, response)` pairs the agent generated.
3. For each tick, pick an anchor in the user message (e.g. the heartbeat task ID or fault category), put it in `match.user_prompt_contains`, and copy the assistant turns into the `turns` array.
4. Re-run with `--replay` to verify the script reproduces the desired verdict.

## Known limitations

- **No streaming.** Tier 2's openai provider doesn't request `stream: true`, so this isn't blocking. If a future provider does, the server will need SSE support.
- **Token usage is fake.** All responses report `prompt_tokens: 0, completion_tokens: 0`. Some upstream accounting may complain.
- **No `tool_choice="required"` support beyond the response shape.** The server doesn't validate that the agent actually called the requested tool — it just returns whatever the script says next.
- **Memory contamination across runs.** The daemon persists a SQLite memory store under `<state>/.opsclaw/`, which carries forward to subsequent runs. `rm -rf dev/sim/.state/slot-*` between scenarios if you change scripts.

## Related opsclaw bugs surfaced while building this

While writing the first script I noticed two things in the captured traffic that aren't replay-llm bugs but affect Tier 2 generally:

1. **Heartbeat task seed produces multiple tasks instead of one.** The seed prompt in `daemon_ext.rs::seed_heartbeat_file` uses nested bullet lists (`- Memory: ...`, `- CPU: ...`, etc.). The runtime's HEARTBEAT.md parser treats every `- ` as a top-level task, so each tick fires ~7 mini-tasks. The fix is to flatten the seed into a single bullet (long line) or to teach the parser about indented nesting.
2. **Provider model config is being ignored.** The slot config sets `[providers.models.openai].model = "gpt-5.4"` but observed traffic shows `model: "anthropic/claude-sonnet-4"`. There's an upstream default winning over the per-slot value. Worth tracking down.

Both filed as follow-ups; neither blocks the replay path.
