#!/usr/bin/env python3
"""
OpenAI-compatible HTTP server that replays scripted multi-turn
conversations from a manifest. Used by Tier 2 to make sim runs
deterministic and free.

Wire format
-----------
- POST /v1/chat/completions — handles native-tools requests with
  `messages`, `tools`, `tool_choice`. Returns OpenAI-format
  `chat.completion` objects with `tool_calls` when the script demands.
- GET  /v1/models           — empty list (some providers probe this).

Manifest format
---------------
A YAML-ish JSONL file under `dev/sim/replay-llm/scripts/`. Each line is
a JSON object describing one conversation:

  {
    "conversation": "baseline_silent",
    "match": {"system_prompt_contains": "target 'sim-target'"},
    "turns": [
       {"role": "assistant", "content": "Healthy."}
       // or:
       // {"role": "assistant", "tool_calls": [
       //    {"id": "call_1", "type": "function",
       //     "function": {"name": "monitor", "arguments": "{\"target\":\"sim-target\"}"}}
       //  ]}
    ]
  }

Routing
-------
Each incoming request is matched to one conversation:

1. The first system message (messages[0].role == "system") provides the
   match key. We look for the *first* manifest entry whose
   `match.system_prompt_contains` is a substring of that system prompt.
2. Conversation state is keyed on the SHA-1 of that system prompt,
   so the *same* conversation across multiple turns reuses state.
3. Each turn pops the next entry from `turns`. When the script runs out
   of turns, we return a final assistant message with content
   "[replay-llm] script for <conversation> exhausted at turn <n>" so
   FAILs are obvious.

Determinism
-----------
A scenario that needs N turns must script exactly N turns. Anything off
by one fails loudly at the verdict layer because either (a) the agent
expects a tool result that never arrives, or (b) the agent never sees
the assistant message it needs. This is by design.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def load_manifest(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            entry = json.loads(line)
        except Exception as e:
            print(f"[replay-llm] bad manifest line: {e}", file=sys.stderr)
            continue
        if "conversation" not in entry or "turns" not in entry:
            print(f"[replay-llm] manifest entry missing 'conversation' or 'turns': {entry}",
                  file=sys.stderr)
            continue
        out.append(entry)
    return out


def conversation_id(messages: list[dict[str, Any]]) -> str:
    """Stable id for *this turn-sequence*. The first user message is the
    cleanest anchor: it changes per heartbeat tick (so each tick gets a
    fresh turn counter), but stays constant across the multi-step
    tool-use loop within that tick. Falls back to system message if no
    user message present."""
    for m in messages:
        if m.get("role") == "user":
            blob = json.dumps(m, sort_keys=True)
            return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]
    sys_msgs = [m for m in messages if m.get("role") == "system"]
    blob = json.dumps(sys_msgs[0] if sys_msgs else {}, sort_keys=True)
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]


def role_text(messages: list[dict[str, Any]], role: str) -> str:
    """Concatenate all text content for messages of the given role.
    Multi-part content (list of {type, text}) is flattened."""
    out: list[str] = []
    for m in messages:
        if m.get("role") != role:
            continue
        content = m.get("content")
        if isinstance(content, str):
            out.append(content)
        elif isinstance(content, list):
            for p in content:
                if isinstance(p, dict):
                    out.append(p.get("text", ""))
                else:
                    out.append(str(p))
    return "\n".join(out)


def find_conversation(
    manifest: list[dict[str, Any]], messages: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Match by *any* of: system_prompt_contains, user_prompt_contains,
    or any_message_contains. First entry whose declared needles all
    appear in the right places wins."""
    sys_blob = role_text(messages, "system")
    user_blob = role_text(messages, "user")
    all_blob = "\n".join(role_text(messages, r) for r in ("system", "user", "assistant", "tool"))
    for entry in manifest:
        match = entry.get("match") or {}
        sys_needle = match.get("system_prompt_contains")
        usr_needle = match.get("user_prompt_contains")
        any_needle = match.get("any_message_contains")
        if sys_needle and sys_needle not in sys_blob:
            continue
        if usr_needle and usr_needle not in user_blob:
            continue
        if any_needle and any_needle not in all_blob:
            continue
        # Empty match block matches everything, which is useful as a
        # catch-all fallback at the end of a manifest.
        return entry
    return None


def build_completion(
    model: str, content: str | None, tool_calls: list[dict[str, Any]] | None,
    finish_reason: str = "stop",
) -> dict[str, Any]:
    """Construct an OpenAI chat.completion object with optional tool_calls."""
    msg: dict[str, Any] = {"role": "assistant"}
    if tool_calls:
        msg["tool_calls"] = tool_calls
        msg["content"] = content  # may be None; OpenAI allows it
        if finish_reason == "stop":
            finish_reason = "tool_calls"
    else:
        msg["content"] = content if content is not None else ""

    return {
        "id": f"chatcmpl-{uuid.uuid4()}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": msg,
                "finish_reason": finish_reason,
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def exhausted_completion(model: str, conversation: str, turn: int) -> dict[str, Any]:
    return build_completion(
        model,
        content=f"[replay-llm] script for {conversation!r} exhausted at turn {turn}",
        tool_calls=None,
    )


def unmatched_completion(model: str) -> dict[str, Any]:
    return build_completion(
        model,
        content="[replay-llm] no manifest entry matched the system prompt; "
                "add or fix the conversation script under dev/sim/replay-llm/scripts/",
        tool_calls=None,
    )


class Replayer:
    """Keeps per-conversation turn state across requests. Thread-safe."""

    def __init__(self, manifest_path: Path, requests_log: Path | None = None) -> None:
        self.manifest_path = manifest_path
        self.requests_log = requests_log
        self.lock = threading.Lock()
        self.turn_counter: dict[str, int] = {}
        self.manifest: list[dict[str, Any]] = load_manifest(manifest_path)

    def reload(self) -> None:
        with self.lock:
            self.manifest = load_manifest(self.manifest_path)

    def next_turn(self, body: dict[str, Any]) -> dict[str, Any]:
        model = body.get("model", "")
        messages = body.get("messages") or []

        # Re-read on every request so script edits are picked up live.
        self.reload()

        conv = find_conversation(self.manifest, messages)
        if conv is None:
            return unmatched_completion(model)

        conv_id = conversation_id(messages)
        with self.lock:
            n = self.turn_counter.get(conv_id, 0)
            self.turn_counter[conv_id] = n + 1

        turns = conv.get("turns") or []
        name = conv.get("conversation", "?")
        if n >= len(turns):
            return exhausted_completion(model, name, n)

        turn = turns[n]
        return build_completion(
            model,
            content=turn.get("content"),
            tool_calls=turn.get("tool_calls"),
            finish_reason=turn.get("finish_reason", "stop"),
        )


class Handler(BaseHTTPRequestHandler):
    replayer: Replayer | None = None

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.endswith("/models"):
            self._send_json(200, {"object": "list", "data": []})
            return
        self._send_json(404, {"error": f"unhandled path {self.path}"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw or b"{}")
        except Exception:
            self._send_json(400, {"error": "invalid json"})
            return

        if not self.path.endswith("/chat/completions"):
            self._send_json(404, {"error": f"unhandled path {self.path}"})
            return

        assert Handler.replayer is not None  # set in main()
        if Handler.replayer.requests_log:
            with open(Handler.replayer.requests_log, "a") as f:
                f.write(json.dumps(body) + "\n")
        resp = Handler.replayer.next_turn(body)
        self._send_json(200, resp)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[replay-llm] {self.address_string()} - {fmt % args}\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--log-requests", type=Path, default=None,
                    help="If set, every incoming request body is appended as JSONL to this file.")
    args = ap.parse_args()

    Handler.replayer = Replayer(args.manifest, requests_log=args.log_requests)
    print(
        f"[replay-llm] listening on {args.host}:{args.port}, "
        f"manifest={args.manifest} ({len(Handler.replayer.manifest)} conversation(s))",
        file=sys.stderr,
    )

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
