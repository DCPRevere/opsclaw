#!/usr/bin/env python3
"""
Minimal OpenAI-compatible HTTP server that returns scripted responses
from a manifest file. Used by Tier 2 to make sim runs deterministic
and free.

Status: SCAFFOLD ONLY. The wire format is correct enough for the
opsclaw daemon to send a request, but multi-turn tool-call replay
(receive system prompt → return tool_call → receive tool result →
return next tool_call → eventually return final answer) is not yet
implemented. See README.md for the gap analysis and extension plan.

Usage:
    python3 server.py --port 18080 --manifest scripts/example.jsonl

The manifest format (one event per line) is:
    {"match": {...}, "response": {...}}

Where `match` is an opaque request signature (model, last user message,
tool result if any) and `response` is the OpenAI-format reply to send.

The current scaffold matches *only* on model+message-count and returns
a single canned reply. Extend match/response handling for richer
behaviour.
"""
from __future__ import annotations
import argparse
import json
import sys
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
            out.append(json.loads(line))
        except Exception as e:
            print(f"[replay-llm] bad manifest line: {e}", file=sys.stderr)
    return out


def request_signature(body: dict[str, Any]) -> dict[str, Any]:
    """Reduce an OpenAI request to the parts that scripts can reasonably
    match against. Today: model + number of messages + last role +
    a slice of last content. Extend as scripts demand richer matching."""
    model = body.get("model", "")
    messages = body.get("messages") or []
    last = messages[-1] if messages else {}
    content = last.get("content") or ""
    if not isinstance(content, str):
        content = json.dumps(content)
    return {
        "model": model,
        "msg_count": len(messages),
        "last_role": last.get("role", ""),
        "last_content_head": content[:200],
    }


def find_response(manifest: list[dict[str, Any]], sig: dict[str, Any]) -> dict[str, Any] | None:
    """Naive linear scan. First match wins. Return the `response` body
    or None if nothing matches. A None match means the server returns
    a 500 so the daemon's failure mode is loud, not silent."""
    for entry in manifest:
        m = entry.get("match") or {}
        if all(sig.get(k) == v for k, v in m.items()):
            return entry.get("response")
    return None


def default_completion(model: str) -> dict[str, Any]:
    """A safe fallback when the manifest is empty: refuse to respond
    so the user notices the manifest is missing rather than getting
    silently mocked behaviour."""
    return {
        "id": f"chatcmpl-{uuid.uuid4()}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "[replay-llm scaffold] no manifest entry matched this request. "
                               "Add a script under dev/sim/replay-llm/scripts/ to drive the agent.",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


class Handler(BaseHTTPRequestHandler):
    manifest_path: Path = Path()
    manifest: list[dict[str, Any]] = []

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw or b"{}")
        except Exception:
            self._send_json(400, {"error": "invalid json"})
            return

        # Re-read the manifest each call so script edits are picked up
        # without restarting the server. Cheap; manifests are tiny.
        Handler.manifest = load_manifest(Handler.manifest_path)

        if self.path.endswith("/chat/completions"):
            sig = request_signature(body)
            resp = find_response(Handler.manifest, sig)
            if resp is None:
                resp = default_completion(body.get("model", ""))
            self._send_json(200, resp)
            return

        # Models list — daemon's pre-flight may probe this.
        if self.path.endswith("/models"):
            self._send_json(200, {"object": "list", "data": []})
            return

        self._send_json(404, {"error": f"unhandled path {self.path}"})

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter logs
        sys.stderr.write(f"[replay-llm] {self.address_string()} - {fmt % args}\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--manifest", type=Path, required=True)
    args = ap.parse_args()

    Handler.manifest_path = args.manifest
    Handler.manifest = load_manifest(args.manifest)
    print(f"[replay-llm] listening on {args.host}:{args.port}, manifest={args.manifest} "
          f"({len(Handler.manifest)} entries)", file=sys.stderr)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
