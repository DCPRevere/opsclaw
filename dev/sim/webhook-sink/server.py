"""Minimal HTTP server that captures POST requests to a JSONL file."""

import json
import os
import sys
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

DATA_FILE = os.environ.get("WEBHOOK_DATA_FILE", "/data/requests.jsonl")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""

        # Log to stdout for real-time visibility
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[{ts}] POST {self.path} — {body}", flush=True)

        # Append to JSONL file
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"raw": body}

        entry = {"timestamp": ts, "path": self.path, "payload": parsed}
        with open(DATA_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"received"}')

    def do_GET(self):
        """Serve the captured requests for easy inspection."""
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE) as f:
                data = f.read()
        else:
            data = ""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data.encode("utf-8"))

    def log_message(self, fmt, *args):
        # Suppress default request logging (we log manually above)
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"Webhook sink listening on port {port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down", flush=True)
        sys.exit(0)
