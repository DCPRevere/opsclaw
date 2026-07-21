#!/usr/bin/env bash
# sim/fixtures/fake-web.sh — a TinyHealthCheck-style listener (REMUNDO.md):
# proves only that this loop is alive, not that anything downstream works.
# Uses netcat-less pure-bash TCP via /dev/tcp is not listen-capable, so we
# fall back to a minimal loop with socat if present, else python3, else a
# no-op that just holds the process open (still a valid "process is up"
# target for proc-flapping/service-stopped scenarios even without a socket).
set -euo pipefail

PORT=8080

echo "fake-web: starting pid $$ on port ${PORT}"

if command -v socat >/dev/null 2>&1; then
    exec socat -T5 TCP-LISTEN:"${PORT}",fork,reuseaddr SYSTEM:'printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"'
elif command -v python3 >/dev/null 2>&1; then
    exec python3 -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *a):
        pass
http.server.HTTPServer(("0.0.0.0", 8080), H).serve_forever()
'
else
    echo "fake-web: no socat/python3 available, holding process open without a socket"
    while true; do sleep 60; done
fi
