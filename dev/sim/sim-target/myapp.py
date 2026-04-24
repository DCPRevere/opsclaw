#!/usr/bin/env python3
"""
myapp — sentinel service for the sim. Binds port 8080, answers 200 on /,
writes /var/run/myapp.pid, and logs each request to /var/log/myapp.log.

Scenarios kill this or block its port to produce realistic "service
down" / "port closed" / "deadlocked-but-bound" faults.
"""
from __future__ import annotations
import os
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

PIDFILE = "/var/run/myapp.pid"
LOGFILE = "/var/log/myapp.log"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"myapp ok\n")

    def log_message(self, fmt, *args):
        with open(LOGFILE, "a") as f:
            f.write(
                f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
                f"{self.address_string()} {fmt % args}\n"
            )


def main() -> int:
    os.makedirs(os.path.dirname(PIDFILE), exist_ok=True)
    with open(PIDFILE, "w") as f:
        f.write(str(os.getpid()))
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    with open(LOGFILE, "a") as f:
        f.write(f"[{time.time():.0f}] myapp started pid={os.getpid()}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
