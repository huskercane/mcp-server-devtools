#!/usr/bin/env python3
"""A stand-in vendor upstream for the published-image smoke test.

Answers every GET with an empty JSON array and appends the request's
``Authorization`` header to the file named on the command line, so the
smoke test can assert that the secret the gateway sent upstream is the one
it resolved from Vault — and never the reference text.

Usage: fake-upstream.py PORT SEEN_FILE
"""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def main(argv: list[str]) -> int:
    port = int(argv[1])
    seen = Path(argv[2])

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (http.server naming)
            with seen.open("a", encoding="utf-8") as sink:
                sink.write(f"{self.path} {self.headers.get('Authorization', '')}\n")
            body = b"[]"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            sys.stderr.write("upstream: " + format % args + "\n")

    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
