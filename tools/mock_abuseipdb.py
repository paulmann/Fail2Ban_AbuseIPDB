#!/usr/bin/env python3
"""Mock AbuseIPDB API v2 for local tests and demos.

Listens on 127.0.0.1:PORT, records every request as one JSON line and replies
like the real service.  Failure modes are selected by the last octet of the
reported IP, which makes error-path tests deterministic:

  .250 -> HTTP 429 (per-IP rate limit)
  .251 -> HTTP 422 (invalid report)
  .252 -> HTTP 500 on the first attempt, 200 afterwards

Usage:
  python3 tools/mock_abuseipdb.py <requests.jsonl> [port]
"""
import http.server
import json
import sys
import urllib.parse
from typing import Dict

OUT = sys.argv[1] if len(sys.argv) > 1 else "requests.jsonl"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8899
STATE: Dict[str, int] = {}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the test output clean
        pass

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        record = {
            "method": "POST",
            "path": self.path,
            "headers": {
                key: value
                for key, value in self.headers.items()
                if key.lower() in ("key", "accept", "content-type", "user-agent")
            },
            "body": raw,
        }
        with open(OUT, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

        fields = urllib.parse.parse_qs(raw)
        ip = (fields.get("ip") or [""])[0]
        if ip.endswith(".250"):
            self._send(
                429,
                {
                    "errors": [
                        {
                            "detail": "You can only report the same IP address (`%s`) once in 15 minutes."
                            % ip,
                            "status": 429,
                            "source": {"parameter": "ip"},
                        }
                    ]
                },
            )
        elif ip.endswith(".251"):
            self._send(422, {"errors": [{"detail": "The ip must be a valid IP address.", "status": 422}]})
        elif ip.endswith(".252") and not STATE.get(ip):
            STATE[ip] = 1
            self._send(500, {"errors": [{"detail": "simulated transient error", "status": 500}]})
        else:
            self._send(200, {"data": {"ipAddress": ip, "abuseConfidenceScore": 50}})

    def do_GET(self):
        self._send(200, {"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0}})


def main() -> int:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("mock AbuseIPDB API on http://127.0.0.1:%d (requests -> %s)" % (PORT, OUT), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())