"""Failover arbiter ("witness"): decides which node may report, and nothing else.

Why a separate service instead of a lease file on shared storage: two nodes
renewing the same file concurrently both believe they are the leader, and a split
brain spends the AbuseIPDB budget twice while breaking the per-IP interval.  A
single arbiter that **grants** a lease cannot produce two holders - it is the only
writer, it serialises requests in one process, and it persists the lease so a
restart does not hand leadership to a second node.

Rules that make it safe:

* a lease is granted only when the current one has **expired** or the same node
  asks again (renewal);
* the arbiter never revokes: it refuses the next renewal instead, and the lease
  runs out on its own.  So a node that cannot reach the arbiter keeps a lease it
  already holds until the deadline - by then nobody else can have been granted it;
* there is no state beyond the lease: no queue, no key, no history.  Losing this
  service stops *changes* of leader, it does not stop reporting.

The client side lives in :mod:`abuseipdb_reporter.witness_client`.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional

#: Lease requests larger than this are rejected before the body is read.
MAX_BODY_BYTES = 4096
LEASE_PATH = "/v1/lease"
RELEASE_PATH = "/v1/release"
STATUS_PATH = "/v1/status"


class LeaseStore:
    """The only mutable state: who holds the lease and until when."""

    def __init__(self, state_path: str = "", clock=time.time):
        self.state_path = state_path
        self.clock = clock
        self._lock = threading.Lock()
        self.owner = ""
        self.expires = 0
        self.term = 0
        self._load()

    # ---------------------------------------------------------------- storage
    def _load(self) -> None:
        if not self.state_path or not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError):
            return
        if not isinstance(payload, dict):
            return
        self.owner = str(payload.get("owner", "") or "")
        self.expires = int(payload.get("expires", 0) or 0)
        self.term = int(payload.get("term", 0) or 0)

    def _save(self) -> None:
        if not self.state_path:
            return
        directory = os.path.dirname(self.state_path) or "."
        try:
            os.makedirs(directory, exist_ok=True)
            handle = tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=directory, prefix=".lease-", suffix=".tmp", delete=False
            )
            temporary = handle.name
            try:
                json.dump({"owner": self.owner, "expires": self.expires, "term": self.term}, handle)
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                handle.close()
            os.replace(temporary, self.state_path)
        except OSError:
            # A witness that cannot persist still arbitrates correctly in memory;
            # it only loses the protection against its own restart.
            pass

    # ------------------------------------------------------------------- api
    def snapshot(self) -> Dict:
        now = int(self.clock())
        return {
            "owner": self.owner,
            "expires": self.expires,
            "term": self.term,
            "now": now,
            "live": bool(self.owner) and int(self.expires) > now,
        }

    def acquire(self, node_id: str, ttl: int) -> Dict:
        node_id = str(node_id or "").strip()[:64]
        ttl = max(30, min(int(ttl or 0), 86400))
        with self._lock:
            now = int(self.clock())
            live = bool(self.owner) and int(self.expires) > now
            if live and self.owner != node_id:
                return {
                    "granted": False,
                    "owner": self.owner,
                    "expires": self.expires,
                    "term": self.term,
                    "now": now,
                    "reason": "lease held by %s until %d" % (self.owner, self.expires),
                }
            if not node_id:
                return {"granted": False, "reason": "node_id is required", "now": now}
            if self.owner != node_id:
                self.term += 1
            self.owner = node_id
            self.expires = now + ttl
            self._save()
            return {
                "granted": True,
                "owner": self.owner,
                "expires": self.expires,
                "term": self.term,
                "now": now,
                "ttl": ttl,
            }

    def release(self, node_id: str) -> Dict:
        with self._lock:
            now = int(self.clock())
            if not self.owner or (node_id and self.owner != str(node_id)[:64]):
                return {"released": False, "owner": self.owner, "now": now}
            previous = self.owner
            self.owner = ""
            self.expires = 0
            self.term += 1
            self._save()
            return {"released": True, "previous": previous, "now": now}


class WitnessHandler(BaseHTTPRequestHandler):
    """Three routes, no framework."""

    store: LeaseStore = None  # type: ignore[assignment]
    secret: str = ""
    server_version = "abuseipdb-witness/1.5"
    sys_version = ""

    def _send(self, code: int, payload: Dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorised(self) -> bool:
        if not self.secret:
            return True
        provided = self.headers.get("X-Coord-Secret", "")
        import hmac

        return hmac.compare_digest(self.secret, provided or "")

    def _body(self) -> Optional[Dict]:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if self.path.split("?")[0] != STATUS_PATH:
            self._send(404, {"error": "not found"})
            return
        self._send(200, dict(self.store.snapshot(), role="witness"))

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        path = self.path.split("?")[0]
        if path not in (LEASE_PATH, RELEASE_PATH):
            self._send(404, {"error": "not found"})
            return
        if not self._authorised():
            self._send(403, {"error": "forbidden"})
            return
        payload = self._body()
        if payload is None:
            self._send(400, {"error": "bad request"})
            return
        node_id = str(payload.get("node_id") or "")
        if path == LEASE_PATH:
            answer = self.store.acquire(node_id, payload.get("ttl", 900))
            self._send(200 if answer.get("granted") else 409, answer)
        else:
            self._send(200, self.store.release(node_id))

    def log_message(self, fmt: str, *args) -> None:
        return


def make_server(cfg, store: Optional[LeaseStore] = None) -> ThreadingHTTPServer:
    """Build the HTTP(S) server from a configuration object.

    Reuses the reporter configuration: ``coord_bind``/``coord_port`` decide where it
    listens, ``tls_cert``/``tls_key`` switch it to HTTPS, ``shared_secret_file``
    protects the lease.
    """
    from .coordination import _ssl_context, load_secret

    handler = type(
        "BoundWitnessHandler",
        (WitnessHandler,),
        {
            "store": store
            or LeaseStore(getattr(cfg, "lease_state_path", "") or "", clock=time.time),
            "secret": load_secret(getattr(cfg, "shared_secret_file", "")),
        },
    )
    server = ThreadingHTTPServer(
        (str(getattr(cfg, "coord_bind", "127.0.0.1")), int(getattr(cfg, "coord_port", 8765))),
        handler,
    )
    context = _ssl_context(cfg, server_side=True)
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.daemon_threads = True
    return server


def serve(cfg, store: Optional[LeaseStore] = None) -> None:
    from . import log

    server = make_server(cfg, store=store)
    log.log(
        cfg,
        "witness: listening on %s:%d (mode=%s, tls=%s)"
        % (
            getattr(cfg, "coord_bind", ""),
            int(getattr(cfg, "coord_port", 0)),
            getattr(cfg, "coordination_mode", ""),
            "yes" if getattr(cfg, "tls_cert", "") else "no",
        ),
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
