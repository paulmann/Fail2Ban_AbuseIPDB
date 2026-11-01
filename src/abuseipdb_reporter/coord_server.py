"""The leader-side endpoint that accepts events pushed by follower nodes.

It is deliberately tiny: two routes, one shared secret, the standard library.
The endpoint never reports anything itself - it only queues the events into the
leader's own SQLite queue, where the normal worker picks them up and applies the
account-wide rate limits.

Run it next to the worker:

    abuseipdb-coord --check          # validate secret and settings, then exit
    abuseipdb-coord                  # serve on coord_bind:coord_port

The endpoint is meant for a trusted network: see ``docs/COORDINATION.md`` for the
firewall, TLS and failover rules.  HTTPS is available without extra packages -
set ``tls_cert``/``tls_key`` and the same socket is wrapped with the standard
library ``ssl`` module.  ``GET /v1/health`` answers without the shared secret and
is what a monitoring system should poll.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

from . import __version__, coordination, db, log, metrics
from .config import Config, load_config

#: Refuse requests larger than this (a push batch is a few kilobytes).
MAX_BODY_BYTES = 1024 * 1024
#: Route names, kept short because they are typed into firewalls and proxies.
SYNC_PATH = "/v1/sync"
#: 1.3 name of the same endpoint; kept so an older follower keeps working.
PUSH_PATH = "/v1/push"
STATUS_PATH = "/v1/status"
HEALTH_PATH = coordination.HEALTH_PATH
#: How long the lease answer is reused inside the endpoint, seconds.
LEASE_CACHE_TTL = 60


class CoordHandler(BaseHTTPRequestHandler):
    """Authenticated request handler; the server instance carries cfg and secret."""

    cfg: Config  # set on the bound subclass
    secret: str = ""
    server_version = "abuseipdb-coord/" + __version__
    sys_version = ""

    # -- helpers ---------------------------------------------------------
    def _path(self) -> str:
        return self.path.split("?", 1)[0]

    def _authorised(self) -> bool:
        return coordination._secret_matches(self.secret, self.headers.get("X-Coord-Secret"))

    def _send(self, code: int, payload: Dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body_length(self) -> Optional[int]:
        raw = self.headers.get("Content-Length")
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    # -- routes ----------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        if self._path() not in (SYNC_PATH, PUSH_PATH):
            self._send(404, {"error": "not found"})
            return
        if not self._authorised():
            self._send(403, {"error": "forbidden"})
            return
        if not self._may_lead():
            self._send(
                409,
                {
                    "error": "this node is not the leader right now",
                    "lease": self._lease(),
                },
            )
            return
        length = self._body_length()
        if length is None or length <= 0:
            self._send(400, {"error": "empty body"})
            return
        if length > MAX_BODY_BYTES:
            self._send(413, {"error": "body too large"})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._send(400, {"error": "bad json"})
            return
        if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
            self._send(400, {"error": "events must be a list"})
            return
        try:
            since = int(payload.get("since") or 0)
        except (TypeError, ValueError):
            since = 0
        raw_jails = payload.get("jails")
        jails = [str(name) for name in raw_jails] if isinstance(raw_jails, list) else None
        answer = coordination.sync_response(
            self.cfg,
            str(payload.get("node_id") or ""),
            payload["events"],
            since=since,
            jails=jails,
        )
        self._send(200, answer)

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        path = self._path()
        if path == HEALTH_PATH:
            # No secret: a monitoring system must be able to ask "are you alive"
            # without holding cluster credentials.  Nothing sensitive is returned.
            self._send(200, dict(coordination.health_document(self.cfg), lease=self._lease()))
            return
        if path != STATUS_PATH:
            self._send(404, {"error": "not found"})
            return
        if not self._authorised():
            self._send(403, {"error": "forbidden"})
            return
        self._send(200, leader_status(self.cfg))

    def _may_lead(self) -> bool:
        """A candidate in ``auto`` mode must hold the lease before it accepts work."""
        if coordination.mode_of(self.cfg) != coordination.MODE_AUTO:
            return True
        return bool(self._lease().get("effective") == coordination.MODE_LEADER)

    def _lease(self) -> Dict:
        """Cached view of the failover lease (empty when failover is manual)."""
        cache = getattr(self.server, "lease_cache", None)
        now = int(time.time())
        if cache and now - int(cache.get("ts", 0)) < LEASE_CACHE_TTL:
            return cache.get("value", {})
        value: Dict = {}
        if str(getattr(self.cfg, "failover", "none") or "none").lower() == "witness":
            conn = db.connect(self.cfg.db_path)
            try:
                value = coordination.role_summary(self.cfg, conn=conn, now=now)
            except Exception as error:  # noqa: BLE001 - health must answer anyway
                value = {"error": repr(error)}
            finally:
                conn.close()
        self.server.lease_cache = {"ts": now, "value": value}  # type: ignore[attr-defined]
        return value

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003 - stdlib hook
        """Silence the default per-request stderr log; the project log decides."""
        return


def leader_status(cfg: Config) -> Dict[str, object]:
    """Small status document a follower can query with the same secret."""
    conn = db.connect(cfg.db_path)
    try:
        snapshot = metrics.build(cfg, status_path=getattr(cfg, "status_path", ""))
        return {
            "ok": True,
            "role": "leader",
            "mode": coordination.mode_of(cfg),
            "effective": coordination.effective_role(cfg, conn=conn),
            "node_id": cfg.node_id,
            "version": __version__,
            "tls": bool(getattr(cfg, "tls_cert", "")),
            "pending": db.pending_count(conn),
            "unpushed": db.unpushed_count(conn),
            "sync_cursor": int(db.get_meta(conn, coordination.CURSOR_KEY, "0") or 0),
            "reported_cache": int(snapshot.get("reported_cache_entries", 0)),
            "reports_today": int(snapshot.get("reports_today", 0)),
            "accepted_total": int(snapshot.get("accepted_total", 0)),
            "rejected_total": int(snapshot.get("rejected_total", 0)),
            "lease": coordination.role_summary(cfg, conn=conn).get("lease", {}),
        }
    finally:
        conn.close()


def make_server(
    cfg: Config, secret: Optional[str] = None, host: Optional[str] = None, port: Optional[int] = None
) -> ThreadingHTTPServer:
    """Build (but do not start) the endpoint; useful for tests and for systemd."""
    if secret is None:
        secret = coordination.load_secret(cfg.shared_secret_file)
    if not secret:
        raise ValueError(
            "coordination secret is missing: %s (see docs/COORDINATION.md)"
            % (cfg.shared_secret_file,)
        )
    handler = type("BoundCoordHandler", (CoordHandler,), {"cfg": cfg, "secret": secret})
    bind = host or cfg.coord_bind
    number = int(port if port is not None else cfg.coord_port)
    server = ThreadingHTTPServer((bind, number), handler)
    server.daemon_threads = True
    context = coordination._ssl_context(cfg, server_side=True)
    if context is not None:
        # Wrap after bind: the certificate is only loaded when both files exist.
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.tls = True  # type: ignore[attr-defined]
    else:
        server.tls = False  # type: ignore[attr-defined]
    return server


def serve(cfg: Config, host: Optional[str] = None, port: Optional[int] = None) -> int:
    """Serve until interrupted; returns a process exit code."""
    server = make_server(cfg, host=host, port=port)
    address = server.server_address
    log.log(
        cfg,
        "coord: leader endpoint on %s:%s%s (mode=%s, node=%s)"
        % (
            address[0],
            address[1],
            " with TLS" if getattr(server, "tls", False) else "",
            coordination.mode_of(cfg),
            cfg.node_id or "unset",
        ),
    )
    if coordination.mode_of(cfg) != coordination.MODE_LEADER:
        log.log(
            cfg,
            "coord: warning: mode is %r, so this node will not report pushed events"
            % coordination.mode_of(cfg),
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive use
        log.log(cfg, "coord: stopping on interrupt")
    finally:
        server.server_close()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="abuseipdb-coord",
        description="Leader endpoint that accepts events pushed by follower nodes.",
    )
    parser.add_argument("--config", default=None, help="path to reporter.conf")
    parser.add_argument("--bind", default=None, help="override coord_bind")
    parser.add_argument("--port", type=int, default=None, help="override coord_port")
    parser.add_argument(
        "--check", action="store_true", help="validate the configuration and exit"
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    mode = coordination.mode_of(cfg)
    bind = args.bind or cfg.coord_bind
    port = int(args.port or cfg.coord_port)

    if args.check:
        secret = coordination.load_secret(cfg.shared_secret_file)
        print("mode: %s" % mode)
        print("node_id: %s" % (cfg.node_id or "(unset)"))
        print("bind: %s:%d" % (bind, port))
        print(
            "secret: %s"
            % ("present" if secret else "MISSING (%s)" % cfg.shared_secret_file)
        )
        return 0 if secret else 2

    if mode == coordination.MODE_FOLLOWER:
        print(
            "error: this node is a follower; the endpoint belongs to the leader "
            "(set [coordination] mode = leader there)",
            file=sys.stderr,
        )
        return 2
    try:
        return serve(cfg, host=args.bind, port=args.port)
    except ValueError as error:
        print("error: %s" % error, file=sys.stderr)
        return 1
    except OSError as error:
        print("error: cannot bind %s:%d: %s" % (bind, port, error), file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
