"""Leader/follower coordination for one shared AbuseIPDB account.

Why: AbuseIPDB limits are **per account**, not per host.  When several servers
are protected by fail2ban but share one API key, each of them would drain its own
queue and the account budget would be spent `n` times faster, with the per-IP
interval violated between hosts.

With coordination enabled, exactly one node reports:

* ``mode = leader``  - reports as usual **and** accepts events pushed by others;
* ``mode = follower`` - never touches the API; it pushes its queued events to the
  leader over a small authenticated HTTP endpoint and marks them delivered;
* ``mode = none``    - the default: every node reports for itself (1.2.x
  behaviour, fully backward compatible).

Design constraints, in order of importance:

* the ban path never blocks (a follower's push happens in the worker, not in the
  fail2ban action);
* the API key exists only on the leader - followers do not even need one;
* no new dependencies: ``urllib`` on the client, ``http.server`` on the leader;
* failover is manual by design: move the key, flip ``mode``, restart the timer.
  There is no election, no shared lease and no hidden consensus.

Security: the shared secret is a long random string read from a file (mode 600).
It travels in the ``X-Coord-Secret`` header and is compared in constant time.
The endpoint speaks plain HTTP, so bind it to a trusted network or put it behind
a reverse proxy with TLS - see ``docs/COORDINATION.md``.
"""
from __future__ import annotations

import hmac
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Sequence, Tuple

from . import db, iputil, log
from .config import Config

MODE_NONE = "none"
MODE_LEADER = "leader"
MODE_FOLLOWER = "follower"

#: Upper bound on how many events one push may carry (follower side).
MAX_EVENTS_PER_PUSH = 500
#: Upper bound on how many events the leader accepts in one request.
MAX_EVENTS_PER_REQUEST = 5000
#: Default HTTP timeout for coordination calls, seconds.
DEFAULT_TIMEOUT = 15
USER_AGENT = "fail2ban-abuseipdb-coord/1.3"


def mode_of(cfg: Config) -> str:
    """Effective coordination role of this node."""
    return str(getattr(cfg, "coordination_mode", MODE_NONE) or MODE_NONE).strip().lower()


def is_follower(cfg: Config) -> bool:
    return mode_of(cfg) == MODE_FOLLOWER


def is_leader(cfg: Config) -> bool:
    return mode_of(cfg) == MODE_LEADER


def load_secret(path: str) -> str:
    """Read the shared secret; an empty string means "not configured"."""
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def events_to_payload(rows: Sequence) -> List[Dict[str, int]]:
    """Convert pending event rows into a JSON-serialisable list."""
    payload: List[Dict[str, int]] = []
    for row in rows:
        payload.append(
            {
                "ip": str(row["ip"]),
                "jail": str(row["jail"]),
                "event_time": int(row["event_time"]),
                "bantime": int(row["bantime"] or 0),
                "failures": int(row["failures"] or 0),
            }
        )
    return payload


class LeaderClient:
    """HTTP client a follower uses to reach its leader."""

    def __init__(self, url: str, secret: str, timeout: int = DEFAULT_TIMEOUT):
        self.url = str(url or "").rstrip("/")
        self.secret = secret
        self.timeout = int(timeout or DEFAULT_TIMEOUT)

    def _scheme_ok(self) -> bool:
        scheme = urllib.parse.urlsplit(self.url).scheme.lower()
        return scheme in ("http", "https") and bool(urllib.parse.urlsplit(self.url).netloc)

    def push_events(self, node_id: str, events: Sequence[Dict]) -> Tuple[bool, str]:
        """POST one batch of events.  Returns ``(delivered, message)``."""
        if not events:
            return True, "empty"
        if not self._scheme_ok():
            return False, "leader_url must be an http(s) URL, got %r" % (self.url,)
        if not self.secret:
            return False, "shared secret is empty"
        payload = {"node_id": str(node_id or "unknown"), "events": list(events)}
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            "%s/v1/push" % self.url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "X-Coord-Secret": self.secret,
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", "replace")
                return response.status == 200, body[:200]
        except urllib.error.HTTPError as error:
            try:
                detail = error.read().decode("utf-8", "replace")[:200]
            except Exception:  # noqa: BLE001 - the body is best effort
                detail = ""
            return False, "HTTP %s: %s" % (error.code, detail)
        except Exception as error:  # noqa: BLE001 - transport errors are reported as-is
            return False, repr(error)

    def get_status(self) -> Optional[Dict]:
        """Fetch the leader's status document (``None`` on any failure)."""
        if not self._scheme_ok():
            return None
        request = urllib.request.Request(
            "%s/v1/status" % self.url,
            headers={"X-Coord-Secret": self.secret, "User-Agent": USER_AGENT},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001 - status is informational only
            return None


def _secret_matches(expected: str, provided: Optional[str]) -> bool:
    """Constant-time comparison; an unset secret never matches."""
    if not expected or not provided:
        return False
    return hmac.compare_digest(str(expected), str(provided))


def pending_batch(cfg: Config, conn) -> List[Dict[str, int]]:
    """Events this follower still has to deliver (used by dry-run too)."""
    limit = min(int(getattr(cfg, "push_batch_size", 50) or 50), MAX_EVENTS_PER_PUSH)
    return events_to_payload(db.pending_events_for_push(conn, limit))


def push_pending(cfg: Config, conn) -> Tuple[int, str]:
    """Follower path: deliver one batch of pending events to the leader.

    Returns ``(marked, reason)``.  ``marked`` is the number of events the leader
    acknowledged; on any failure it stays 0 and nothing is marked, so the next
    tick retries the same events.
    """
    secret = load_secret(getattr(cfg, "shared_secret_file", ""))
    if not secret:
        return 0, "missing shared secret (%s)" % (getattr(cfg, "shared_secret_file", ""),)
    if not getattr(cfg, "leader_url", ""):
        return 0, "missing leader_url"
    rows = db.pending_events_for_push(
        conn, min(int(getattr(cfg, "push_batch_size", 50) or 50), MAX_EVENTS_PER_PUSH)
    )
    if not rows:
        return 0, "nothing to push"

    client = LeaderClient(cfg.leader_url, secret, timeout=int(cfg.timeout))
    delivered, message = client.push_events(cfg.node_id or "unknown", events_to_payload(rows))
    if not delivered:
        log.log(cfg, "coord: push of %d events failed: %s" % (len(rows), message))
        return 0, message
    marked = db.mark_pushed(conn, [row["id"] for row in rows])
    log.log(
        cfg,
        "coord: pushed %d events to leader %s (%s)" % (marked, cfg.leader_url, message),
    )
    return marked, "ok"


def accept_events(cfg: Config, events: Sequence, node_id: str = "") -> Dict[str, int]:
    """Leader path: validate pushed events and queue them locally.

    The leader applies **the same** filters as its own enqueue path (invalid
    address, ignored ranges, skipped jails), so a follower cannot smuggle in an
    address the leader would never report.  Duplicates collapse through the
    normal 5-minute window in :func:`db.enqueue`.
    """
    accepted = inserted = rejected = 0
    conn = db.connect(cfg.db_path)
    try:
        for event in list(events)[:MAX_EVENTS_PER_REQUEST]:
            accepted += 1
            if not isinstance(event, dict):
                rejected += 1
                continue
            address = iputil.parse_ip(str(event.get("ip", "")))
            jail = str(event.get("jail", "") or "").strip()
            if address is None or not jail:
                rejected += 1
                continue
            if jail in cfg.skip_jails:
                rejected += 1
                continue
            if iputil.is_ignored(address, cfg.ignore_ranges):
                rejected += 1
                continue
            event_time = int(event.get("event_time") or 0) or None
            if db.enqueue(
                conn,
                str(address),
                jail,
                event_time=event_time,
                bantime=int(event.get("bantime") or 0),
                failures=int(event.get("failures") or 0),
            ):
                inserted += 1
    finally:
        conn.close()
    log.log(
        cfg,
        "coord: accepted %d events from %s (%d new, %d rejected)"
        % (accepted, node_id or "unknown", inserted, rejected),
    )
    return {"accepted": accepted, "inserted": inserted, "rejected": rejected}
