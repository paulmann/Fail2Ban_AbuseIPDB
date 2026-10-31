"""Leader/follower coordination: report deduplication and ban propagation.

One AbuseIPDB account, several protected hosts.  The **leader** is the only node
that talks to the API; the others push their ban events to it.  Every sync is a
two-way exchange:

```
follower ──POST /v1/sync {node_id, events, since}──► leader
         ◄──── {accepted, inserted, rejected,
                recently_reported: {ip: ts},      # do not report these again
                to_ban: [{ip, jail}],             # ban them here as well
                next_since} ─────────────────────
```

* ``recently_reported`` keeps a node from reporting an address the cluster has
  already reported inside the AbuseIPDB window - also right after a role change.
* ``to_ban`` propagates a ban seen on one node to the others, so an attacker who
  moves between hosts meets the same firewall everywhere.
* ``since`` is the follower's cursor: the leader answers with the bans created
  after it and never echoes a ban back to the node it came from.

Roles: ``none`` (standalone, the default), ``leader`` (reports and serves
``abuseipdb-coord``), ``follower`` (pushes, applies remote bans, never reports).

Failover stays **manual** on purpose.  A lease on shared storage looks automatic
but cannot be made safe without an atomic compare-and-swap: two nodes renewing a
file lease concurrently both believe they are the leader, and a split brain
spends the account budget twice and breaks the per-IP interval. Moving the key
and flipping ``mode`` is slower and always correct.

Security notes: the shared secret is compared in constant time; the endpoint is
plain HTTP by design (bind it privately or put TLS in front); remote bans are
filtered against ``[ignore] ranges`` and the node's own ``server_ip``, capped per
run, and can never be un-bans.
"""
from __future__ import annotations

import dataclasses
import hmac
import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import db, iputil, log
from .config import Config

MODE_NONE = "none"
MODE_LEADER = "leader"
MODE_FOLLOWER = "follower"

#: meta key holding the follower's sync cursor
CURSOR_KEY = "coord_since"
#: meta key caching the jail list this node can actually ban in
JAILS_KEY = "coord_jails"
#: how long the cached jail list is trusted, seconds
JAILS_TTL = 3600

#: Upper bound on how many events one push may carry (follower side).
MAX_EVENTS_PER_PUSH = 500
#: Upper bound on how many events the leader accepts in one request.
MAX_EVENTS_PER_REQUEST = 5000
#: Upper bound on how many remote bans one sync may apply (safety, per run).
MAX_REMOTE_BANS = 200
#: Default HTTP timeout for coordination calls, seconds.
DEFAULT_TIMEOUT = 20
#: A ban older than this is not worth propagating (the attacker is long gone).
MAX_PROPAGATION_AGE = 2 * 3600
USER_AGENT = "fail2ban-abuseipdb-coord/1.4"
#: Jail names fail2ban accepts; anything else is never passed to the CLI.
JAIL_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
#: Runner signature: (argv, timeout) -> (returncode, stdout, stderr)
Runner = Callable[..., Tuple[int, str, str]]


@dataclasses.dataclass
class SyncResult:
    """Outcome of one follower sync."""

    pushed: int = 0
    banned: int = 0
    merged: int = 0
    pending: int = 0
    reason: str = ""
    next_since: int = 0


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


def _local_jails(
    cfg: Config, conn, runner: Optional[Runner] = None, now: Optional[int] = None
) -> List[str]:
    """Jails this node can actually ban in, cached for :data:`JAILS_TTL`.

    A follower that does not have a jail cannot apply a ban for it:
    ``fail2ban-client`` answers ``NOK: unable to find jail``, which becomes a logged
    error per address on every sync.  Declaring the list keeps the leader from
    sending what would only fail here.  An empty list means "unknown"
    (fail2ban-client missing or no output) and makes the leader send everything,
    exactly as in 1.4.0.
    """
    moment = int(now if now is not None else time.time())
    cached = db.get_meta(conn, JAILS_KEY, "")
    if cached:
        stamp, _, names = cached.partition("|")
        try:
            fresh = moment - int(stamp) < JAILS_TTL
        except ValueError:
            fresh = False
        if fresh:
            return [name for name in names.split(",") if name]
    run = runner or _fail2ban_runner
    code, out, _ = run(["fail2ban-client", "status"], 12)
    if code != 0 or not out:
        return []
    names: List[str] = []
    for line in out.splitlines():
        if "Jail list:" in line:
            _, _, tail = line.partition("Jail list:")
            names = [
                item.strip() for item in tail.replace("\t", " ").split(",") if item.strip()
            ]
            break
    names = [name for name in names if JAIL_RE.match(name)]
    db.set_meta(conn, JAILS_KEY, "%d|%s" % (moment, ",".join(names)))
    return names


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

    def _url_ok(self) -> bool:
        parts = urllib.parse.urlsplit(self.url)
        return parts.scheme.lower() in ("http", "https") and bool(parts.netloc)

    def sync(
        self, node_id: str, events: Sequence[Dict], since: int = 0, jails: Optional[Sequence[str]] = None
    ) -> Tuple[bool, Dict]:
        """POST one sync request.  Returns ``(delivered, response)``."""
        if not self._url_ok():
            return False, {"error": "leader_url must be an http(s) URL, got %r" % (self.url,)}
        if not self.secret:
            return False, {"error": "shared secret is empty"}
        payload = {
            "node_id": str(node_id or "unknown"),
            "events": list(events),
            "since": int(since or 0),
        }
        if jails:
            payload["jails"] = [str(name) for name in jails]
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            "%s/v1/sync" % self.url,
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
                return response.status == 200, _json_or_empty(body)
        except urllib.error.HTTPError as error:
            try:
                detail = error.read().decode("utf-8", "replace")[:300]
            except Exception:  # noqa: BLE001 - the body is best effort
                detail = ""
            return False, {"error": "HTTP %s: %s" % (error.code, detail)}
        except Exception as error:  # noqa: BLE001 - transport errors are reported as-is
            return False, {"error": repr(error)}

    def get_status(self) -> Optional[Dict]:
        """Fetch the leader's status document (``None`` on any failure)."""
        if not self._url_ok():
            return None
        request = urllib.request.Request(
            "%s/v1/status" % self.url,
            headers={"X-Coord-Secret": self.secret, "User-Agent": USER_AGENT},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return _json_or_empty(response.read().decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001 - status is informational only
            return None


def _json_or_empty(text: str) -> Dict:
    try:
        payload = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _secret_matches(expected: str, provided: Optional[str]) -> bool:
    """Constant-time comparison; an unset secret never matches."""
    if not expected or not provided:
        return False
    return hmac.compare_digest(str(expected), str(provided))


def _fail2ban_runner(argv: Sequence[str], timeout: int = 12) -> Tuple[int, str, str]:
    """Run ``fail2ban-client`` without a shell; returns (rc, stdout, stderr)."""
    try:
        result = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return int(result.returncode), result.stdout or "", result.stderr or ""
    except (OSError, subprocess.SubprocessError) as error:
        return 1, "", repr(error)


def apply_remote_bans(
    cfg: Config,
    items: Sequence,
    limit: Optional[int] = None,
    runner: Optional[Runner] = None,
) -> int:
    """Ban addresses a peer reported.  Returns how many were applied.

    Rails, in order: the address must parse, must not be in ``[ignore] ranges``,
    must not be this node's own ``server_ip``, the jail name must look like a jail
    name, and at most ``limit`` bans are applied per run (default
    ``max_remote_bans_per_run``, hard ceiling :data:`MAX_REMOTE_BANS`).  The
    function never un-bans anything.
    """
    run = runner or _fail2ban_runner
    cap = int(limit if limit is not None else getattr(cfg, "max_remote_bans_per_run", 20) or 20)
    cap = max(1, min(cap, MAX_REMOTE_BANS))
    own = str(getattr(cfg, "server_ip", "") or "").strip()

    applied = 0
    for item in list(items or []):
        if applied >= cap:
            log.log(cfg, "coord: remote ban cap reached (%d), rest deferred" % cap)
            break
        if not isinstance(item, dict):
            continue
        text = str(item.get("ip") or "").strip()
        jail = str(item.get("jail") or "").strip()
        address = iputil.parse_ip(text)
        if address is None:
            continue
        if iputil.is_ignored(address, cfg.ignore_ranges):
            log.log(cfg, "coord: skip remote ban of ignored address %s" % text)
            continue
        if own and text == own:
            log.log(cfg, "coord: skip remote ban of own server_ip %s" % text)
            continue
        if not JAIL_RE.match(jail):
            log.log(cfg, "coord: skip remote ban with invalid jail %r" % (jail,))
            continue
        code, out, err = run(["fail2ban-client", "set", jail, "banip", text])
        if code == 0:
            applied += 1
            log.log(cfg, "coord: remote ban applied %s in %s" % (text, jail))
        else:
            # "already banned" is the normal answer for a repeated sync
            detail = (err or out or "").strip().splitlines()
            log.log(
                cfg,
                "coord: remote ban not applied %s in %s: rc=%s %s"
                % (text, jail, code, (detail[-1] if detail else "")[:160]),
            )
    return applied


def pending_batch(cfg: Config, conn) -> List[Dict[str, int]]:
    """Events this follower still has to deliver (used by dry-run too)."""
    limit = min(int(getattr(cfg, "push_batch_size", 50) or 50), MAX_EVENTS_PER_PUSH)
    return events_to_payload(db.pending_events_for_push(conn, limit))


def follower_sync(
    cfg: Config, conn, runner: Optional[Runner] = None, now: Optional[int] = None
) -> SyncResult:
    """Follower path: one two-way sync with the leader."""
    result = SyncResult()
    moment = int(now if now is not None else time.time())
    secret = load_secret(getattr(cfg, "shared_secret_file", ""))
    if not secret:
        result.reason = "missing shared secret (%s)" % (getattr(cfg, "shared_secret_file", ""),)
        result.pending = db.unpushed_count(conn)
        return result
    if not getattr(cfg, "leader_url", ""):
        result.reason = "missing leader_url"
        result.pending = db.unpushed_count(conn)
        return result

    since = int(db.get_meta(conn, CURSOR_KEY, "0") or 0)
    if since <= 0:
        # First sync: adopt the leader's *recent* bans (bounded by
        # MAX_PROPAGATION_AGE), not the whole history of the queue.
        since = moment - MAX_PROPAGATION_AGE
        db.set_meta(conn, CURSOR_KEY, since)

    rows = db.pending_events_for_push(
        conn, min(int(getattr(cfg, "push_batch_size", 50) or 50), MAX_EVENTS_PER_PUSH)
    )
    jails = _local_jails(cfg, conn, runner=runner, now=moment) if getattr(cfg, "sync_bans", True) else []
    client = LeaderClient(cfg.leader_url, secret, timeout=int(cfg.timeout))
    delivered, response = client.sync(
        cfg.node_id or "unknown", events_to_payload(rows), since, jails=jails
    )
    if not delivered:
        result.reason = str(response.get("error") or "sync failed")[:200]
        result.pending = db.unpushed_count(conn)
        log.log(cfg, "coord: sync failed: %s" % result.reason)
        return result

    if rows:
        result.pushed = db.mark_pushed(conn, [row["id"] for row in rows])

    if getattr(cfg, "sync_bans", True):
        result.banned = apply_remote_bans(cfg, response.get("to_ban") or [], runner=runner)

    result.merged = db.merge_reported(
        conn, response.get("recently_reported") or {}, source="leader", now=moment
    )
    next_since = int(response.get("next_since") or moment)
    if next_since > 0:
        db.set_meta(conn, CURSOR_KEY, next_since)
        result.next_since = next_since

    result.pending = db.unpushed_count(conn)
    result.reason = "ok"
    log.log(
        cfg,
        "coord: sync ok pushed=%d remote_bans=%d cache+%d pending=%d"
        % (result.pushed, result.banned, result.merged, result.pending),
    )
    return result


def push_pending(cfg: Config, conn) -> Tuple[int, str]:
    """Backward-compatible wrapper around :func:`follower_sync` (1.3 callers)."""
    result = follower_sync(cfg, conn)
    return result.pushed, result.reason


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
                origin=str(node_id or "")[:64],
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


def sync_response(
    cfg: Config,
    node_id: str,
    events: Sequence,
    since: int = 0,
    jails: Optional[Sequence[str]] = None,
    now: Optional[int] = None,
) -> Dict:
    """Full leader answer for one follower sync.

    ``jails`` is what the follower says it can ban in; when it is known, bans for
    any other jail are left out of ``to_ban`` - that node would only answer
    ``unable to find jail``.  An empty or missing list keeps the old behaviour
    (send everything), so a 1.4.0 follower is unaffected.
    """
    moment = int(now if now is not None else time.time())
    counts = accept_events(cfg, events, node_id)
    window = max(int(getattr(cfg, "peer_dedupe_window", 900) or 900), 900)
    wanted = {str(name) for name in jails or () if JAIL_RE.match(str(name))}
    limit = int(getattr(cfg, "max_sync_bans", 50) or 50)
    conn = db.connect(cfg.db_path)
    try:
        recently = db.recent_reports(conn, moment - window)
        oldest = max(moment - MAX_PROPAGATION_AGE, int(since or 0))
        fetched = db.bans_since(
            conn,
            since=oldest,
            exclude_origin=node_id,
            limit=limit * 4 if wanted else limit,
        )
    finally:
        conn.close()
    if wanted:
        fetched = [item for item in fetched if item["jail"] in wanted][:limit]
    payload = dict(counts)
    payload.update(
        {
            "ok": True,
            "node_id": cfg.node_id,
            "version": _version(),
            "recently_reported": recently,
            "to_ban": fetched,
            "next_since": moment,
        }
    )
    return payload


def _version() -> str:
    from . import __version__

    return __version__
