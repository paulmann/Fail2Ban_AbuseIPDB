"""State snapshot: what the queue, the cluster role and the last run look like now.

Two consumers need the same numbers and must never disagree:

* ``abuseipdb-report --metrics`` prints a Prometheus text-exposition document to
  stdout - that is what a monitoring agent (Zabbix ``UserParameter``, node_exporter
  textfile collector, ``curl`` in a check script) reads;
* the reporter writes the same document next to the queue on every run, so a
  ``textfile`` collector picks it up without any extra service.

The snapshot is read-only: opening a missing database creates an empty queue, which
is exactly what a freshly installed host should report (zeros), and every field is
computed in one place so the numbers are consistent with each other.
"""
from __future__ import annotations

import datetime
import json
import os
import time
from typing import Any, Dict, List, Optional

from . import __version__, coordination, db

#: Metric name prefix; the same as :data:`abuseipdb_reporter.status.METRIC_PREFIX`.
PREFIX = "abuseipdb_reporter"


def _iso(ts: int) -> str:
    """Local ISO timestamp; a clock far in the past must not break monitoring.

    Windows refuses some pre-1980 timestamps with ``OSError: [Errno 22]``, and a
    snapshot is also rendered in tests with a synthetic ``now``, so the UTC form is
    the fallback instead of an exception.
    """
    try:
        return datetime.datetime.fromtimestamp(int(ts)).astimezone().isoformat(timespec="seconds")
    except (OSError, OverflowError, ValueError):
        moment = datetime.datetime.fromtimestamp(int(ts), tz=datetime.timezone.utc)
        return moment.isoformat(timespec="seconds")


def _int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def read_last_run(path: str) -> Dict[str, Any]:
    """Last run document written by the reporter (``{}`` when absent or broken)."""
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


#: Prefixes stripped when a caller uses the Prometheus name instead of the key.
NAME_PREFIXES = (PREFIX + "_", "coord_")


def name_candidates(name: str) -> List[str]:
    """All snapshot keys one metric name may mean, most specific first.

    Monitoring agents speak the Prometheus name (``coord_accepted_total``), the
    snapshot stores the shorter key (``accepted_total``).  Accepting both here keeps
    the two spellings from drifting apart - a mismatch used to answer "unknown
    metric" for nine of the twenty-one items.
    """
    text = str(name or "").strip()
    found: List[str] = []

    def push(value: str) -> None:
        if value and value not in found:
            found.append(value)

    push(text)
    for prefix in NAME_PREFIXES:
        if text.startswith(prefix):
            push(text[len(prefix):])
    return found


def read_snapshot(path: str) -> Dict[str, Any]:
    """Last JSON snapshot written by the reporter (``{}`` when absent or broken)."""
    return read_last_run(path)


def build(
    cfg,
    now: Optional[int] = None,
    status_path: str = "",
    leader_state: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Collect one snapshot.

    ``leader_state`` is passed in by the caller when it has just asked the leader
    (``--coord-status``); the snapshot itself never performs network calls, so it
    stays usable from a monitoring agent with a hard timeout.
    """
    moment = int(now if now is not None else time.time())
    snapshot: Dict[str, Any] = {
        "ts": moment,
        "iso": _iso(moment),
        "version": __version__,
        "mode": coordination.mode_of(cfg),
        "node_id": str(getattr(cfg, "node_id", "") or ""),
        "leader_url": str(getattr(cfg, "leader_url", "") or ""),
        "enabled": bool(getattr(cfg, "enabled", True)),
        "sync_bans": bool(getattr(cfg, "sync_bans", True)),
        "failover": str(getattr(cfg, "failover", "none") or "none"),
        "tls": bool(getattr(cfg, "tls_cert", "")),
    }
    counters = (
        "pending_events",
        "unpushed_events",
        "reported_cache_entries",
        "cursor",
        "last_sync",
        "last_sync_ok",
        "sync_failures",
        "lease_held",
        "lease_expires",
        "accepted_total",
        "inserted_total",
        "rejected_total",
        "remote_bans_total",
        "reports_today",
    )
    conn = None
    try:
        conn = db.connect(cfg.db_path)
        snapshot["pending_events"] = db.pending_count(conn)
        snapshot["unpushed_events"] = db.unpushed_count(conn)
        snapshot["reported_cache_entries"] = _int(
            conn.execute("SELECT COUNT(*) FROM reported_cache").fetchone()[0]
        )
        snapshot["cursor"] = _int(db.get_meta(conn, coordination.CURSOR_KEY, "0"))
        snapshot["last_sync"] = _int(db.get_meta(conn, coordination.LAST_SYNC_KEY, "0"))
        snapshot["last_sync_ok"] = _int(db.get_meta(conn, coordination.LAST_SYNC_OK_KEY, "0"))
        snapshot["sync_failures"] = _int(db.get_meta(conn, coordination.SYNC_FAILURES_KEY, "0"))
        snapshot["lease_owner"] = db.get_meta(conn, coordination.LEASE_KEY, "")
        snapshot["lease_held"] = 1 if snapshot["lease_owner"] == (cfg.node_id or "") else 0
        snapshot["lease_expires"] = _int(db.get_meta(conn, coordination.LEASE_EXPIRES_KEY, "0"))
        snapshot["accepted_total"] = _int(db.get_meta(conn, coordination.ACCEPTED_KEY, "0"))
        snapshot["inserted_total"] = _int(db.get_meta(conn, coordination.INSERTED_KEY, "0"))
        snapshot["rejected_total"] = _int(db.get_meta(conn, coordination.REJECTED_KEY, "0"))
        snapshot["remote_bans_total"] = _int(db.get_meta(conn, coordination.REMOTE_BANS_KEY, "0"))
        snapshot["reports_today"] = db.reports_today(
            conn, moment, getattr(cfg, "daily_budget_timezone", "utc")
        )
    except Exception as error:  # noqa: BLE001 - a broken queue must not break monitoring
        snapshot["error"] = repr(error)
        for key in counters:
            snapshot.setdefault(key, 0)
        snapshot.setdefault("lease_owner", "")
    finally:
        if conn is not None:
            conn.close()

    last = read_last_run(status_path or getattr(cfg, "status_path", ""))
    if last:
        snapshot["last_run_ts"] = _int(last.get("ts"))
        snapshot["last_run_sent"] = _int(last.get("sent"))
        snapshot["last_run_skipped"] = _int(last.get("skipped"))
        snapshot["last_run_errors"] = _int(last.get("errors"))
        snapshot["last_run_crawlers_skipped"] = _int(last.get("crawlers_skipped"))
        snapshot["last_run_stopped"] = str(last.get("stopped", "") or "")
    else:
        snapshot["last_run_ts"] = 0
        snapshot["last_run_sent"] = snapshot["last_run_skipped"] = snapshot["last_run_errors"] = 0
        snapshot["last_run_crawlers_skipped"] = 0
        snapshot["last_run_stopped"] = ""

    snapshot["max_per_day"] = _int(getattr(cfg, "max_reports_per_day", 0))
    snapshot["budget_remaining"] = max(0, snapshot["max_per_day"] - snapshot["reports_today"])
    snapshot["last_run_age_seconds"] = (
        max(0, moment - snapshot["last_run_ts"]) if snapshot["last_run_ts"] else -1
    )
    snapshot["cursor_lag_seconds"] = (
        max(0, moment - snapshot["cursor"]) if snapshot["cursor"] else -1
    )
    snapshot["last_sync_age_seconds"] = (
        max(0, moment - snapshot["last_sync"]) if snapshot["last_sync"] else -1
    )
    if leader_state is not None:
        snapshot["leader_up"] = 1 if leader_state else 0
        snapshot["leader_role"] = str((leader_state or {}).get("role", "") or "")
    else:
        snapshot["leader_up"] = -1
        snapshot["leader_role"] = ""
    return snapshot


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def prometheus(snapshot: Dict[str, Any]) -> str:
    """Render a snapshot as a Prometheus text-exposition document."""
    lines = []

    def metric(name: str, kind: str, help_text: str, value) -> None:
        full = "%s_%s" % (PREFIX, name)
        lines.append("# HELP %s %s" % (full, help_text))
        lines.append("# TYPE %s %s" % (full, kind))
        lines.append("%s %s" % (full, value))

    lines.append(
        '%s_info{version="%s",mode="%s",node_id="%s",failover="%s",tls="%s"} 1'
        % (
            PREFIX,
            _escape(snapshot.get("version", "")),
            _escape(snapshot.get("mode", "")),
            _escape(snapshot.get("node_id", "")),
            _escape(snapshot.get("failover", "")),
            "yes" if snapshot.get("tls") else "no",
        )
    )
    metric(
        "enabled",
        "gauge",
        "1 when reporting is enabled in the configuration.",
        1 if snapshot.get("enabled") else 0,
    )
    metric(
        "sync_bans",
        "gauge",
        "1 when bans from other nodes are applied here.",
        1 if snapshot.get("sync_bans") else 0,
    )
    metric(
        "pending_events",
        "gauge",
        "Ban events waiting for an AbuseIPDB report.",
        snapshot.get("pending_events", 0),
    )
    metric(
        "unpushed_events",
        "gauge",
        "Follower: events not delivered to the leader yet.",
        snapshot.get("unpushed_events", 0),
    )
    metric(
        "reported_cache_entries",
        "gauge",
        "Addresses reported by the cluster inside the dedupe window.",
        snapshot.get("reported_cache_entries", 0),
    )
    metric(
        "reports_today",
        "gauge",
        "Reports accepted since the budget day started.",
        snapshot.get("reports_today", 0),
    )
    metric("max_per_day", "gauge", "Configured daily budget.", snapshot.get("max_per_day", 0))
    metric(
        "budget_remaining",
        "gauge",
        "Reports still allowed today.",
        snapshot.get("budget_remaining", 0),
    )
    metric(
        "last_run_timestamp_seconds",
        "gauge",
        "Unix time of the last reporter run (0 when it never ran).",
        snapshot.get("last_run_ts", 0),
    )
    metric(
        "last_run_age_seconds",
        "gauge",
        "Seconds since the last reporter run (-1 when it never ran).",
        snapshot.get("last_run_age_seconds", -1),
    )
    metric(
        "last_run_sent",
        "gauge",
        "Reports accepted during the last run.",
        snapshot.get("last_run_sent", 0),
    )
    metric(
        "last_run_skipped",
        "gauge",
        "Addresses skipped during the last run.",
        snapshot.get("last_run_skipped", 0),
    )
    metric(
        "last_run_crawlers_skipped",
        "gauge",
        "Addresses skipped during the last run because they are verified crawlers.",
        snapshot.get("last_run_crawlers_skipped", 0),
    )
    metric(
        "last_run_errors",
        "gauge",
        "Errors during the last run.",
        snapshot.get("last_run_errors", 0),
    )
    metric(
        "coord_cursor_lag_seconds",
        "gauge",
        "Follower: seconds since the leader cursor was refreshed (-1 when never).",
        snapshot.get("cursor_lag_seconds", -1),
    )
    metric(
        "coord_last_sync_timestamp_seconds",
        "gauge",
        "Follower: unix time of the last successful sync.",
        snapshot.get("last_sync", 0),
    )
    metric(
        "coord_last_sync_age_seconds",
        "gauge",
        "Follower: seconds since the last successful sync (-1 when never).",
        snapshot.get("last_sync_age_seconds", -1),
    )
    metric(
        "coord_last_sync_ok",
        "gauge",
        "Follower: 1 when the last sync attempt succeeded.",
        snapshot.get("last_sync_ok", 0),
    )
    metric(
        "coord_sync_failures",
        "gauge",
        "Follower: consecutive failed sync attempts.",
        snapshot.get("sync_failures", 0),
    )
    metric(
        "coord_accepted_total",
        "counter",
        "Leader: events accepted from followers.",
        snapshot.get("accepted_total", 0),
    )
    metric(
        "coord_inserted_total",
        "counter",
        "Leader: events queued from followers.",
        snapshot.get("inserted_total", 0),
    )
    metric(
        "coord_rejected_total",
        "counter",
        "Leader: events refused by the leader's filters.",
        snapshot.get("rejected_total", 0),
    )
    metric(
        "coord_remote_bans_total",
        "counter",
        "Follower: bans applied from other nodes.",
        snapshot.get("remote_bans_total", 0),
    )
    metric(
        "lease_held",
        "gauge",
        "1 when this node holds the failover lease.",
        snapshot.get("lease_held", 0),
    )
    metric(
        "lease_expires",
        "gauge",
        "Unix time the failover lease expires (0 when none).",
        snapshot.get("lease_expires", 0),
    )
    metric(
        "leader_up",
        "gauge",
        "Follower: 1 when the leader answered, 0 when it did not, -1 when unknown.",
        snapshot.get("leader_up", -1),
    )
    if snapshot.get("leader_role"):
        lines.append(
            '%s_coord_leader_role{role="%s"} 1' % (PREFIX, _escape(snapshot["leader_role"]))
        )
    if snapshot.get("last_run_stopped"):
        lines.append(
            '%s_last_run_stopped{reason="%s"} 1'
            % (PREFIX, _escape(snapshot["last_run_stopped"]))
        )
    return "\n".join(lines) + "\n"
