"""Machine-readable run status: a JSON file and an optional Prometheus textfile.

The reporter runs from a timer, so "did the last run work, and what is still
queued?" must be answerable without parsing the log.  ``status.json`` is
rewritten atomically on **every** exit path (disabled, missing key, budget
exhausted, normal end), and the same numbers can be exported for the
node_exporter ``textfile`` collector.

Writing status is strictly best effort: a read-only or missing directory must
never turn a successful report run into a failed one.
"""
from __future__ import annotations

import datetime
import json
import os
import tempfile
import time
from typing import Any, Dict, Optional

#: Default location of the JSON status file (same directory as the queue).
DEFAULT_STATUS_PATH = "/var/lib/abuseipdb/status.json"

#: Metric name prefix used in the Prometheus textfile.
METRIC_PREFIX = "abuseipdb_reporter"


def _iso(ts: int) -> str:
    return datetime.datetime.fromtimestamp(int(ts)).astimezone().isoformat(timespec="seconds")


def build(cfg, result, now: Optional[int] = None, version: str = "") -> Dict[str, Any]:
    """Turn a :class:`reporter.RunResult` into the status document."""
    moment = int(now if now is not None else time.time())
    return {
        "ts": moment,
        "iso": _iso(moment),
        "version": version,
        "enabled": bool(getattr(cfg, "enabled", True)),
        "sent": int(getattr(result, "sent", 0)),
        "skipped": int(getattr(result, "skipped", 0)),
        "errors": int(getattr(result, "errors", 0)),
        "pending": int(getattr(result, "pending", 0)),
        "today": int(getattr(result, "today", 0)),
        "max_per_day": int(getattr(cfg, "max_reports_per_day", 0)),
        "retry_after": int(getattr(result, "retry_after", 0) or 0),
        "waited_seconds": round(float(getattr(result, "waited", 0.0) or 0.0), 3),
        "crawlers_skipped": int(getattr(result, "crawlers_skipped", 0) or 0),
        "stopped": str(getattr(result, "stopped_reason", "") or ""),
        "budget_timezone": str(getattr(cfg, "daily_budget_timezone", "utc")),
    }


def prometheus(payload: Dict[str, Any]) -> str:
    """Render *payload* as a Prometheus text-exposition document."""
    lines = []

    def metric(name: str, kind: str, help_text: str, value) -> None:
        full = "%s_%s" % (METRIC_PREFIX, name)
        lines.append("# HELP %s %s" % (full, help_text))
        lines.append("# TYPE %s %s" % (full, kind))
        lines.append("%s %s" % (full, value))

    metric("pending_events", "gauge", "Ban events waiting for an AbuseIPDB report.", payload["pending"])
    metric("reports_today", "gauge", "Reports accepted by AbuseIPDB since the budget day started.", payload["today"])
    metric("sent_last_run", "gauge", "Reports accepted during the last run.", payload["sent"])
    metric("skipped_last_run", "gauge", "IPs skipped during the last run (interval or rate limit).", payload["skipped"])
    metric("errors_last_run", "gauge", "Errors during the last run (transient API or build errors).", payload["errors"])
    metric(
        "crawlers_skipped_last_run",
        "gauge",
        "Addresses skipped because they belong to a verified crawler.",
        payload.get("crawlers_skipped", 0),
    )
    metric("run_timestamp_seconds", "gauge", "Unix time of the last run.", payload["ts"])
    metric("run_ok", "gauge", "1 when the last run finished without an error stop.", 0 if payload["errors"] else 1)
    metric("budget_remaining", "gauge", "Reports still allowed today.", max(0, int(payload["max_per_day"]) - int(payload["today"])))
    lines.append(
        '%s_info{version="%s",stopped="%s",budget_timezone="%s"} 1'
        % (METRIC_PREFIX, payload["version"], payload["stopped"], payload["budget_timezone"])
    )
    return "\n".join(lines) + "\n"


def write_text(path: str, text: str) -> bool:
    """Atomically replace *path* with *text*; ``False`` when it is not writable."""
    if not path:
        return False
    directory = os.path.dirname(path) or "."
    temporary = ""
    try:
        os.makedirs(directory, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=directory, prefix=".status-", suffix=".tmp", delete=False
        )
        temporary = handle.name
        try:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            handle.close()
        os.replace(temporary, path)
        return True
    except OSError:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        return False


def write_json(path: str, payload: Dict[str, Any]) -> bool:
    """Atomically replace *path* with the JSON form of *payload*."""
    return write_text(path, json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def record(
    cfg, result, now: Optional[int] = None, version: str = ""
) -> Dict[str, Any]:
    """Write the status files configured in *cfg* and return the payload."""
    payload = build(cfg, result, now=now, version=version)
    if getattr(cfg, "status_path", ""):
        write_json(cfg.status_path, payload)
    if getattr(cfg, "prometheus_textfile", ""):
        write_text(cfg.prometheus_textfile, prometheus(payload))
    return payload


def read(path: str) -> Optional[Dict[str, Any]]:
    """Load a status document; ``None`` when it is absent or unreadable."""
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None
