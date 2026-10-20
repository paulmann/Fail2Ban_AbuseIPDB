"""The reporter: drains the local queue into AbuseIPDB, respecting API limits."""
from __future__ import annotations

import datetime
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from . import api, comments, db, evidence, log
from .config import Config

#: injectable HTTP function signature: (url, api_key, fields, timeout) -> (status, body)
HttpFunction = Callable[..., "tuple"]


@dataclass
class RunResult:
    """Outcome of one reporter run (used by the CLI and by tests)."""

    sent: int = 0
    skipped: int = 0
    errors: int = 0
    pending: int = 0
    today: int = 0
    payloads: List[Dict[str, str]] = field(default_factory=list)
    stopped_reason: str = ""


def _midnight(now: int) -> int:
    moment = datetime.datetime.fromtimestamp(now)
    return int(moment.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())


def gather_lines(cfg: Config, ip: str, jails: List[str]) -> Dict[str, List[str]]:
    """Read fail2ban evidence for every jail the IP was banned in."""
    limit = int(cfg.evidence_max_lines) * 2
    return {jail: evidence.read_matches(cfg.fail2ban_db, ip, jail, limit=limit) for jail in jails}


def run_once(
    cfg: Config,
    now: Optional[int] = None,
    dry_run: bool = False,
    http: Optional[HttpFunction] = None,
) -> RunResult:
    """Process the queue once.  Returns counters and (for dry-run) payloads."""
    http = http or api.request
    result = RunResult()
    if not cfg.enabled:
        result.stopped_reason = "disabled"
        log.log(cfg, "report: disabled in config")
        return result
    if not cfg.api_key and not dry_run:
        result.stopped_reason = "missing api key"
        log.log(cfg, "report: ERROR api_key is empty")
        return result

    now = int(now if now is not None else time.time())
    conn = db.connect(cfg.db_path)
    try:
        today = _midnight(now)
        sent_today = db.reported_since(conn, today)
        result.today = sent_today
        budget = min(
            int(cfg.max_reports_per_run), max(0, int(cfg.max_reports_per_day) - sent_today)
        )
        if budget <= 0:
            result.stopped_reason = "daily budget exhausted"
            log.log(cfg, "report: daily budget exhausted (%d today), nothing to do" % sent_today)
            result.pending = db.pending_count(conn)
            return result

        rows = db.pending_ips(conn, int(cfg.max_attempts), int(cfg.max_reports_per_run) * 4)
        log.log(
            cfg,
            "report: run start, pending_ips=%d budget=%d today=%d" % (len(rows), budget, sent_today),
        )

        for row in rows:
            if result.sent >= budget:
                result.stopped_reason = "run budget exhausted"
                break
            ip = row["ip"]
            last = db.last_success(conn, ip)
            if last and now - last < int(cfg.min_interval_ip):
                result.skipped += 1
                continue

            events = db.events_for(conn, ip)
            if not events:
                continue
            jails = sorted({event["jail"] for event in events})
            lines_by_jail = gather_lines(cfg, ip, jails)

            try:
                comment, categories, timestamp = comments.build_comment(
                    cfg, ip, events, jails, lines_by_jail, now=now
                )
            except Exception as error:  # noqa: BLE001 - one bad IP must not stop the run
                result.errors += 1
                log.log(cfg, "report: build error for %s: %r" % (ip, error))
                continue

            fields = {
                "ip": ip,
                "categories": ",".join(str(value) for value in categories),
                "comment": comment,
                "timestamp": timestamp,
            }
            if dry_run:
                result.payloads.append(fields)
                result.sent += 1
                continue

            status, body = http(cfg.api_url, cfg.api_key, fields, cfg.timeout)
            primary_jail = max(
                jails, key=lambda jail: (len(lines_by_jail.get(jail) or []), jail == events[-1]["jail"])
            )
            db.record_attempt(
                conn, ip, primary_jail, status or 0, fields["categories"], comment, body, reported_at=now
            )

            if status == 200:
                db.mark_reported(conn, ip)
                result.sent += 1
                log.log(
                    cfg,
                    "reported ip=%s jail=%s cats=%s size=%d -> 200 %s"
                    % (
                        ip,
                        primary_jail,
                        fields["categories"],
                        len(comment.encode("utf-8")),
                        body[:160],
                    ),
                )
            elif status == 429:
                result.skipped += 1
                log.log(cfg, "rate limited for ip=%s: %s" % (ip, body[:240]))
                if "once in 15 minutes" not in body and "same IP" not in body:
                    result.stopped_reason = "global rate limit"
                    log.log(cfg, "report: global rate limit reached, stopping run")
                    conn.commit()
                    break
            elif status in (400, 422):
                db.mark_invalid(conn, ip, body)
                result.errors += 1
                log.log(cfg, "invalid report for ip=%s: %s" % (ip, body[:240]))
            elif status == 401:
                result.stopped_reason = "unauthorized"
                log.log(cfg, "report: ERROR 401 unauthorized - API key rejected, stopping run")
                conn.commit()
                break
            else:
                db.bump_attempts(conn, ip, int(cfg.max_attempts))
                result.errors += 1
                log.log(cfg, "transient error for ip=%s: %s %s" % (ip, status, body[:200]))

            conn.commit()
            if not dry_run:
                time.sleep(1)

        db.cleanup(conn, int(cfg.retention_days), now=now)
        result.pending = db.pending_count(conn)
        conn.commit()
    finally:
        conn.close()

    log.log(
        cfg,
        "report: run done sent=%d skipped=%d errors=%d pending=%d"
        % (result.sent, result.skipped, result.errors, result.pending),
    )
    return result