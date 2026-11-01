"""The reporter: drains the local queue into AbuseIPDB, respecting API limits."""
from __future__ import annotations

import datetime
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import __version__, api, comments, coordination, db, evidence, log, metrics, status
from .config import Config

#: injectable HTTP function signature: (url, api_key, fields, timeout) ->
#: (status, body) or (status, body, retry_after)
HttpFunction = Callable[..., "tuple"]

#: Safety cap on an adaptive pause, even if the configuration is larger.
MAX_BACKOFF_SECONDS = 300.0


@dataclass
class RunResult:
    """Outcome of one reporter run (used by the CLI and by tests)."""

    sent: int = 0
    skipped: int = 0
    errors: int = 0
    pending: int = 0
    today: int = 0
    retry_after: int = 0
    waited: float = 0.0
    banned: int = 0
    payloads: List[Dict[str, str]] = field(default_factory=list)
    stopped_reason: str = ""


def _midnight(now: int) -> int:
    """Local midnight of *now* (kept for callers that want the old behaviour)."""
    moment = datetime.datetime.fromtimestamp(now)
    return int(moment.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())


def day_start(now: int, timezone: str = "utc") -> int:
    """Start of the current budget day as a unix timestamp.

    AbuseIPDB resets its daily quota at 00:00 UTC, so counting from a local
    midnight can overshoot the quota for hours (`utc` is the default and the
    documented behaviour).  ``local`` is kept for operators who deliberately
    align the budget with their own day.
    """
    if str(timezone).strip().lower() in ("local", "localtime"):
        moment = datetime.datetime.fromtimestamp(now)
        return int(moment.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    moment = datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc)
    return int(moment.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())


def _unpack(outcome: Sequence) -> Tuple[Optional[int], str, Optional[int]]:
    """Accept both ``(status, body)`` and ``(status, body, retry_after)``.

    Injected clients and third-party wrappers written against 1.1 return a
    two-tuple; treating that as "no Retry-After" keeps them working.
    """
    try:
        length = len(outcome)
    except TypeError:  # pragma: no cover - defensive
        return None, repr(outcome), None
    if length >= 3:
        return outcome[0], outcome[1], outcome[2]
    if length == 2:
        return outcome[0], outcome[1], None
    return None, repr(outcome), None  # pragma: no cover - defensive


def next_delay(
    cfg: Config, streak: int = 0, retry_after: Optional[int] = None
) -> float:
    """Seconds to wait before the next API call.

    * an explicit ``Retry-After`` wins, capped by ``retry_after_cap``;
    * without errors the configured ``request_delay`` is used;
    * each consecutive transient failure doubles the pause (exponential
      backoff) up to the same cap, so a struggling API is not hammered.
    """
    cap = min(float(getattr(cfg, "retry_after_cap", 60) or 60), MAX_BACKOFF_SECONDS)
    if retry_after is not None and int(retry_after) > 0:
        return min(float(int(retry_after)), cap)
    base = max(0.0, float(getattr(cfg, "request_delay", 1.0) or 0.0))
    if streak <= 0 or base <= 0.0:
        return base
    return min(base * (2 ** min(int(streak), 6)), cap)


def gather_lines(cfg: Config, ip: str, jails: List[str]) -> Dict[str, List[str]]:
    """Read fail2ban evidence for every jail the IP was banned in."""
    limit = int(cfg.evidence_max_lines) * 2
    return {jail: evidence.read_matches(cfg.fail2ban_db, ip, jail, limit=limit) for jail in jails}


def _publish(
    cfg: Config, result: RunResult, now: Optional[int] = None, dry_run: bool = False
) -> None:
    """Write the JSON/Prometheus status files; never raises.

    A dry run produces no real reports, so it must not overwrite the status of
    the last real run with numbers that never happened.
    """
    if dry_run:
        return
    try:
        status.record(cfg, result, now=now, version=__version__)
    except Exception as error:  # noqa: BLE001 - monitoring must not break reporting
        log.log(cfg, "report: status write failed: %r" % (error,))
    try:
        snapshot = metrics.build(cfg, now=now, status_path=getattr(cfg, "status_path", ""))
        path = getattr(cfg, "metrics_textfile", "")
        if path:
            status.write_text(path, metrics.prometheus(snapshot))
        json_path = getattr(cfg, "metrics_json_path", "")
        if json_path:
            status.write_json(json_path, snapshot)
    except Exception as error:  # noqa: BLE001 - monitoring must not break reporting
        log.log(cfg, "report: metrics write failed: %r" % (error,))


def _run_follower(
    cfg: Config,
    result: RunResult,
    now: int,
    dry_run: bool,
    runner: Optional[coordination.Runner] = None,
) -> RunResult:
    """Follower role: two-way sync with the leader, never call the API.

    ``result.sent`` counts events the leader accepted, ``result.banned`` counts
    remote bans applied here through ``fail2ban-client``, and ``pending`` counts
    events still waiting for delivery - a growing number is a real symptom (leader
    down, wrong secret), not a steady state.
    """
    conn = db.connect(cfg.db_path)
    try:
        if dry_run:
            batch = coordination.pending_batch(cfg, conn)
            result.payloads.extend(batch)
            result.stopped_reason = "follower dry-run"
            log.log(cfg, "coord: dry-run, would push %d event(s)" % len(batch))
        else:
            synced = coordination.follower_sync(cfg, conn, runner=runner, now=now)
            result.sent = synced.pushed
            result.banned = synced.banned
            result.stopped_reason = "follower (%s)" % synced.reason
            log.log(
                cfg,
                "coord: follower run done pushed=%d banned=%d pending=%d attempts=%d (%s)"
                % (
                    synced.pushed,
                    synced.banned,
                    synced.pending,
                    synced.attempts,
                    synced.reason,
                ),
            )
        db.cleanup(conn, int(cfg.retention_days), now=now)
        result.pending = db.unpushed_count(conn)
    finally:
        conn.close()
    _publish(cfg, result, now, dry_run=dry_run)
    return result


def run_once(
    cfg: Config,
    now: Optional[int] = None,
    dry_run: bool = False,
    http: Optional[HttpFunction] = None,
    runner: Optional[coordination.Runner] = None,
) -> RunResult:
    """Process the queue once.  Returns counters and (for dry-run) payloads.

    ``runner`` is the injectable ``fail2ban-client`` callable used by the follower
    role to apply remote bans (tests pass a fake; production uses subprocess).
    """
    http = http or api.request
    result = RunResult()
    now = int(now if now is not None else time.time())
    if not cfg.enabled:
        result.stopped_reason = "disabled"
        log.log(cfg, "report: disabled in config")
        _publish(cfg, result, now, dry_run=dry_run)
        return result
    try:
        role = coordination.effective_role(cfg, now=now)
    except Exception as error:  # noqa: BLE001 - never report on an unknown role
        role = coordination.MODE_FOLLOWER
        log.log(cfg, "report: role resolution failed (%r), acting as follower" % (error,))
    if role == coordination.MODE_FOLLOWER:
        return _run_follower(cfg, result, now, dry_run, runner=runner)
    if not cfg.api_key and not dry_run:
        result.stopped_reason = "missing api key"
        log.log(cfg, "report: ERROR api_key is empty")
        _publish(cfg, result, now, dry_run=dry_run)
        return result

    conn = db.connect(cfg.db_path)
    try:
        today = day_start(now, getattr(cfg, "daily_budget_timezone", "utc"))
        sent_today = db.reported_since(conn, today)
        result.today = sent_today
        budget = min(
            int(cfg.max_reports_per_run), max(0, int(cfg.max_reports_per_day) - sent_today)
        )
        if budget <= 0:
            result.stopped_reason = "daily budget exhausted"
            log.log(cfg, "report: daily budget exhausted (%d today), nothing to do" % sent_today)
            result.pending = db.pending_count(conn)
            _publish(cfg, result, now, dry_run=dry_run)
            return result

        rows = db.pending_ips(conn, int(cfg.max_attempts), int(cfg.max_reports_per_run) * 4)
        log.log(
            cfg,
            "report: run start, pending_ips=%d budget=%d today=%d tz=%s"
            % (
                len(rows),
                budget,
                sent_today,
                getattr(cfg, "daily_budget_timezone", "utc"),
            ),
        )

        streak = 0
        for row in rows:
            if result.sent >= budget:
                result.stopped_reason = "run budget exhausted"
                break
            ip = row["ip"]
            last = db.last_success(conn, ip)
            if last and now - last < int(cfg.min_interval_ip):
                result.skipped += 1
                continue
            if db.is_recently_reported(
                conn, ip, getattr(cfg, "peer_dedupe_window", 900), now=now
            ):
                # A peer (or this node before a role change) already reported it:
                # finish the events locally, never spend the API call twice.
                db.mark_reported(conn, ip)
                conn.commit()
                result.skipped += 1
                log.log(cfg, "report: %s already reported recently, skipped" % ip)
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

            status_code, body, retry_after = _unpack(
                http(cfg.api_url, cfg.api_key, fields, cfg.timeout)
            )
            primary_jail = max(
                jails, key=lambda jail: (len(lines_by_jail.get(jail) or []), jail == events[-1]["jail"])
            )
            db.record_attempt(
                conn,
                ip,
                primary_jail,
                status_code or 0,
                fields["categories"],
                comment,
                body,
                reported_at=now,
            )
            if retry_after:
                result.retry_after = max(result.retry_after, int(retry_after))

            if status_code == 200:
                db.mark_reported(conn, ip)
                result.sent += 1
                streak = 0
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
            elif status_code == 429:
                result.skipped += 1
                streak += 1
                log.log(cfg, "rate limited for ip=%s: %s" % (ip, body[:240]))
                if "once in 15 minutes" not in body and "same IP" not in body:
                    result.stopped_reason = "global rate limit"
                    if retry_after:
                        log.log(
                            cfg,
                            "report: global rate limit, API asked to retry in %ss" % retry_after,
                        )
                    log.log(cfg, "report: global rate limit reached, stopping run")
                    conn.commit()
                    break
            elif status_code in (400, 422):
                db.mark_invalid(conn, ip, body)
                result.errors += 1
                streak = 0
                log.log(cfg, "invalid report for ip=%s: %s" % (ip, body[:240]))
            elif status_code == 401:
                result.stopped_reason = "unauthorized"
                log.log(cfg, "report: ERROR 401 unauthorized - API key rejected, stopping run")
                conn.commit()
                break
            else:
                db.bump_attempts(conn, ip, int(cfg.max_attempts))
                result.errors += 1
                streak += 1
                log.log(cfg, "transient error for ip=%s: %s %s" % (ip, status_code, body[:200]))

            conn.commit()
            delay = next_delay(
                cfg, streak=streak, retry_after=retry_after if status_code == 429 else None
            )
            if delay > 0:
                result.waited += delay
                time.sleep(delay)

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
    _publish(cfg, result, now, dry_run=dry_run)
    return result
