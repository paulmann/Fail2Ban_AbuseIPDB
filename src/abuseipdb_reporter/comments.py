"""Comment (report description) construction."""
from __future__ import annotations

import datetime
import time
from typing import Dict, Iterable, List, Sequence, Tuple

from . import db, evidence
from .config import Config

#: Human readable attack type per jail.
JAIL_DESCRIPTIONS: Dict[str, str] = {
    "sshd": "SSH brute-force",
    "proftpd": "FTP brute-force",
    "exim-auth-fail": "SMTP AUTH brute-force",
    "exim-isp": "SMTP abuse",
    "nginx-attack-scan": "web application vulnerability scanning/exploitation attempts",
    "nginx-wp-login": "WordPress login brute-force",
    "nginx-php-probe": "web shell probing (requests to non-existent PHP scripts)",
    "nginx-forbidden": "web application attack (requests blocked by server rules)",
}


def iso(ts: int) -> str:
    """Unix timestamp -> ISO-8601 with the local timezone offset."""
    return datetime.datetime.fromtimestamp(int(ts)).astimezone().isoformat(timespec="seconds")


def human_duration(seconds) -> str:
    """86400 -> ``1d`` (compact, human readable)."""
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return str(seconds)
    if seconds <= 0:
        return "unknown"
    for suffix, divisor in (("w", 604800), ("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if seconds % divisor == 0:
            return "%d%s" % (seconds // divisor, suffix)
    return "%ds" % seconds


def truncate_bytes(text: str, limit: int) -> str:
    """Truncate *text* so that its UTF-8 representation is at most *limit* bytes."""
    raw = text.encode("utf-8")
    if len(raw) <= limit:
        return text
    return raw[: max(0, limit - 3)].decode("utf-8", "ignore").rstrip() + "..."


def categories_for(cfg: Config, jails: Iterable[str]) -> List[int]:
    """Union of AbuseIPDB categories over all jails of one IP."""
    categories = set()
    for jail in jails:
        categories.update(cfg.categories_for(jail))
    return sorted(categories)


def build_comment(
    cfg: Config,
    ip: str,
    events: Sequence,
    jails: Sequence[str],
    lines_by_jail: Dict[str, List[str]],
    now: int = None,
) -> Tuple[str, List[int], str]:
    """Build (comment, categories, timestamp) for one IP.

    The comment is intentionally PII-free: it contains the attack type, time,
    counters, generic patterns and the URLs that the attacker requested.
    """
    now = int(now if now is not None else time.time())
    n = len(events)
    first = min(int(event["event_time"]) for event in events)
    last = max(int(event["event_time"]) for event in events)
    total_failures = sum(int(event["failures"] or 0) for event in events)
    bantimes = sorted({int(event["bantime"] or 0) for event in events if event["bantime"]})

    parts = []
    if cfg.server_ip:
        parts.append("Automated fail2ban report from server %s." % cfg.server_ip)
    else:
        parts.append("Automated fail2ban report.")

    descriptions: List[str] = []
    for jail in jails:
        description = JAIL_DESCRIPTIONS.get(jail, "abuse detected by fail2ban")
        if description not in descriptions:
            descriptions.append(description)
    parts.append("Attack type: %s (jails: %s)." % ("; ".join(descriptions), ", ".join(jails)))

    observed = "Observed: %s" % iso(first)
    if last != first:
        observed += " .. %s" % iso(last)
    parts.append(observed + ".")

    detections = "Detections: %d ban event(s)" % n
    if total_failures:
        detections += ", %d failed attempts" % total_failures
    parts.append(detections + ".")
    if bantimes:
        parts.append("Ban duration: %s." % ", ".join(human_duration(value) for value in bantimes))

    patterns: List[str] = []
    indicators: List[str] = []
    fallback_lines: List[str] = []
    sqli = False
    for jail in jails:
        lines = lines_by_jail.get(jail) or []
        jail_patterns, jail_indicators, jail_sqli = evidence.classify(jail, lines)
        for value in jail_patterns:
            if value not in patterns:
                patterns.append(value)
        for value in jail_indicators:
            if value not in indicators:
                indicators.append(value)
        sqli = sqli or jail_sqli
        # Raw log lines are only used for web jails: they contain the attacker's
        # URLs, which are safe to publish.  SSH/FTP/mail lines can contain
        # attacker-chosen usernames, so for those only generic patterns are sent.
        if jail.startswith("nginx") and lines and not jail_indicators:
            if len(lines) > len(fallback_lines):
                fallback_lines = list(lines)

    if patterns:
        parts.append("Patterns: %s." % "; ".join(patterns[:5]))
    if indicators:
        parts.append("Sample requests/indicators:")
        parts.extend("  " + value for value in indicators[: int(cfg.evidence_max_lines)])
    elif fallback_lines:
        parts.append("Log evidence:")
        parts.extend(
            "  " + evidence.clean_line(value)[:150]
            for value in fallback_lines[: int(cfg.evidence_max_lines)]
        )
    parts.append("Reported automatically; no personal data included.")

    comment = truncate_bytes("\n".join(parts), int(cfg.comment_max_bytes))

    categories = categories_for(cfg, jails)
    if sqli and 16 not in categories:
        categories = sorted(categories + [16])

    # AbuseIPDB expects a recent timestamp; an old backlog is reported as "now".
    sent_ts = first if now - first < 23 * 3600 else now
    return comment, categories, iso(sent_ts)