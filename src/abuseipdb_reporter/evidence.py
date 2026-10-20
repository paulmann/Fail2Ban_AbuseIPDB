"""Evidence extraction.

Fail2ban keeps the log lines that triggered a ban in its own SQLite database
(``bips.data``, JSON field ``matches``).  Reading them lets us build a useful
AbuseIPDB comment without touching production log files and without ever
passing attacker-controlled text through a shell.
"""
from __future__ import annotations

import json
import re
import sqlite3
from typing import Iterable, List, Sequence, Tuple

#: timestamps and syslog hostnames are noise for an abuse report
TS_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ][0-9:.+]+ ?")
HOSTNAME_PREFIX_RE = re.compile(r"^\S+\s+(?=[\w.+-]*\[\d+\]:)")
#: "GET /path HTTP/1.1" -> method + path (+ status when the log has it)
WEB_REQUEST_RE = re.compile(
    r'"(GET|POST|HEAD|PUT|PATCH|OPTIONS|DELETE|PROPFIND|TRACE|CONNECT)'
    r' (\S+)(?: HTTP/[0-9.]+)?"(?: (\d{3}))?'
)
SQLI_RE = re.compile(
    r"(?i)(union[\s+]+(?:all[\s+]+)?select|information_schema|sleep\s*\(|benchmark\s*\("
    r"|or\s+1\s*=\s*1|%27|@@version|load_file\s*\(|into\s+outfile)"
)


def clean_line(line: str) -> str:
    """Collapse whitespace and strip timestamp/hostname prefixes."""
    text = re.sub(r"\s+", " ", str(line)).strip()
    text = TS_PREFIX_RE.sub("", text)
    text = HOSTNAME_PREFIX_RE.sub("", text)
    return text


def _flatten_matches(raw_matches: Iterable) -> List[str]:
    """Fail2ban stores matches either as strings or as (prefix, date, suffix)."""
    lines: List[str] = []
    for item in raw_matches or []:
        if isinstance(item, str):
            text = item
        elif isinstance(item, (list, tuple)):
            text = "".join(part for part in item if isinstance(part, str))
        else:
            continue
        text = clean_line(text)
        if text and text not in lines:
            lines.append(text)
    return lines


def read_matches(fail2ban_db: str, ip: str, jail: str, limit: int = 8) -> List[str]:
    """Return up to *limit* log lines that fail2ban recorded for ip/jail."""
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % fail2ban_db, uri=True, timeout=5)
    except sqlite3.Error:
        return []
    try:
        row = conn.execute(
            "SELECT data FROM bips WHERE ip=? AND jail=?", (ip, jail)
        ).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()
    if not row or not row[0]:
        return []
    try:
        payload = json.loads(row[0])
    except (TypeError, ValueError):
        return []
    return _flatten_matches(payload.get("matches") or [])[:limit]


def classify(jail: str, lines: Sequence[str]) -> Tuple[List[str], List[str], bool]:
    """Extract human-readable patterns, sample indicators and a SQLi flag.

    Only attacker-provided data is returned (URLs, failure kinds); usernames
    that the attacker tried are intentionally **not** included.
    """
    patterns: List[str] = []
    indicators: List[str] = []
    sqli = False

    def add(collection: List[str], value: str) -> None:
        if value and value not in collection:
            collection.append(value)

    for line in lines:
        if jail.startswith("nginx"):
            if SQLI_RE.search(line):
                sqli = True
            match = WEB_REQUEST_RE.search(line)
            if not match:
                continue
            uri = match.group(2)
            short = uri if len(uri) <= 120 else uri[:117] + "..."
            item = "%s %s" % (match.group(1), short)
            if match.group(3):
                item += " -> %s" % match.group(3)
            add(indicators, item)
            continue

        low = line.lower()
        if jail == "sshd":
            if "invalid user" in low:
                add(patterns, "invalid usernames tried")
            if "failed password for root" in low:
                add(patterns, "root password attempts")
            if "failed password for invalid user" in low:
                add(patterns, "password attempts for invalid users")
            if "maximum authentication attempts exceeded" in low:
                add(patterns, "exceeded MaxAuthTries")
            if "authentication failure" in low:
                add(patterns, "PAM authentication failures")
        elif jail == "proftpd":
            if "no such user" in low:
                add(patterns, "FTP login with non-existent user")
            if "incorrect password" in low:
                add(patterns, "wrong FTP password")
            if "login failed" in low:
                add(patterns, "FTP login failed")
        elif jail.startswith("exim"):
            if " 535 " in line:
                add(patterns, "SMTP AUTH with incorrect credentials (535)")
            if " 435 " in line:
                add(patterns, "SMTP AUTH rejected by auth backend (435)")
            if "unable to authenticate" in low:
                add(patterns, "SMTP authentication failure")
    return patterns, indicators, sqli