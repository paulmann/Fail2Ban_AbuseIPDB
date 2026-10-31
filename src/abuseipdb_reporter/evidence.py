"""Evidence extraction.

Fail2ban keeps the log lines that triggered a ban in its own SQLite database
(``bips.data``, JSON field ``matches``).  Reading them lets us build a useful
AbuseIPDB comment without touching production log files and without ever
passing attacker-controlled text through a shell.

Classification is a **registry**: ``CLASSIFIERS`` maps jail-name prefixes to a
function that turns log lines into (patterns, indicators, sqli flag).  Adding a
new service means adding one entry and one function here - the core reporter
and comment builder stay untouched.  A jail nobody registered still gets the
generic treatment (request lines and SQL-injection detection), so an unknown
web jail produces usable evidence instead of silence.
"""
from __future__ import annotations

import json
import re
import sqlite3
import urllib.parse
from typing import Callable, Iterable, List, Sequence, Tuple

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

#: Jail name prefixes that log HTTP requests; their lines are safe to publish
#: (URL only) and never contain attacker-chosen usernames.
WEB_JAIL_PREFIXES = ("nginx", "apache", "haproxy", "lighttpd", "openresty", "traefik")

#: A classifier: log lines -> (patterns, indicators, sqli flag)
Classifier = Callable[[Sequence[str]], Tuple[List[str], List[str], bool]]


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


def is_web_jail(jail: str) -> bool:
    """True when *jail* is a web server jail (request lines, not usernames)."""
    return str(jail or "").lower().startswith(WEB_JAIL_PREFIXES)


def _web_indicators(lines: Sequence[str]) -> Tuple[List[str], bool]:
    """Extract (request indicators, sqli flag) from HTTP log lines."""
    indicators: List[str] = []
    sqli = False
    for line in lines:
        # Attackers send percent-encoded payloads (``%20UNION%20SELECT``), so
        # the SQLi patterns are matched against the decoded form as well.
        if SQLI_RE.search(line) or SQLI_RE.search(urllib.parse.unquote(line)):
            sqli = True
        match = WEB_REQUEST_RE.search(line)
        if not match:
            continue
        uri = match.group(2)
        short = uri if len(uri) <= 120 else uri[:117] + "..."
        item = "%s %s" % (match.group(1), short)
        if match.group(3):
            item += " -> %s" % match.group(3)
        if item not in indicators:
            indicators.append(item)
    return indicators, sqli


def _classify_web(lines: Sequence[str]) -> Tuple[List[str], List[str], bool]:
    indicators, sqli = _web_indicators(lines)
    return [], indicators, sqli


def _classify_generic(lines: Sequence[str]) -> Tuple[List[str], List[str], bool]:
    """Unknown jail: keep whatever request/attack markers the lines carry."""
    indicators, sqli = _web_indicators(lines)
    patterns: List[str] = []
    for line in lines:
        decoded = urllib.parse.unquote(line)
        if (SQLI_RE.search(line) or SQLI_RE.search(decoded)) and "SQL injection attempts" not in patterns:
            patterns.append("SQL injection attempts")
    return patterns, indicators, sqli


def _classify_sshd(lines: Sequence[str]) -> Tuple[List[str], List[str], bool]:
    patterns: List[str] = []

    def add(value: str) -> None:
        if value not in patterns:
            patterns.append(value)

    for line in lines:
        low = line.lower()
        if "invalid user" in low:
            add("invalid usernames tried")
        if "failed password for root" in low:
            add("root password attempts")
        if "failed password for invalid user" in low:
            add("password attempts for invalid users")
        if "maximum authentication attempts exceeded" in low:
            add("exceeded MaxAuthTries")
        if "authentication failure" in low:
            add("PAM authentication failures")
        if "no matching host key" in low or "no matching key exchange" in low:
            add("unsupported SSH client handshake")
        if "connection closed by authenticating user" in low and "preauth" not in low:
            add("aborted SSH authentication")
    return patterns, [], False


def _classify_ftp(lines: Sequence[str]) -> Tuple[List[str], List[str], bool]:
    patterns: List[str] = []

    def add(value: str) -> None:
        if value not in patterns:
            patterns.append(value)

    for line in lines:
        low = line.lower()
        if "no such user" in low:
            add("FTP login with non-existent user")
        if "incorrect password" in low:
            add("wrong FTP password")
        if "login failed" in low or "fail login" in low:
            add("FTP login failed")
        if "authentication failure" in low:
            add("PAM authentication failures")
        if "anonymous" in low and ("login" in low or "user" in low):
            add("anonymous FTP login attempts")
    return patterns, [], False


def _classify_smtp(lines: Sequence[str]) -> Tuple[List[str], List[str], bool]:
    patterns: List[str] = []

    def add(value: str) -> None:
        if value not in patterns:
            patterns.append(value)

    for line in lines:
        low = line.lower()
        if " 535 " in line:
            add("SMTP AUTH with incorrect credentials (535)")
        if " 435 " in line:
            add("SMTP AUTH rejected by auth backend (435)")
        if "unable to authenticate" in low:
            add("SMTP authentication failure")
        if "sasl" in low and ("failed" in low or "error" in low):
            add("SMTP AUTH failure (SASL)")
        if "too many errors" in low or "too many failures" in low:
            add("SMTP session aborted after repeated failures")
    return patterns, [], False


def _classify_imap(lines: Sequence[str]) -> Tuple[List[str], List[str], bool]:
    patterns: List[str] = []

    def add(value: str) -> None:
        if value not in patterns:
            patterns.append(value)

    for line in lines:
        low = line.lower()
        if "aborted login" in low:
            add("IMAP/POP3 authentication aborted")
        if "auth failed" in low or "authentication failed" in low:
            add("IMAP/POP3 authentication failures")
        if "disconnected" in low and "auth" in low:
            add("IMAP/POP3 client disconnected during authentication")
    return patterns, [], False


#: Ordered registry: the first prefix that matches the jail name wins.
#: Extension point - append a new ``((prefix, ...), function)`` pair to support
#: another service without touching the reporter.
CLASSIFIERS: Tuple[Tuple[Tuple[str, ...], Classifier], ...] = (
    (("sshd", "ssh-", "dropbear"), _classify_sshd),
    (("proftpd", "vsftpd", "pure-ftpd", "pureftpd"), _classify_ftp),
    (("exim", "postfix", "sendmail", "smtpd"), _classify_smtp),
    (("dovecot", "courier", "cyrus"), _classify_imap),
    (WEB_JAIL_PREFIXES, _classify_web),
)


def classifier_for(jail: str) -> Classifier:
    """Return the classifier for *jail* (generic fallback for unknown names)."""
    name = str(jail or "").lower()
    for prefixes, function in CLASSIFIERS:
        if name.startswith(prefixes):
            return function
    return _classify_generic


def classify(jail: str, lines: Sequence[str]) -> Tuple[List[str], List[str], bool]:
    """Extract human-readable patterns, sample indicators and a SQLi flag.

    Only attacker-provided data is returned (URLs, failure kinds); usernames
    that the attacker tried are intentionally **not** included.
    """
    return classifier_for(jail)(lines)
