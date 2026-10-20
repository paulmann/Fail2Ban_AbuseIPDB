"""Configuration model and loader.

The reporter is configured by a single INI file (default:
``/etc/abuseipdb/reporter.conf``).  Every option has a safe default so the
tool can be started with a minimal file that only contains the API key.
"""
from __future__ import annotations

import configparser
import ipaddress
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

DEFAULT_CONFIG_PATH = "/etc/abuseipdb/reporter.conf"
DEFAULT_LOG_PATH = "/var/log/abuseipdb-reporter.log"
DEFAULT_DB_PATH = "/var/lib/abuseipdb/abuseipdb.sqlite3"
DEFAULT_FAIL2BAN_DB = "/var/lib/fail2ban/fail2ban.sqlite3"
DEFAULT_API_URL = "https://api.abuseipdb.com/api/v2/report"
DEFAULT_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

#: Default AbuseIPDB categories per fail2ban jail.
#: https://www.abuseipdb.com/categories
DEFAULT_CATEGORY_MAP: Dict[str, str] = {
    "sshd": "18,22",
    "proftpd": "18,5",
    "exim-auth-fail": "18",
    "exim-isp": "18,11",
    "nginx-attack-scan": "21,19",
    "nginx-wp-login": "21,18",
    "nginx-php-probe": "21,15",
    "nginx-forbidden": "21",
}

#: Ranges that must never be reported: our own/trusted hosts, private,
#: loopback, reserved and documentation networks.
DEFAULT_IGNORE_RANGES = (
    "0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,"
    " 172.16.0.0/12, 192.168.0.0/16, 192.0.2.0/24, 198.51.100.0/24,"
    " 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4,"
    " ::1/128, fc00::/7, fe80::/10, 2001:db8::/32"
)


def _as_bool(value, default=True) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "yes", "true", "on")


def _as_int(value, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def parse_ranges(raw: str) -> Tuple[ipaddress._BaseNetwork, ...]:
    """Parse a comma/whitespace separated list of CIDR ranges."""
    networks: List[ipaddress._BaseNetwork] = []
    for part in str(raw or "").replace("\n", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue  # a malformed range must not stop the reporter
    return tuple(networks)


@dataclass
class Config:
    """Effective reporter configuration."""

    path: str = DEFAULT_CONFIG_PATH
    enabled: bool = True
    api_key: str = ""
    api_url: str = DEFAULT_API_URL
    check_url: str = DEFAULT_CHECK_URL
    timeout: int = 25
    min_interval_ip: int = 1200
    max_reports_per_run: int = 25
    max_reports_per_day: int = 900
    comment_max_bytes: int = 1000
    evidence_max_lines: int = 4
    skip_jails: Tuple[str, ...] = ("recidive",)
    db_path: str = DEFAULT_DB_PATH
    fail2ban_db: str = DEFAULT_FAIL2BAN_DB
    retention_days: int = 30
    max_attempts: int = 10
    server_ip: str = ""
    hostname: str = ""
    log_path: str = DEFAULT_LOG_PATH
    ignore_ranges: Tuple[ipaddress._BaseNetwork, ...] = ()
    category_map: Dict[str, str] = field(default_factory=dict)
    quiet: bool = False

    def categories_for(self, jail: str) -> List[int]:
        """Return AbuseIPDB category IDs for a jail (sorted, de-duplicated)."""
        raw = self.category_map.get(jail) or DEFAULT_CATEGORY_MAP.get(jail, "21")
        cats = []
        for part in str(raw).split(","):
            part = part.strip()
            if part.isdigit():
                cats.append(int(part))
        return sorted(set(cats)) or [21]


def load_config(path: Optional[str] = None, quiet: bool = False) -> Config:
    """Load configuration from *path* (missing file yields safe defaults)."""
    path = path or os.environ.get("ABUSEIPDB_REPORTER_CONFIG") or DEFAULT_CONFIG_PATH
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(path)
    except configparser.Error:
        parser = configparser.ConfigParser(interpolation=None)

    def get(section: str, option: str, fallback: str = "") -> str:
        try:
            return parser.get(section, option, fallback=fallback)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback

    category_map = dict(DEFAULT_CATEGORY_MAP)
    if parser.has_section("category_map"):
        for jail, value in parser.items("category_map"):
            category_map[jail.strip()] = value.strip()

    skip = tuple(
        x.strip() for x in get("abuseipdb", "skip_jails", "recidive").split(",") if x.strip()
    )

    ranges_raw = get("ignore", "ranges", DEFAULT_IGNORE_RANGES)
    if not ranges_raw.strip():
        ranges_raw = DEFAULT_IGNORE_RANGES

    return Config(
        path=path,
        enabled=_as_bool(get("abuseipdb", "enabled", "yes"), True),
        api_key=get("abuseipdb", "api_key", "").strip(),
        api_url=get("abuseipdb", "api_url", DEFAULT_API_URL).strip(),
        check_url=get("abuseipdb", "check_url", DEFAULT_CHECK_URL).strip(),
        timeout=_as_int(get("abuseipdb", "timeout", "25"), 25),
        min_interval_ip=_as_int(get("abuseipdb", "min_interval_ip", "1200"), 1200),
        max_reports_per_run=_as_int(get("abuseipdb", "max_reports_per_run", "25"), 25),
        max_reports_per_day=_as_int(get("abuseipdb", "max_reports_per_day", "900"), 900),
        comment_max_bytes=_as_int(get("abuseipdb", "comment_max_bytes", "1000"), 1000),
        evidence_max_lines=_as_int(get("abuseipdb", "evidence_max_lines", "4"), 4),
        skip_jails=skip,
        db_path=get("database", "path", DEFAULT_DB_PATH).strip() or DEFAULT_DB_PATH,
        fail2ban_db=get("database", "fail2ban_db", DEFAULT_FAIL2BAN_DB).strip()
        or DEFAULT_FAIL2BAN_DB,
        retention_days=_as_int(get("database", "retention_days", "30"), 30),
        max_attempts=_as_int(get("database", "max_attempts", "10"), 10),
        server_ip=get("report", "server_ip", "").strip(),
        hostname=get("report", "hostname", "").strip(),
        log_path=get("logging", "path", DEFAULT_LOG_PATH).strip() or DEFAULT_LOG_PATH,
        ignore_ranges=parse_ranges(ranges_raw),
        category_map=category_map,
        quiet=quiet,
    )