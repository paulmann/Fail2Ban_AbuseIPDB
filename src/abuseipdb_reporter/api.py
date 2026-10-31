"""Thin HTTP client for the AbuseIPDB API v2.

No third-party dependencies: ``urllib`` from the standard library is enough
for two endpoints and keeps the installer free of pip requirements.

Every call returns ``(status, body, retry_after)``:

* ``status`` is ``None`` for transport-level failures (DNS, TLS, timeout);
* ``body`` is the raw response text (or the transport error, for ``None``);
* ``retry_after`` is the delay the API asked for, in seconds, taken from the
  ``Retry-After`` header of a ``429`` response (``None`` when absent).  Both
  the delta-seconds and the HTTP-date forms defined by RFC 9110 are accepted,
  because proxies in front of the API add their own.
"""
from __future__ import annotations

import datetime
import email.utils
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Optional, Tuple

from .config import Config

USER_AGENT = "fail2ban-abuseipdb-reporter/1.2 (+https://github.com/paulmann/Fail2Ban_AbuseIPDB)"

#: Parsed HTTP outcome: (status, body, retry_after).
Outcome = Tuple[Optional[int], str, Optional[int]]


def parse_retry_after(value: Optional[str], now: Optional[float] = None) -> Optional[int]:
    """Return seconds to wait from a ``Retry-After`` header value.

    ``None`` when the value is missing, empty or not understood: an unparsable
    header must not stop the run.
    """
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if raw.isdigit():
        return int(raw)
    try:
        when = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:  # HTTP-dates are always GMT; be forgiving anyway
        when = when.replace(tzinfo=datetime.timezone.utc)
    moment = datetime.datetime.fromtimestamp(
        now if now is not None else datetime.datetime.now().timestamp(),
        tz=datetime.timezone.utc,
    )
    return max(0, int((when - moment).total_seconds()))


def _retry_after_from_headers(headers) -> Optional[int]:
    if headers is None:
        return None
    try:
        return parse_retry_after(headers.get("Retry-After"))
    except (AttributeError, TypeError):
        return None


def request(
    url: str, api_key: str, fields: Optional[Dict[str, str]] = None, timeout: int = 25
) -> Outcome:
    """Perform a GET (no fields) or form-encoded POST and return the outcome."""
    headers = {
        "Key": api_key,
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    body = None
    if fields is not None:
        body = urllib.parse.urlencode(fields).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request_obj = urllib.request.Request(
        url, data=body, headers=headers, method="POST" if body is not None else "GET"
    )
    try:
        with urllib.request.urlopen(request_obj, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as error:
        try:
            return (
                error.code,
                error.read().decode("utf-8", "replace"),
                _retry_after_from_headers(error.headers),
            )
        finally:
            error.close()
    except Exception as error:  # noqa: BLE001 - transport errors are reported as-is
        return None, repr(error), None


def post_report(
    cfg: Config, ip: str, categories: str, comment: str, timestamp: str
) -> Outcome:
    """Submit one abuse report; returns ``(HTTP status, body, retry_after)``."""
    return request(
        cfg.api_url,
        cfg.api_key,
        {
            "ip": ip,
            "categories": categories,
            "comment": comment,
            "timestamp": timestamp,
        },
        cfg.timeout,
    )


def check_key(cfg: Config) -> Outcome:
    """Validate the API key with a harmless ``/check`` request."""
    url = "%s?ipAddress=8.8.8.8&maxAgeInDays=1" % cfg.check_url
    return request(url, cfg.api_key, None, cfg.timeout)
