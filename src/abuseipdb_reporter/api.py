"""Thin HTTP client for the AbuseIPDB API v2.

No third-party dependencies: ``urllib`` from the standard library is enough
for two endpoints and keeps the installer free of pip requirements.
"""
from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Optional, Tuple

from .config import Config

USER_AGENT = "fail2ban-abuseipdb-reporter/1.0 (+https://github.com/paulmann/Fail2Ban_AbuseIPDB)"


def request(
    url: str, api_key: str, fields: Optional[Dict[str, str]] = None, timeout: int = 25
) -> Tuple[Optional[int], str]:
    """Perform a GET (no fields) or form-encoded POST and return (status, body).

    ``status`` is ``None`` for transport-level failures (DNS, TLS, timeout).
    """
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
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        try:
            return error.code, error.read().decode("utf-8", "replace")
        finally:
            error.close()
    except Exception as error:  # noqa: BLE001 - transport errors are reported as-is
        return None, repr(error)


def post_report(
    cfg: Config, ip: str, categories: str, comment: str, timestamp: str
) -> Tuple[Optional[int], str]:
    """Submit one abuse report; returns (HTTP status, response body)."""
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


def check_key(cfg: Config) -> Tuple[Optional[int], str]:
    """Validate the API key with a harmless ``/check`` request."""
    url = "%s?ipAddress=8.8.8.8&maxAgeInDays=1" % cfg.check_url
    return request(url, cfg.api_key, None, cfg.timeout)