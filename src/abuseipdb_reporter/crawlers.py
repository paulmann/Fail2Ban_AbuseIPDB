"""Is this address a legitimate crawler?

A ban is reversible; an abuse report is not.  AbuseIPDB reports are public and the
API has no delete, so a crawler banned by mistake would be named as an abuser
forever, in a report that also carries our own evidence text.  This module is the
rail that stops that: an address that belongs to a published crawler network, or
whose reverse DNS says "I am Googlebot" **and** resolves back to that address, is
never reported.

Two checks, because neither alone is enough:

* **published ranges** - Google and OpenAI publish machine-readable lists
  (``crawler_ranges.py``, generated from
  ``developers.google.com/static/search/apis/ipranges/googlebot.json`` and
  ``openai.com/{gptbot,searchbot,chatgpt-user}.json``).  Exact, but only for the
  publishers that offer one, and only as fresh as the last regeneration.
* **reverse DNS with forward confirmation** - ``crawlers.googlebot.com`` is only
  trusted when that name resolves back to the same address, which is exactly the
  verification Google and Bing document.  This covers Bing (``search.msn.com``),
  Yandex, Apple, Amazon, Common Crawl, ByteDance and Perplexity, whose ranges are
  either unpublished or too broad to whitelist wholesale (Apple's is a /8).

What this does **not** claim: a crawler that publishes neither a list nor a
resolvable name cannot be recognised here.  ClaudeBot is the notable case - it is
visible in the audit tool by its user-agent, not by address, and the documentation
says so instead of pretending otherwise.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Dict, List, Optional, Sequence, Tuple

from . import crawler_ranges

#: Reverse-DNS suffixes that identify a crawler, most specific first.
RDNS_SUFFIXES: Sequence[Tuple[str, str]] = (
    ("googlebot.com", "Googlebot"),
    ("google.com", "Google"),
    ("search.msn.com", "Bingbot"),
    ("yandex.com", "YandexBot"),
    ("yandex.ru", "YandexBot"),
    ("yandex.net", "YandexBot"),
    ("applebot.apple.com", "Applebot"),
    ("amazonbot.amazon", "Amazonbot"),
    ("commoncrawl.org", "CCBot"),
    ("bytedance.com", "Bytespider"),
    ("perplexity.ai", "PerplexityBot"),
    ("openai.com", "OpenAI"),
    ("openai.org", "OpenAI"),
)

_networks: Optional[Tuple[List, List]] = None
#: (address, forward_check) -> (found, name); the flag belongs in the key, because a
#: lookup without confirmation must not poison a confirmed one.
_dns_cache: Dict[Tuple[str, bool], Tuple[bool, str]] = {}


def networks() -> Tuple[List, List]:
    """Collapsed IPv4 and IPv6 networks from the generated module (built once)."""
    global _networks
    if _networks is None:
        v4, v6 = [], []
        for label, items in crawler_ranges.RANGES.items():
            for item in items:
                try:
                    net = ipaddress.ip_network(item, strict=False)
                except ValueError:
                    continue
                (v4 if net.version == 4 else v6).append(net)
        _networks = (
            list(ipaddress.collapse_addresses(v4)),
            list(ipaddress.collapse_addresses(v6)),
        )
    return _networks


def in_published_range(address) -> Optional[str]:
    """Label of the first published list that contains *address*, if any."""
    label_hint = ""
    for label, items in crawler_ranges.RANGES.items():
        for item in items:
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                continue
            if address.version != net.version:
                continue
            if address in net:
                label_hint = label
                return label_hint
    return None


def _rdns(address) -> str:
    try:
        return socket.gethostbyaddr(str(address))[0].rstrip(".").lower()
    except (OSError, socket.herror, socket.gaierror):
        return ""


def _forward_matches(name: str, address) -> bool:
    try:
        infos = socket.getaddrinfo(name, None)
    except (OSError, socket.gaierror):
        return False
    for info in infos:
        try:
            candidate = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if candidate == address:
            return True
    return False


def rdns_crawler(address, forward_check: bool = True) -> Optional[str]:
    """Crawler name when reverse DNS (and the forward check) says so."""
    key = (str(address), bool(forward_check))
    if key in _dns_cache:
        found, name = _dns_cache[key]
        return name if found else None
    name = _rdns(address)
    result = None
    if name:
        for suffix, label in RDNS_SUFFIXES:
            if name == suffix or name.endswith("." + suffix):
                if not forward_check or _forward_matches(name, address):
                    result = "%s (%s)" % (label, name)
                break
    _dns_cache[key] = (result is not None, result or "")
    return result


def is_crawler(
    text: str,
    use_dns: bool = True,
    forward_check: bool = True,
    timeout: float = 2.0,
) -> Tuple[bool, str]:
    """``(True, reason)`` when the address must not be reported as an abuser."""
    try:
        address = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return False, ""
    label = in_published_range(address)
    if label:
        return True, "published %s range" % label
    if not use_dns:
        return False, ""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name = rdns_crawler(address, forward_check=forward_check)
    finally:
        socket.setdefaulttimeout(previous)
    if name:
        return True, "verified crawler: %s" % name
    return False, ""


def range_count() -> Dict[str, int]:
    """How many ranges were loaded, per list (used by ``--crawler-status``)."""
    return {label: len(items) for label, items in crawler_ranges.RANGES.items()}


def sources() -> Dict[str, dict]:
    return dict(crawler_ranges.SOURCES)
