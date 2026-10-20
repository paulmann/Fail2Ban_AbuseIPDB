"""IP address helpers."""
from __future__ import annotations

import ipaddress
from typing import Iterable, Optional

IPAddress = ipaddress._BaseAddress
IPNetwork = ipaddress._BaseNetwork


def parse_ip(value) -> Optional[IPAddress]:
    """Return an ``ipaddress`` object or ``None`` when *value* is not an IP."""
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def is_ignored(ip: IPAddress, networks: Iterable[IPNetwork]) -> bool:
    """True when *ip* belongs to one of the ignored networks."""
    return any(ip in network for network in networks)