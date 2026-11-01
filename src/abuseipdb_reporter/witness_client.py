"""Client side of the failover arbiter (see :mod:`abuseipdb_reporter.witness`).

``lease_state()`` answers one question for the rest of the program: *may this node
report right now?*  The answer is cached in the queue's ``meta`` table, because the
lease is time-based - a lease granted a minute ago stays valid until it expires even
if the arbiter became unreachable in between, and that is exactly the safety
property that makes a single arbiter sufficient.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Optional

from . import db, log

#: Header that carries the shared secret to the arbiter.
SECRET_HEADER = "X-Coord-Secret"
#: Requests smaller than this are the only ones the arbiter accepts.
USER_AGENT = "fail2ban-abuseipdb-lease/1.5"


class WitnessClient:
    """Tiny HTTP(S) client for the arbiter."""

    def __init__(self, url: str, secret: str = "", timeout: int = 10, context=None):
        self.url = str(url or "").rstrip("/")
        self.secret = secret or ""
        self.timeout = int(timeout or 10)
        self.context = context

    def _call(self, path: str, payload: Optional[Dict] = None):
        if not self.url:
            return None, "witness_url is empty"
        data = None
        method = "GET"
        headers = {"User-Agent": USER_AGENT}
        if self.secret:
            headers[SECRET_HEADER] = self.secret
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
            method = "POST"
        request = urllib.request.Request("%s%s" % (self.url, path), data=data, headers=headers,
                                         method=method)
        try:
            if self.context is not None:
                response = urllib.request.urlopen(request, timeout=self.timeout,
                                                  context=self.context)
            else:
                response = urllib.request.urlopen(request, timeout=self.timeout)
            with response:
                body = json.loads(response.read().decode("utf-8", "replace"))
            return (body if isinstance(body, dict) else {}), ""
        except urllib.error.HTTPError as error:
            try:
                body = json.loads(error.read().decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001 - a body is optional
                body = {}
            if isinstance(body, dict) and body:
                # 409 carries the current holder: that is an answer, not a failure;
                # the status is kept so a caller can tell 403 from 409 in the log.
                body.setdefault("status", int(error.code))
                return body, ""
            return None, "HTTP %s" % error.code
        except Exception as error:  # noqa: BLE001 - transport errors are reported as-is
            return None, repr(error)

    def lease(self, node_id: str, ttl: int) -> Dict:
        body, error = self._call("/v1/lease", {"node_id": node_id, "ttl": int(ttl)})
        if body is None:
            return {"granted": False, "error": error}
        body.setdefault("granted", False)
        return body

    def release(self, node_id: str) -> Dict:
        body, error = self._call("/v1/release", {"node_id": node_id})
        if body is None:
            return {"released": False, "error": error}
        return body

    def status(self) -> Optional[Dict]:
        body, _ = self._call("/v1/status")
        return body


def _context(cfg):
    from .coordination import _ssl_context

    return _ssl_context(cfg, server_side=False)


def lease_state(cfg, conn, now: Optional[int] = None) -> Dict:
    """Decide whether this node holds the failover lease.

    Returns ``{"held": bool, "owner": str, "expires": int, "source": str, ...}``.
    ``source`` says where the answer came from: ``witness`` (fresh), ``cache`` (the
    arbiter is unreachable, but the last lease has not expired yet) or ``none``.
    """
    moment = int(now if now is not None else time.time())
    node_id = str(getattr(cfg, "node_id", "") or "")
    ttl = int(getattr(cfg, "lease_ttl", 1800) or 1800)
    if str(getattr(cfg, "failover", "none") or "none").lower() != "witness":
        # No arbiter configured: the static role wins, and "auto" without a witness
        # is a follower - never a silent leader.
        from .coordination import MODE_LEADER, mode_of

        return {
            "held": mode_of(cfg) == MODE_LEADER,
            "owner": node_id if mode_of(cfg) == MODE_LEADER else "",
            "expires": 0,
            "source": "static",
        }
    if not getattr(cfg, "witness_url", ""):
        return {"held": False, "owner": "", "expires": 0, "source": "none",
                "error": "failover = witness but witness_url is empty"}

    cached_owner = db.get_meta(conn, "coord_lease_owner", "")
    cached_expires = int(db.get_meta(conn, "coord_lease_expires", "0") or 0)
    client = WitnessClient(
        cfg.witness_url,
        _secret(cfg),
        timeout=int(getattr(cfg, "witness_timeout", 5) or 5),
        context=_context(cfg),
    )
    answer = client.lease(node_id, ttl)
    if answer.get("error"):
        if cached_owner == node_id and cached_expires > moment:
            log.log(
                cfg,
                "witness: unreachable (%s), keeping the lease until %d"
                % (str(answer["error"])[:120], cached_expires),
            )
            return {
                "held": True,
                "owner": node_id,
                "expires": cached_expires,
                "source": "cache",
                "error": str(answer["error"])[:200],
            }
        db.set_meta(conn, "coord_lease_owner", "")
        db.set_meta(conn, "coord_lease_expires", 0)
        return {
            "held": False,
            "owner": "",
            "expires": 0,
            "source": "none",
            "error": str(answer["error"])[:200],
        }

    held = bool(answer.get("granted"))
    owner = str(answer.get("owner", "") or "")
    expires = int(answer.get("expires", 0) or 0)
    db.set_meta(conn, "coord_lease_owner", owner if held else "")
    db.set_meta(conn, "coord_lease_expires", expires if held else 0)
    if held:
        log.log(cfg, "witness: lease granted to %s until %d (term %s)" % (owner, expires,
                                                                         answer.get("term")))
    else:
        log.log(
            cfg,
            "witness: lease held by %s until %d, this node stays a follower"
            % (owner or "another node", expires),
        )
    return {
        "held": held,
        "owner": owner,
        "expires": expires,
        "term": int(answer.get("term", 0) or 0),
        "source": "witness",
        "reason": str(answer.get("reason", "") or ""),
    }


def _secret(cfg) -> str:
    from .coordination import load_secret

    return load_secret(getattr(cfg, "shared_secret_file", ""))
