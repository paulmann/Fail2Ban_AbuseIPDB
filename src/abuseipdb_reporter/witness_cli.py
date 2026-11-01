"""Entry point for the failover arbiter: ``abuseipdb-witness``."""
from __future__ import annotations

import sys

from .witness import serve


def main(argv=None) -> int:
    import argparse
    import json

    from . import __version__
    from .config import load_config
    from .witness import LeaseStore

    parser = argparse.ArgumentParser(
        prog="abuseipdb-witness",
        description=(
            "Failover arbiter: grants a time-limited leadership lease to one node. "
            "Run it on a host that is not one of the reporter nodes."
        ),
    )
    parser.add_argument("--config", default=None, help="path to reporter.conf")
    parser.add_argument("--bind", default=None, help="override coord_bind")
    parser.add_argument("--port", type=int, default=None, help="override coord_port")
    parser.add_argument(
        "--state", default=None, help="lease state file (default lease_state_path)"
    )
    parser.add_argument("--check", action="store_true", help="validate the configuration and exit")
    parser.add_argument(
        "--status", action="store_true", help="print the current lease from the state file and exit"
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    bind = args.bind or cfg.coord_bind
    port = int(args.port or cfg.coord_port)
    state_path = args.state or getattr(cfg, "lease_state_path", "")

    if args.status:
        store = LeaseStore(state_path)
        print(json.dumps(store.snapshot(), indent=2, sort_keys=True))
        return 0

    if args.check:
        from .coordination import load_secret

        secret = load_secret(cfg.shared_secret_file)
        print("bind: %s:%d" % (bind, port))
        print("tls: %s" % ("yes" if getattr(cfg, "tls_cert", "") else "no"))
        print("state: %s" % (state_path or "(memory only)"))
        print(
            "secret: %s"
            % ("present" if secret else "MISSING (%s)" % cfg.shared_secret_file)
        )
        return 0 if secret else 2

    cfg.coord_bind = bind
    cfg.coord_port = port
    if state_path:
        cfg.lease_state_path = state_path
    try:
        serve(cfg)
    except OSError as error:
        print("error: cannot bind %s:%d: %s" % (bind, port, error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
