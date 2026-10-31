"""Set keys of the ``[coordination]`` section of a reporter.conf in place.

Why a helper instead of ``sed``:

* the configuration shipped by the installer already contains the section (with
  ``mode = none``), and appending a second one makes ``configparser`` fail with
  ``DuplicateSectionError``;
* comments and the order of the existing keys must survive - the file is the
  operator's document, not ours;
* the file is mode 600, so the rewrite must stay atomic and keep the mode.

Usage on a host:

    sudo python3 tools/set_coordination.py --config /etc/abuseipdb/reporter.conf \
        --mode follower --node-id web-1 --leader-url http://10.0.0.5:8765

Only the keys passed as options change; everything else is left untouched. If
the section does not exist, it is created with the documented defaults.
"""
from __future__ import annotations

import argparse
import io
import os
import sys

SECTION = "coordination"
#: key order used when the section has to be created from scratch
DEFAULTS = (
    ("mode", "none"),
    ("node_id", ""),
    ("leader_url", ""),
    ("shared_secret_file", "/etc/abuseipdb/.coord.secret"),
    ("coord_bind", "127.0.0.1"),
    ("coord_port", "8765"),
    ("push_batch_size", "50"),
)
ORDER = [key for key, _ in DEFAULTS]


def _section_bounds(lines):
    """Return (start, end) line indexes of the [coordination] block, or None."""
    start = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not (stripped.startswith("[") and stripped.endswith("]")):
            continue
        name = stripped[1:-1].strip().lower()
        if name == SECTION and start is None:
            start = index
        elif start is not None:
            return start, index
    if start is None:
        return None
    return start, len(lines)


def rewrite(text: str, updates) -> str:
    lines = text.splitlines()
    bounds = _section_bounds(lines)
    if bounds is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append("[%s]" % SECTION)
        current = dict(DEFAULTS)
        current.update(updates)
        for key in ORDER:
            lines.append("%s = %s" % (key, current[key]))
    else:
        start, end = bounds
        body = lines[start + 1 : end]
        replaced = set()
        new_body = []
        for line in body:
            stripped = line.strip()
            is_option = "=" in line and not stripped.startswith(("#", ";"))
            key = line.split("=", 1)[0].strip() if is_option else ""
            if key in updates:
                new_body.append("%s = %s" % (key, updates[key]))
                replaced.add(key)
            else:
                new_body.append(line)
        missing = [key for key in ORDER if key in updates and key not in replaced]
        if missing:
            insert_at = len(new_body)
            while insert_at > 0 and not new_body[insert_at - 1].strip():
                insert_at -= 1
            for key in missing:
                new_body.insert(insert_at, "%s = %s" % (key, updates[key]))
                insert_at += 1
        lines[start + 1 : end] = new_body
    result = "\n".join(lines)
    return result + "\n" if text.endswith("\n") else result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Rewrite [coordination] keys in place.")
    parser.add_argument("--config", default="/etc/abuseipdb/reporter.conf")
    parser.add_argument("--mode", choices=("none", "leader", "follower"), default=None)
    parser.add_argument("--node-id", default=None)
    parser.add_argument("--leader-url", default=None)
    parser.add_argument("--secret-file", default=None)
    parser.add_argument("--bind", default=None)
    parser.add_argument("--port", default=None)
    parser.add_argument("--batch-size", default=None)
    parser.add_argument("--show", action="store_true", help="print the result, write nothing")
    args = parser.parse_args(argv)

    updates = {
        "mode": args.mode,
        "node_id": args.node_id,
        "leader_url": args.leader_url,
        "shared_secret_file": args.secret_file,
        "coord_bind": args.bind,
        "coord_port": args.port,
        "push_batch_size": args.batch_size,
    }
    updates = {key: value for key, value in updates.items() if value is not None}
    if not updates:
        print("nothing to change", file=sys.stderr)
        return 2

    path = args.config
    with io.open(path, encoding="utf-8", newline="") as handle:
        original = handle.read()
    result = rewrite(original, updates)
    if args.show:
        print(result)
        return 0
    if result == original:
        print("no change: %s" % path)
        return 0

    mode_bits = os.stat(path).st_mode & 0o777
    temporary = path + ".f2b-tmp"
    with io.open(temporary, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(result)
    os.chmod(temporary, mode_bits)
    os.replace(temporary, path)
    print("updated [%s] in %s: %s" % (SECTION, path, ", ".join(sorted(updates))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
