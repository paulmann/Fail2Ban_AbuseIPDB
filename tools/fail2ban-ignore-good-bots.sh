#!/bin/bash
# Add the published crawler networks to the existing [DEFAULT] ignoreip.
#
# Merge, never overwrite: 99-anti-attack.local already carries the management
# addresses and the Cloudflare ranges, and fail2ban lets the last file win for that
# option.  Runs read-only with --dry-run, backs up before writing, validates with
# fail2ban-client -t before restarting.
set -eu

FILE=${FILE:-/etc/fail2ban/jail.d/99-anti-attack.local}
DRY=${1:-}
# Narrow, crawler-specific networks only.  Google: the crawler space plus the two
# special-crawl /23s.  OpenAI: GPTBot /24s from openai.com/gptbot.json (2026-09-22).
# Deliberately absent: 34.0.0.0/8, 35.0.0.0/8, 20.0.0.0/8, 17.0.0.0/8 - those are
# whole clouds, and a scraper renting a GCP VM must still be bannable.
CRAWLERS="66.249.64.0/19 192.178.4.0/23 192.178.6.0/23 20.171.206.0/24 20.171.207.0/24 52.230.152.0/24 132.196.86.0/24 172.182.202.0/25 172.182.204.0/24 172.182.207.0/25 172.182.214.0/24 172.182.215.0/24 4.227.36.0/25 20.125.66.80/28 74.7.175.128/25 74.7.227.0/25 74.7.228.0/25 74.7.230.0/25 74.7.241.0/25 74.7.242.0/25 74.7.243.128/25 74.7.244.0/25"

echo "== current ignoreip (DEFAULT)"
fail2ban-client get sshd ignoreip | sed -n 's/^|- /    /p' | head -40

python3 - "$FILE" "$CRAWLERS" "$DRY" <<'PY'
import re
import sys

path, crawlers, dry = sys.argv[1], sys.argv[2].split(), sys.argv[3] == "--dry-run"
text = open(path, encoding="utf-8").read()

# find the DEFAULT block (the file starts with [DEFAULT] before the first jail)
match = re.search(r"^\[DEFAULT\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
if not match:
    raise SystemExit("no [DEFAULT] section in %s" % path)
block = match.group(1)

# collect the existing networks from the (possibly multi-line) ignoreip option
opt = re.search(r"^ignoreip\s*=\s*(.*?)(?=^\S|\Z)", block, re.M | re.S)
if not opt:
    raise SystemExit("no ignoreip in [DEFAULT]")
existing = opt.group(1).split()
missing = [net for net in crawlers if net not in existing]
print("existing entries: %d, crawler entries to add: %d" % (len(existing), len(missing)))
if not missing:
    print("nothing to do: all crawler ranges are already ignored")
    raise SystemExit(0)
if dry:
    print("dry run, would add: %s" % " ".join(missing))
    raise SystemExit(0)

merged = existing + missing
# keep the original shape: one option, continuation lines indented
lines = []
for index, net in enumerate(merged):
    lines.append(("ignoreip = " if index == 0 else "          ") + net)
comment = (
    "# Google/OpenAI crawler networks (2026-11-01).  A ban can be lifted, an\n"
    "# AbuseIPDB report cannot be deleted, and a good bot must not be banned.\n"
    "# Regenerate: python tools/update_crawler_ranges.py\n"
)
replacement = comment + "\n".join(lines) + "\n"
new_block = block[: opt.start()] + replacement + block[opt.end():]
new_text = text[: match.start(1)] + new_block + text[match.end(1):]
open(path + ".bak-goodbots", "w", encoding="utf-8").write(text)
open(path, "w", encoding="utf-8").write(new_text)
print("written %s (backup %s.bak-goodbots)" % (path, path))
PY

echo
echo "== validate the configuration"
fail2ban-client -t

echo
echo "== restart and verify"
if [ "${DRY}" != "--dry-run" ]; then
    systemctl restart fail2ban
    sleep 4
    systemctl is-active fail2ban
    fail2ban-client get sshd ignoreip | grep -cE '66\.249\.|192\.178\.|20\.171\.|52\.230\.' || true
    fail2ban-client status | sed -n '2p'
fi
