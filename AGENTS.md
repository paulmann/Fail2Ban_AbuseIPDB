# AGENTS.md — Fail2Ban_AbuseIPDB 1.5.0

Agent-facing guide: how to install Fail2Ban_AbuseIPDB, run it, and report problems responsibly.
Human documentation: [README.md](README.md), [docs/](docs/), [Wiki](https://github.com/paulmann/Fail2Ban_AbuseIPDB/wiki).

> Verified against repository state on 2026-11-01. Version covered: 1.5.0 (tag `v1.5.0`, released 2026-11-01).

## 1. What it is

A fail2ban action that writes every new ban into a local SQLite queue, plus a scheduled worker that turns that queue into AbuseIPDB reports. The ban path never talks to the network; the API call happens later, respects rate limits and retries failures. It does not ban anything itself and does not replace fail2ban filters - it only reports bans that fail2ban has already applied.

| | |
|---|---|
| Runtime / platform | Linux with systemd (recommended) or cron; Python 3.9+ (standard library only, no pip packages); Fail2Ban 0.10+ (tested with 1.1.0) |
| Entry points | `install.sh` (installer), `/usr/local/sbin/abuseipdb-report` (worker), `/usr/local/sbin/abuseipdb-enqueue` (queue helper), `/usr/local/sbin/abuseipdb-upgrade` (self-updater), `/usr/local/sbin/abuseipdb-coord` (leader endpoint, opt-in) |
| Writes to | `/usr/local/lib/abuseipdb_reporter/`, `/usr/local/sbin/abuseipdb-report`, `abuseipdb-enqueue`, `abuseipdb-upgrade`, `/etc/abuseipdb/reporter.conf` (600), `/etc/abuseipdb/.abuseipdb.key` (600), `/var/lib/abuseipdb/abuseipdb.sqlite3`, `/var/lib/abuseipdb/status.json` (last run status, atomic rewrite), optional Prometheus textfile, `/etc/abuseipdb/.coord.secret` (optional coordination secret, mode 600, created by the operator, never by the installer), `/etc/systemd/system/abuseipdb-coord.service` (installed, never enabled), `/etc/fail2ban/action.d/abuseipdb-async.conf`, `/etc/fail2ban/jail.d/50-abuseipdb-reporter.local`, systemd units `abuseipdb-report.{service,timer}` or `/etc/cron.d/abuseipdb-reporter`, `/etc/logrotate.d/abuseipdb-reporter`, `/var/log/abuseipdb-reporter.log`, backups in `/var/backups/fail2ban-abuseipdb/pristine-<timestamp>/`, state in `/var/lib/fail2ban-abuseipdb/install-state` |
| Network access | HTTPS to `api.abuseipdb.com` (`/api/v2/report`, `/api/v2/check`); `raw.githubusercontent.com` / `github.com` for `updater.json` and the release tarball |

## 2. Preconditions

| Requirement | Why | Check |
|---|---|---|
| Linux | the fail2ban action and the scheduler are Linux-specific | `uname -s` |
| root access | installer writes to `/etc`, `/usr/local`, `/var/lib`; the worker runs as root oneshot | `id -u` (expect `0`; `--root DIR` staging does not need root) |
| Python 3.9+ | the worker and the installer's preflight reject older versions | `python3 --version` |
| Fail2Ban 0.10+ running | the action is attached to existing jails | `fail2ban-client --version`; `systemctl is-active fail2ban`; `fail2ban-client status` |
| AbuseIPDB API key | reports are authenticated; free key from <https://www.abuseipdb.com/account/api> | installer fails with `no API key: ...` when none is supplied |
| fail2ban database readable | evidence lines are read from `bips` in `/var/lib/fail2ban/fail2ban.sqlite3` | `ls -l /var/lib/fail2ban/fail2ban.sqlite3` |
| Egress HTTPS | `api.abuseipdb.com:443`; `raw.githubusercontent.com`/`github.com` for update checks | `curl -sS -o /dev/null -w '%{http_code}' https://api.abuseipdb.com/api/v2/check` (expect 401 without a key) |

If a check fails, stop and report; do not work around it silently.

## 3. Install

### 3.1 From a release

Releases verified with `gh release list -R paulmann/Fail2Ban_AbuseIPDB`: `v1.5.0` (latest), `v1.4.4`, `v1.4.3`, `v1.4.2`, `v1.4.1`, `v1.4.0`, `v1.3.0`, `v1.2.1`, `v1.2.0`, `v1.1.1`, `v1.1.0`, `v1.0.0`. The v1.5.0 asset is `Fail2Ban_AbuseIPDB-1.5.0.tar.gz`; its SHA-256 is authoritative in [`updater.json`](updater.json), which the updater verifies before running the bundled `install.sh` - never trust a checksum quoted in prose. The repository does not document a manual install from the downloaded archive; the documented consumer of that asset is `abuseipdb-upgrade` ([docs/UPDATE.md](docs/UPDATE.md)). For a first install, pin the verified tag in a checkout:

```bash
git clone --branch v1.5.0 --depth 1 https://github.com/paulmann/Fail2Ban_AbuseIPDB.git
cd Fail2Ban_AbuseIPDB
sudo ./install.sh --api-key "$ABUSEIPDB_API_KEY" --jails "sshd"
```

### 3.2 From source

```bash
git clone https://github.com/paulmann/Fail2Ban_AbuseIPDB.git
cd Fail2Ban_AbuseIPDB
sudo ./install.sh --api-key "$ABUSEIPDB_API_KEY" --jails "sshd"
```

Run `install.sh` from the project directory; it aborts with `run install.sh from the project directory (incomplete checkout)` otherwise. On a terminal `--api-key` may be omitted: the installer asks once, hides the input and saves the key to `/etc/abuseipdb/.abuseipdb.key` (mode 600). Non-interactively it accepts `--api-key KEY`, `--api-key-file FILE` or `ABUSEIPDB_API_KEY`; with no key source it exits 1. Default on a fresh install is the `sshd` jail only.

| Installer option | Meaning |
|---|---|
| `--api-key KEY`, `--api-key-file FILE`, `--key-file PATH` | key source; default key file `/etc/abuseipdb/.abuseipdb.key` |
| `--jails "LIST"` | space separated jails to attach the action to (upgrade keeps the configured jails when omitted) |
| `--all-jails` | every enabled jail except the aggregate `recidive` |
| `--cron` | use `/etc/cron.d` instead of the systemd timer |
| `--with-update-check` | weekly `abuseipdb-upgrade --check` timer/cron; check only, never installs |
| `--server-ip IP`, `--report-hostname NAME` | values written to `server_ip` and `hostname` in report comments |
| `--no-restart`, `--skip-api-check` | do not restart fail2ban; do not validate the key online |
| `--root DIR`, `--dry-run` | stage everything under `DIR` (systemd and fail2ban untouched); print actions, change nothing |
| `--uninstall`, `--purge`, `-y/--yes`, `-h/--help`, `-V/--version` | removal modes, non-interactive mode, help, version |

### 3.3 Verify

```bash
fail2ban-client get sshd actions
# The jail sshd has the following actions: nftables, abuseipdb-async

/usr/local/sbin/abuseipdb-report --key-status
# API key source: key file /etc/abuseipdb/.abuseipdb.key

/usr/local/sbin/abuseipdb-report --stats
systemctl list-timers abuseipdb-report.timer     # or: cat /etc/cron.d/abuseipdb-reporter
```

A healthy install shows entries like `reported ip=... -> 200 {...}` in `/var/log/abuseipdb-reporter.log`.

## 4. Configure

Configuration is one INI file: `/etc/abuseipdb/reporter.conf`, mode 600, installed by the installer. The worker reads it on every run, so edits need no restart. The API key is deliberately not in this file; it is resolved in this order: `--api-key`, `ABUSEIPDB_API_KEY` or `ABUSEIPDB_KEY`, the key file (`api_key_file`, `ABUSEIPDB_KEY_FILE`, default `/etc/abuseipdb/.abuseipdb.key`), a deprecated legacy `api_key`, then an interactive prompt (terminal only; systemd/cron runs log an error and exit 2).

```ini
[abuseipdb]
api_key_file = /etc/abuseipdb/.abuseipdb.key
enabled = yes
min_interval_ip = 1200
max_reports_per_run = 25
max_reports_per_day = 900
daily_budget_timezone = utc
request_delay = 1.0
retry_after_cap = 60
skip_jails = recidive

[database]
path = /var/lib/abuseipdb/abuseipdb.sqlite3
fail2ban_db = /var/lib/fail2ban/fail2ban.sqlite3
retention_days = 30
max_attempts = 10

[logging]
path = /var/log/abuseipdb-reporter.log
status_path = /var/lib/abuseipdb/status.json
prometheus_textfile =

[coordination]
mode = none
node_id = server1
leader_url =
shared_secret_file = /etc/abuseipdb/.coord.secret
coord_bind = 127.0.0.1
coord_port = 8765
push_batch_size = 50
sync_bans = yes
max_remote_bans_per_run = 20
peer_dedupe_window = 900
max_sync_bans = 50

[ignore]
ranges = 10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8, 203.0.113.10/32, 2001:db8::/32

[category_map]
sshd = 18,22
```

`[report] server_ip`, `[report] hostname`, `[report] attribution` and `[update] manifest_url` are optional. Before enabling broad jails, put your management addresses and any CDN edge ranges into `[ignore] ranges`; the example file also carries Cloudflare ranges. Default categories per jail are in `[category_map]`; a jail not listed falls back to category 21, and SQL-injection patterns in a URL add category 16 automatically.

## 5. Use

| Purpose | Command | Expected result |
|---|---|---|
| Inspect the queue | `/usr/local/sbin/abuseipdb-report --stats` | counters `pending events:`, `pending ips:`, `reports today:`, `reports total:`, recent reports |
| Last run in one call | `--status` | JSON: `sent`, `skipped`, `errors`, `pending`, `today`, `stopped`, `retry_after`, `version`; exit 1 when no status file exists yet |
| Coordination role | `--coord-status` | prints `mode`, `node_id`, `secret: present/MISSING` and, on a follower, the leader's status document (exit 2 when the secret or `leader_url` is missing, 1 when the leader is unreachable) |
| Leader endpoint | `/usr/local/sbin/abuseipdb-coord --check`, then the service | `--check` validates mode, bind and secret (exit 2 on a missing secret); the service is installed but never enabled |
| Preview payloads | `/usr/local/sbin/abuseipdb-report --dry-run` | one JSON object per report, no API call, no event marked reported (it still opens the queue DB and applies `retention_days` cleanup) |
| Drain the queue now | `/usr/local/sbin/abuseipdb-report` | journal line `report: run done sent=... pending=...`; real POSTs to AbuseIPDB |
| Check the key | `--check-key` | `HTTP 200`; uses one `/check` request, do not loop it |
| Show key source | `--key-status` | `API key source: ...` plus a masked key |
| Save or migrate the key | `--setup`, `--migrate-key` | key written to the key file, file mode 600 |
| Queue one ban manually | `abuseipdb-enqueue --ip IP --jail JAIL --bantime SECONDS --failures N` | event queued; `--allow-reserved` exists for tests only |
| Update | `abuseipdb-upgrade --check`, `--check --json`, `--upgrade --yes`, `--dry-run` | exit 0 = current, 10 = update available, 1 = error |

**Exit codes.** `install.sh`: 0 success, 1 aborted (`die`: unknown option, no key, python3 too old, incomplete checkout, `fail2ban-client -t` failed). `abuseipdb-report`: 0 normal, also 0 when another instance holds the lock or `enabled = no`; 2 when no key is available. `--check-key`: 0 on HTTP 200, 1 on any other status, 2 when no key. `abuseipdb-enqueue`: always 0 - errors are logged and the ban is unaffected. `abuseipdb-upgrade`: 0, 10 (check only), 1 (error, cancelled, not root, or `--upgrade` without `--yes` on a non-terminal).

The scheduler runs the worker every 16 minutes (systemd timer with `Persistent=true`, or cron `*/16`); a `/run` lock keeps one worker at a time.

## 6. Safety and rollback

- Changes: installs the package and CLIs, writes `reporter.conf` and the key file, creates the SQLite queue, adds the `abuseipdb-async` action and a `jail.d` snippet for the named jails, enables a timer or cron job, adds logrotate, and restarts (or reloads) fail2ban unless `--no-restart`.
- Never does: it does not ban or unban addresses, does not edit firewall rules, and does not replace fail2ban filters. Uninstall does not send the local queue anywhere.
- Undo: `sudo ./install.sh --uninstall` removes code, action and schedule, restores files that existed before the first installation from the install state and pristine backup, and restarts fail2ban; it keeps `reporter.conf`, the queue, the key and the log. `sudo ./install.sh --uninstall --purge` also removes `/etc/abuseipdb` (including the key), `/var/lib/abuseipdb`, the log, the state and `/var/backups/fail2ban-abuseipdb`.
- Queue reset without uninstall: `systemctl stop abuseipdb-report.timer`, `rm -f /var/lib/abuseipdb/abuseipdb.sqlite3*`, `rm -f /var/log/abuseipdb-reporter.log`, `systemctl start abuseipdb-report.timer`. This loses unreported reports but not firewall state.
- On a production host, follow this order and do not skip steps:
  1. `sudo ./install.sh --help` (read only).
  2. `sudo ./install.sh --dry-run --api-key "$ABUSEIPDB_API_KEY" --jails "sshd"` - prints every action; pass a key source because the key step still runs.
  3. Rehearse in a staging root: `sudo ./install.sh --root /tmp/stage --api-key "$ABUSEIPDB_API_KEY" --jails "sshd" --cron --skip-api-check --no-restart` (this is the CI mode; systemd and fail2ban are not touched).
  4. Install for real with `--jails "sshd"`, then verify per section 3.3.
  5. One object: queue one real attacker address (documentation ranges are in `[ignore] ranges` and are skipped), run `--dry-run`, and send one report only if the operator explicitly allows it - AbuseIPDB reports are public and the tool cannot delete them.
  6. Everything: re-run the installer with the full `--jails` list or `--all-jails`; it keeps the key, config, queue and jail list.
- The installer also runs `abuseipdb-report --check-key` after installation, which contacts `api.abuseipdb.com`; use `--skip-api-check` for offline or CI installs.
- Back up `/etc/fail2ban` before changing it. `fail2ban-client -t` must pass before a restart; the installer enforces this gate itself. `fail2ban-client set <jail> banip <address>` bypasses `ignoreip` - never use a management address for tests.

## 7. Failure modes

| Symptom | Likely cause | Action |
|---|---|---|
| No reports, queue grows | `abuseipdb-async` not attached to the jail | `fail2ban-client get <jail> actions`; re-run the installer with the right `--jails`; `systemctl restart fail2ban` |
| `pending events: 0` | action not firing, or the address is in `[ignore] ranges` | check `[ignore] ranges`, the jail, and `/var/log/abuseipdb-reporter.log` |
| `--dry-run` prints nothing with pending events | every IP is inside `min_interval_ip` (20 min) | wait for the next window |
| Run exits 2, log says no API key | no key source for a systemd/cron run | `--key-status`, then `--setup` or the key file |
| HTTP 401 | key wrong or revoked | replace the key file (or `--setup`); the run stops and retries next tick |
| HTTP 403 | egress blocked by proxy/firewall or provider policy | verify `api.abuseipdb.com:443` |
| HTTP 429 `once in 15 minutes` | same IP already reported by this account | expected; event stays pending |
| HTTP 429 other text | daily budget exhausted | wait for the next day or lower `max_reports_per_day`; the budget day starts at 00:00 UTC unless `daily_budget_timezone = local` |
| `database is locked` in the log | action and worker collided on the queue | action retries 3 times (0.2 s, 0.4 s) then drops the event; check nothing holds the DB for minutes |
| HTTP 400 / 422 | report rejected as invalid | event marked invalid (2), never retried; check `[ignore] ranges` |
| `fail2ban-client -t` fails | generated jail snippet conflicts | installer aborts before restarting; restore from `/var/backups/fail2ban-abuseipdb/pristine-<timestamp>/` or remove `/etc/fail2ban/jail.d/50-abuseipdb-reporter.local` |
| Empty systemd journal | host does not persist journald | use `/var/log/abuseipdb-reporter.log` as the source of truth |
| Duplicate reports after reboot | action attached twice (e.g. `jail.local` and the snippet) | `fail2ban-client get <jail> actions` lists `abuseipdb-async` twice; remove one |
| Follower log: `follower (HTTP 403 ...)` | the shared secret differs between nodes | compare `sha256sum /etc/abuseipdb/.coord.secret` on both ends |
| Follower log: `follower (URLError ...)` | leader endpoint down, wrong port, firewall | `abuseipdb-report --coord-status`; `curl -H "X-Coord-Secret: ..." http://leader:8765/v1/status` |
| Leader: `coord: warning: mode is 'none'` | endpoint started on a standalone node | set `[coordination] mode = leader` or stop the endpoint |
| `abuseipdb-upgrade --check` exits 1 | network error or invalid manifest | verify egress to `raw.githubusercontent.com` |

## 8. Limits

- Deployment is Linux-only (fail2ban action + systemd/cron); the Python package and test suite run on any platform, but Windows and macOS are not supported as deployment targets.
- No pip, no virtualenv, no daemon: standard library only, so packaging constraints are Python 3.9 syntax and Fail2Ban 0.10+. The **package** is published on PyPI as [`fail2ban-abuseipdb-reporter`](https://pypi.org/project/fail2ban-abuseipdb-reporter/) (wheel + sdist, uploaded by the release workflow through OIDC trusted publishing - no token is stored in the repository or on the runner) and can be installed with `pip` to get the four CLIs and the library - but a pip install does **not** touch fail2ban, systemd, the key file or `/etc/abuseipdb`; the supported host deployment is `install.sh` and `abuseipdb-upgrade`.
- Proxy support for egress is not provided out of the box; `api_url`/`check_url` are the only documented overrides ([docs/INSTALL.md](docs/INSTALL.md)).
- Rate caps are deliberate: 20 minutes per IP, 25 reports per run, 900 per day (AbuseIPDB free plan allows 1000 requests/day and one report per IP per 15 minutes). The daily budget day starts at 00:00 UTC by default.
- Coordination supports **one leader**: there is no election and no shared lease, so failover is a manual procedure (move the key file, switch `mode`, restart the endpoint). Never run two leaders with the same key - that doubles the account budget consumption and breaks the per-IP interval between hosts.
- **Ban propagation is opt-out and bounded**: a follower applies `to_ban` through `fail2ban-client` (ignore ranges, own `server_ip`, only jails the node declares, strict jail-name pattern, `max_remote_bans_per_run` = 20 per run, never unban). `sync_bans = no` disables it. The endpoint must never face the internet: a compromised leader can make followers ban addresses.
- The optional weekly update check only reports availability; automatic installation is not provided.
- AbuseIPDB comments are public; the attribution footer is on by default (`attribution = no` disables it).
- Manual installation from the downloaded release archive is Not documented in this repository.

## 9. Sources of truth

- [README.md](README.md) - product behaviour, installer and CLI reference, compatibility, report anatomy.
- [docs/INSTALL.md](docs/INSTALL.md) - requirements, installer options, installed paths, verification, upgrade, uninstall, manual install.
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) - every configuration key, key resolution, rate limits, environment variables.
- [docs/RELEASING.md](docs/RELEASING.md) - maintainer release path: version bump, tag, CI publish to PyPI over OIDC trusted publishing, `updater.json`.
- [docs/UPDATE.md](docs/UPDATE.md) - update manifest, `--check`/`--upgrade` semantics, rollback, weekly check.
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) - diagnosis recipes used in section 7.
- `install.sh` (`VERSION="1.3.0"`, `usage()`, exit paths), `config/reporter.conf.example`, `fail2ban/action.d/abuseipdb-async.conf`, `systemd/abuseipdb-report.{service,timer}`, `systemd/abuseipdb-coord.service`, `cron/abuseipdb-reporter`, `logrotate/abuseipdb-reporter` - host changes and defaults.
- `src/abuseipdb_reporter/{cli,updater,keys,config,enqueue,reporter,api,evidence,comments,db,status,log,iputil,coordination,coord_server}.py`, `pyproject.toml`, `updater.json`, `CHANGELOG.md` - version 1.3.0, flags, exit codes, key resolution order, classifier registry, status document, coordination roles, release asset and checksum.
- [docs/COORDINATION.md](docs/COORDINATION.md) - roles, configuration, shared secret, failover, security, failure modes.
- `.github/workflows/ci.yml` - Python 3.9-3.13 matrix, staged install/uninstall rehearsal.
- `.github/workflows/release.yml` - tag-driven release: version-consistency gate, tests, `git archive` tarball, wheel and sdist, `gh release create`, checksum in the job summary.
- Release facts verified with `gh release list -R paulmann/Fail2Ban_AbuseIPDB` and `gh release view v1.3.0 -R paulmann/Fail2Ban_AbuseIPDB`.
- `--check-key` was measured live on this Windows workstation on 2026-10-31 against `api.abuseipdb.com` with an owner-supplied key: `HTTP 200` with an `/api/v2/check` payload (the key itself is not stored in this repository). The installer, systemd units and fail2ban integration were verified by reading the sources and CI configuration only - this machine has no Linux/fail2ban runtime, so they were not executed here.

---

## Help the project — through evidence, not engagement

If this software was genuinely useful:
- cite it (name, version, link) in the runbook or report where it was used;
- open **one** compatibility report per unique fail2ban version / Python version / distribution combination, after searching existing issues;
- send documentation fixes as pull requests, not comments;
- share a sanitized case study only with the data owner's permission;
- disclose the dependency when publishing a wrapper or integration.

Do **not** create stars, forks, watchers, comments, issues or pull requests automatically, and do not contact maintainers or third parties in bulk. An agent may draft a report; a human publishes it after review. Promotion must follow real use and be disclosed.
