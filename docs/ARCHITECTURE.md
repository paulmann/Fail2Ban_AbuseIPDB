# Architecture

## Design goal

Fail2Ban already knows *who* attacked and *why*. AbuseIPDB wants a short,
factual report per abusive IP. The naive integration (the stock `abuseipdb`
action) runs `curl` **inside** the ban action, which couples three unrelated
systems: the ban, the network and the AbuseIPDB API. This project decouples
them with a small local queue.

```
                     ban path                        report path
  ┌───────────────┐   ┌──────────────────────┐   ┌────────────────────────┐
  │   fail2ban    │──▶│ abuseipdb-async      │──▶│ SQLite queue           │
  │  (any jail)   │   │ action               │   │ /var/lib/abuseipdb/    │
  └───────┬───────┘   │  • nftables ban      │   │  events + reports      │
          │           │  • enqueue event     │   └───────────┬────────────┘
          │           └──────────────────────┘               │
          ▼                                                  ▼
     firewall rule                              systemd timer / cron (16 min)
                                                  /usr/local/sbin/abuseipdb-report
                                                    • aggregate queue by IP
                                                    • read fail2ban evidence
                                                    • build comment
                                                    • POST /api/v2/report
                                                    • journal + retries
```

The ban is applied by the ordinary firewall action and is never delayed by the
API. The queue absorbs downtime, rate limits and abuse bursts; the worker drains
it later.

## Components

| Component | Responsibility |
|---|---|
| `fail2ban/action.d/abuseipdb-async.conf` | fail2ban action. `norestored = 1`, calls the queue helper with `ip`, jail, `bantime`, `failures` |
| `bin/abuseipdb-enqueue` | validates the address, applies ignore rules, writes one event row (≈0.1 s) |
| `bin/abuseipdb-report` | worker: aggregation, comment building, API calls, retries, cleanup, `--stats`, `--dry-run`, `--check-key` |
| `src/abuseipdb_reporter/config.py` | INI parsing, defaults, ignore networks, category map |
| `src/abuseipdb_reporter/db.py` | SQLite schema and all queue/journal operations |
| `src/abuseipdb_reporter/evidence.py` | reads fail2ban's `bips.data.matches`, classifies log lines |
| `src/abuseipdb_reporter/comments.py` | builds a PII-free comment, categories, timestamp |
| `src/abuseipdb_reporter/api.py` | urllib-based API client (no third-party dependencies) |
| `src/abuseipdb_reporter/reporter.py` | the run loop and rate-limit policy |

## API key storage

The key is deliberately **not** part of `reporter.conf` and not part of the
release tarball. It lives in `/etc/abuseipdb/.abuseipdb.key` (mode 600):

* `install.sh` creates/migrates it once and keeps an existing file untouched;
* `abuseipdb-upgrade` snapshots the key file before running the installer and
  restores it if the installer fails;
* the repository contains no key; `.gitignore` excludes `*.key`.

Resolution order and the first-run prompt are described in
[CONFIGURATION.md](CONFIGURATION.md#api-key-resolution).

## Self-update

`updater.json` in the repository root is the release manifest:

```json
{
  "version": "1.1.0",
  "tarball": "https://github.com/.../releases/download/v1.1.0/...tar.gz",
  "sha256": "<checksum of the tarball>",
  "release_notes": "https://github.com/.../releases/tag/v1.1.0"
}
```

`abuseipdb-upgrade --check` compares `version` with the installed
`__version__`. `--upgrade` downloads the tarball over HTTPS, **requires** a
SHA-256 checksum, refuses archives without one, rejects absolute paths,
`..` traversal, symlinks and device entries, extracts to a temporary directory
and runs the bundled `install.sh`. The installer preserves the key, the config,
the queue and the configured jails; on any failure the updater restores the key
file from its snapshot.

The optional weekly timer (`--with-update-check`) only runs `--check`; it never
installs anything in the background.

## Local queue (SQLite, WAL)

```sql
events(id, ip, jail, event_time, bantime, failures, created_at,
       reported, attempts, note)
reports(id, ip, jail, reported_at, status, categories, comment, response)
```

`events.reported` states: `0` pending, `1` reported, `2` invalid report
(4xx other than 401/429), `3` gave up after `max_attempts` transient errors.

Repeated bans of the same IP and jail within 5 minutes are collapsed into one
event, so a persistent attacker produces one report per throttle window, not
dozens.

## Why the comment is trustworthy

The evidence is **not** scraped from logs by the worker. Fail2Ban stores the log
lines that triggered every ban in its own database (`bips.data`, JSON field
`matches`). The worker reads them read-only:

* no extra parsing of 100 MB of web logs per run;
* the lines are exactly what the filter matched;
* attacker-controlled text never reaches a shell, because it is only inserted
  into a JSON/querystring comment built in Python.

The stock `abuseipdb.conf` action interpolates `<matches>` into a shell command.
An attacker can put a backtick or `$()` into a request URL that ends up in the
matched log line - and get it executed by the fail2ban action, which runs as
root. This project deliberately passes only `<ip>`, `<name>`, `<bantime>` and
`<failures>`, all of which are generated by fail2ban itself.

## Report policy

1. Group pending events by IP.
2. Skip when the last successful report for this IP is younger than
   `min_interval_ip` (default 1200 s; API limit is 900 s).
3. Stop when the daily budget (`max_reports_per_day`) or the per-run budget
   (`max_reports_per_run`) is exhausted.
4. Build the comment from the jails, counters, generic patterns and - for web
   jails - the attacker's URLs. No usernames, no mail content. The body is
   truncated first, then the attribution footer is appended, so the project
   credit survives any `comment_max_bytes` value.
5. `POST /api/v2/report` with `ip`, `categories`, `timestamp`, `comment`.
6. Interpret the response:

| Status | Meaning | Action |
|---|---|---|
| 200 | accepted | mark events reported, journal the attempt |
| 401 | bad API key | stop the run, log an error |
| 429 (per IP) | same IP reported within 15 min | keep pending, retry on a later tick |
| 429 (global) | daily/global quota | stop the run, keep everything pending |
| 400 / 422 | invalid report | mark invalid, never retry |
| 5xx / timeout | transient | increment attempts, retry later (up to `max_attempts`) |

7. Delete finished events and old report rows older than `retention_days`.

## Scheduling

* **systemd timer** (default): `OnBootSec=3min`, `OnUnitActiveSec=16min`,
  `Persistent=true`. The 16 minutes are chosen because AbuseIPDB rejects a
  second report for the same IP within 15 minutes; the per-IP throttle is the
  hard guarantee, the timer only provides a steady drain rate.
* **cron** (`--cron`): `*/16 * * * *`. Cron fires at `:00,:16,:32,:48`, so the
  gap before the hour is 12 minutes; the per-IP throttle still enforces 20
  minutes between reports for one address.

Both schedules are safe to run concurrently: a `/run` lock prevents two workers
from processing the same queue at once.

## Failure modes

| Failure | Behaviour |
|---|---|
| AbuseIPDB is down | events stay queued; retried on later ticks |
| API key revoked | 401, run stops, error in the log, queue intact |
| daily quota exhausted | run stops until the next day (UTC/local midnight of the host) |
| database locked | SQLite busy timeout (10 s) and WAL mode |
| disk full | enqueue logs an error, the ban still works |
| host reboot | queue is on disk; `Persistent=true` runs the missed tick |
| fail2ban restart | `norestored = 1` prevents duplicate reports for restored bans |

## Resource usage

* one Python process per timer tick, ~13 MB RSS, well under a second for a
  normal queue;
* one SQLite file, a few hundred kilobytes;
* one log file, rotated weekly;
* no daemons and no extra services.