# Configuration

The reporter has a single INI file: `/etc/abuseipdb/reporter.conf`.
It is installed with mode `600` (root only). Since 1.1.0 the API key lives in
its own file (`api_key_file`), but the configuration stays root-only anyway: it
may still carry a legacy `api_key` until `--migrate-key` has been run, and it
names the reporting server and the trusted networks.

`/usr/local/sbin/abuseipdb-report --config /path/to/other.conf` is honoured, as
is the `ABUSEIPDB_REPORTER_CONFIG` environment variable.

## `[abuseipdb]`

| Option | Default | Meaning |
|---|---|---|
| `api_key_file` | `/etc/abuseipdb/.abuseipdb.key` | file with the API key (mode 600). Preferred location |
| `api_key` | *(empty)* | **deprecated** legacy key in the config; migrated by `--migrate-key` |
| `api_url` | `https://api.abuseipdb.com/api/v2/report` | report endpoint |
| `check_url` | `https://api.abuseipdb.com/api/v2/check` | endpoint used by `--check-key` |
| `enabled` | `yes` | `no` pauses sending; bans keep being queued |
| `timeout` | `25` | HTTP timeout, seconds |
| `min_interval_ip` | `1200` | minimum seconds between two reports for the same IP (API allows one per 900 s) |
| `max_reports_per_run` | `25` | cap per timer tick |
| `max_reports_per_day` | `900` | daily budget; free AbuseIPDB plan allows 1000 requests/day |
| `daily_budget_timezone` | `utc` | which midnight starts the budget day: `utc` (AbuseIPDB resets its quota at 00:00 UTC) or `local` |
| `request_delay` | `1.0` | seconds between two API calls; doubles after each transient error |
| `retry_after_cap` | `60` | upper bound for any pause, in seconds (also caps a `Retry-After` header) |
| `comment_max_bytes` | `1000` | comment is truncated to this size (API hard limit 1024) |
| `evidence_max_lines` | `4` | how many evidence lines/URLs to include |
| `skip_jails` | `recidive` | comma separated jails that are never reported |

## `[logging]`

| Option | Default | Meaning |
|---|---|---|
| `path` | `/var/log/abuseipdb-reporter.log` | one line per event, per report and per error |
| `status_path` | `/var/lib/abuseipdb/status.json` | machine-readable status of the last run; set it to an empty value to disable the file |
| `prometheus_textfile` | *(empty)* | if set, the same numbers are written as a Prometheus text-exposition file for the `node_exporter` textfile collector |

See [Monitoring](#monitoring-status-file-and-metrics) below.

## API key resolution

The key is read in this order:

1. `--api-key` command line option (one-off, never saved);
2. `ABUSEIPDB_API_KEY` or `ABUSEIPDB_KEY` environment variable;
3. the key file (`api_key_file`, `ABUSEIPDB_KEY_FILE` env, default
   `/etc/abuseipdb/.abuseipdb.key`);
4. legacy `api_key` in this config file (deprecated);
5. interactive prompt - only when a human runs the command on a terminal
   (systemd/cron runs never prompt; they log an error and exit).

`abuseipdb-report --setup` asks for the key and saves it; `--migrate-key` moves
a legacy `api_key` into the key file and blanks the config line;
`--key-status` shows the source and a masked key.

## `[database]`

| Option | Default | Meaning |
|---|---|---|
| `path` | `/var/lib/abuseipdb/abuseipdb.sqlite3` | local queue and report journal |
| `fail2ban_db` | `/var/lib/fail2ban/fail2ban.sqlite3` | fail2ban's database; the matched log lines are read from its `bips` table |
| `retention_days` | `30` | finished events and report attempts are deleted after this period |
| `max_attempts` | `10` | transient API errors are retried; after this many attempts the event is marked "gave up" |

## `[report]`

| Option | Default | Meaning |
|---|---|---|
| `server_ip` | *(auto-detected by the installer)* | shown in the comment as the reporting server |
| `hostname` | *(auto-detected)* | reserved for comments/logs |
| `attribution` | `yes` | append the project credit to every report |
| `attribution_text` | `Reported via Fail2Ban_AbuseIPDB Monitor: https://github.com/paulmann/Fail2Ban_AbuseIPDB` | text of the credit; replace it with your own link or a neutral phrase |

`server_ip` and `hostname` are informational only. Leave them empty to omit the
server line.

### Attribution footer

Every report ends with a small credit:

```
--
Reported via Fail2Ban_AbuseIPDB Monitor: https://github.com/paulmann/Fail2Ban_AbuseIPDB
```

AbuseIPDB comments are public, so this is how the project gets discovered by
other administrators. The footer is appended **after** the body is truncated and
is therefore never cut off, even with a very small `comment_max_bytes`. Disable
it for neutral reports:

```ini
[report]
attribution = no
```

or replace it with your own text/link:

```ini
[report]
attribution_text = Reported by ACME edge scanner
```

## `[update]`

| Option | Default | Meaning |
|---|---|---|
| `manifest_url` | `https://raw.githubusercontent.com/paulmann/Fail2Ban_AbuseIPDB/main/updater.json` | manifest used by `abuseipdb-upgrade`; override for mirrors or testing |

## `[ignore]`

`ranges` is a comma/whitespace separated list of CIDR ranges that must never be
reported. An inline `# comment` after a value is dropped (since 1.2.1), so the
documented style below works as written. The defaults cover private, loopback,
link-local, documentation and reserved space. **Add your own management addresses and any trusted networks**,
and keep CDN ranges (the example contains Cloudflare's IPv4/IPv6 ranges) if
sites behind those CDNs are protected by fail2ban - otherwise a banned CDN edge
address would be reported instead of the real client.

```ini
[ignore]
ranges = 10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8,
         203.0.113.10/32, 2001:db8::/32,
         173.245.48.0/20, 103.21.244.0/22   # examples: extend as needed
```

## `[category_map]`

Maps a fail2ban jail to one or more AbuseIPDB category IDs
(<https://www.abuseipdb.com/categories>). The default mapping:

| Jail | Categories | Meaning |
|---|---|---|
| `sshd` | 18,22 | Brute-Force, SSH |
| `proftpd`, `vsftpd`, `pure-ftpd` | 18,5 | Brute-Force, FTP Brute-Force |
| `exim-auth-fail` | 18 | Brute-Force |
| `exim-isp` | 18,11 | Brute-Force, Email Spam |
| `postfix`, `postfix-sasl` | 18 | Brute-Force |
| `dovecot` | 18 | Brute-Force |
| `nginx-attack-scan` | 21,19 | Web App Attack, Bad Web Bot |
| `nginx-wp-login` | 21,18 | Web App Attack, Brute-Force |
| `nginx-php-probe` | 21,15 | Web App Attack, Hacking |
| `nginx-forbidden` | 21 | Web App Attack |
| `nginx-badbots`, `nginx-botsearch` | 19,21 | Bad Web Bot, Web App Attack |
| `nginx-noscript` | 21,15 | Web App Attack, Hacking |
| `apache-auth` | 18 | Brute-Force |
| `apache-badbots` | 19,21 | Bad Web Bot, Web App Attack |

SQL-injection attempts are detected automatically (patterns such as
`UNION SELECT`, `information_schema`, `OR 1=1`, `sleep(`, `load_file(`) and
category **16** is added to the report. Percent-encoded payloads
(`%20UNION%20SELECT`) are matched too, because the line is also checked after
URL-decoding.

### Evidence classifiers

Log lines are turned into report text by a **registry** of classifiers
(`src/abuseipdb_reporter/evidence.py`, `CLASSIFIERS`), matched by jail-name
prefix:

| Prefixes | Classifier | Output |
|---|---|---|
| `sshd`, `ssh-`, `dropbear` | SSH | password/root/PAM patterns, MaxAuthTries |
| `proftpd`, `vsftpd`, `pure-ftpd` | FTP | non-existent user, wrong password, PAM failures |
| `exim`, `postfix`, `sendmail`, `smtpd` | SMTP | AUTH codes 535/435, SASL failures |
| `dovecot`, `courier`, `cyrus` | mailbox | aborted/failed IMAP and POP3 logins |
| `nginx`, `apache`, `haproxy`, `lighttpd`, `openresty`, `traefik` | web | request line + status, SQLi flag |
| anything else | generic | request lines and SQLi flag when the lines carry them |

Add support for another service by appending one `((prefix, ...), function)`
pair to `CLASSIFIERS` - the reporter and the comment builder stay untouched.
Until then an unknown jail still gets the generic treatment instead of an empty
report.

Add your own jails without touching code:

```ini
[category_map]
my-dovecot-jail = 18,11
my-api-abuse-jail = 21,15
```

Any jail not listed falls back to category `21` (Web App Attack) except the
built-in defaults above.

## What a report looks like

The API receives `ip`, `categories`, `timestamp` and `comment` (<= 1024 bytes).
The comment is generated from the queued events and from the log lines that
fail2ban itself recorded for the ban:

```
Automated fail2ban report from server 203.0.113.10.
Attack type: SSH brute-force (jails: sshd).
Observed: 2026-01-02T03:04:05+00:00.
Detections: 1 ban event(s), 4 failed attempts.
Ban duration: 4d.
Patterns: PAM authentication failures; root password attempts; invalid usernames tried.
Log evidence:
  sshd-session[123]: pam_unix(sshd:auth): authentication failure; ... rhost=198.51.100.7
  sshd-session[123]: Failed password for root from 198.51.100.7 port 22 ssh2
No personal data included.
--
Reported via Fail2Ban_AbuseIPDB Monitor: https://github.com/paulmann/Fail2Ban_AbuseIPDB
```

For web jails the evidence block contains the attacker's own requests
(`GET /.env -> 404`, `GET /wp-admin/install.php?step=1 -> 404`, ...), which is
usually the most useful part for other AbuseIPDB users.

**Privacy:** attempted usernames are deliberately not included (they are
attacker-chosen strings and add no value to the report); mail content and
addresses are never included. Only the attacker's own IP and requests are sent.

## Timestamp

The `timestamp` is the time of the first queued ban for that IP, in ISO-8601
with the local timezone offset. If an event stayed in the queue for more than
23 hours (API downtime, exhausted daily budget), the report uses the current
time instead, so AbuseIPDB never receives a stale timestamp.

## Rate limits

AbuseIPDB limits the free plan to **1000 reports + checks per day** and accepts
**one report per IP per 15 minutes**. The reporter enforces:

* `min_interval_ip` = 1200 s (20 minutes) between reports for the same IP;
* `max_reports_per_day` = 900, leaving headroom for `--check-key`;
* `max_reports_per_run` = 25, keeping each timer tick short;
* on HTTP 429 the run stops (global limit) or the IP is deferred (per-IP limit),
  and the events stay queued.

The worker also reacts to what the API says:

* a `Retry-After` header (delta-seconds or HTTP-date) sets the pause before the
  next call, capped by `retry_after_cap`;
* each consecutive transient failure (5xx, transport error, 429) doubles the
  pause from `request_delay`, up to the same cap, so a struggling API is not
  hammered; one success resets it;
* the daily budget starts at **00:00 UTC** by default, which is when AbuseIPDB
  resets the account quota. `daily_budget_timezone = local` restores counting
  from the host's own midnight.

`--check-key` uses one `/check` request; do not run it in a loop.

## Monitoring: status file and metrics

Every run (except `--dry-run`) rewrites
`/var/lib/abuseipdb/status.json` atomically, so the answer to "is it working?"
needs no log parsing:

```bash
abuseipdb-report --status
```

```json
{
  "budget_timezone": "utc",
  "errors": 0,
  "iso": "2026-10-31T19:20:00+00:00",
  "max_per_day": 900,
  "pending": 3,
  "retry_after": 0,
  "sent": 2,
  "skipped": 0,
  "stopped": "",
  "today": 42,
  "ts": 1767260400,
  "version": "1.2.1",
  "waited_seconds": 2.0
}
```

With `prometheus_textfile` set, the same numbers are exported for the
`node_exporter` textfile collector:

```
abuseipdb_reporter_pending_events 3
abuseipdb_reporter_reports_today 42
abuseipdb_reporter_sent_last_run 2
abuseipdb_reporter_skipped_last_run 0
abuseipdb_reporter_errors_last_run 0
abuseipdb_reporter_run_timestamp_seconds 1767260400
abuseipdb_reporter_run_ok 1
abuseipdb_reporter_budget_remaining 858
abuseipdb_reporter_info{version="1.2.1",stopped="",budget_timezone="utc"} 1
```

Writing status is best effort: an unwritable directory is logged and never turns
a successful run into a failed one. A dry run never overwrites the status of the
last real run.

## Environment variables

| Variable | Meaning |
|---|---|
| `ABUSEIPDB_API_KEY`, `ABUSEIPDB_KEY` | key for the installer and for the reporter (`--api-key` alternative) |
| `ABUSEIPDB_KEY_FILE` | alternative path to the key file |
| `ABUSEIPDB_REPORTER_CONFIG` | config path used by the CLI when `--config` is omitted |

## Applying changes

The worker reads the configuration on every run, so a change to
`/etc/abuseipdb/reporter.conf` (including the API key) takes effect on the next
timer tick - no restart is needed. Changes to the fail2ban action or jail
snippet require `fail2ban-client -t && systemctl restart fail2ban`.