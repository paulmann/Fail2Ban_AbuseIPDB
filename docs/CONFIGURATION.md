# Configuration

The reporter has a single INI file: `/etc/abuseipdb/reporter.conf`.
It is installed with mode `600` (root only) because it contains the API key.

`/usr/local/sbin/abuseipdb-report --config /path/to/other.conf` is honoured, as
is the `ABUSEIPDB_REPORTER_CONFIG` environment variable.

## `[abuseipdb]`

| Option | Default | Meaning |
|---|---|---|
| `api_key` | *(empty)* | AbuseIPDB API key. Required for sending |
| `api_url` | `https://api.abuseipdb.com/api/v2/report` | report endpoint |
| `check_url` | `https://api.abuseipdb.com/api/v2/check` | endpoint used by `--check-key` |
| `enabled` | `yes` | `no` pauses sending; bans keep being queued |
| `timeout` | `25` | HTTP timeout, seconds |
| `min_interval_ip` | `1200` | minimum seconds between two reports for the same IP (API allows one per 900 s) |
| `max_reports_per_run` | `25` | cap per timer tick |
| `max_reports_per_day` | `900` | daily budget; free AbuseIPDB plan allows 1000 requests/day |
| `comment_max_bytes` | `1000` | comment is truncated to this size (API hard limit 1024) |
| `evidence_max_lines` | `4` | how many evidence lines/URLs to include |
| `skip_jails` | `recidive` | comma separated jails that are never reported |

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

## `[ignore]`

`ranges` is a comma/whitespace separated list of CIDR ranges that must never be
reported. The defaults cover private, loopback, link-local, documentation and
reserved space. **Add your own management addresses and any trusted networks**,
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
| `proftpd` | 18,5 | Brute-Force, FTP Brute-Force |
| `exim-auth-fail` | 18 | Brute-Force |
| `exim-isp` | 18,11 | Brute-Force, Email Spam |
| `nginx-attack-scan` | 21,19 | Web App Attack, Bad Web Bot |
| `nginx-wp-login` | 21,18 | Web App Attack, Brute-Force |
| `nginx-php-probe` | 21,15 | Web App Attack, Hacking |
| `nginx-forbidden` | 21 | Web App Attack |

SQL-injection attempts are detected automatically (patterns such as
`UNION SELECT`, `information_schema`, `OR 1=1`, `sleep(`, `load_file(`) and
category **16** is added to the report.

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
* on HTTP 429 the run stops (or the IP is deferred), and the events stay queued.

`--check-key` uses one `/check` request; do not run it in a loop.

## Environment variables

| Variable | Meaning |
|---|---|
| `ABUSEIPDB_API_KEY` | key for the installer (`--api-key` alternative) |
| `ABUSEIPDB_REPORTER_CONFIG` | config path used by the CLI when `--config` is omitted |

## Applying changes

The worker reads the configuration on every run, so a change to
`/etc/abuseipdb/reporter.conf` (including the API key) takes effect on the next
timer tick - no restart is needed. Changes to the fail2ban action or jail
snippet require `fail2ban-client -t && systemctl restart fail2ban`.