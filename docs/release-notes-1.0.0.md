## Fail2Ban_AbuseIPDB v1.0.0

The first public release: an asynchronous **fail2ban → AbuseIPDB** reporter.

### Why

The stock AbuseIPDB action runs `curl` inside the fail2ban ban action. A slow
API, a rate limit, a revoked key or an attacker-controlled URL in `<matches>`
all become problems of the **ban path** - which is supposed to be instant and
local. v1.0.0 separates the two: bans are queued in SQLite and reported by a
scheduled worker.

### Highlights

- **Fail2ban action** `abuseipdb-async` with `norestored = 1` - no duplicate
  reports after a fail2ban restart.
- **Durable local queue** (SQLite, WAL) with deduplication of repeated bans.
- **Scheduled worker** - systemd timer every 16 minutes, or cron; missed runs are
  caught up after downtime.
- **Evidence-backed comments** - attack type, time window, ban duration, failure
  counts, generic patterns and the attacker's own request URLs, read from
  fail2ban's own database. No log scraping, no shell interpolation.
- **Correct AbuseIPDB categories** per jail; SQL-injection attempts add category
  16 automatically.
- **Privacy by design** - no attempted usernames, no mail content, no client
  domains in reports.
- **Self-advertising footer** - every report ends with a configurable credit
  (`Reported via Fail2Ban_AbuseIPDB Monitor: ...`), appended after truncation
  so it is always visible; disable it with `attribution = no`.
- **Rate-limit aware** - one report per IP per 20 minutes, 900/day, 25/run.
- **Production installer** - backups, `fail2ban-client -t` gate, staging mode,
  idempotent upgrade, state-driven uninstall and `--purge`.
- **Zero dependencies** - Python standard library only.
- **Tested** - 57 unit tests, an end-to-end integration test against a mock API,
  shellcheck and a staged install/uninstall job in CI.

### Requirements

Linux, Python 3.9+, Fail2Ban 0.10+, root, and a free
[AbuseIPDB API key](https://www.abuseipdb.com/account/api).

### Install

```bash
git clone https://github.com/paulmann/Fail2Ban_AbuseIPDB.git
cd Fail2Ban_AbuseIPDB
sudo ./install.sh --api-key "YOUR_ABUSEIPDB_API_KEY" \
  --jails "sshd nginx-attack-scan nginx-wp-login proftpd"
```

Full documentation: [README.md](https://github.com/paulmann/Fail2Ban_AbuseIPDB/blob/main/README.md),
[docs/INSTALL.md](https://github.com/paulmann/Fail2Ban_AbuseIPDB/blob/main/docs/INSTALL.md),
[docs/CONFIGURATION.md](https://github.com/paulmann/Fail2Ban_AbuseIPDB/blob/main/docs/CONFIGURATION.md).