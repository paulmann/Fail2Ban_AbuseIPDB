# Troubleshooting

Start with the three commands that answer most questions:

```bash
/usr/local/sbin/abuseipdb-report --stats
tail -n 50 /var/log/abuseipdb-reporter.log
fail2ban-client get sshd actions
```

## Reports are not sent

Work through the checklist in order:

1. **Is the action attached?**
   `fail2ban-client get <jail> actions` must list `abuseipdb-async`.
   If not, re-run the installer with the right `--jails` list and restart
   fail2ban (`systemctl restart fail2ban`; a plain `reload` may not rebuild the
   action list on all fail2ban versions).
2. **Are events queued?**
   `abuseipdb-report --stats` shows `pending events`. If it is 0, the action is
   not firing or the address is filtered by `[ignore] ranges`.
3. **Does the dry run build a payload?**
   `abuseipdb-report --dry-run` - it prints JSON and sends nothing. An empty
   output with pending events usually means every IP is inside the throttle
   window; wait 20 minutes.
4. **Is the worker running?**
   `systemctl list-timers abuseipdb-report.timer` (systemd) or
   `cat /etc/cron.d/abuseipdb-reporter` (cron).
   `systemctl start abuseipdb-report` runs it immediately and logs to
   `/var/log/abuseipdb-reporter.log`.
5. **Is the API key valid?**
   `abuseipdb-report --check-key` - expects `HTTP 200`.
6. **Is the reporter enabled?**
   `enabled = no` in `reporter.conf` pauses sending (bans are still queued).

## The first run asks for an API key / no key found

The reporter resolves the key from `--api-key`, `ABUSEIPDB_API_KEY`, the key
file (`/etc/abuseipdb/.abuseipdb.key`) or a legacy `api_key` in the config. On
a terminal it asks once and saves the key to the key file. Under systemd/cron
there is no terminal: if the key is missing the run logs
`No AbuseIPDB API key found...` and exits with code 2.

```bash
abuseipdb-report --key-status     # where does the key come from?
abuseipdb-report --setup          # ask for it and save it
abuseipdb-report --migrate-key    # move a legacy api_key out of reporter.conf
```

The key file is mode 600 and is never rewritten by updates.

## Updates

```bash
abuseipdb-upgrade --check         # 0 = up to date, 10 = update available, 1 = error
abuseipdb-upgrade --upgrade       # verify SHA-256 and run the installer
```

If the check fails, verify egress to
`raw.githubusercontent.com` / `github.com`. The updater refuses an archive
without a checksum and aborts on a mismatch (nothing is installed, the key file
is restored if it was touched).

## HTTP 401 / 403

* `401` - the key is wrong or revoked. Update `api_key` in
  `/etc/abuseipdb/reporter.conf` (no restart needed).
* `403` - the key is valid but the endpoint is blocked (proxy/firewall or a
  provider policy). Check egress to `api.abuseipdb.com:443`.

## HTTP 429

* The detail contains *"once in 15 minutes"* - expected: the same IP was already
  reported by this account. The event stays pending and is retried later.
* Anything else - the daily limit (1000 on the free plan) is exhausted. The run
  stops; reduce `max_reports_per_day` or wait for the next day.

## HTTP 400 / 422

The report was rejected as invalid (for example a non-public address, or a
malformed value). The event is marked `2` (invalid) and is never retried. Check
`[ignore] ranges` and the API changelog.

## The queue grows and does not drain

* `stopped_reason` in the log (`daily budget exhausted`, `global rate limit`,
  `unauthorized`) names the cause;
* an abuse burst (hundreds of unique addresses in minutes) is normal for a busy
  server: 25 reports per tick and 900 per day are the configured ceilings. The
  queue keeps every event and drains over time; nothing is lost.

## fail2ban configuration test fails after installation

The installer runs `fail2ban-client -t` and aborts **before** restarting
fail2ban if the configuration is invalid. Restore the previous files from
`/var/backups/fail2ban-abuseipdb/<timestamp>/`, or remove the generated snippet:

```bash
rm -f /etc/fail2ban/jail.d/50-abuseipdb-reporter.local
fail2ban-client -t && systemctl restart fail2ban
```

The generated snippet only adds an `action` line to the jails you named. A jail
that is not otherwise configured is harmless but unusual - remove its section.

## The systemd journal has no entries

Some minimal hosts do not persist journald logs at all. The reporter writes a
regular file (`/var/log/abuseipdb-reporter.log`) for exactly this reason; use it
as the source of truth.

## `python3` is too old

The worker requires Python 3.9+. On older distributions install a newer Python
or use the distribution's backported packages.

## IPv6

Addresses are supported everywhere: queue, ignore ranges, categories and the API
payload. Make sure the `[ignore]` list also contains your IPv6 management
prefixes.

## Duplicate reports after a reboot

They should not happen: the action has `norestored = 1`, so bans restored from
fail2ban's database are not queued again. If you see duplicates, check that you
did not attach the action twice (for example, once in `jail.local` and once in
the generated snippet) - `fail2ban-client get <jail> actions` would then list
`abuseipdb-async` twice.

## How to reset everything

```bash
systemctl stop abuseipdb-report.timer
rm -f /var/lib/abuseipdb/abuseipdb.sqlite3*
rm -f /var/log/abuseipdb-reporter.log
systemctl start abuseipdb-report.timer
```

The queue only contains bans that have not been reported yet; removing it loses
those reports but does not affect the firewall state.