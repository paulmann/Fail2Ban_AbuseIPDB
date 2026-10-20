# Installation

## Requirements

| Requirement | Notes |
|---|---|
| Linux | systemd (recommended) or cron |
| Python | 3.9 or newer, standard library only (no pip packages) |
| Fail2Ban | 0.10+ with `fail2ban-client` available |
| Root access | the installer writes to `/etc`, `/usr/local`, `/var/lib` |
| AbuseIPDB account | free API key from <https://www.abuseipdb.com/account/api> |

The reporter itself needs no outbound access except HTTPS to `api.abuseipdb.com`
(port 443). One-way egress through a proxy is not supported out of the box; see
`docs/CONFIGURATION.md` if you need to change the API URLs.

## Quick install

```bash
git clone https://github.com/paulmann/Fail2Ban_AbuseIPDB.git
cd Fail2Ban_AbuseIPDB
sudo ./install.sh --api-key "YOUR_ABUSEIPDB_API_KEY"
```

On a terminal `--api-key` may be omitted: the installer asks for the key once
and saves it to `/etc/abuseipdb/.abuseipdb.key` (mode 600). The key is kept in
that file - not in the config - so re-installing and self-updating never
overwrite it.

The default attaches the action to the `sshd` jail only. To report web attacks
as well, list the jails you actually have:

```bash
sudo ./install.sh --api-key "YOUR_ABUSEIPDB_API_KEY" \
  --jails "sshd nginx-attack-scan nginx-wp-login nginx-php-probe proftpd exim-auth-fail"
```

Or attach it to every enabled jail (aggregate jail `recidive` is skipped
automatically):

```bash
sudo ./install.sh --api-key "YOUR_ABUSEIPDB_API_KEY" --all-jails
```

The installer is idempotent: running it again upgrades the code, keeps your
existing `reporter.conf` and queue, and re-creates the fail2ban snippet for the
jails you pass.

## Installer options

| Option | Meaning |
|---|---|
| `--api-key KEY` | AbuseIPDB API key (alternatively `ABUSEIPDB_API_KEY` env or `--api-key-file`) |
| `--api-key-file FILE` | read the key from the first line of a file |
| `--key-file PATH` | API key file location (default `/etc/abuseipdb/.abuseipdb.key`) |
| `--with-update-check` | install a weekly `abuseipdb-upgrade --check` timer/cron (check only) |
| `--jails "LIST"` | space separated jails to attach the action to (default: existing jails on upgrade, `sshd` on a fresh install) |
| `--all-jails` | attach to every enabled jail (except `recidive`) |
| `--server-ip IP` | value written to `server_ip` (shown in report comments) |
| `--report-hostname NAME` | value written to `hostname` |
| `--cron` | use `/etc/cron.d` instead of the systemd timer |
| `--no-restart` | do not restart fail2ban after installation |
| `--skip-api-check` | do not validate the key online |
| `--root DIR` | stage the whole installation under `DIR` (testing/containers); systemd and fail2ban are not touched |
| `--dry-run` | print every action, change nothing |
| `--uninstall` | remove installed files (keeps config and queue) |
| `--purge` | with `--uninstall`: also remove config, queue and logs |
| `-y`, `--yes` | non-interactive mode |
| `-h`, `--help` | full help |
| `-V`, `--version` | version |

## What gets installed

| Path | Purpose |
|---|---|
| `/usr/local/lib/abuseipdb_reporter/` | Python package (standard library only) |
| `/usr/local/sbin/abuseipdb-report` | worker: sends queued reports (timer/cron) |
| `/usr/local/sbin/abuseipdb-enqueue` | queue helper, called by the fail2ban action |
| `/usr/local/sbin/abuseipdb-upgrade` | self-update client (`--check` / `--upgrade`) |
| `/etc/abuseipdb/reporter.conf` | configuration, **mode 600** (no secrets) |
| `/etc/abuseipdb/.abuseipdb.key` | API key, **mode 600**, never touched by updates |
| `/var/lib/abuseipdb/abuseipdb.sqlite3` | local queue and report journal |
| `/var/lib/fail2ban-abuseipdb/install-state` | state of the first installation, for clean uninstall |
| `/var/backups/fail2ban-abuseipdb/pristine-<timestamp>/` | copies of files that existed before the first installation |
| `/etc/fail2ban/action.d/abuseipdb-async.conf` | the fail2ban action |
| `/etc/fail2ban/jail.d/50-abuseipdb-reporter.local` | attaches the action to the selected jails |
| `/etc/systemd/system/abuseipdb-report.{service,timer}` | schedule (16 minutes) |
| `/etc/cron.d/abuseipdb-reporter` | alternative schedule when `--cron` is used |
| `/etc/logrotate.d/abuseipdb-reporter` | log rotation |
| `/var/log/abuseipdb-reporter.log` | reporter log |

## Verification

```bash
# 1. The action must be attached to the jail(s)
fail2ban-client get sshd actions
#    ... has the following actions: nftables, abuseipdb-async

# 2. Check where the API key comes from
/usr/local/sbin/abuseipdb-report --key-status

# 3. Queue a ban (use a real attacker address from your logs, NOT your own IP!)
/usr/local/sbin/abuseipdb-enqueue --ip 198.51.100.7 --jail sshd \
  --bantime 86400 --failures 4

# 4. Inspect queue and payload without sending anything
/usr/local/sbin/abuseipdb-report --stats
/usr/local/sbin/abuseipdb-report --dry-run

# 5. Send it and watch the result
/usr/local/sbin/abuseipdb-report
tail -n 20 /var/log/abuseipdb-reporter.log
```

> **Important:** `fail2ban-client set <jail> banip <address>` bypasses the
> `ignoreip` list (this is fail2ban behaviour, not a bug of this tool). Never
> test it with your own management address - you will lock yourself out if the
> ban action covers all ports.

A healthy installation shows `reports today: N`, `pending events: 0` and entries
like `reported ip=... -> 200 {"data":{"abuseConfidenceScore":...}}` in the log.
Automatic bans appear in the queue within seconds and are sent on the next
timer tick (at most 16 minutes later).

## systemd timer vs cron

The default is a systemd timer that runs every 16 minutes with `Persistent=true`
(a missed run after downtime is executed on the next boot). Use `--cron` when
systemd is unavailable; the cron job runs at `:00,:16,:32,:48`, and the per-IP
throttle in the reporter still guarantees at least 20 minutes between reports
for the same address.

```bash
systemctl list-timers abuseipdb-report.timer     # systemd
cat /etc/cron.d/abuseipdb-reporter              # cron
```

## Manual installation

If you prefer not to run the installer:

```bash
install -d -m 755 /usr/local/lib/abuseipdb_reporter
install -m 644 src/abuseipdb_reporter/*.py /usr/local/lib/abuseipdb_reporter/
install -m 755 bin/abuseipdb-report bin/abuseipdb-enqueue /usr/local/sbin/
install -d -m 700 /etc/abuseipdb /var/lib/abuseipdb
install -m 600 config/reporter.conf.example /etc/abuseipdb/reporter.conf
# edit /etc/abuseipdb/reporter.conf: set api_key
install -m 644 fail2ban/action.d/abuseipdb-async.conf /etc/fail2ban/action.d/
install -m 644 fail2ban/jail.d/abuseipdb-reporter.local.example \
             /etc/fail2ban/jail.d/50-abuseipdb-reporter.local
install -m 644 systemd/abuseipdb-report.service systemd/abuseipdb-report.timer \
             /etc/systemd/system/
install -m 644 logrotate/abuseipdb-reporter /etc/logrotate.d/
fail2ban-client -t && systemctl restart fail2ban
systemctl daemon-reload && systemctl enable --now abuseipdb-report.timer
```

Adjust the example jail file to the jails you actually run, then remove the
lines for jails that do not exist (a `[jail]` section that is not configured
anywhere is harmless, but it is cleaner to keep it in sync).

## Upgrade

Two supported ways:

```bash
# 1. self-update (checks updater.json on GitHub, verifies SHA-256, runs the installer)
sudo /usr/local/sbin/abuseipdb-upgrade --check
sudo /usr/local/sbin/abuseipdb-upgrade --upgrade

# 2. from a fresh checkout (installer detects the configured jails)
git pull
sudo ./install.sh
```

Both keep the key file, `reporter.conf`, the queue and the list of jails. The
previous version of every replaced file is stored under
`/var/backups/fail2ban-abuseipdb/pristine-<timestamp>/`. See
[UPDATE.md](UPDATE.md) for the updater design and safety rules.

## Uninstall

```bash
sudo ./install.sh --uninstall          # keeps config, queue, key and logs
sudo ./install.sh --uninstall --purge  # removes everything, including the key
```

Uninstall restores the files that existed before the installation (from the
install state and pristine backup directory), removes the fail2ban action and restarts
fail2ban. The local queue is not sent anywhere on uninstall.

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).