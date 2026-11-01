# Zabbix module

Monitoring for the reporter, ready to import. One template, one agent
`UserParameter`, eight triggers, and a per-server service tree so the Zabbix
**Services** page answers "is ban reporting healthy on each server" at a glance.

Measured against **Zabbix 8.0.0** with agent 2; the template is importable into
Zabbix 7.x by regenerating it with `--zabbix-version 7.0`.

## What is monitored

| Item | Meaning | Type |
|---|---|---|
| Pending events | ban events waiting to be reported | unsigned |
| Unpushed events | follower: events not delivered to the leader | unsigned |
| Reported cache entries | addresses reported by the cluster inside the dedupe window | unsigned |
| Reports today / Daily budget / Budget remaining | account budget state | unsigned |
| Last run age | seconds since the reporter ran | float, `s` |
| Last run sent / skipped / errors | what the last run did | unsigned |
| Sync cursor lag / Last sync age | follower: staleness of the cursor and of the last successful sync | float, `s` |
| Sync failures | follower: consecutive failed sync attempts | unsigned |
| Leader up | 1 = the leader answered, 0 = it did not, -1 = not a follower | float |
| Lease held / Lease expires | failover arbiter state | unsigned |
| Events accepted / inserted / rejected | leader: what followers pushed (cumulative) | unsigned |
| Remote bans applied | follower: bans applied from other nodes (cumulative) | unsigned |
| Enabled | 1 when `[abuseipdb] enabled = yes` | unsigned |

| Trigger | Severity | Threshold |
|---|---|---|
| no reporter run for 2 hours | Average | `last_run_age_seconds > {$ABUSEIPDB.RUN_STALE}` |
| last run had errors | Information | `last_run_errors > 0` |
| queue is growing | Warning | `pending_events > {$ABUSEIPDB.PENDING.MAX}` |
| daily budget exhausted | Warning | `budget_remaining = 0` |
| follower has not synced for 45 minutes | High | `coord_last_sync_age_seconds > {$ABUSEIPDB.SYNC_STALE}` |
| follower sync is failing | High | `coord_sync_failures > 2` |
| leader is unreachable | High | `leader_up = 0` |
| unpushed backlog | Average | `unpushed_events > 500` |

Macros `{$ABUSEIPDB.PENDING.MAX}` (200), `{$ABUSEIPDB.RUN_STALE}` (7200) and
`{$ABUSEIPDB.SYNC_STALE}` (2700) are template macros - override them per host.

Every trigger carries two tags: `server={HOST.HOST}` and
`service=fail2ban-abuseipdb`. That is what the Services tree matches, so a service
per server is a one-line creation, not a manual mapping.

## Files

| File | Purpose |
|---|---|
| `monitoring/zabbix/fail2ban_abuseipdb.yaml` | the template (generated, do not edit) |
| `monitoring/zabbix/userparameter_fail2ban_abuseipdb.conf` | agent 2 key definition |
| `monitoring/zabbix/abuseipdb-metrics-sudoers` | optional sudo rule for the agent |
| `tools/gen_zabbix_template.py` | regenerates the files from the metric list |

## Install on a monitored host

```bash
# 1. the reporter itself must be installed (install.sh) - the module reads its data
abuseipdb-report --version

# 2. the agent key
sudo install -m 644 monitoring/zabbix/userparameter_fail2ban_abuseipdb.conf \
     /etc/zabbix/zabbix_agent2.d/userparameter_fail2ban_abuseipdb.conf
sudo systemctl restart zabbix-agent2

# 3. the snapshot must be readable by the agent user
#    (the reporter writes /var/lib/abuseipdb/metrics.json and .prom)
sudo chmod 755 /var/lib/abuseipdb
sudo chmod 644 /var/lib/abuseipdb/metrics.json /var/lib/abuseipdb/metrics.prom

# 4. verify locally, as the agent user
sudo -u zabbix zabbix_agent2 -t 'fail2ban.abuseipdb.metric[pending_events]'
# fail2ban.abuseipdb.metric[pending_events]       [u|0]
```

If the snapshot must stay `0600 root:root`, install
`monitoring/zabbix/abuseipdb-metrics-sudoers` as `/etc/sudoers.d/zabbix-abuseipdb`
(mode 0440) and change the `UserParameter` command to the commented `sudo` form -
`visudo -c` must pass before the agent is restarted.

## Import and link

```powershell
# import the template (updateExisting is on: re-running is safe and idempotent)
pwsh -File tools/zabbix-import.ps1 -Import
```

The script logs in over the API, imports
`monitoring/zabbix/fail2ban_abuseipdb.yaml`, then links the template to the hosts it
is given, **keeping every template they already have**:

```powershell
pwsh -File tools/zabbix-import.ps1 -Hosts 'vps-176-99-5-35','hp-debian','vpn-exit-de-web'
```

The credentials come from the RAGRAF vault (`Zabbix администратор md @192.168.31.31`),
never from the command line.

## Services tree

The module ships `tools/zabbix-services.ps1`, which creates one **parent service**
and one **child per server**, each with problem tags `server=<host>` and
`service=fail2ban-abuseipdb`:

```powershell
pwsh -File tools/zabbix-services.ps1 -Hosts 'vps-176-99-5-35','hp-debian','vpn-exit-de-web'
pwsh -File tools/zabbix-services.ps1 -Status          # show the tree and its status
```

Result on the Services page:

```
Fail2Ban AbuseIPDB                     (worst of the children)
├── Fail2Ban AbuseIPDB / vps-176-99-5-35
├── Fail2Ban AbuseIPDB / hp-debian
└── Fail2Ban AbuseIPDB / vpn-exit-de-web
```

A child turns yellow/red when a trigger of that server fires: a dead reporter, a
follower that cannot reach its leader, a growing queue or a spent budget. The parent
aggregates - one glance answers "is abuse reporting working anywhere".

## What this module deliberately does not do

* It does not poll AbuseIPDB itself. The reporter's own snapshot is the source; a
  second poller would spend the API budget twice.
* It does not alert on "no data" by default (Zabbix handles that with its own
  `nodata()` triggers if you want them). Enable them per host if a missing item must
  page someone.
* It does not read the log file. `status.json`, `metrics.prom`, `metrics.json` and
  `--metric` cover every number; a log trigger would break on a changed message.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| item `ZBX_NOTSUPPORTED` | the CLI is missing, or the agent cannot read the snapshot | `sudo -u zabbix zabbix_agent2 -t 'fail2ban.abuseipdb.metric[pending_events]'` |
| all values `0` on a busy host | the reporter never ran, so no snapshot exists | `abuseipdb-report --stats`, check the timer |
| `unsupported` string as a value | the item name is not in the snapshot | `abuseipdb-report --metric <name>` to see the accepted names |
| values stuck | the item interval is longer than the reporter's | the reporter rewrites the snapshot every run (16 min); `delay = 5m` is the generated default |
| triggers never fire | the template is linked but tags were changed | keep `server={HOST.HOST}` and `service=fail2ban-abuseipdb` - the services match them |
