# Zabbix module for Fail2Ban_AbuseIPDB

| File | Goes to | Purpose |
|---|---|---|
| `userparameter_fail2ban_abuseipdb.conf` | `/etc/zabbix/zabbix_agent2.d/` | one `UserParameter` returning the Prometheus snapshot |
| `fail2ban_abuseipdb.yaml` | imported as a template (UI or API) | 22 items, 9 triggers, 3 macros |
| `abuseipdb-metrics-sudoers` | `/etc/sudoers.d/zabbix-abuseipdb` (optional) | lets the agent run the CLI when the metrics file is unreadable |

Regenerate after changing the metric list: `python tools/gen_zabbix_template.py`
(the generator test fails when the checked-in files are stale).

Import (API; the UI path is Data collection -> Templates -> Import):

```bash
python tools/zabbix_template.py import --url https://zabbix.example/api_jsonrpc.php \
    --user Admin --password-env ZBX_PASSWORD
python tools/zabbix_template.py link --url ... --user Admin --hosts host1,host2
```

Triggers carry `server={HOST.HOST}` and `service=fail2ban-abuseipdb`, so one Zabbix
**service** per server matches them:

| Service | Problem tags |
|---|---|
| `Fail2Ban AbuseIPDB` (parent) | — |
| `Fail2Ban AbuseIPDB / <host>` | `server=<host>` **and** `service=fail2ban-abuseipdb` |

Details and the meaning of every number: `docs/ZABBIX.md`.
