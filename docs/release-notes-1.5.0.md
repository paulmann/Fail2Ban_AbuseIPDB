## v1.5.0 — automatic failover, TLS, and a Zabbix module

Three things 1.4.x left to the operator: failover was manual, the endpoint spoke
plain HTTP, and nothing watched either of them. All three are now built in and
optional - the defaults do not change.

### Automatic failover that cannot split

`mode = auto` plus `failover = witness` hands the decision to a second, deliberately
tiny service:

```
   node-a (auto) ──POST /v1/lease {node_id, ttl}──►  abuseipdb-witness
   node-b (auto) ◄── {granted: true|false, owner, expires, term} ──┘
```

* the arbiter is the **only** writer of the lease, so it cannot grant it twice;
* it never revokes - it refuses the next renewal and the lease runs out;
* a node that cannot reach the arbiter keeps the lease it already holds until it
  expires, because nobody else can have been granted it before then;
* an expired or missing lease means **follower**. There is no path where a lost
  arbiter produces two leaders;
* the lease is persisted, so restarting the arbiter does not hand leadership to a
  second node.

No lease file on shared storage: two nodes renewing one file concurrently both
believe they are the leader, which is exactly the split brain this avoids.

### TLS from the standard library

```ini
[coordination]
tls_cert = /etc/abuseipdb/tls/cert.pem      # leader: switch the endpoint to HTTPS
tls_key  = /etc/abuseipdb/tls/key.pem
tls_client_ca = /etc/abuseipdb/tls/ca.pem   # optional: require client certificates
```

Followers verify through `tls_ca` (a self-signed certificate may be its own CA) and
can present a client certificate for mTLS. TLS 1.2 is the floor. nginx/Caddy
examples are in `docs/COORDINATION.md` for installations that prefer to terminate
TLS in front.

### Monitoring

* `GET /v1/health` answers **without** the shared secret: role, mode, node, version,
  TLS and the lease. Safe to poll from an untrusted network.
* `abuseipdb-report --metrics` prints Prometheus text, `--metric <name>` prints one
  value, and the reporter writes `metrics.prom` + `metrics.json` after every run.
* New series: coordination counters (accepted / inserted / rejected / remote bans),
  cursor lag, last-sync age, consecutive sync failures, leader reachability, lease
  state and expiry.

### Zabbix module (template + agent key + service tree)

`monitoring/zabbix/` holds a **Zabbix 8.0** template with 21 items, 8 triggers and 3
macros, an agent 2 `UserParameter`, and the scripts that install them:

```powershell
pwsh -File tools/zabbix-import.ps1 -Import          # template + link to the hosts
pwsh -File tools/zabbix-services.ps1                # parent service + one child per server
```

Every trigger carries `server={HOST.HOST}` and `service=fail2ban-abuseipdb`, so each
server gets its own service and the parent aggregates them. The template is generated
from the metric list, so a renamed metric fails a test instead of going silently
missing. Details: `docs/ZABBIX.md`.

### Robustness

* A failed sync is retried `sync_attempts` times per run with exponential backoff; a
  `4xx` is not retried, because a wrong secret does not fix itself.
* A failed `fail2ban-client status` no longer blanks the declared jail list (it stays
  valid up to 24 hours), and an empty answer never overwrites a known one.
* `abuseipdb-coord` answers `409` when an `auto` node does not hold the lease, instead
  of queueing events it will never report.

### Upgrade

`abuseipdb-upgrade --upgrade --yes`. Nothing changes for `mode = none`,
`failover = none` and no TLS: those are the defaults, and the new files
(`abuseipdb-witness`, its unit) are installed but not enabled.
