# Multi-host coordination (one AbuseIPDB account, several servers)

AbuseIPDB limits are **per account**, not per host: 1000 requests/day on the free
plan and one report per IP per 15 minutes. If five protected servers each run the
reporter with the same key, the account budget is spent five times faster and two
hosts can report the same address within the forbidden window.

Coordination fixes that without breaking the project's rules: the ban path still
never touches the network, no new dependency is added, and the API key exists on
exactly one machine. Since 1.4.0 a sync is **two-way**: the follower sends its
bans and receives back the address list the cluster has already reported plus the
bans it is missing.

```
        follower (web-1)                       follower (mail-1)
   fail2ban -> queue (SQLite)              fail2ban -> queue (SQLite)
        │  ▲                                    │  ▲
        │  └─ to_ban: ban them here             │  └─ to_ban / recently_reported
        │     recently_reported: don't report   │
        └───────────► POST /v1/sync ◄───────────┘
                            │
                            ▼
                 leader (edge-1): abuseipdb-coord
                 queue (SQLite) -> abuseipdb-report -> AbuseIPDB API
                 holds the key, owns the account limits
```

## Roles

| `[coordination] mode` | Behaviour |
|---|---|
| `none` (default) | standalone: every node reports for itself. Identical to 1.2.x. |
| `leader` | reports as usual **and** runs `abuseipdb-coord` to answer follower syncs. Holds the API key. |
| `follower` | never calls the API and needs no API key: pushes its queued bans, applies the bans it is told about, keeps the "already reported" cache. |
| `auto` | candidate: leader while it holds the failover lease, follower otherwise. Needs `failover = witness`; without it the node is a follower, never a silent leader. |

A follower's `abuseipdb-report` run is one sync request. If it fails, nothing is
marked, the events stay queued and the next timer tick retries them - a leader
outage delays reports, it never loses them.

## Configuration

```ini
[coordination]
# none | leader | follower
mode = none
# human name of this node; appears in the leader's log
node_id = server1
# follower only: where the leader listens
leader_url = http://10.0.0.5:8765
# shared secret, mode 600, identical on every node
shared_secret_file = /etc/abuseipdb/.coord.secret
# leader only: where the endpoint listens and on which port
coord_bind = 127.0.0.1
coord_port = 8765
# how many events one sync carries
push_batch_size = 50
# follower: apply bans reported by other nodes through fail2ban-client
sync_bans = yes
# safety rail: remote bans per run (hard ceiling 200)
max_remote_bans_per_run = 20
# an address reported inside this window is never reported again (API: 15 min)
peer_dedupe_window = 900
# leader: how many bans one answer may carry
max_sync_bans = 50
```

| Key | Default | Meaning |
|---|---|---|
| `mode` | `none` | role of this node |
| `node_id` | *(empty)* | name used in logs and in the leader's status |
| `leader_url` | *(empty)* | base URL of the leader, `http://` or `https://` only |
| `shared_secret_file` | `/etc/abuseipdb/.coord.secret` | file with the shared secret (mode 600) |
| `coord_bind` | `127.0.0.1` | address the leader endpoint binds to |
| `coord_port` | `8765` | port of the leader endpoint |
| `push_batch_size` | `50` | events per sync (1-500, hard cap 500) |
| `sync_bans` | `yes` | follower applies remote bans; `no` only syncs events and the cache |
| `max_remote_bans_per_run` | `20` | cap on bans applied in one run (hard ceiling 200) |
| `peer_dedupe_window` | `900` | seconds an address counts as "already reported" |
| `max_sync_bans` | `50` | cap on bans the leader puts into one answer |
| `sync_attempts` | `3` | follower: attempts per run before giving up until the next tick |
| `sync_retry_base` | `1.0` | follower: base delay of the exponential backoff, seconds |
| `failover` | `none` | `none` (manual) or `witness` (an arbiter grants the lease) |
| `witness_url` | *(empty)* | where `abuseipdb-witness` listens |
| `witness_timeout` | `5` | lease request timeout, seconds |
| `lease_ttl` | `1800` | how long a granted lease stays valid, seconds |
| `lease_state_path` | `/var/lib/abuseipdb/witness-lease.json` | arbiter state file |
| `tls_cert` / `tls_key` | *(empty)* | switch the leader endpoint to HTTPS |
| `tls_client_ca` | *(empty)* | require a client certificate (mTLS) |
| `tls_ca` | *(empty)* | follower: CA (or the self-signed certificate) to trust |
| `tls_verify` | `yes` | follower: verify the leader certificate |
| `tls_client_cert` / `tls_client_key` | *(empty)* | follower: client certificate for mTLS |

The timeout of coordination calls reuses `[abuseipdb] timeout`.

## Create the shared secret

One generated value, copied to every node:

```bash
openssl rand -hex 32 | sudo tee /etc/abuseipdb/.coord.secret >/dev/null
sudo chmod 600 /etc/abuseipdb/.coord.secret
sudo chown root:root /etc/abuseipdb/.coord.secret
```

Distribution is your business (configuration management, `scp`, a vault). The
reporter never prints the value: `abuseipdb-coord --check` and
`abuseipdb-report --coord-status` only say whether it is present or missing.

Verify that all nodes really share the same value - a mismatch is the most common
coordination failure:

```bash
sha256sum /etc/abuseipdb/.coord.secret        # identical on every node
```

## Leader setup

Editing `[coordination]` by hand is error-prone: the configuration shipped by the
installer already contains the section, and a second section makes
`configparser` fail. Use the helper shipped in the source tree, which rewrites
exactly the keys you pass, keeps every comment and preserves the 600 mode:

```bash
sudo python3 tools/set_coordination.py --config /etc/abuseipdb/reporter.conf \
    --mode leader --node-id edge-1 --bind 0.0.0.0 --port 8765
```

Then:

```bash
# 1. the leader also reports, so it needs the API key as usual
sudo /usr/local/sbin/abuseipdb-report --check-key

# 2. example of the resulting section (written by the helper above)
#    [coordination]
#    mode = leader
#    node_id = edge-1
#    coord_bind = 0.0.0.0        # only behind a firewall / trusted network
#    coord_port = 8765

# 3. validate, then start the endpoint
sudo /usr/local/sbin/abuseipdb-coord --check
sudo systemctl enable --now abuseipdb-coord.service

# 4. verify locally
curl -s -H "X-Coord-Secret: $(sudo cat /etc/abuseipdb/.coord.secret)" \
     http://127.0.0.1:8765/v1/status
```

`abuseipdb-coord.service` is installed by `install.sh` but **never enabled**: an
endpoint nobody asked for must not open a port.

A reference firewall unit (keep it next to the endpoint, enabled only together
with it):

```ini
[Unit]
Description=Restrict the coordination port to known peers
Before=abuseipdb-coord.service
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -C INPUT -i lo -p tcp --dport 8765 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -p tcp --dport 8765 -j ACCEPT; iptables -C INPUT -p tcp --dport 8765 -s 10.0.0.0/24 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 8765 -s 10.0.0.0/24 -j ACCEPT; iptables -C INPUT -p tcp --dport 8765 -j DROP 2>/dev/null || iptables -A INPUT -p tcp --dport 8765 -j DROP'

[Install]
WantedBy=multi-user.target
```

## Follower setup

The follower needs `fail2ban-client` in `PATH` (it ships with fail2ban) and the
jails it is asked to use must exist locally - a ban for an unknown jail is logged
and skipped, never retried in a loop.

```bash
sudo python3 tools/set_coordination.py --config /etc/abuseipdb/reporter.conf \
    --mode follower --node-id web-1 --leader-url http://10.0.0.5:8765

sudo /usr/local/sbin/abuseipdb-report --coord-status   # leader status, cursor, cache
sudo /usr/local/sbin/abuseipdb-report --dry-run        # what would be pushed
sudo /usr/local/sbin/abuseipdb-report                  # one sync (push + apply)
sudo /usr/local/sbin/abuseipdb-report --stats          # pending / pushed / cache
```

The timer or cron job stays as it is: the follower's worker *is* the syncher.

## Two-way sync

Request (follower → leader):

```json
{
  "node_id": "web-1",
  "since": 1793481600,
  "jails": ["sshd", "nginx-php-probe"],
  "events": [{"ip": "198.51.100.7", "jail": "sshd", "event_time": 1793481612,
              "bantime": 3600, "failures": 5}]
}
```

Answer (leader → follower):

```json
{
  "ok": true, "node_id": "edge-1",
  "accepted": 1, "inserted": 1, "rejected": 0,
  "recently_reported": {"203.0.113.9": 1793481500},
  "to_ban": [{"ip": "198.51.100.10", "jail": "sshd",
              "event_time": 1793481400, "bantime": 86400}],
  "next_since": 1793481620
}
```

* **`accepted` / `inserted` / `rejected`** - what happened to the pushed events.
  The leader applies its own filters (valid address, `[ignore] ranges`,
  `skip_jails`), so a follower cannot make it report something it would never
  report itself.
* **`recently_reported`** - addresses reported successfully inside
  `peer_dedupe_window`. The follower stores them in its own cache.
* **`to_ban`** - bans created after the follower's `since` that did **not** come
  from that follower: the leader's own bans plus the ones other nodes pushed. An
  event is never echoed back to the node it came from (the `events.origin` column
  records who reported it). Since 1.4.1 the follower also declares the `jails` it
  can ban in, and the leader leaves out the rest: a host without
  `nginx-php-probe` is never asked to ban in it. An absent or empty list means
  "unknown" and sends everything.
* **`next_since`** - the new cursor. If the answer is lost, the follower simply
  repeats the request: `to_ban` is idempotent (`fail2ban-client` answers "already
  banned") and the leader's 5-minute deduplication absorbs repeated events.

The first sync adopts the leader's bans from the **last two hours** (bounded by
`max_sync_bans`), not the whole history of its queue - a new node should not replay
1866 old bans in one tick.

## Report deduplication

`reported_cache(ip, reported_at, source)` is written locally:

* the leader records its own successful reports there and sends them out;
* a follower merges `recently_reported` from every answer;
* before reporting an address, the reporting node checks the cache; a hit inside
  `peer_dedupe_window` means "somebody already reported it" - the events are
  marked reported locally and **no API call is made**;
* timestamps from a peer are clamped to *now*, so a broken clock (or a hostile
  peer) cannot block an address for years.

This matters most right after a role change: a follower promoted to leader in a
failover will not re-report addresses the cluster reported minutes ago.

## Ban propagation

`to_ban` entries are applied with

```
fail2ban-client set <jail> banip <address>
```

Rails, in order:

| Rail | Effect |
|---|---|
| address must parse | garbage from a peer is ignored |
| `[ignore] ranges` | private, loopback, documentation and your own trusted networks are never banned |
| own `server_ip` | a node never bans the address it reports from |
| jail must be in this node's own list (1.4.1) | the node declares its jails; the leader sends nothing else |
| jail name must match `^[A-Za-z0-9._@-]{1,64}$` | nothing shell-like ever reaches the command (the command is executed without a shell at all) |
| `max_remote_bans_per_run` (20, ceiling 200) | one sync cannot flood a node with bans |
| no unban, ever | the feature can only add bans; nothing can lift one |

`sync_bans = no` disables propagation on a node entirely (events and the
reported-cache still sync). A ban the node already has produces
`already banned` and is counted as not applied - harmless.

## Failover

Two strategies, both safe; the second is new in 1.5.0.

### Manual (default, `failover = none`)

1. On the broken leader: `systemctl stop abuseipdb-coord`, then stop the worker if the host is unusable.
2. On the new leader: copy `/etc/abuseipdb/.abuseipdb.key` and
   `/etc/abuseipdb/.coord.secret`, set `mode = leader` with its own `node_id`, start
   `abuseipdb-coord`, check `--check-key`.
3. On every follower: point `leader_url` at the new host and run
   `abuseipdb-report --coord-status`.
4. On the old leader when it returns: set `mode = follower`, or keep it off.
   **Never leave two leaders reporting with the same key.**

### Automatic with an arbiter (`failover = witness`)

A second, deliberately tiny service decides **who may report** and nothing else:

```
   node-a (auto) ──POST /v1/lease {node_id, ttl}──►  abuseipdb-witness
   node-b (auto) ◄── {granted: true|false, owner, expires, term} ──┘
```

* the arbiter is the only writer of the lease, so it cannot grant it twice;
* it **never revokes**: it refuses the next renewal and the lease runs out;
* a node that cannot reach the arbiter keeps a lease it already holds until it
  expires - by then nobody else can have been granted it;
* an expired or missing lease means **follower**; there is no path where a lost
  arbiter produces two leaders;
* the state file (`lease_state_path`) survives a restart, so restarting the arbiter
  does not hand leadership to a second node.

Setup:

```bash
# 1. on a third host (not a candidate), same secret file as the cluster
sudo /usr/local/sbin/abuseipdb-witness --check
sudo systemctl enable --now abuseipdb-witness.service

# 2. on every candidate: mode = auto, then two extra keys
sudo python3 tools/set_coordination.py --config /etc/abuseipdb/reporter.conf \
    --mode auto --node-id node-a --leader-url https://10.0.0.5:8765
#   [coordination]
#   failover = witness
#   witness_url = http://10.0.0.9:8765

# 3. verify: exactly one node says "effective role: leader"
abuseipdb-report --coord-status
```

The lease is renewed on every run, so `lease_ttl` must be **longer than the timer
interval** (16 minutes by default → 1800 s is the default). Stop the leader and the
next run on another candidate takes the lease; the old leader, when it comes back,
asks again, is refused, and stays a follower - `--coord-status` prints the owner and
the deadline it saw.

Every candidate needs the API key, because any of them can become the leader. That is
the price of automatic failover; with `failover = none` only the designated leader
needs it.

### What is deliberately not implemented

A lease file on shared storage (NFS, a shared directory) cannot be made safe without
an atomic compare-and-swap: two nodes renewing it concurrently both believe they are
the leader, and a split brain spends the account budget twice while breaking the
per-IP interval. Keepalived/corosync with a shared VIP is a valid alternative - it
solves the same problem at the network layer - but it needs two addresses and a
virtual IP, which is more than most installations want for a reporting helper.

## TLS

TLS comes from the standard library, so enabling it costs nothing:

```ini
[coordination]
# leader: server certificate (and optionally require client certificates)
tls_cert = /etc/abuseipdb/tls/cert.pem
tls_key  = /etc/abuseipdb/tls/key.pem
tls_client_ca = /etc/abuseipdb/tls/ca.pem     # optional: mTLS

# follower
leader_url = https://10.0.0.5:8765
tls_ca = /etc/abuseipdb/tls/ca.pem            # CA; for a self-signed cert, the cert itself
#tls_client_cert = /etc/abuseipdb/tls/client.pem   # when the leader requires mTLS
#tls_client_key  = /etc/abuseipdb/tls/client-key.pem
```

Rules:

* `tls_cert` **and** `tls_key` switch the listener to HTTPS; only one of them is a
  configuration error and the endpoint refuses to start.
* TLS 1.2 is the floor; the certificate is verified against the system store plus
  `tls_ca`. `tls_verify = no` exists for a test rig and nowhere else - it disables the
  hostname check too.
* A self-signed certificate works: point `tls_ca` at the certificate itself.
* The secret stays in `X-Coord-Secret` on top of TLS; either layer authenticates the
  caller, both together cost nothing.

Self-signed pair for a lab:

```bash
sudo install -d -m 700 /etc/abuseipdb/tls
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout /etc/abuseipdb/tls/key.pem -out /etc/abuseipdb/tls/cert.pem \
  -subj "/CN=edge-1" -addext "subjectAltName=IP:10.0.0.5"
sudo chmod 600 /etc/abuseipdb/tls/key.pem
```

If you would rather terminate TLS elsewhere, put nginx or Caddy in front and keep
`coord_bind = 127.0.0.1`:

```nginx
location /v1/ {
    proxy_pass http://127.0.0.1:8765;
    proxy_set_header X-Coord-Secret $http_x_coord_secret;
    allow 10.0.0.0/24; deny all;
    # ssl_certificate / ssl_certificate_key from the server block
}
```

```caddyfile
coord.example.internal {
    reverse_proxy 127.0.0.1:8765
    @peers remote_ip 10.0.0.0/24
    handle @peers
    respond 403
}
```

## Health endpoint and monitoring

`GET /v1/health` answers **without** the shared secret and returns liveness-level
facts only, so a monitoring host can poll it from an untrusted network:

```json
{"ok": true, "role": "leader", "mode": "auto", "node_id": "edge-1",
 "version": "1.5.0", "tls": true, "time": 1793481600,
 "lease": {"mode": "auto", "effective": "leader",
           "lease": {"held": true, "owner": "edge-1", "expires": 1793483400}}}
```

`GET /v1/status` (secret required) adds the queue: `pending`, `unpushed`,
`reported_cache`, `reports_today`, `accepted_total`, `rejected_total`, `lease`.

`abuseipdb-report --metrics` prints a Prometheus document with the same numbers, and
the reporter writes it to `metrics_textfile` (`/var/lib/abuseipdb/metrics.prom`) plus
a JSON twin (`metrics_json_path`) on every run. `abuseipdb-report --metric <name>`
prints one value out of the JSON snapshot - that is what the Zabbix module uses, see
[ZABBIX.md](ZABBIX.md).

Alerts worth having:

| Symptom | Metric | Why it matters |
|---|---|---|
| reporter stopped running | `last_run_age_seconds > 7200` | bans queue up, nothing is reported |
| follower cannot reach the leader | `coord_sync_failures > 2`, `leader_up = 0` | reports are stuck on that node |
| queue growing | `pending_events > 200` | budget exhausted, key invalid, or leader down |
| budget spent | `budget_remaining = 0` | nothing more today; the queue drains after midnight UTC |
| nobody holds the lease | `lease_held = 0` on every node | nobody reports - check `witness_url` and the arbiter |

## Retries and a bad `fail2ban-client`

* A follower retries a failed sync `sync_attempts` times inside one run, with an
  exponential delay (`sync_retry_base` doubling, capped). A `4xx` from the leader is
  **not** retried: a wrong secret does not fix itself. Events stay queued, so a leader
  outage delays reports and never loses them.
* The jail list a node declares is cached for an hour. A failed
  `fail2ban-client status` no longer blanks it: the previous answer stays valid for up
  to 24 hours, so a fail2ban restart does not turn into a flood of ban requests for
  jails the node does have. An empty answer is remembered for one TTL and never
  overwrites a known list.

## Security

* The shared secret is a file, mode 600, compared in constant time
  (`hmac.compare_digest`); a missing or wrong value gets HTTP 403.
* The endpoint speaks plain HTTP. Bind it to a private interface, restrict it with
  a firewall or systemd (`IPAddressAllow=`), or terminate TLS in front of it. A
  minimal workable setup: `coord_bind = 10.0.0.5` plus
  `iptables -A INPUT -p tcp --dport 8765 -s 10.0.0.0/24 -j ACCEPT`.
* **A firewall that ends with `-j DROP` must accept loopback first.** Otherwise the
  leader's own health check (`curl -H "X-Coord-Secret: ..." http://127.0.0.1:8765/v1/status`)
  fails with `HTTP 000` while everything looks configured - measured on a live
  host: the peers kept syncing, the local check did not. Order the rules as
  loopback → each peer → DROP (see the unit in the next paragraph).
* Requests larger than 1 MiB are rejected with 413 before the body is read; the
  per-request event count is capped at 5000.
* **Ban propagation is a real power.** A compromised leader can make every
  follower ban addresses it names - that is why the rails above exist and why the
  endpoint must not face the internet. A follower can never unban, never report,
  and never make the leader report something outside its filters.
* Rotate the secret by writing the new value on the leader and on every follower;
  no restart is needed (the file is read on every sync).
* The API key must not exist on followers - with `mode = follower` it is never
  read.

## Operations

```bash
abuseipdb-coord --check                  # configuration and secret, then exit 0/2
abuseipdb-coord --bind 10.0.0.5 --port 8765
abuseipdb-report --coord-status          # role, leader status, cursor, cache size
abuseipdb-report --stats                 # pending / pushed to leader / reported cache
journalctl -u abuseipdb-coord -n 50      # leader endpoint
grep -E 'coord:|already reported' /var/log/abuseipdb-reporter.log

# what the cache knows about one address
sqlite3 /var/lib/abuseipdb/abuseipdb.sqlite3 \
  "SELECT ip, reported_at, source FROM reported_cache WHERE ip='198.51.100.7'"
```

## Failure modes

| Symptom | Cause | Action |
|---|---|---|
| `follower (HTTP 403 ...)` | secret differs between nodes | compare `sha256sum /etc/abuseipdb/.coord.secret` |
| `follower (missing shared secret ...)` | file absent or unreadable | create it, mode 600 |
| `follower (URLError ...)` | leader down, wrong port, firewall | `curl -H "X-Coord-Secret: ..." http://leader:8765/v1/status` |
| `waiting for push` grows, leader `pending` stays 0 | follower points at the wrong leader | `--coord-status` on the follower |
| `coord: remote ban not applied ... unable to find jail` | the jail does not exist on that node (1.4.1 filters these out; a 1.4.0 follower still receives them) | upgrade the follower, or add the jail there |
| local `curl` to `/v1/status` answers `HTTP 000` while peers sync fine | the port firewall ends with DROP and never accepts loopback | add `-i lo ... ACCEPT` before the DROP rule (see Security) |
| `coord: remote ban cap reached` | more than `max_remote_bans_per_run` bans in one answer | normal after an attack burst; the rest arrives on later ticks |
| reports stop with `already reported recently` in the log | the address is inside `peer_dedupe_window` | expected - the cluster already reported it |
| Leader reports `unpushed` instead of `pending` | the leader itself is configured as a follower | set `mode = leader` |
| Events accepted but never reported | leader has no API key, or the budget is exhausted | `abuseipdb-report --status` on the leader |

## Interaction with the rest of the design

* `pushed` (1.3.0) marks events delivered to the leader; `origin` (1.4.0) records
  which node reported a ban, so it is never sent back to that node. Both are added
  by an in-place migration: an existing queue is upgraded on first open.
* Pushed events stop being "pending" for that node and are deleted by the normal
  `retention_days` cleanup; the reported cache is pruned by the same cleanup.
* `--dry-run` on a follower prints the events that would be pushed and applies
  nothing - no bans, no cache updates.
* `status.json` and the Prometheus textfile keep working: on a follower, `sent`
  counts delivered events, `banned` counts remote bans applied, and `pending`
  counts events that still have to leave the node.
