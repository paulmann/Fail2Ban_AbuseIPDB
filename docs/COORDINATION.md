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
  records who reported it).
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
| jail name must match `^[A-Za-z0-9._@-]{1,64}$` | nothing shell-like ever reaches the command (the command is executed without a shell at all) |
| `max_remote_bans_per_run` (20, ceiling 200) | one sync cannot flood a node with bans |
| no unban, ever | the feature can only add bans; nothing can lift one |

`sync_bans = no` disables propagation on a node entirely (events and the
reported-cache still sync). A ban the node already has produces
`already banned` and is counted as not applied - harmless.

## Failover (deliberate, manual)

There is no election and no lease on purpose. A lease file on shared storage looks
automatic but cannot be made safe without an atomic compare-and-swap: two nodes
renewing it concurrently both believe they are the leader, and a split brain
spends the account budget twice while breaking the per-IP interval. A manual switch
is slower and always correct.

1. On the broken leader: `systemctl stop abuseipdb-coord`, then stop the worker if
   the host is unusable.
2. On the new leader: copy `/etc/abuseipdb/.abuseipdb.key` and
   `/etc/abuseipdb/.coord.secret`, set `mode = leader` with its own `node_id`,
   start `abuseipdb-coord`, check `--check-key`.
3. On every follower: point `leader_url` at the new host and run
   `abuseipdb-report --coord-status`.
4. On the old leader when it returns: set `mode = follower`, or keep it off.
   **Never leave two leaders reporting with the same key.**

Queues are local, so nothing is lost: followers keep retrying and the new leader
receives everything still pending. The reported cache also travels, so the new
leader does not repeat a report the old one made two minutes ago.

## Security

* The shared secret is a file, mode 600, compared in constant time
  (`hmac.compare_digest`); a missing or wrong value gets HTTP 403.
* The endpoint speaks plain HTTP. Bind it to a private interface, restrict it with
  a firewall or systemd (`IPAddressAllow=`), or terminate TLS in front of it. A
  minimal workable setup: `coord_bind = 10.0.0.5` plus
  `iptables -A INPUT -p tcp --dport 8765 -s 10.0.0.0/24 -j ACCEPT`.
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
| `coord: remote ban not applied ... unable to find jail` | the jail does not exist on that node | add the jail there or narrow `to_ban` with `skip_jails` on the leader |
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
