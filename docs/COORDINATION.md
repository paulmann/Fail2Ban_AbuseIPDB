# Multi-host coordination (one AbuseIPDB account, several servers)

AbuseIPDB limits are **per account**, not per host: 1000 requests/day on the free
plan and one report per IP per 15 minutes. If five protected servers each run the
reporter with the same key, the account budget is spent five times faster and two
hosts can report the same address within the forbidden window.

Coordination fixes that without breaking the project's rules: the ban path still
never touches the network, no new dependency is added, and the API key exists on
exactly one machine.

```
        follower (web-1)               follower (mail-1)
   fail2ban -> queue (SQLite)      fail2ban -> queue (SQLite)
                 |                              |
                 |  POST /v1/push (secret)      |
                 +--------------+---------------+
                                |
                                v
                     leader (edge-1)  abuseipdb-coord
                        queue (SQLite) -> abuseipdb-report -> AbuseIPDB API
                        holds the API key, owns the rate limits
```

## Roles

| `[coordination] mode` | Behaviour |
|---|---|
| `none` (default) | standalone: every node reports for itself. Identical to 1.2.x - upgrading changes nothing. |
| `leader` | reports as usual **and** runs `abuseipdb-coord` to accept pushed events. Holds the API key. |
| `follower` | never calls the API and needs no API key: the worker pushes its queued events to the leader and marks them delivered. |

A follower's `abuseipdb-report` run does exactly one thing: `POST /v1/push` with
a batch of events. If the push fails, nothing is marked, the events stay queued
and the next timer tick retries them - a leader outage delays reports, it never
loses them.

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
# how many events one push carries
push_batch_size = 50
```

| Key | Default | Meaning |
|---|---|---|
| `mode` | `none` | role of this node |
| `node_id` | *(empty)* | name used in logs and in the leader's status |
| `leader_url` | *(empty)* | base URL of the leader, `http://` or `https://` only |
| `shared_secret_file` | `/etc/abuseipdb/.coord.secret` | file with the shared secret (mode 600) |
| `coord_bind` | `127.0.0.1` | address the leader endpoint binds to |
| `coord_port` | `8765` | port of the leader endpoint |
| `push_batch_size` | `50` | events per push (1-500, hard cap 500) |

The timeout of coordination calls reuses `[abuseipdb] timeout`.

## Create the shared secret

One generated value, copied to every node:

```bash
openssl rand -hex 32 | sudo tee /etc/abuseipdb/.coord.secret >/dev/null
sudo chmod 600 /etc/abuseipdb/.coord.secret
sudo chown root:root /etc/abuseipdb/.coord.secret
```

Distribution is your business (configuration management, `scp`, a vault). The
reporter never prints it: `abuseipdb-coord --check` and
`abuseipdb-report --coord-status` only report `secret: present` or `MISSING`.

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

# 4. verify
sudo /usr/local/sbin/abuseipdb-report --coord-status
curl -s -H "X-Coord-Secret: $(sudo cat /etc/abuseipdb/.coord.secret)" \
     http://127.0.0.1:8765/v1/status
```

`abuseipdb-coord.service` is installed by `install.sh` but **never enabled**: an
endpoint nobody asked for must not open a port. Enable it only on the leader.

## Follower setup

```bash
# 1. no API key needed; remove it from the follower if it is there
sudo /usr/local/sbin/abuseipdb-report --coord-status   # after the config edit

# 2. point this node at the leader (same helper as on the leader)
sudo python3 tools/set_coordination.py --config /etc/abuseipdb/reporter.conf \
    --mode follower --node-id web-1 --leader-url http://10.0.0.5:8765

# 3. check the path end to end
sudo /usr/local/sbin/abuseipdb-report --coord-status   # prints the leader's status
sudo /usr/local/sbin/abuseipdb-report --dry-run        # prints what would be pushed
sudo /usr/local/sbin/abuseipdb-report                  # pushes one batch
sudo /usr/local/sbin/abuseipdb-report --stats          # "waiting for push" counter
```

The timer or cron job stays as it is: the follower's worker *is* the pusher.

## What the leader does with pushed events

The leader applies the same filters as its own enqueue path before queueing an
event: the address must parse, must not be inside `[ignore] ranges`, and the jail
must not be in `skip_jails`. Rejected events are counted in the response, so a
misconfigured follower does not flood the leader with addresses it would never
report.

Duplicates collapse through the normal 5-minute deduplication window, which makes
a lost acknowledgement harmless: the follower retries, the leader answers
`inserted: 0`, the follower marks the events as delivered.

## Failover (deliberate, manual)

There is no election, no lease file and no hidden consensus - the failure modes of
those are worse than the outage they try to hide.

1. On the broken leader: `sudo systemctl stop abuseipdb-coord.timer`-style stop of
   the endpoint (`systemctl stop abuseipdb-coord`) and stop the worker if the host
   is unusable.
2. On the new leader: copy `/etc/abuseipdb/.abuseipdb.key` and
   `/etc/abuseipdb/.coord.secret`, set `mode = leader`, `node_id`, start
   `abuseipdb-coord`, check `--check-key`.
3. On every follower: point `leader_url` at the new host, run
   `abuseipdb-report --coord-status`.
4. On the old leader (when it returns): set `mode = follower` **or** keep it off;
   never leave two leaders reporting with the same key.

Queues are local, so nothing is lost during the switch: followers keep retrying
and the new leader receives everything that is still pending.

## Security

* The shared secret is a file, mode 600, and is compared in constant time
  (`hmac.compare_digest`); a missing or wrong value gets HTTP 403.
* The endpoint speaks plain HTTP. Bind it to a private interface, restrict it with
  a firewall or systemd (`IPAddressAllow=`), or terminate TLS in front of it. A
  minimal workable setup: `coord_bind = 10.0.0.5` plus
  `iptables -A INPUT -p tcp --dport 8765 -s 10.0.0.0/24 -j ACCEPT`.
* Requests larger than 1 MiB are rejected with 413 before the body is read; the
  per-request event count is capped at 5000.
* The follower cannot report, ban or unban anything: it can only enqueue events
  the leader would accept anyway.
* Rotate the secret by writing the new value on the leader and on every follower;
  no restart is needed (the file is read on every push).
* The API key must not exist on followers - with `mode = follower` it is never
  read.

## Operations

```bash
abuseipdb-coord --check                  # configuration and secret, then exit 0/2
abuseipdb-coord --bind 10.0.0.5 --port 8765
abuseipdb-report --coord-status          # role + leader status (followers)
abuseipdb-report --stats                 # "waiting for push" counter (followers)
journalctl -u abuseipdb-coord -n 50      # leader endpoint
grep 'coord:' /var/log/abuseipdb-reporter.log
```

## Failure modes

| Symptom | Cause | Action |
|---|---|---|
| `follower (HTTP 403 ...)` in the log | secret differs between nodes | compare `sha256sum` of `/etc/abuseipdb/.coord.secret` on both ends |
| `follower (missing shared secret ...)` | file absent or unreadable | create it, mode 600 |
| `follower (URLError...)` | leader down, wrong port, firewall | `curl -H "X-Coord-Secret: ..." http://leader:8765/v1/status` |
| `waiting for push` grows, leader `pending` stays 0 | follower points at the wrong leader | `--coord-status` on the follower |
| Leader reports `unpushed` instead of `pending` | leader itself was configured as a follower | set `mode = leader` |
| Events accepted but never reported | leader has no API key or the budget is exhausted | `abuseipdb-report --status` on the leader |
| `coord: warning: mode is 'none'` | endpoint started on a standalone node | set `mode = leader` or stop the endpoint |

## Interaction with the rest of the design

* `pushed` is a column on `events` (added by an in-place migration in 1.3.0);
  pushed events are no longer "pending" for this node, are excluded from every
  local reporting query, and are deleted by the normal `retention_days` cleanup.
* `--dry-run` on a follower prints the events that would be pushed and changes
  nothing.
* The status file (`status.json`) and Prometheus textfile keep working: on a
  follower, `sent` counts delivered events and `pending` counts events that still
  have to leave the node.
