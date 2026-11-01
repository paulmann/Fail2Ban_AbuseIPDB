## v1.6.0 - good bots are never banned into a public report

A ban can be lifted. An AbuseIPDB report cannot be deleted. That asymmetry is what
this release fixes.

### What was measured first

`tools/audit-good-bots.sh` (read-only) on the three production hosts, 7 days:

| Host | Crawler requests | 403 | 429 | Banned now | Any banned address a crawler? |
|---|---|---|---|---|---|
| 5.35 | 5,404 | 0 | 0 | 329 | no |
| hp-debian | 228 | 0 | 0 | 1 | no |
| 199.195.197.95 | 14 | 0 | 0 | 1 | no |

Nothing was blocked. The filters match probe *paths* (`.env`, `.git/`, `phpmyadmin`),
never a user-agent, and nginx has no user-agent rules. The one jail that could catch a
crawler is `nginx-forbidden` (ten 403s an hour), and no crawler received a 403.

39 responses were 503 from `limit_req` - throttling, not a ban, and not fail2ban.

### The rail

Before a report is built, an address is checked twice:

1. **published ranges** - generated from the publishers' own JSON into
   `crawler_ranges.py`, with each list's `creationTime`:

   | List | Ranges | Published |
   |---|---|---|
   | Googlebot / InspectionTool / AdsBot / Storebot | 317 | 2026-10-30 |
   | GPTBot | 18 | 2026-09-22 |
   | OAI-SearchBot | 39 | 2026-01-02 |
   | ChatGPT-User | 235 | 2026-10-27 |

2. **reverse DNS with forward confirmation** - Bing, Yandex, Apple, Amazon, Common
   Crawl, ByteDance, Perplexity. The name only counts when it resolves back to the
   same address, which is the verification Google and Bing document.

A match means no API call: the event is finished locally, the skip is logged, counted
(`crawlers_skipped` in `status.json`) and exported
(`abuseipdb_reporter_last_run_crawlers_skipped`), with a Zabbix trigger because a
skipped crawler means a **jail rule is wrong**.

```bash
abuseipdb-report --crawler-status              # lists loaded, publisher dates
abuseipdb-report --crawler-check 66.249.66.5   # crawler (published google range)
abuseipdb-report --crawler-check 157.55.39.10  # crawler (verified: Bingbot (msnbot-...))
```

On a real host (5.35, temporary directory, installed config untouched):

```
dry run: skipped=1 crawlers_skipped=1
pending after the run: 1     # the ordinary address stays queued
```

### Deliberate limits

* No user-agent trust: anybody can send `Googlebot`.
* No broad ranges: Apple publishes none and lives in `17.0.0.0/8`, so it is verified by
  reverse DNS instead. "All of GCP" or "all of Cloudflare" is never whitelisted.
* ClaudeBot cannot be recognised by address - Anthropic publishes neither a range nor a
  resolvable name. The audit tool still sees it by user-agent, and the documentation
  says so instead of implying coverage.

### Also

`tools/update_crawler_ranges.py` regenerates the range module; `docs/GOOD-BOTS.md` is
the full measured answer. Zabbix module: 22 items, 9 triggers. Tests: **249**.

### Upgrade

`abuseipdb-upgrade --upgrade --yes`. Nothing to configure: the rail is on by default.
