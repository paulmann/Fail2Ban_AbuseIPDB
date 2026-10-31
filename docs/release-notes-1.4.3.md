## v1.4.3 — a fresh release is visible immediately

Cut minutes after 1.4.2, from a real annoyance: `abuseipdb-upgrade --check` on
three hosts kept answering *"you are running the latest version"* while the
manifest on GitHub already named the next version.

### Cause

`updater.json` is served by `raw.githubusercontent.com`, and the CDN in front of
it answers `Cache-Control: max-age=300` with `X-Cache: HIT`. The updater asked for
the same URL every time, so for up to five minutes after a release it read the
previous manifest — and reported "no update" instead of failing loudly.

### Fixed

* The manifest request now carries a unique query parameter,
  `_f2b_nocache=<epoch>`. The CDN keys its cache on the full URL and the origin
  ignores unknown parameters, so a new release is seen at once, while the response
  stays a plain HTTP GET that any proxy can serve.
* Only `raw.githubusercontent.com` is rewritten. A self-hosted manifest or a URL
  carrying a signature is requested **unchanged** — appending a parameter there
  could invalidate the signature.

### Changed

* Tests: **188** (was 183): the parameter is unique per call, an existing query
  string survives, other hosts are untouched, and `fetch_manifest` really uses the
  rewritten URL.

### Upgrade

`abuseipdb-upgrade --upgrade --yes`. Irony noted: the host that needs this fix is
also the host that cannot see the fix, because its current updater still reads the
cached manifest — give the CDN its five minutes once, then every later release is
immediate.
