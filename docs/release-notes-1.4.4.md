## v1.4.4 — the manifest is read where nothing caches it

1.4.3 tried to fix this and did not. This release does, and says how it was
checked.

### What was wrong with 1.4.3

The fix appended `_f2b_nocache=<epoch>` to the `raw.githubusercontent.com` URL,
assuming the CDN keys its cache on the full URL. Measured on a live repository:
after a commit that changed the file, repeated probes of **both** the plain and the
query-string URL kept returning the old content for minutes, and the two flipped
back and forth independently — the parameter does not reliably reach the origin.
So a host could still be told *"you are running the latest version"* while the
manifest already named the next one.

### Fixed

* The updater derives the GitHub API URL from the configured raw URL

  ```
  raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>
      → api.github.com/repos/<owner>/<repo>/contents/<path>?ref=<ref>
  ```

  and asks for it with `Accept: application/vnd.github.raw`, which returns the file
  itself. `api.github.com` is not CDN-cached: it answered with the new version
  while the raw URL was still stale.
* The configured URL remains the **fallback** — a rate limit (`60/hour` without a
  token), blocked egress or a network error falls back to the raw file, so a
  restricted host still gets update checks.
* A custom `[update] manifest_url` that is not a GitHub raw URL is requested
  exactly as configured, once, with no rewriting at all.

### Verified

* Unit tests (193 total): the raw→API mapping (nested path, tag ref), API-first
  order, fallback on `HTTP 403`, one single request for a foreign host, both
  sources failing with both named in the error, the `Accept` header present only for
  `api.github.com`.
* Live measurement, on a production host, against a scratch branch: the file was
  changed from `0.0.2` to `0.0.3` and both sources were polled every 15 s for two
  minutes.

  ```
  t=  0s  raw=0.0.2  api=0.0.2  via_updater=0.0.2
  t= 15s  raw=0.0.2  api=0.0.3  via_updater=0.0.3
  ...
  t=120s  raw=0.0.2  api=0.0.3  via_updater=0.0.3
  ```

  `raw` never left the old copy inside that window; the API and the fixed updater
  saw the new one from the first poll after the push.

### Upgrade

`abuseipdb-upgrade --upgrade --yes`. A host on 1.4.3 keeps the useless parameter
until it upgrades; a host on 1.4.2 or older may need one five-minute CDN window
before it sees this release. After that, every release is visible immediately.
