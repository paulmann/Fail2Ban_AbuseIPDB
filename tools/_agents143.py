import io

p = "AGENTS.md"
t = io.open(p, encoding="utf-8").read()
pairs = [
    ("# AGENTS.md — Fail2Ban_AbuseIPDB 1.4.2", "# AGENTS.md — Fail2Ban_AbuseIPDB 1.4.3"),
    ("Version covered: 1.4.2 (tag `v1.4.2`, released 2026-11-01).",
     "Version covered: 1.4.3 (tag `v1.4.3`, released 2026-11-01)."),
    ("`v1.4.2` (latest), `v1.4.1`, `v1.4.0`", "`v1.4.3` (latest), `v1.4.2`, `v1.4.1`, `v1.4.0`"),
    ("The v1.4.2 asset is `Fail2Ban_AbuseIPDB-1.4.2.tar.gz`;",
     "The v1.4.3 asset is `Fail2Ban_AbuseIPDB-1.4.3.tar.gz`;"),
    ("git clone --branch v1.4.2 --depth 1", "git clone --branch v1.4.3 --depth 1"),
]
for a, b in pairs:
    if a in t:
        t = t.replace(a, b)
        print("ok:", a[:48])
    else:
        print("MISS:", a[:48])
io.open(p, "w", encoding="utf-8", newline="\n").write(t)
