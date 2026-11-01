"""Fetch the published crawler ranges and write ``crawler_ranges.py``.

Why generated, not hand-written: a stale CIDR list is worse than none - it says
"this address is a crawler" about an address somebody else now owns.  The file this
script writes therefore carries the source URL and the publisher's own
``creationTime`` for every list, so its age is visible in the repository.

Usage:

    python tools/update_crawler_ranges.py            # rewrite the module
    python tools/update_crawler_ranges.py --check    # report drift, change nothing

Only lists that exist in machine-readable form are fetched.  Publishers without one
(Bing, Apple, Yandex, Anthropic, Perplexity, ByteDance, Common Crawl) are verified at
run time by reverse DNS with forward confirmation instead - see
``abuseipdb_reporter.crawlers``.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "src", "abuseipdb_reporter", "crawler_ranges.py")

#: label -> (url, comment)
SOURCES = {
    "google": (
        "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
        "Googlebot, Google-InspectionTool, AdsBot-Google, Storebot-Google",
    ),
    "openai_gptbot": ("https://openai.com/gptbot.json", "GPTBot (model training)"),
    "openai_searchbot": ("https://openai.com/searchbot.json", "OAI-SearchBot (search index)"),
    "openai_user": ("https://openai.com/chatgpt-user.json", "ChatGPT-User (user-initiated)"),
}


def fetch(url: str, timeout: int = 30) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "fail2ban-abuseipdb-ranges/1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def prefixes(payload: dict) -> list:
    out = []
    for item in payload.get("prefixes", []) or []:
        value = item.get("ipv4Prefix") or item.get("ipv6Prefix")
        if value:
            out.append(str(value))
    return out


def render(lists: dict) -> str:
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    lines = [
        '"""Published crawler ranges - generated, do not edit by hand.',
        "",
        "Regenerate with ``python tools/update_crawler_ranges.py``; the generator records",
        "the publisher's own ``creationTime`` next to every list, so the age of each range",
        "set is visible here instead of being guessed from a commit date.",
        "",
        "Only publishers that offer a machine-readable list appear here.  Bing, Apple,",
        "Yandex, Amazon, Common Crawl, ByteDance and Perplexity are verified at run time by",
        "reverse DNS with forward confirmation (``crawlers.is_crawler``), which needs no",
        'list at all and cannot go stale."""',
        "from __future__ import annotations",
        "",
        f'GENERATED_AT = "{stamp}"',
        "",
        "#: label -> publisher creation time of the fetched document",
        "SOURCES = {",
    ]
    for label, meta in sorted(lists.items()):
        lines.append('    "%s": {"url": "%s", "creation_time": "%s", "count": %d, "comment": "%s"},'
                     % (label, meta["url"], meta["creation_time"], len(meta["prefixes"]),
                        meta["comment"]))
    lines += ["}", "", "#: label -> CIDR strings exactly as published", "RANGES = {"]
    for label, meta in sorted(lists.items()):
        lines.append('    "%s": (' % label)
        for prefix in meta["prefixes"]:
            lines.append('        "%s",' % prefix)
        lines.append("    ),")
    lines += ["}", ""]
    return "\n".join(lines)


def collect() -> dict:
    lists = {}
    for label, (url, comment) in SOURCES.items():
        payload = fetch(url)
        items = prefixes(payload)
        if not items:
            raise SystemExit("%s: no prefixes in the document" % url)
        lists[label] = {
            "url": url,
            "comment": comment,
            "creation_time": str(payload.get("creationTime", "")),
            "prefixes": sorted(set(items)),
        }
    return lists


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Fetch published crawler ranges.")
    parser.add_argument("--check", action="store_true", help="report drift, write nothing")
    parser.add_argument("--out", default=TARGET)
    args = parser.parse_args(argv)

    lists = collect()
    text = render(lists)
    current = ""
    if os.path.exists(args.out):
        with open(args.out, "r", encoding="utf-8") as handle:
            current = handle.read()
    if args.check:
        if current == text:
            print("up to date: %d lists, %d ranges"
                  % (len(lists), sum(len(v["prefixes"]) for v in lists.values())))
            return 0
        print("stale: the published lists changed; run without --check")
        return 1
    with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    print("written: %s (%d lists, %d ranges)"
          % (args.out, len(lists), sum(len(v["prefixes"]) for v in lists.values())))
    for label, meta in sorted(lists.items()):
        print("  %-18s %3d ranges, publisher creation time %s"
              % (label, len(meta["prefixes"]), meta["creation_time"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
