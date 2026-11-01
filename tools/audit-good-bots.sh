#!/bin/bash
# Read-only audit: does fail2ban (or nginx in front of it) block legitimate crawlers?
#
# Answers five questions and changes nothing:
#   1. which jails exist and what triggers them
#   2. are any currently banned addresses crawlers (reverse DNS + forward confirmation)
#   3. does ignoreip cover crawler networks at all
#   4. what status codes do the known bots get in the access logs, per bot family
#   5. does nginx itself block crawlers (user-agent rules, deny rules, rate limits)
#
# Run as root on the host: bash audit-good-bots.sh [days]
set -u

DAYS=${1:-7}
LOG_DIRS=(/var/www/httpd-logs /var/log/nginx /var/log/apache2)
BOT_UA='Googlebot|Google-InspectionTool|AdsBot-Google|Storebot-Google|Bingbot|msnbot|GPTBot|OAI-SearchBot|ChatGPT-User|ClaudeBot|Claude-Web|anthropic-ai|Applebot|YandexBot|YandexImages|CCBot|PerplexityBot|Bytespider|Amazonbot|DuckDuckBot|cohere-ai|meta-externalagent|facebookexternalhit|LinkedInBot|Slackbot|Twitterbot'

echo "===================== 1. jails"
fail2ban-client --version 2>/dev/null | head -1
fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' ' | tr -s ' ' | sed 's/^ *//;s/ *$//' | tr ' ' '\n' | while read -r j; do
    [ -z "$j" ] && continue
    printf "  %-20s maxretry=%-3s findtime=%-6s bantime=%s\n" \
        "$j" "$(fail2ban-client get "$j" maxretry)" "$(fail2ban-client get "$j" findtime)" "$(fail2ban-client get "$j" bantime)"
done

echo
echo "===================== 2. are banned addresses crawlers?"
python3 - <<'PY' > /tmp/_aigb_bans.txt
import subprocess
raw = subprocess.run(["fail2ban-client", "banned"], capture_output=True, text=True).stdout
try:
    data = eval(raw)
except Exception:
    data = []
ips = set()
if isinstance(data, list):
    for item in data:
        for jail, values in item.items():
            ips.update(values)
print("\n".join(sorted(ips)))
PY
echo "  banned now: $(wc -l < /tmp/_aigb_bans.txt)"
hits=0
while read -r ip; do
    [ -z "$ip" ] && continue
    name=$(dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//')
    [ -z "$name" ] && continue
    if echo "$name" | grep -qEi 'googlebot\.com|^.*\.google\.com|search\.msn\.com|openai\.com|openai\.org|applebot\.apple\.com|yandex\.(com|net|ru)|amazonbot\.amazon|commoncrawl\.org|bytedance\.com|perplexity\.ai'; then
        forward=$(dig +short "$name" A 2>/dev/null | grep -cx "$ip")
        echo "  CRAWLER $ip -> $name (forward confirms: $forward)"
        hits=$((hits + 1))
    fi
done < /tmp/_aigb_bans.txt
[ "$hits" -eq 0 ] && echo "  none: no banned address reverse-resolves to a known crawler domain"

echo
echo "===================== 3. ignoreip coverage"
fail2ban-client get sshd ignoreip 2>/dev/null | sed -n 's/^|- //p' | tr '\n' ' ' | fold -w 150 | sed 's/^/  /'
echo
echo "  crawler networks in ignoreip: $(fail2ban-client get sshd ignoreip 2>/dev/null | grep -cE '66\.249\.|157\.55\.39|207\.46\.13|40\.77\.167|20\.171\.|4\.227\.' ) (0 = none)"

echo
echo "===================== 4. what the bots actually get (last $DAYS days)"
files=$(find "${LOG_DIRS[@]}" -maxdepth 1 -type f -name '*.log' -mtime -"$DAYS" 2>/dev/null)
[ -z "$files" ] && files=$(find "${LOG_DIRS[@]}" -maxdepth 1 -type f -name '*.log*' 2>/dev/null)
if [ -z "$files" ]; then
    echo "  no logs found in: ${LOG_DIRS[*]}"
else
    echo "  log files considered: $(echo "$files" | wc -l)"
    # one pass: keep only lines carrying a known bot user-agent, then parse the code
    # (the log format differs between hosts, so the code is taken from the first
    # quoted number after the request, not from a fixed field position)
    # shellcheck disable=SC2086  # $files is a deliberate list of paths
    grep -ahE "$BOT_UA" $files 2>/dev/null | python3 -c '
import re, sys
UA = re.compile(r"(Googlebot|Google-InspectionTool|AdsBot-Google|Storebot-Google|Bingbot|msnbot|GPTBot|OAI-SearchBot|ChatGPT-User|ClaudeBot|Claude-Web|anthropic-ai|Applebot|YandexBot|YandexImages|CCBot|PerplexityBot|Bytespider|Amazonbot|DuckDuckBot|cohere-ai|meta-externalagent|facebookexternalhit|LinkedInBot|Slackbot|Twitterbot)", re.I)
CODE = re.compile(r"\"\s+(\d{3})\s")
rows = []
for line in sys.stdin:
    ua = UA.search(line)
    code = CODE.search(line)
    if ua and code:
        rows.append((ua.group(1), int(code.group(1))))
if not rows:
    print("  no request with a known bot user-agent in these logs")
    raise SystemExit
from collections import defaultdict
stat = defaultdict(lambda: defaultdict(int))
for bot, code in rows:
    stat[bot][code] += 1
print("  requests carrying a known bot user-agent: %d" % len(rows))
print()
print("  %-22s %6s %6s %6s %6s %6s %6s" % ("bot", "total", "ok/3xx", "403", "429", "503", "other4xx"))
for bot in sorted(stat, key=lambda b: -sum(stat[b].values())):
    codes = stat[bot]
    total = sum(codes.values())
    ok = sum(n for c, n in codes.items() if c < 400)
    f403 = codes.get(403, 0)
    f429 = codes.get(429, 0)
    f503 = codes.get(503, 0)
    other = sum(n for c, n in codes.items() if c >= 400 and c not in (403, 429, 503))
    print("  %-22s %6d %6d %6d %6d %6d %6d" % (bot, total, ok, f403, f429, f503, other))
bad = [(b, c) for b, c in rows if c in (403, 429, 444)]
print()
if bad:
    print("  BLOCKING statuses (403/429/444) per bot - these could trip a jail:")
    seen = defaultdict(int)
    for bot, code in bad:
        seen[(bot, code)] += 1
    for (bot, code), n in sorted(seen.items(), key=lambda kv: -kv[1]):
        print("    %-22s %s x%d" % (bot, code, n))
else:
    print("  no 403/429/444 for any known bot: nginx never refuses them, so")
    print("  nginx-forbidden has nothing to ban on")
'
fi

echo "===================== 5. nginx-side rules that can hit crawlers"
# shellcheck disable=SC2016  # $http_user_agent is a literal nginx variable
bad=$(grep -rlsE 'http_user_agent.*(bot|crawler|spider)|if \(\$http_user_agent|limit_req|deny all' /etc/nginx /etc/apache2 /usr/local/nginx/conf 2>/dev/null | head -30)
if [ -z "$bad" ]; then
    echo "  no user-agent, rate-limit or deny rules found"
else
    echo "  files with such rules: $(echo "$bad" | wc -l)"
    echo "  --- user-agent rules (the only kind that can target a bot on purpose):"
    # shellcheck disable=SC2016  # $http_user_agent is a literal nginx variable
    grep -rhnE 'http_user_agent.*(bot|crawler|spider)|if \(\$http_user_agent' /etc/nginx /etc/apache2 2>/dev/null | sed 's/^/    /' | head -10
    echo "  --- rate limits (a crawler that hits them gets 503, not a ban):"
    grep -rhoE 'limit_req_zone [^;]*' /etc/nginx 2>/dev/null | sed 's/^/    /' | head -6
fi

rm -f /tmp/_aigb_*
echo
echo "===================== done (nothing was changed)"
