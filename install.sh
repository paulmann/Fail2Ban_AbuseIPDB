#!/usr/bin/env bash
# ============================================================================
#  Fail2Ban_AbuseIPDB installer
#  Installs the asynchronous fail2ban -> AbuseIPDB reporter on a Linux host.
#
#  Usage: sudo ./install.sh --api-key <KEY> [--jails "sshd nginx-attack-scan"]
#  See --help and docs/INSTALL.md for all options.
# ============================================================================
set -euo pipefail

PROG="$(basename "$0")"
VERSION="1.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PREFIX="/usr/local"
ROOT=""
API_KEY="${ABUSEIPDB_API_KEY:-}"
API_KEY_FILE=""
KEY_FILE="/etc/abuseipdb/.abuseipdb.key"
JAILS=""
JAILS_EXPLICIT=0
ALL_JAILS=0
WITH_UPDATE_CHECK=0
DRY_RUN=0
UNINSTALL=0
PURGE=0
USE_CRON=0
DO_RESTART=1
SKIP_API_CHECK=0
ASSUME_YES=0
SERVER_IP=""
REPORT_HOSTNAME=""
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

STATE="/var/lib/fail2ban-abuseipdb/install-state"
PRISTINE="/var/backups/fail2ban-abuseipdb/pristine-${TIMESTAMP}"
STATE_DIR="/var/lib/fail2ban-abuseipdb"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
c_red=''; c_green=''; c_yellow=''; c_reset=''
if [ -t 1 ]; then
  c_red=$'\033[31m'; c_green=$'\033[32m'; c_yellow=$'\033[33m'; c_reset=$'\033[0m'
fi

log()  { printf '%s\n' "$*"; }
info() { printf '%s[info]%s %s\n'  "$c_green"  "$c_reset" "$*"; }
warn() { printf '%s[warn]%s %s\n'  "$c_yellow" "$c_reset" "$*" >&2; }
die()  { printf '%s[error]%s %s\n' "$c_red"    "$c_reset" "$*" >&2; exit 1; }

path() { printf '%s%s' "$ROOT" "$1"; }

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] %s\n' "$*"
    return 0
  fi
  "$@"
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# API key handling
#
# The key lives in its own file (KEY_FILE) and is never part of the config or
# of the code archive, so re-installing / self-updating cannot overwrite it.
# ---------------------------------------------------------------------------
key_target() { path "$KEY_FILE"; }

key_file_value() {
  local target
  target="$(key_target)"
  if [ -r "$target" ]; then
    head -n 1 "$target" | tr -d '[:space:]'
  fi
}

save_key_file() {
  local key="$1" target
  target="$(key_target)"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] write API key to %s (mode 600)
' "$target"
    return 0
  fi
  install -d -m 700 "$(dirname "$target")"
  ( umask 077; printf '%s\n' "$key" > "$target" )
  chmod 600 "$target"
}

legacy_config_key() {
  local config
  config="$(path "/etc/abuseipdb/reporter.conf")"
  [ -r "$config" ] || return 0
  sed -n 's/^[[:space:]]*api_key[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*/\1/p' "$config" | head -n 1
}

# Resolve the key: --api-key > ABUSEIPDB_API_KEY > existing key file >
# legacy api_key in the config > interactive prompt (first run).
install_key() {
  local key="" source=""
  key="$(printf '%s' "$API_KEY" | tr -d '[:space:]')"
  if [ -n "$key" ]; then
    source="command line / environment"
  else
    key="$(key_file_value)"
    [ -n "$key" ] && source="existing key file"
  fi
  if [ -z "$key" ]; then
    key="$(legacy_config_key)"
    key="$(printf '%s' "$key" | tr -d '[:space:]')"
    [ -n "$key" ] && source="legacy api_key in reporter.conf (migrated)"
  fi
  if [ -z "$key" ]; then
    if [ -t 0 ]; then
      printf 'Enter your AbuseIPDB API key (input hidden, saved to %s): ' "$(key_target)" >&2
      read -r -s key
      printf '\n' >&2
      key="$(printf '%s' "$key" | tr -d '[:space:]')"
      [ -n "$key" ] || die "empty API key"
      source="interactive prompt"
    else
      die "no API key: pass --api-key, set ABUSEIPDB_API_KEY, write $(key_target), or run interactively"
    fi
  fi
  case "$key" in
    *[!0-9a-fA-F]*) warn "API key contains non-hex characters - check it" ;;
  esac
  [ "${#key}" -eq 80 ] || warn "API key length is ${#key}, expected 80 - check it"
  if [ "$source" = "existing key file" ]; then
    info "existing API key file kept untouched: $(key_target)"
    return 0
  fi
  save_key_file "$key"
  info "API key configured ($source) in $(key_target)"
}

usage() {
  cat <<EOF
Fail2Ban_AbuseIPDB installer v${VERSION}

Installs a queue-based fail2ban -> AbuseIPDB reporter:
an action queues every new ban in SQLite, a systemd timer (or cron) sends
rich abuse reports to https://api.abuseipdb.com/api/v2/report.

Usage:
  sudo ./install.sh [--api-key KEY] [options]

API key (first installation):
  --api-key KEY          AbuseIPDB API key (saved to the key file, mode 600)
  --api-key-file FILE    read the key from a file (first line)
                         (or set the ABUSEIPDB_API_KEY environment variable;
                         on a terminal the installer asks for the key and saves it)
  --key-file PATH        key file location (default: /etc/abuseipdb/.abuseipdb.key)

Optional:
  --jails "LIST"         space separated fail2ban jails to attach the action to
                         (default on upgrade: the jails already configured;
                         on a fresh install: "sshd")
  --all-jails            attach to every enabled jail except aggregate jails
                         (recidive)
  --with-update-check    install a weekly systemd timer/cron check for updates
                         (abuseipdb-upgrade --check - check only, never installs automatically)
  --server-ip IP         value for "server_ip" in the report comment
  --report-hostname NAME value for "hostname" in the report comment
  --cron                 use cron instead of the systemd timer
  --no-restart           do not restart fail2ban after installation
  --skip-api-check       do not validate the API key online
  --root DIR             stage the installation under DIR (testing/containers);
                         systemd and fail2ban are not touched
  --dry-run              print what would be done, change nothing
  --uninstall            remove the installation (keeps config and queue)
  --purge                with --uninstall: also delete config, queue and logs
  -y, --yes              do not ask for confirmation
  -h, --help             show this help
  -V, --version          show version

Examples:
  sudo ./install.sh --api-key "\$KEY"
  sudo ./install.sh --api-key "\$KEY" --jails "sshd nginx-attack-scan nginx-wp-login"
  sudo ./install.sh --api-key "\$KEY" --all-jails --cron
  sudo ./install.sh --uninstall
  sudo ./install.sh --uninstall --purge
EOF
}

# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --api-key)          API_KEY="${2:-}"; shift 2 ;;
    --api-key-file)     API_KEY_FILE="${2:-}"; shift 2 ;;
    --key-file)         KEY_FILE="${2:-}"; shift 2 ;;
    --jails)            JAILS="${2:-}"; JAILS_EXPLICIT=1; shift 2 ;;
    --all-jails)        ALL_JAILS=1; JAILS_EXPLICIT=1; shift ;;
    --with-update-check) WITH_UPDATE_CHECK=1; shift ;;
    --server-ip)        SERVER_IP="${2:-}"; shift 2 ;;
    --report-hostname)  REPORT_HOSTNAME="${2:-}"; shift 2 ;;
    --cron)             USE_CRON=1; shift ;;
    --no-restart)       DO_RESTART=0; shift ;;
    --skip-api-check)   SKIP_API_CHECK=1; shift ;;
    --root)             ROOT="${2:-}"; shift 2 ;;
    --dry-run)          DRY_RUN=1; shift ;;
    --uninstall)        UNINSTALL=1; shift ;;
    --purge)            PURGE=1; shift ;;
    -y|--yes)           ASSUME_YES=1; shift ;;
    -h|--help)          usage; exit 0 ;;
    -V|--version)       echo "$PROG $VERSION"; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

if [ -n "$ROOT" ]; then
  if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p "$ROOT" || die "cannot create --root directory: $ROOT"
  fi
  if [ -d "$ROOT" ]; then
    ROOT="$(cd "$ROOT" && pwd)"
  fi
  [ "$ROOT" = "/" ] && ROOT=""
fi

if [ -n "$API_KEY_FILE" ]; then
  [ -r "$API_KEY_FILE" ] || die "cannot read --api-key-file: $API_KEY_FILE"
  API_KEY="$(head -n 1 "$API_KEY_FILE" | tr -d '\r\n')"
fi
# strip whitespace that easily slips in when the key is pasted
API_KEY="$(printf '%s' "$API_KEY" | tr -d '[:space:]')"

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
require_root() {
  if [ -z "$ROOT" ] && [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    die "must be run as root (or use --root DIR for a staged installation)"
  fi
}

check_python() {
  local py
  py="$(command -v python3 || true)"
  [ -n "$py" ] || die "python3 not found; install it first (apt install python3)"
  "$py" - <<'PY'
import sys
if sys.version_info < (3, 9):
    sys.exit("python3 >= 3.9 is required, found %s" % sys.version.split()[0])
PY
}

check_layout() {
  local missing=0
  for item in src/abuseipdb_reporter config/reporter.conf.example \
              fail2ban/action.d/abuseipdb-async.conf systemd/abuseipdb-report.service \
              systemd/abuseipdb-report.timer logrotate/abuseipdb-reporter cron/abuseipdb-reporter \
              systemd/abuseipdb-upgrade-check.service systemd/abuseipdb-upgrade-check.timer \
              cron/abuseipdb-upgrade-check updater.json \
              bin/abuseipdb-enqueue bin/abuseipdb-report bin/abuseipdb-upgrade; do
    if [ ! -e "$SCRIPT_DIR/$item" ]; then
      warn "missing project file: $item"
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || die "run install.sh from the project directory (incomplete checkout)"
}

detect_jails() {
  if [ "$ALL_JAILS" -eq 1 ]; then
    local detected
    detected="$(fail2ban-client status 2>/dev/null \
      | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' ' || true)"
    if [ -n "$detected" ]; then
      JAILS="$detected"
      info "detected jails: $JAILS"
    else
      warn "could not detect jails, falling back to sshd"
      JAILS="sshd"
    fi
  elif [ "$JAILS_EXPLICIT" -eq 0 ]; then
    local existing
    existing="$(path "/etc/fail2ban/jail.d/50-abuseipdb-reporter.local")"
    if [ -r "$existing" ]; then
      JAILS="$(sed -n 's/^\[\([^]]*\)\][[:space:]]*$/\1/p' "$existing" \
        | grep -v '^DEFAULT$' | tr '\n' ' ' || true)"
      [ -n "$JAILS" ] || JAILS="sshd"
      info "upgrade: keeping already configured jails: $JAILS"
    else
      JAILS="sshd"
    fi
  fi
  local cleaned="" jail
  for jail in $JAILS; do
    case "$jail" in
      *[!a-zA-Z0-9_-]*) die "invalid jail name: $jail" ;;
    esac
    [ "$jail" = "recidive" ] && { warn "skipping aggregate jail recidive"; continue; }
    cleaned="$cleaned $jail"
  done
  JAILS="${cleaned# }"
  [ -n "$JAILS" ] || die "no jails selected"
}

# ---------------------------------------------------------------------------
# file helpers
# ---------------------------------------------------------------------------
# Record the state of a path at the FIRST installation only.  Re-installing must
# not turn our own files into "previous versions" that uninstall would restore.
backup_file() {
  local file="$1" rel
  rel="${file#"$ROOT"}"
  rel="${rel#/}"
  local state_file
  state_file="$(path "$STATE")"
  if [ "$DRY_RUN" -eq 0 ] && [ -r "$state_file" ] && grep -qF "${rel}|" "$state_file"; then
    return 0
  fi
  if [ -e "$file" ]; then
    mkdir -p "$(dirname "$(path "/$PRISTINE/$rel")")"
    run cp -a "$file" "$(path "/$PRISTINE/$rel")"
    [ "$DRY_RUN" -eq 1 ] || printf '%s|1|%s\n' "$rel" "$PRISTINE/$rel" >> "$state_file"
  else
    [ "$DRY_RUN" -eq 1 ] || printf '%s|0|\n' "$rel" >> "$state_file"
  fi
}

install_file() {
  local source="$1" target="$2" mode="$3"
  backup_file "$target"
  run install -D -m "$mode" "$source" "$target"
}

write_generated() {
  local target="$1" mode="$2" content="$3"
  backup_file "$target"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] write %s (mode %s)\n' "$target" "$mode"
    return 0
  fi
  mkdir -p "$(dirname "$target")"
  printf '%s' "$content" > "$target"
  chmod "$mode" "$target"
}

# ---------------------------------------------------------------------------
# installation steps
# ---------------------------------------------------------------------------
prepare_dirs() {
  run install -d -m 755 "$(path "$PREFIX/lib")"
  run install -d -m 755 "$(path "$PREFIX/lib/abuseipdb_reporter")"
  run install -d -m 755 "$(path "$PREFIX/sbin")"
  run install -d -m 700 "$(path "/etc/abuseipdb")"
  run install -d -m 700 "$(path "/var/lib/abuseipdb")"
  run install -d -m 700 "$(path "$STATE_DIR")"
  if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p "$(path "$PRISTINE")"
    if [ ! -e "$(path "$STATE")" ]; then
      : > "$(path "$STATE")"
    fi
  fi
}

install_code() {
  local file
  for file in "$SCRIPT_DIR"/src/abuseipdb_reporter/*.py; do
    install_file "$file" "$(path "$PREFIX/lib/abuseipdb_reporter/$(basename "$file")")" 644
  done
  if [ -f "$SCRIPT_DIR/src/abuseipdb_reporter/py.typed" ]; then
    install_file "$SCRIPT_DIR/src/abuseipdb_reporter/py.typed" \
                 "$(path "$PREFIX/lib/abuseipdb_reporter/py.typed")" 644
  fi
  install_file "$SCRIPT_DIR/bin/abuseipdb-enqueue" "$(path "$PREFIX/sbin/abuseipdb-enqueue")" 755
  install_file "$SCRIPT_DIR/bin/abuseipdb-report"  "$(path "$PREFIX/sbin/abuseipdb-report")"  755
  install_file "$SCRIPT_DIR/bin/abuseipdb-upgrade" "$(path "$PREFIX/sbin/abuseipdb-upgrade")" 755
}

install_config() {
  local target content tmp
  target="$(path "/etc/abuseipdb/reporter.conf")"
  if [ -e "$target" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      printf '[dry-run] keep config, ensure api_key_file=%s and empty api_key in %s\n' "$KEY_FILE" "$target"
      return 0
    fi
    tmp="$(mktemp)"
    awk -v keyfile="$KEY_FILE" '
      BEGIN { in_abuseipdb = 0; key_line = 0 }
      /^\[abuseipdb\][[:space:]]*$/ { in_abuseipdb = 1 }
      /^\[/ && $0 !~ /^\[abuseipdb\]/ { in_abuseipdb = 0 }
      /^[[:space:]]*api_key[[:space:]]*=/ { print "api_key ="; next }
      /^[[:space:]]*api_key_file[[:space:]]*=/ { print "api_key_file = " keyfile; key_line = 1; next }
      { print }
      END { if (!key_line) print "api_key_file = " keyfile }
    ' "$target" > "$tmp"
    install -m 600 "$tmp" "$target"
    rm -f "$tmp"
    info "existing config kept (api_key_file=$KEY_FILE, legacy api_key cleared): $target"
    return 0
  fi

  content="$(sed -e "s|^api_key_file = .*|api_key_file = ${KEY_FILE}|" \
                 -e "s|^server_ip = .*|server_ip = ${SERVER_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}|" \
                 -e "s|^hostname = .*|hostname = ${REPORT_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}|" \
                 "$SCRIPT_DIR/config/reporter.conf.example")"
  write_generated "$target" 600 "$content"
}

install_fail2ban() {
  local target jail snippet
  target="$(path "/etc/fail2ban/action.d/abuseipdb-async.conf")"
  install_file "$SCRIPT_DIR/fail2ban/action.d/abuseipdb-async.conf" "$target" 644

  snippet="[DEFAULT]
action_abuseipdb_async = abuseipdb-async
"
  for jail in $JAILS; do
    snippet="$snippet
[$jail]
action = %(action_)s
         %(action_abuseipdb_async)s
"
  done
  write_generated "$(path "/etc/fail2ban/jail.d/50-abuseipdb-reporter.local")" 644 "$snippet"

  if [ -z "$ROOT" ] && have fail2ban-client; then
    if ! run fail2ban-client -t; then
      die "fail2ban configuration test failed - nothing was restarted; restore files from $(path "$PRISTINE")"
    fi
  fi
}

install_scheduler() {
  if [ "$USE_CRON" -eq 0 ] && [ -d /run/systemd/system ] && [ -z "$ROOT" ]; then
    install_file "$SCRIPT_DIR/systemd/abuseipdb-report.service" \
                 "$(path "/etc/systemd/system/abuseipdb-report.service")" 644
    install_file "$SCRIPT_DIR/systemd/abuseipdb-report.timer" \
                 "$(path "/etc/systemd/system/abuseipdb-report.timer")" 644
    run systemctl daemon-reload
    run systemctl enable --now abuseipdb-report.timer
    info "systemd timer enabled: abuseipdb-report.timer (every 16 minutes)"
  else
    install_file "$SCRIPT_DIR/cron/abuseipdb-reporter" "$(path "/etc/cron.d/abuseipdb-reporter")" 644
    info "cron job installed: /etc/cron.d/abuseipdb-reporter"
  fi
  install_file "$SCRIPT_DIR/logrotate/abuseipdb-reporter" \
               "$(path "/etc/logrotate.d/abuseipdb-reporter")" 644

  if [ "$WITH_UPDATE_CHECK" -eq 1 ]; then
    if [ "$USE_CRON" -eq 0 ] && [ -d /run/systemd/system ] && [ -z "$ROOT" ]; then
      install_file "$SCRIPT_DIR/systemd/abuseipdb-upgrade-check.service" \
                   "$(path "/etc/systemd/system/abuseipdb-upgrade-check.service")" 644
      install_file "$SCRIPT_DIR/systemd/abuseipdb-upgrade-check.timer" \
                   "$(path "/etc/systemd/system/abuseipdb-upgrade-check.timer")" 644
      run systemctl daemon-reload
      run systemctl enable --now abuseipdb-upgrade-check.timer
      info "weekly update check enabled: abuseipdb-upgrade-check.timer"
    else
      install_file "$SCRIPT_DIR/cron/abuseipdb-upgrade-check" \
                   "$(path "/etc/cron.d/abuseipdb-upgrade-check")" 644
      info "weekly update check installed: /etc/cron.d/abuseipdb-upgrade-check"
    fi
  fi
}

restart_fail2ban() {
  [ -z "$ROOT" ] || return 0
  [ "$DO_RESTART" -eq 1 ] || { warn "fail2ban restart skipped (--no-restart)"; return 0; }
  if have systemctl && systemctl is-active --quiet fail2ban 2>/dev/null; then
    run systemctl restart fail2ban
    sleep 3
    info "fail2ban restarted"
  elif have fail2ban-client; then
    run fail2ban-client reload
    info "fail2ban reloaded"
  else
    warn "fail2ban is not running - start it manually"
  fi
}

post_checks() {
  [ -z "$ROOT" ] || return 0
  local report_bin="$PREFIX/sbin/abuseipdb-report"
  if [ -x "$report_bin" ]; then
    info "queue statistics after installation:"
    "$report_bin" --stats || true
  fi
  if [ "$SKIP_API_CHECK" -eq 0 ] && [ -x "$report_bin" ]; then
    info "validating the AbuseIPDB API key (one check request)..."
    if "$report_bin" --check-key --no-prompt >/tmp/.abuseipdb-check.$$ 2>&1; then
      info "API key is valid"
    else
      warn "API key check failed:"
      sed -n '1,3p' /tmp/.abuseipdb-check.$$ >&2 || true
    fi
    rm -f /tmp/.abuseipdb-check.$$
  fi
}

print_summary() {
  cat <<EOF

$(printf '%s' "$c_green")Fail2Ban_AbuseIPDB installed$(printf '%s' "$c_reset")

  code:      $PREFIX/lib/abuseipdb_reporter, $PREFIX/sbin/abuseipdb-report
             $PREFIX/sbin/abuseipdb-enqueue, $PREFIX/sbin/abuseipdb-upgrade
  config:    /etc/abuseipdb/reporter.conf (mode 600)
  api key:   $KEY_FILE (mode 600, never overwritten by updates)
  queue:     /var/lib/abuseipdb/abuseipdb.sqlite3
  fail2ban:  action /etc/fail2ban/action.d/abuseipdb-async.conf
             attached to jails: $(printf '%s' "$JAILS")
  schedule:  $([ "$USE_CRON" -eq 1 ] && echo "cron (/etc/cron.d/abuseipdb-reporter)" || echo "systemd timer (abuseipdb-report.timer)")
  state:     $STATE (original files: $PRISTINE)
  log:       /var/log/abuseipdb-reporter.log

Useful commands:
  $PREFIX/sbin/abuseipdb-report --stats
  $PREFIX/sbin/abuseipdb-report --dry-run
  $PREFIX/sbin/abuseipdb-report --check-key
  $PREFIX/sbin/abuseipdb-upgrade --check            # self-update check
  $PREFIX/sbin/abuseipdb-upgrade --upgrade          # install the update
  systemctl list-timers abuseipdb-report.timer      # when systemd is used
  tail -f /var/log/abuseipdb-reporter.log

Next: verify that the action really fires on the next ban -
see docs/INSTALL.md, section "Verification".
EOF
}

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------
uninstall() {
  info "uninstalling Fail2Ban_AbuseIPDB (ROOT='${ROOT:-/}')"
  [ -z "$ROOT" ] || info "staged root: $ROOT"

  if [ -z "$ROOT" ]; then
    if have systemctl; then
      run systemctl disable --now abuseipdb-report.timer 2>/dev/null || true
      run systemctl disable --now abuseipdb-upgrade-check.timer 2>/dev/null || true
    fi
  fi

  local state
  state="$(path "$STATE")"
  if [ -r "$state" ]; then
    while IFS='|' read -r rel existed backup; do
      [ -n "$rel" ] || continue
      case "$rel" in
        *install-state|*'..'*|etc/abuseipdb/reporter.conf) continue ;;
      esac
      local target="$ROOT/$rel"
      if [ "$existed" = "1" ] && [ -n "$backup" ] && [ -e "$(path "/$backup")" ]; then
        run install -D -m "$(stat -c '%a' "$(path "/$backup")" 2>/dev/null || echo 644)" \
          "$(path "/$backup")" "$target"
        info "restored previous version: $rel"
      else
        run rm -f "$target"
        info "removed: $rel"
      fi
    done < "$state"
  else
    warn "install state not found ($state); removing well-known paths"
    run rm -f "$(path "$PREFIX/sbin/abuseipdb-report")" "$(path "$PREFIX/sbin/abuseipdb-enqueue")"
    run rm -rf "$(path "$PREFIX/lib/abuseipdb_reporter")"
    run rm -f "$(path "/etc/fail2ban/action.d/abuseipdb-async.conf")"
    run rm -f "$(path "/etc/fail2ban/jail.d/50-abuseipdb-reporter.local")"
    run rm -f "$(path "/etc/systemd/system/abuseipdb-report.service")" \
               "$(path "/etc/systemd/system/abuseipdb-report.timer")"
    run rm -f "$(path "/etc/systemd/system/abuseipdb-upgrade-check.service")" \
               "$(path "/etc/systemd/system/abuseipdb-upgrade-check.timer")"
    run rm -f "$(path "/etc/cron.d/abuseipdb-reporter")" \
               "$(path "/etc/cron.d/abuseipdb-upgrade-check")" \
               "$(path "/etc/logrotate.d/abuseipdb-reporter")"
  fi

  # remove bytecode and the (now empty) package directory left by Python runs
  run rm -rf "$(path "$PREFIX/lib/abuseipdb_reporter/__pycache__")"
  if [ -z "$ROOT" ] && [ -d "$(path "$PREFIX/lib/abuseipdb_reporter")" ]; then
    rmdir "$(path "$PREFIX/lib/abuseipdb_reporter")" 2>/dev/null || true
  fi
  run rm -f "$(path "$STATE")"

  if [ -z "$ROOT" ]; then
    if have systemctl; then
      run systemctl daemon-reload || true
    fi
    if [ "$DO_RESTART" -eq 1 ] && have systemctl && systemctl is-active --quiet fail2ban 2>/dev/null; then
      run systemctl restart fail2ban && info "fail2ban restarted (action removed)"
    fi
  fi

  if [ "$PURGE" -eq 1 ]; then
    run rm -rf "$(path "/var/lib/abuseipdb")" "$(path "/etc/abuseipdb")"
    run rm -f "$(path "/var/log/abuseipdb-reporter.log")"
    run rm -rf "$(path "$STATE_DIR")"
    run rm -rf "$(path "/var/backups/fail2ban-abuseipdb")"
    info "configuration, queue and logs removed (--purge)"
  else
    info "configuration, queue and API key file kept; remove them with --purge"
  fi
  info "original files (if any) kept in: $PRISTINE"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  [ "$DRY_RUN" -eq 1 ] || [ -n "$ROOT" ] || require_root
  check_layout

  if [ "$UNINSTALL" -eq 1 ]; then
    if [ "$PURGE" -eq 1 ] && [ "$ASSUME_YES" -eq 0 ] && [ -t 0 ]; then
      printf 'Delete configuration, queue and logs? [y/N] '
      read -r answer
      case "$answer" in
        y|Y|yes|YES) ;;
        *) die "aborted" ;;
      esac
    fi
    uninstall
    exit 0
  fi

  check_python
  detect_jails

  info "installing to ${ROOT:-/} (PREFIX=$PREFIX, jails: $JAILS)"
  prepare_dirs
  install_code
  install_key
  install_config
  install_fail2ban
  install_scheduler
  restart_fail2ban
  post_checks
  print_summary
}

main "$@"