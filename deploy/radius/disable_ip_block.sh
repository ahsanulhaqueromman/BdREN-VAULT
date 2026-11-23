#!/usr/bin/env bash
# Remove the old "block an attacker's IP for 2 days" FreeRADIUS policy (dbms_ip_block) that earlier
# VAULT versions installed with enable_ip_block.sh. VAULT no longer blocks addresses.
#
#   1. takes "dbms_ip_block" out of authorize { } of sites-enabled/default
#   2. puts the plain "sql" line of Post-Auth-Type REJECT back (every rejected login is logged again)
#   3. deletes policy.d/dbms_ip_block
#   4. checks the FreeRADIUS configuration; if the check fails the previous files are put back
#   5. restarts FreeRADIUS, so nobody stays blocked
#   6. drops the dbms_ip_block table (only after FreeRADIUS no longer reads it)
#
# Safe to run more than once; does nothing on a server that never had the policy.
# install.sh runs it by itself when it finds the policy.
#
# Usage:   sudo bash /opt/vault/deploy/radius/disable_ip_block.sh
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/vault}"
ENV_FILE="${ENV_FILE:-$APP_DIR/.env}"
RAD_DIR="${RAD_DIR:-/etc/freeradius/3.0}"
say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m OK\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run it with sudo:  sudo bash $0"
[ -d "$RAD_DIR" ] || { ok "FreeRADIUS folder $RAD_DIR not found; nothing to remove"; exit 0; }
SITE="$(readlink -f "$RAD_DIR/sites-enabled/default" 2>/dev/null || true)"
POLICY="$RAD_DIR/policy.d/dbms_ip_block"

CHANGED=0
if [ -n "$SITE" ] && [ -f "$SITE" ] && grep -q "dbms_ip_block" "$SITE"; then CHANGED=1; fi
if [ -f "$POLICY" ] || ls "$POLICY".bak-* >/dev/null 2>&1; then CHANGED=1; fi

if [ "$CHANGED" = 1 ]; then
  STAMP="$(date +%Y%m%d-%H%M%S)"
  BACKUP_DIR="$(mktemp -d)"
  [ -f "$SITE" ] && cp -p "$SITE" "$BACKUP_DIR/site"
  [ -f "$POLICY" ] && cp -p "$POLICY" "$BACKUP_DIR/policy"
  restore() {
    [ -f "$BACKUP_DIR/site" ] && cp -p "$BACKUP_DIR/site" "$SITE"
    [ -f "$BACKUP_DIR/policy" ] && cp -p "$BACKUP_DIR/policy" "$POLICY"
    return 0
  }

  if [ -f "$SITE" ]; then
    # 1 + 2: drop the "dbms_ip_block" call; turn the wrapped
    #     # dbms_ip_block: skip ...
    #     if (!&control:Tmp-String-8) {
    #         sql
    #     }
    # back into the plain "sql" line it was made from.
    awk 'BEGIN{st=0}
         st==0 && /^[ \t]*dbms_ip_block[ \t]*$/ {next}
         st==0 && /dbms_ip_block: skip/ {match($0,/^[ \t]*/); ind=substr($0,1,RLENGTH); st=1; next}
         st==1 && /^[ \t]*if[ \t]*\(!&control:Tmp-String-8\)[ \t]*\{[ \t]*$/ {st=2; next}
         st==2 {s=$0; sub(/^[ \t]*/,"",s); print ind s; st=3; next}
         st==3 && /^[ \t]*\}[ \t]*$/ {st=0; next}
         {st=0; print}' "$SITE" > "$SITE.new"
    if grep -q "dbms_ip_block\|Tmp-String-8" "$SITE.new"; then
      rm -f "$SITE.new"
      die "$SITE has a dbms_ip_block layout this script does not know; nothing was changed. Remove the 'dbms_ip_block' line from authorize { } and the 'if (!&control:Tmp-String-8) { ... }' around sql in Post-Auth-Type REJECT by hand."
    fi
    cat "$SITE.new" > "$SITE"; rm -f "$SITE.new"
    ok "dbms_ip_block taken out of $SITE"
  fi
  # 3
  rm -f "$POLICY" "$POLICY".bak-* "$POLICY.new"
  ok "policy removed: $POLICY"

  # 4 + 5
  RADIUSD="$(command -v freeradius || command -v radiusd || true)"
  [ -n "$RADIUSD" ] || { restore; die "freeradius binary not found; the previous files were put back"; }
  say "Checking the FreeRADIUS configuration"
  if ! "$RADIUSD" -C >/tmp/dbms-ipblock-off.log 2>&1; then
    restore
    die "FreeRADIUS configuration check failed (see /tmp/dbms-ipblock-off.log). The previous files were put back."
  fi
  rm -rf "$BACKUP_DIR"
  ok "configuration is valid"
  systemctl restart freeradius 2>/dev/null || systemctl restart radiusd
  ok "FreeRADIUS restarted without IP blocking; no address is blocked any more"
else
  ok "the IP blocking policy is not installed"
fi

# 6: the table (FreeRADIUS no longer reads it)
if [ -r "$ENV_FILE" ] && command -v mysql >/dev/null 2>&1; then
  env_get() { grep -E "^$1=" "$ENV_FILE" | tail -n1 | cut -d= -f2- | sed -E -e 's/[[:space:]]+#.*$//' -e 's/^[[:space:]]+|[[:space:]]+$//g' -e 's/^["'\'']//' -e 's/["'\'']$//' || true; }
  DB_NAME="$(env_get RADIUS_DB_NAME)"; DB_NAME="${DB_NAME:-radius}"
  DB_USER="$(env_get RADIUS_DB_USER)"; DB_USER="${DB_USER:-radius}"
  DB_PASS="$(env_get RADIUS_DB_PASSWORD)"
  DB_HOST="$(env_get RADIUS_DB_HOST)"; DB_HOST="${DB_HOST:-127.0.0.1}"
  DB_PORT="$(env_get RADIUS_DB_PORT)"; DB_PORT="${DB_PORT:-3306}"
  if [ -n "$DB_PASS" ]; then
    MYCNF="$(mktemp)"; chmod 600 "$MYCNF"; trap 'rm -f "$MYCNF"' EXIT
    printf '[client]\nuser=%s\npassword=%s\nhost=%s\nport=%s\n' "$DB_USER" "$DB_PASS" "$DB_HOST" "$DB_PORT" > "$MYCNF"
    if mysql --defaults-extra-file="$MYCNF" -N -B "$DB_NAME" -e "DROP TABLE IF EXISTS dbms_ip_block"; then
      ok "table dbms_ip_block removed"
    else
      warn "could not remove the dbms_ip_block table (nothing uses it now; it can stay)"
    fi
  fi
fi
