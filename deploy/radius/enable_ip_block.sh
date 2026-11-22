#!/usr/bin/env bash
# Turn on "block an attacker's IP for 2 days after a login with an unknown username"
# (policy: deploy/radius/dbms_ip_block - read it for how it works and what is never blocked).
#
#   1. installs the policy into FreeRADIUS's policy.d, with the allowed local device accounts from
#      RADIUS_BLOCK_ALLOW_USERS in .env (comma-separated, default "hasuk")
#   2. adds "dbms_ip_block" to authorize { } of sites-enabled/default, right after the sql line
#   3. checks the FreeRADIUS configuration (the previous files are put back if the check fails)
#   4. restarts FreeRADIUS
#
# The dbms_ip_block table must exist first:  python manage.py radius_init   (install.sh does this).
# Safe to run again; run it again after changing RADIUS_BLOCK_ALLOW_USERS.
#
# Usage:   sudo bash /opt/vault/deploy/radius/enable_ip_block.sh
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/vault}"
ENV_FILE="${ENV_FILE:-$APP_DIR/.env}"
RAD_DIR="${RAD_DIR:-/etc/freeradius/3.0}"
SRC="$(cd "$(dirname "$0")" && pwd)/dbms_ip_block"
say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m OK\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run it with sudo:  sudo bash $0"
[ -f "$SRC" ] || die "Policy file not found: $SRC"
[ -d "$RAD_DIR/policy.d" ] || die "FreeRADIUS folder $RAD_DIR/policy.d not found (set RAD_DIR=...)"
SITE="$(readlink -f "$RAD_DIR/sites-enabled/default" 2>/dev/null || true)"
[ -f "$SITE" ] || die "$RAD_DIR/sites-enabled/default not found"

# allowed local accounts -> SQL list 'a','b'  (only safe username characters are kept)
ALLOW="hasuk"
if [ -r "$ENV_FILE" ]; then
  v="$(grep -E '^RADIUS_BLOCK_ALLOW_USERS=' "$ENV_FILE" | tail -n1 | cut -d= -f2- | sed -E 's/^["'\'']|["'\'']$//g' || true)"
  [ -n "$v" ] && ALLOW="$v"
fi
LIST=""
IFS=',' read -ra NAMES <<< "$ALLOW"
for n in "${NAMES[@]}"; do
  n="$(printf '%s' "$n" | tr -d '[:space:]')"
  [[ "$n" =~ ^[A-Za-z0-9._@-]{1,64}$ ]] || continue
  LIST="${LIST:+$LIST,}'$n'"
done
[ -n "$LIST" ] || LIST="''"
say "Allowed local accounts (never cause a block): $LIST"

STAMP="$(date +%Y%m%d-%H%M%S)"
POLICY="$RAD_DIR/policy.d/dbms_ip_block"
[ -f "$POLICY" ] && cp -p "$POLICY" "$POLICY.bak-$STAMP"
cp -p "$SITE" "$SITE.dbms-backup-$STAMP"
restore() {
  if [ -f "$POLICY.bak-$STAMP" ]; then mv -f "$POLICY.bak-$STAMP" "$POLICY"; else rm -f "$POLICY"; fi
  cp -p "$SITE.dbms-backup-$STAMP" "$SITE"
}

sed "s/__ALLOW_USERS__/$LIST/" "$SRC" > "$POLICY.new"
install -m 640 -o root -g freerad "$POLICY.new" "$POLICY" 2>/dev/null || install -m 640 "$POLICY.new" "$POLICY"
rm -f "$POLICY.new"
ok "policy installed: $POLICY"

if grep -qE '^[[:space:]]*dbms_ip_block[[:space:]]*$' "$SITE"; then
  ok "authorize { } already runs dbms_ip_block"
else
  awk 'BEGIN{inauth=0;done=0}
       /^authorize[ \t]*\{/{inauth=1}
       {print}
       inauth && !done && /^[ \t]*-?sql[ \t]*$/ {print "\tdbms_ip_block"; done=1}
       inauth && /^\}/{inauth=0}' "$SITE" > "$SITE.new"
  if grep -q "dbms_ip_block" "$SITE.new"; then
    cat "$SITE.new" > "$SITE"; rm -f "$SITE.new"; ok "added dbms_ip_block to authorize { } after sql"
  else
    rm -f "$SITE.new"; restore
    die "No 'sql' line inside authorize { } of $SITE; add 'dbms_ip_block' after it by hand"
  fi
fi

# Post-Auth-Type REJECT: don't write repeat attempts from a blocked address to the login log
# (the policy marks them with control:Tmp-String-8; they are counted in dbms_ip_block.hits instead)
if grep -q "dbms_ip_block: skip" "$SITE"; then
  ok "repeat attempts from blocked addresses are already left out of the login log"
else
  awk 'BEGIN{inrej=0;done=0}
       /^[ \t]*Post-Auth-Type[ \t]+REJECT[ \t]*\{/{inrej=1}
       inrej && !done && /^[ \t]*-?sql[ \t]*$/ {
         match($0,/^[ \t]*/); ind=substr($0,1,RLENGTH); s=$0; sub(/^[ \t]*/,"",s)
         print ind "# dbms_ip_block: skip the login log for repeat attempts from a blocked address"
         print ind "if (!&control:Tmp-String-8) {"
         print ind "\t" s
         print ind "}"
         done=1; next }
       inrej && /^[ \t]*\}/{inrej=0}
       {print}' "$SITE" > "$SITE.new"
  if grep -q "dbms_ip_block: skip" "$SITE.new"; then
    cat "$SITE.new" > "$SITE"; ok "repeat attempts from blocked addresses left out of the login log"
  else
    ok "Post-Auth-Type REJECT does not log to sql here; nothing to change"
  fi
  rm -f "$SITE.new"
fi

RADIUSD="$(command -v freeradius || command -v radiusd || true)"
[ -n "$RADIUSD" ] || { restore; die "freeradius binary not found"; }
say "Checking the FreeRADIUS configuration"
if ! "$RADIUSD" -C >/tmp/dbms-ipblock-check.log 2>&1; then
  restore
  die "FreeRADIUS configuration check failed (see /tmp/dbms-ipblock-check.log). The previous files were restored."
fi
ok "configuration is valid"
rm -f "$SITE.dbms-backup-$STAMP" "$POLICY.bak-$STAMP"
systemctl restart freeradius 2>/dev/null || systemctl restart radiusd
ok "FreeRADIUS restarted. Unknown-username logins now block the source IP for 2 days."
