#!/usr/bin/env bash
# Record WHICH DEVICE every RADIUS login came from, so the Authentication Audit page can show
# "user X logged in on device Y".
#
# FreeRADIUS's standard radpostauth table stores only username, result and time. This script:
#   1. adds three columns to radpostauth: nasipaddress (device IP), nasidentifier (device name it sends)
#      and calledstationid (Called-Station-Id: port / AP / SSID the device reports)
#   2. changes ONLY the "post-auth" query of FreeRADIUS's SQL module so it fills those columns
#      (device IP = NAS-IP-Address, or the packet's source address when the device does not send it)
#   3. checks the FreeRADIUS configuration; if the check fails the original file is put back
#   4. restarts FreeRADIUS
#
# Safe to run more than once (it does nothing when already done). Logins recorded BEFORE this script
# ran have no device; every login after it does.
#
# Usage:   sudo bash /opt/vault/deploy/radius/enable_login_log.sh
#          (reads RADIUS_DB_* from /opt/vault/.env; set ENV_FILE=/path/.env to use another file)
set -euo pipefail

ENV_FILE="${ENV_FILE:-/opt/vault/.env}"
say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m OK\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run it with sudo:  sudo bash $0"
[ -r "$ENV_FILE" ] || die "Cannot read $ENV_FILE (set ENV_FILE=/path/to/.env)"
command -v mysql >/dev/null || die "The mysql client is not installed (apt install mariadb-client or mysql-client)"
command -v perl  >/dev/null || die "perl is required"

env_get() { grep -E "^$1=" "$ENV_FILE" | tail -n1 | cut -d= -f2- | sed -E -e 's/[[:space:]]+#.*$//' -e 's/^[[:space:]]+|[[:space:]]+$//g' -e 's/^["'\'']//' -e 's/["'\'']$//' || true; }
DB_NAME="$(env_get RADIUS_DB_NAME)"; DB_NAME="${DB_NAME:-radius}"
DB_USER="$(env_get RADIUS_DB_USER)"; DB_USER="${DB_USER:-radius}"
DB_PASS="$(env_get RADIUS_DB_PASSWORD)"
DB_HOST="$(env_get RADIUS_DB_HOST)"; DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="$(env_get RADIUS_DB_PORT)"; DB_PORT="${DB_PORT:-3306}"
[ -n "$DB_PASS" ] || die "RADIUS_DB_PASSWORD is empty in $ENV_FILE"

# password in a private temp file, never on the command line
MYCNF="$(mktemp)"; chmod 600 "$MYCNF"; trap 'rm -f "$MYCNF"' EXIT
printf '[client]\nuser=%s\npassword=%s\nhost=%s\nport=%s\n' "$DB_USER" "$DB_PASS" "$DB_HOST" "$DB_PORT" > "$MYCNF"
sql() { mysql --defaults-extra-file="$MYCNF" -N -B "$DB_NAME" -e "$1"; }

# ---- 1. database columns ----------------------------------------------------------------------
say "Checking the radpostauth table in database '$DB_NAME'"
sql "SELECT 1 FROM radpostauth LIMIT 1" >/dev/null || die "Cannot read radpostauth (wrong database or permissions?)"
has_col() { [ "$(sql "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='radpostauth' AND column_name='$1'")" = "1" ]; }
if has_col nasipaddress; then ok "column nasipaddress already exists"
else sql "ALTER TABLE radpostauth ADD COLUMN nasipaddress VARCHAR(45) NOT NULL DEFAULT ''"; ok "added column nasipaddress"; fi
if has_col nasidentifier; then ok "column nasidentifier already exists"
else sql "ALTER TABLE radpostauth ADD COLUMN nasidentifier VARCHAR(64) NOT NULL DEFAULT ''"; ok "added column nasidentifier"; fi
if has_col calledstationid; then ok "column calledstationid already exists"
else sql "ALTER TABLE radpostauth ADD COLUMN calledstationid VARCHAR(50) NOT NULL DEFAULT ''"; ok "added column calledstationid"; fi
if [ "$(sql "SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='radpostauth' AND index_name='dbms_nasip'")" = "0" ]; then
  sql "CREATE INDEX dbms_nasip ON radpostauth (nasipaddress)"; ok "added an index for searching by device"
fi

# ---- 2. FreeRADIUS post-auth query --------------------------------------------------------------
QUERIES=""
for f in /etc/freeradius/3.0/mods-config/sql/main/mysql/queries.conf \
         /etc/freeradius/mods-config/sql/main/mysql/queries.conf \
         /etc/raddb/mods-config/sql/main/mysql/queries.conf; do
  [ -f "$f" ] && { QUERIES="$f"; break; }
done
[ -n "$QUERIES" ] || die "FreeRADIUS mysql queries.conf not found"
say "FreeRADIUS query file: $QUERIES"

# Already done = the post-auth { } block writes all three device columns.
postauth_has() { perl -0ne 'exit((/^post-auth\s*\{.*?\n\}/sm &&$& =~ /\b'"$1"'\b/) ? 0 : 1)' "$QUERIES"; }
if postauth_has nasipaddress && postauth_has nasidentifier && postauth_has calledstationid; then
  ok "post-auth query already records the device"
  CHANGED=0
else
  BACKUP="$QUERIES.dbms-backup-$(date +%Y%m%d-%H%M%S)"
  cp -p "$QUERIES" "$BACKUP"; ok "backup saved: $BACKUP"
  # Replace the whole query = "..." inside the post-auth { ... } block (only there) with one that also
  # writes the device columns. Rewriting it is more reliable than inserting into the packaged text, whose
  # layout differs between FreeRADIUS versions, and it also upgrades a query patched by an older version
  # of this script (nasipaddress/nasidentifier without calledstationid). Kept from the original query:
  # the authdate format ('%S' on 3.0, '%S.%M' on 3.2) and the optional ${..class...} column.
  perl -0pi -e '
    s{(^post-auth\s*\{.*?\n\})}{
      my $b = $1;
      my $ts  = ($b =~ /\x27(%S(?:\.%M)?)\x27/) ? $1 : "%S";
      my $cls = ($b =~ /\$\{\.\.class\.column_name\}/);
      my $q = "\"\\\n"
        . "\t\tINSERT INTO \${..postauth_table} \\\n"
        . "\t\t\t(username, pass, reply, authdate, nasipaddress, nasidentifier, calledstationid"
        . ($cls ? " \${..class.column_name}" : "") . ") \\\n"
        . "\t\tVALUES ( \\\n"
        . "\t\t\t\x27%{SQL-User-Name}\x27, \\\n"
        . "\t\t\t\x27%{%{User-Password}:-%{Chap-Password}}\x27, \\\n"
        . "\t\t\t\x27%{reply:Packet-Type}\x27, \\\n"
        . "\t\t\t\x27$ts\x27, \\\n"
        . "\t\t\t\x27%{%{NAS-IP-Address}:-%{Packet-Src-IP-Address}}\x27, \\\n"
        . "\t\t\t\x27%{NAS-Identifier}\x27, \\\n"
        . "\t\t\t\x27%{Called-Station-Id}\x27"
        . ($cls ? " \\\n\t\t\t\${..class.reply_xlat})\"" : ")\"");
      $b .= "\n# DBMS_PATCH_INCOMPLETE"
        unless $b =~ s/(\n[ \t]*query\s*=\s*)"(?:[^"\\]|\\.)*"/$1$q/s;
      $b;
    }sem;
  ' "$QUERIES"
  if grep -q "DBMS_PATCH_INCOMPLETE" "$QUERIES" || ! postauth_has calledstationid; then
    cp -p "$BACKUP" "$QUERIES"
    die "This FreeRADIUS version's post-auth query has an unexpected format; nothing was changed.
       Edit $QUERIES by hand: in the post-auth query add 'nasipaddress, nasidentifier, calledstationid'
       after 'authdate' in the column list, and add
       , '%{%{NAS-IP-Address}:-%{Packet-Src-IP-Address}}', '%{NAS-Identifier}', '%{Called-Station-Id}'
       right after the authdate value ('%S' or '%S.%M')."
  fi
  ok "post-auth query now records the device IP, identifier and Called-Station-Id"
  CHANGED=1
fi

# ---- 3. check the configuration, then restart ---------------------------------------------------
RADIUSD="$(command -v freeradius || command -v radiusd || true)"
[ -n "$RADIUSD" ] || die "freeradius binary not found"
say "Checking the FreeRADIUS configuration"
if ! "$RADIUSD" -C >/tmp/dbms-radius-check.log 2>&1; then
  if [ "${CHANGED}" = "1" ]; then cp -p "$BACKUP" "$QUERIES"; fi
  die "FreeRADIUS configuration check failed (see /tmp/dbms-radius-check.log). The original file was restored."
fi
ok "configuration is valid"
if [ "${CHANGED}" = "1" ]; then
  say "Restarting FreeRADIUS"
  systemctl restart freeradius 2>/dev/null || systemctl restart radiusd
  ok "FreeRADIUS restarted"
fi
echo
ok "Done. New logins are recorded with their device. Open RADIUS / AAA -> Authentication Audit."
