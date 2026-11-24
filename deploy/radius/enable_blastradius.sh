#!/usr/bin/env bash
# BdREN VAULT: protect FreeRADIUS against BlastRADIUS (CVE-2024-3596).
#
# BlastRADIUS: someone on the path between a device and this server can turn a RADIUS "Reject" into an
# "Accept" by forging the MD5 that protects the packet. The fix is the Message-Authenticator attribute
# (an HMAC over the whole packet). FreeRADIUS 3.2.5 and later (and distribution packages with the fix
# back-ported) have two settings for it in radiusd.conf, section security { }:
#
#   require_message_authenticator = auto   a device that sends Message-Authenticator once must always
#                                          send it; a device that never sends it keeps working
#   limit_proxy_state = auto               same idea for the Proxy-State attribute used by the attack
#
# "auto" never locks out a device that does not send the attribute yet, so it is safe to turn on.
# FreeRADIUS with the fix also always adds Message-Authenticator to its answers, which protects every
# device that checks it.
#
# This script:
#   1. checks that this FreeRADIUS knows the settings (else: says to update it, changes nothing)
#   2. adds them to security { } in radiusd.conf (nothing to do when they are already set)
#   3. checks the configuration with "freeradius -C" and restores the old file if it is refused
#   4. restarts FreeRADIUS (not with NO_RESTART=1)
#
# Usage:  sudo bash /opt/vault/deploy/radius/enable_blastradius.sh
# Exit:   0 done or already done, 2 FreeRADIUS too old (update it), 1 error (old configuration kept)
set -uo pipefail

RAD_DIR="${RAD_DIR:-/etc/freeradius/3.0}"
CONF="$RAD_DIR/radiusd.conf"
ok()   { echo "  ok   $*"; }
fail() { echo "ERROR $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run it with sudo"
BIN="$(command -v freeradius || command -v radiusd || true)"
[ -n "$BIN" ] || fail "FreeRADIUS is not installed"
[ -f "$CONF" ] || fail "$CONF not found"
VERSION="$("$BIN" -v 2>/dev/null | grep -oE 'Version [0-9][0-9.]*' | head -n1 | cut -d' ' -f2)"

# 1. does this FreeRADIUS know the settings? Look for the name in the program and its own libraries
known=0
for f in "$BIN" $(ldd "$BIN" 2>/dev/null | awk '/freeradius|radius/ {print $3}'); do
  [ -f "$f" ] && grep -aqs "require_message_authenticator" "$f" && { known=1; break; }
done
if [ "$known" != 1 ]; then
  echo "FreeRADIUS ${VERSION:-?} has no BlastRADIUS protection (needs 3.2.5 or newer, or an updated package)." >&2
  echo "Update it, then run this script again:  sudo apt update && sudo apt install --only-upgrade freeradius" >&2
  exit 2
fi

# 2. already set (not commented out) inside the file?
if grep -Eq '^[[:space:]]*require_message_authenticator[[:space:]]*=' "$CONF" \
   && grep -Eq '^[[:space:]]*limit_proxy_state[[:space:]]*=' "$CONF"; then
  ok "BlastRADIUS protection already set in $CONF (FreeRADIUS ${VERSION:-?})"
  exit 0
fi
grep -Eq '^[[:space:]]*security[[:space:]]*\{' "$CONF" || fail "no security { } section in $CONF"

BACKUP="$CONF.vault-$(date +%Y%m%d%H%M%S)"
cp -p "$CONF" "$BACKUP" || fail "could not back up $CONF"
TMP="$(mktemp)"
awk -v need_req="$(grep -Eq '^[[:space:]]*require_message_authenticator[[:space:]]*=' "$CONF" && echo 0 || echo 1)" \
    -v need_lim="$(grep -Eq '^[[:space:]]*limit_proxy_state[[:space:]]*=' "$CONF" && echo 0 || echo 1)" '
  { print }
  !done && /^[ \t]*security[ \t]*\{/ {
    print "\t# BdREN VAULT: BlastRADIUS (CVE-2024-3596), see deploy/radius/enable_blastradius.sh"
    if (need_req) print "\trequire_message_authenticator = auto"
    if (need_lim) print "\tlimit_proxy_state = auto"
    done = 1
  }' "$CONF" > "$TMP" && cat "$TMP" > "$CONF"
rm -f "$TMP"

# 3. does FreeRADIUS accept it?
if ! "$BIN" -C >/dev/null 2>&1; then
  cp -p "$BACKUP" "$CONF"
  fail "FreeRADIUS refused the new settings (check: sudo freeradius -XC); $CONF was restored"
fi
ok "BlastRADIUS protection added to $CONF (backup: $BACKUP)"

# 4. restart
if [ "${NO_RESTART:-0}" != 1 ]; then
  if systemctl restart freeradius; then ok "FreeRADIUS restarted"
  else cp -p "$BACKUP" "$CONF"; systemctl restart freeradius || true; fail "FreeRADIUS did not start; $CONF was restored"; fi
fi
exit 0
