"""Reads for Command History (/radius/commands)."""
import ipaddress
import logging
from datetime import timedelta

from django.db import Error as DatabaseError
from django.db.models import Count, Q
from django.utils import timezone

from apps.devices import selectors as devices
from apps.radius import selectors as radius

from .models import CommandEvent, ReceiverState, SyslogSource

logger = logging.getLogger("dbms")
WINDOWS = (24, 24 * 7, 24 * 30, 24 * 90, 24 * 365)   # hours the page can cover (= apps.core.period.PRESETS)
KINDS = ("command", "change", "login", "logout", "login-failed")
HEARTBEAT_SECONDS = 30                   # the receiver writes its heartbeat this often
REJECTED_FOR = timedelta(hours=24)       # refused messages are reported this long after the newest one


def allowed_sources():
    """Who may send syslog: ({ip: vendor}, [(network, vendor)]) from NAS Clients - the same addresses the
    firewall opens UDP 514 for (deploy/radius/vault-radius-firewall). Messages from any other address are
    dropped by the receiver."""
    exact, networks = {}, []
    try:
        for address, vendor in radius.nas_addresses():
            try:
                net = ipaddress.ip_network(address, strict=False)
            except ValueError:
                continue
            if net.num_addresses == 1:
                exact[str(net.network_address)] = vendor
            elif net.prefixlen:
                networks.append((net, vendor))
    except DatabaseError:
        logger.warning("Syslog receiver: the RADIUS database (NAS Clients) cannot be read")
        raise
    return exact, networks


def receiver_status(now=None):
    """{"running": bool, "port", "heartbeat", "rejected", "rejected_last_ip", "dropped"} or running False."""
    row = ReceiverState.objects.filter(pk=1).first()
    if not row:
        return {"running": False, "seen": False, "port": None, "rejected": 0, "rejected_last_ip": "", "dropped": 0}
    now = now or timezone.now()
    alive = bool(row.heartbeat and now - row.heartbeat < timedelta(seconds=HEARTBEAT_SECONDS * 3))
    rejected = row.rejected
    # the note "messages were ignored" is only for a recent problem: not after a quiet day, and not once the
    # sender has been added to NAS Clients (its later messages are accepted)
    if not row.rejected_at or now - row.rejected_at > REJECTED_FOR or _is_allowed(row.rejected_last_ip):
        rejected = 0
    return {"running": alive, "seen": True, "port": row.port, "heartbeat": row.heartbeat,
            "rejected": rejected, "rejected_last_ip": row.rejected_last_ip if rejected else "",
            "rejected_at": row.rejected_at if rejected else None, "dropped": row.dropped}


def _is_allowed(ip):
    """True when `ip` is now on NAS Clients (as an address or inside a network)."""
    if not ip:
        return False
    try:
        exact, networks = allowed_sources()
        addr = ipaddress.ip_address(ip)
    except (DatabaseError, ValueError):
        return False
    return ip in exact or any(addr.version == net.version and addr in net for net, _ in networks)


def _period(hours):
    return hours if hours in WINDOWS else 24


def _between(since, until):
    rows = CommandEvent.objects.filter(received_at__gte=since)
    return rows.filter(received_at__lt=until) if until is not None else rows


def history(hours=24, q="", kind="", limit=500, since=None, until=None):
    """Events of the last `hours` - or from `since` to `until` (aware datetimes) - newest first, at most `limit`,
    matching the search, plus the period's totals.
    q matches a user, a device address or name, the user's address or the command text."""
    hours = _period(hours)
    since = since or timezone.now() - timedelta(hours=hours)
    name_of = _namer()
    period = _between(since, until)
    totals = period.aggregate(total=Count("id"), changes=Count("id", filter=Q(kind="change")),
                              commands=Count("id", filter=Q(kind="command")),
                              logins=Count("id", filter=Q(kind="login")),
                              failed=Count("id", filter=Q(kind="login-failed")),
                              users=Count("username", distinct=True), devices=Count("device_ip", distinct=True))
    rows = period
    if kind in KINDS:
        rows = rows.filter(kind=kind)
    q = (q or "").strip()[:100]
    if q:
        match = (Q(username__icontains=q) | Q(device_ip__icontains=q) | Q(source_ip__icontains=q) |
                 Q(command__icontains=q))
        named = [ip for ip in period.values_list("device_ip", flat=True).distinct()[:5000]
                 if q.lower() in name_of(ip).lower()]
        if named:
            match |= Q(device_ip__in=named)
        rows = rows.filter(match)
    events = [{"id": e.id, "ts": e.received_at, "device_ip": e.device_ip, "device": name_of(e.device_ip),
               "username": e.username, "source_ip": "" if set(e.source_ip) <= {"*", " "} else e.source_ip, "kind": e.kind, "command": e.command,
               "result": e.result, "vendor": e.vendor} for e in rows[:limit]]
    top_users = list(period.filter(kind="change").values("username").annotate(n=Count("id")).order_by("-n")[:5])
    return {"hours": hours, "totals": totals, "events": events, "limit": limit, "top_changers": top_users}


# ---- sessions: one user's stay on one device, from login to logout ---------------------------------------------
SESSION_GAP = timedelta(minutes=30)      # this long without activity (and no logout) = the next action is a new session
SAME_MOMENT = timedelta(seconds=15)      # two login (or logout) messages this close are the same login (or logout)
OPEN_FOR = timedelta(minutes=15)         # no logout and active this recently = shown as "Active"
MAX_EVENTS = 20000                       # newest events read per request
LOOK_BACK = timedelta(hours=24)          # a session still going at the start of the period: its login is looked
                                         # for this far back, so it shows when it began (not "Before period")


def _session(username, device_ip, start, login):
    return {"username": username, "device_ip": device_ip, "start": start, "login_seen": login, "end": None,
            "last": start, "source_ip": "", "events": [], "changes": 0, "commands": 0, "failed": False,
            "closed": False}


def _build(items):
    """items of ONE user on ONE device, oldest first -> sessions. See SESSION_GAP / SAME_MOMENT."""
    out, cur = [], None
    for e in items:
        t, kind = e["ts"], e["kind"]
        if kind == "login-failed":
            continue                    # refused logins are not sessions (they are on Authentication Audit)
        if kind == "login":
            if cur and not cur["closed"] and not cur["events"] and t - cur["last"] <= SESSION_GAP:
                cur["last"] = t                       # the same login reported twice (RADIUS + syslog, repeats)
                cur["login_seen"] = True
                cur["source_ip"] = cur["source_ip"] or e["source_ip"]
                continue
            cur = _session(e["username"], e["device_ip"], t, True)
            cur["source_ip"] = e["source_ip"]
            out.append(cur)
            continue
        if kind == "logout":
            if e.get("radius"):     # RADIUS accounting Stop: ends the user's open session on this device
                if cur and not cur["closed"]:
                    cur.update(end=t, last=t, closed=True)
                continue            # none open: already closed by the syslog logout, or began before the period
            if cur and cur["closed"] and cur["end"] and t - cur["end"] <= SAME_MOMENT:
                cur["source_ip"] = cur["source_ip"] or e["source_ip"]     # the same logout reported twice
                continue
            if not cur or cur["closed"] or t - cur["last"] > SESSION_GAP:
                cur = _session(e["username"], e["device_ip"], None, False)   # began before the period / not seen
                out.append(cur)
            cur.update(end=t, last=t, closed=True)
            cur["source_ip"] = cur["source_ip"] or e["source_ip"]
            continue
        if not cur or cur["closed"] or t - cur["last"] > SESSION_GAP:
            cur = _session(e["username"], e["device_ip"], t, False)
            out.append(cur)
        cur["events"].append(e)
        cur["last"] = t
        cur["changes" if kind == "change" else "commands"] += 1
        cur["source_ip"] = cur["source_ip"] or e["source_ip"]
    return out


def sessions(hours=24, q="", user="", device="", with_events=False, limit=500, since=None, until=None):
    """Sessions of the last `hours`, newest activity first: who was on which device, from where, from when to
    when, and what they did. Built from the syslog events plus the RADIUS logins (Access-Accept) of the devices
    that send syslog, so a session has its start time even when the device does not log logins.
    q matches user, device address or name, the user's address or a command; user = exactly one user,
    device = exactly one device address."""
    hours = _period(hours)
    now = timezone.now()
    since = since or now - timedelta(hours=hours)
    read_from = since - LOOK_BACK
    rows = _between(read_from, until)
    if user:
        rows = rows.filter(username=user)
    if device:
        rows = rows.filter(device_ip=device)
    events = [{"id": r["id"], "ts": r["received_at"], "username": r["username"], "device_ip": r["device_ip"],
               "kind": r["kind"], "command": r["command"], "result": r["result"],
               "source_ip": "" if set(r["source_ip"]) <= {"*", " "} else r["source_ip"]}
              for r in rows.order_by("-received_at", "-id").values(
                  "id", "received_at", "username", "device_ip", "kind", "command", "source_ip", "result")[:MAX_EVENTS]]
    events.reverse()
    logging_devices = set(SyslogSource.objects.values_list("ip", flat=True))
    if device:
        logging_devices &= {device}
    try:
        for username, ip, t in radius.accepted_logins(read_from, logging_devices, user, until=until):
            events.append({"id": 0, "ts": t, "username": username, "device_ip": ip, "kind": "login",
                           "command": "", "source_ip": "", "result": "", "radius": True})
    except DatabaseError:
        logger.warning("Command History: RADIUS logins could not be read; sessions start at the first command")
    try:   # logouts from RADIUS accounting (Stop), for devices whose syslog logout message does not arrive
        for username, ip, t in radius.accounting_stops(read_from, logging_devices, user, until=until):
            events.append({"id": 0, "ts": t, "username": username, "device_ip": ip, "kind": "logout",
                           "command": "", "source_ip": "", "result": "", "radius": True})
    except DatabaseError:
        logger.debug("Command History: no RADIUS accounting (radacct) to read logouts from")
    events.sort(key=lambda e: (e["ts"], e["id"]))
    groups = {}
    for e in events:
        groups.setdefault((e["username"], e["device_ip"]), []).append(e)
    found = [s for items in groups.values() for s in _build(items)]
    name_of = _namer()
    q = (q or "").strip().lower()[:100]
    out = []
    for s in found:
        if (s["end"] or s["last"]) < since:
            continue                    # over before the period began (read only to find logins)
        s["device"] = name_of(s["device_ip"])
        if q and not (q in s["username"].lower() or q in s["device_ip"] or q in s["device"].lower()
                      or q in s["source_ip"] or any(q in e["command"].lower() for e in s["events"])):
            continue
        last = s["end"] or s["last"]
        if s["closed"]:
            s["status"] = "closed"
        else:
            s["status"] = "active" if now - last <= OPEN_FOR else "no-logout"
        s["duration"] = int((last - s["start"]).total_seconds()) if s["start"] and last else None
        s["key"] = f'{s["username"]}|{s["device_ip"]}|{(s["start"] or last).isoformat()}'
        out.append(s)
    # sessions still open ("Active") first, then newest login first (a session whose login was not seen
    # counts from its first action)
    out.sort(key=lambda s: (s["status"] == "active", s["start"] or s["last"]), reverse=True)
    totals = {"sessions": len(out),
              "users": len({s["username"] for s in out}), "devices": len({s["device_ip"] for s in out}),
              "changes": sum(s["changes"] for s in out), "commands": sum(s["commands"] for s in out),
              "active": sum(1 for s in out if s["status"] == "active")}
    out = out[:limit]
    for s in out:
        s["event_count"] = len(s["events"])
        if not with_events:
            s["events"] = []
        s.pop("closed", None)
    return {"hours": hours, "sessions": out, "totals": totals, "truncated": len(events) >= MAX_EVENTS}


def sources():
    """Devices that send syslog, newest first, with how many of their messages were user actions."""
    name_of = _namer()
    return [{"ip": s.ip, "device": name_of(s.ip), "first_seen": s.first_seen, "last_seen": s.last_seen,
             "received": s.received, "recognized": s.recognized, "sample": s.last_unrecognized}
            for s in SyslogSource.objects.order_by("-last_seen")[:500]]


def _namer():
    """ip -> device name: NAS Clients / Device Inventory first, else the host name the device sends in syslog."""
    hostnames = {ip: h for ip, h in SyslogSource.objects.exclude(hostname="").values_list("ip", "hostname")[:5000]}
    try:
        return radius.device_namer(hostnames)
    except DatabaseError:
        names = {**hostnames, **devices.names_by_ip()}
        return lambda ip: names.get(ip, "")
