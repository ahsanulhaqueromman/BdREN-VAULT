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
WINDOWS = (24, 24 * 7, 24 * 30)          # hours the page can cover
KINDS = ("command", "change", "login", "logout", "login-failed")
HEARTBEAT_SECONDS = 30                   # the receiver writes its heartbeat this often


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
    return {"running": alive, "seen": True, "port": row.port, "heartbeat": row.heartbeat,
            "rejected": row.rejected, "rejected_last_ip": row.rejected_last_ip, "dropped": row.dropped}


def _period(hours):
    return hours if hours in WINDOWS else 24


def history(hours=24, q="", kind="", limit=500):
    """Events of the last `hours` (newest first, at most `limit`) matching the search, plus the period's totals.
    q matches a user, a device address or name, the user's address or the command text."""
    hours = _period(hours)
    since = timezone.now() - timedelta(hours=hours)
    name_of = _namer()
    period = CommandEvent.objects.filter(received_at__gte=since)
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
               "username": e.username, "source_ip": e.source_ip, "kind": e.kind, "command": e.command,
               "result": e.result, "vendor": e.vendor} for e in rows[:limit]]
    top_users = list(period.filter(kind="change").values("username").annotate(n=Count("id")).order_by("-n")[:5])
    return {"hours": hours, "totals": totals, "events": events, "limit": limit, "top_changers": top_users}


def sources():
    """Devices that send syslog, newest first, with how many of their messages were user actions."""
    name_of = _namer()
    return [{"ip": s.ip, "device": name_of(s.ip), "first_seen": s.first_seen, "last_seen": s.last_seen,
             "received": s.received, "recognized": s.recognized, "sample": s.last_unrecognized}
            for s in SyslogSource.objects.order_by("-last_seen")[:500]]


def _namer():
    try:
        return radius.device_namer()
    except DatabaseError:
        names = devices.names_by_ip()
        return lambda ip: names.get(ip, "")
