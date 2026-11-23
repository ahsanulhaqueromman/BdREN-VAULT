"""Writes for Command History: what the syslog receiver hands over, and the daily clean-up."""
import logging
from datetime import timedelta

from django.db import transaction
from django.db.models import F
from django.utils import timezone

from apps.scheduling.services import get_setting

from .models import CommandEvent, ReceiverState, SyslogSource

logger = logging.getLogger("dbms")


def record(events, stats, now=None):
    """Save one batch from the receiver.
    events: [{"device_ip", "username", "kind", ...}]   stats: {ip: {"received": n, "recognized": n, "sample": str}}"""
    now = now or timezone.now()
    with transaction.atomic():
        if events:
            CommandEvent.objects.bulk_create([CommandEvent(received_at=e.get("at", now), device_ip=e["device_ip"],
                                                           username=e["username"], source_ip=e["source_ip"],
                                                           kind=e["kind"], command=e["command"],
                                                           result=e["result"], vendor=e["vendor"])
                                              for e in events], batch_size=500)
        for ip, s in stats.items():
            source, _ = SyslogSource.objects.get_or_create(ip=ip, defaults={"first_seen": now, "last_seen": now})
            changes = {"last_seen": now, "received": F("received") + s["received"],
                       "recognized": F("recognized") + s["recognized"]}
            if s.get("sample"):
                changes["last_unrecognized"] = s["sample"][:500]
            SyslogSource.objects.filter(pk=source.pk).update(**changes)


def heartbeat(port, rejected=0, rejected_ip="", dropped=0, started=False, now=None):
    """The receiver is alive; add the messages it refused since the last heartbeat."""
    now = now or timezone.now()
    row, _ = ReceiverState.objects.get_or_create(pk=1)
    changes = {"heartbeat": now, "port": port, "rejected": F("rejected") + rejected, "dropped": F("dropped") + dropped}
    if started:
        changes["started_at"] = now
    if rejected_ip:
        changes["rejected_last_ip"] = rejected_ip[:45]
    ReceiverState.objects.filter(pk=1).update(**changes)


def prune_old_events(now=None):
    """Delete command history older than Settings > "Keep logs and backup files for" (Forever = keep all).
    Runs once a day from the background threads. Returns the number of rows removed."""
    try:
        months = int(get_setting("log_retention_months") or 0)
    except ValueError:
        return 0
    if months <= 0:
        return 0
    cutoff = (now or timezone.now()) - timedelta(days=30 * months)
    removed = 0
    while True:                       # in slices, so a large table never locks for long
        ids = list(CommandEvent.objects.filter(received_at__lt=cutoff).values_list("id", flat=True)[:5000])
        if not ids:
            break
        removed += CommandEvent.objects.filter(id__in=ids).delete()[0]
    if removed:
        logger.info("Removed %s command history entries older than %s months", removed, months)
    return removed
