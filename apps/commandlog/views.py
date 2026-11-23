"""Command History API (administrators only). The page is templates/radius/commands.html.

    /api/radius/commands              GET  ?hours=24|168|720 &q= &kind=  events + totals + receiver state
    /api/radius/commands?format=csv   GET  the same filter as a CSV file (up to 50,000 rows)
    /api/radius/commands/sessions     GET  ?hours= &q= &user=   sessions (login to logout); with user= each
                                           session also carries its commands
"""
import csv

from django.http import HttpResponse, JsonResponse
from django.utils import timezone

from apps.core.api import api
from apps.core.utils import DT_FORMAT

from . import selectors as q

CSV_LIMIT = 50000


def _when(value):
    if not value:
        return ""
    if timezone.is_aware(value):
        value = timezone.localtime(value)
    return value.strftime(DT_FORMAT)


def _hours(request):
    try:
        return int(request.GET.get("hours", 24))
    except ValueError:
        return 24


@api(GET="admin")
def commands(request):
    search, kind = request.GET.get("q", ""), request.GET.get("kind", "")
    if request.GET.get("format") == "csv":
        return _csv(q.history(_hours(request), search, kind, limit=CSV_LIMIT))
    data = q.history(_hours(request), search, kind)
    for e in data["events"]:
        e["ts"] = _when(e["ts"])
    status = q.receiver_status()
    status["heartbeat"] = _when(status.get("heartbeat"))
    sources = q.sources()
    for s in sources:
        s["first_seen"], s["last_seen"] = _when(s["first_seen"]), _when(s["last_seen"])
    return JsonResponse({**data, "receiver": status, "sources": sources})


@api(GET="admin")
def sessions(request):
    user = request.GET.get("user", "").strip()[:64]
    data = q.sessions(_hours(request), request.GET.get("q", ""), user, with_events=bool(user))
    for s in data["sessions"]:
        for key in ("start", "end", "last"):
            s[key] = _when(s[key])
        for e in s["events"]:
            e["ts"] = _when(e["ts"])
    return JsonResponse({**data, "user": user})


def _csv(data):
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    stamp = timezone.localtime().strftime("%Y%m%d-%H%M")
    response["Content-Disposition"] = f'attachment; filename="command-history-{stamp}.csv"'
    response["Cache-Control"] = "no-store, private"
    response.write("﻿")                       # so Excel reads the file as UTF-8
    out = csv.writer(response)
    out.writerow(["Time", "User", "Device", "Device IP", "From", "Type", "Command", "Result"])
    for e in data["events"]:
        out.writerow([_when(e["ts"]), _safe(e["username"]), _safe(e["device"]), e["device_ip"], e["source_ip"],
                      e["kind"], _safe(e["command"]), _safe(e["result"])])
    return response


def _safe(value):
    """A cell that starts with = + - @ is run as a formula by spreadsheet programs: keep it text."""
    value = value or ""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value
