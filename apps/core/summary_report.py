"""Summary report: what changed, what failed, and who logged in over the last 7 or 30 days - built as a
PDF on request (Change Reports > "Weekly summary" / "Monthly summary"). Nothing is scheduled or emailed;
it is generated fresh each time someone downloads it."""
import io

from django.utils import timezone

PERIODS = {"weekly": 7, "monthly": 30}   # label -> days back from now


def build_summary(period):
    """Everything the report shows, gathered fresh for the chosen period ("weekly" = last 7 days,
    "monthly" = last 30 days, both ending now)."""
    from apps.backups import selectors as backups
    from apps.devices import selectors as devices
    from apps.radius.selectors import login_summary, recent_logins

    days = PERIODS.get(period, 7)
    end = timezone.localtime()
    start = end - timezone.timedelta(days=days)
    changes = backups.change_report_for(start, end)
    backup_counts = backups.backup_counts_between(start, end)
    logins = login_summary(since=start, until=end)
    login_rows, _ = recent_logins(since=start, until=end, limit=2000)
    accepted_users = sorted({r["username"] for r in login_rows if r["reply"] == "Access-Accept" and r["username"]})
    top_changed = sorted((r for r in changes["devices"] if r["changes"]), key=lambda r: -r["changes"])[:10]
    return {
        "period": period, "days": days, "start": start, "end": end,
        "devices_total": devices.device_count(),
        "devices_changed": changes["summary"]["changed"],
        "devices_unchanged": changes["summary"]["unchanged"],
        "config_changes": changes["summary"]["changes"],
        "lines_added": changes["summary"]["added"],
        "lines_removed": changes["summary"]["removed"],
        "top_changed": top_changed,
        "backups_saved": backup_counts.get("SUCCESS", 0),
        "backups_unchanged": backup_counts.get("UNCHANGED", 0),
        "backups_failed": backup_counts.get("FAILED", 0),
        "logins_total": logins["total"], "logins_accepted": logins["accepted"],
        "logins_rejected": logins["rejected"], "login_users": accepted_users,
    }


def build_pdf(period):
    """(bytes, filename): a short, plain PDF (reportlab, no system package needed) with the summary."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    s = build_summary(period)
    title = "Weekly" if s["period"] == "weekly" else "Monthly"
    styles = getSampleStyleSheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=f"VAULT {title.lower()} summary",
                            topMargin=18 * mm, bottomMargin=18 * mm, leftMargin=18 * mm, rightMargin=18 * mm)
    story = [Paragraph(f"VAULT &ndash; {title} Summary", styles["Title"]),
             Paragraph(f"{s['start'].strftime('%d %b %Y')} &ndash; {s['end'].strftime('%d %b %Y')}"
                       f" ({s['days']} days)", styles["Normal"]),
             Spacer(1, 10 * mm)]

    def table(rows):
        t = Table(rows, colWidths=[85 * mm, 70 * mm])
        t.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 10),
                               ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#4b5a6d")),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 5),
                               ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#e2e8f0"))]))
        return t

    story += [Paragraph("Devices", styles["Heading2"]),
              table([["Devices with at least one backup", f"{s['devices_total']:,}"],
                     ["Devices that changed in this period", f"{s['devices_changed']:,}"],
                     ["Devices unchanged in this period", f"{s['devices_unchanged']:,}"]]),
              Spacer(1, 6 * mm),
              Paragraph("Configuration changes", styles["Heading2"]),
              table([["Configuration changes saved", f"{s['config_changes']:,}"],
                     ["Lines added", f"+{s['lines_added']:,}"],
                     ["Lines removed", f"-{s['lines_removed']:,}"]]),
              Spacer(1, 6 * mm),
              Paragraph("Backup jobs", styles["Heading2"]),
              table([["Saved (configuration changed)", f"{s['backups_saved']:,}"],
                     ["Unchanged", f"{s['backups_unchanged']:,}"],
                     ["Failed", f"{s['backups_failed']:,}"]]),
              Spacer(1, 6 * mm),
              Paragraph("RADIUS logins", styles["Heading2"]),
              table([["Login attempts", f"{s['logins_total']:,}"],
                     ["Accepted", f"{s['logins_accepted']:,}"],
                     ["Rejected", f"{s['logins_rejected']:,}"],
                     ["Different users who logged in", f"{len(s['login_users']):,}"]])]

    if s["top_changed"]:
        story += [Spacer(1, 6 * mm), Paragraph("Most-changed devices", styles["Heading2"]),
                  table([["Device", "Changes"]] + [[r["device"], str(r["changes"])] for r in s["top_changed"]])]
    if s["login_users"]:
        story += [Spacer(1, 6 * mm), Paragraph("Users who logged in", styles["Heading2"]),
                  Paragraph(", ".join(s["login_users"][:100]) + (" ..." if len(s["login_users"]) > 100 else ""),
                            styles["Normal"])]

    doc.build(story)
    filename = f"vault-{s['period']}-summary-{s['end'].strftime('%Y%m%d')}.pdf"
    return buf.getvalue(), filename
