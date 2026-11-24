"""Store the RADIUS passwords that are still in clear text as salted SHA-256, keeping the same passwords.

    sudo -u vault /opt/vault/.venv/bin/python /opt/vault/manage.py radius_hash_passwords --user test1
    sudo -u vault /opt/vault/.venv/bin/python /opt/vault/manage.py radius_hash_passwords

Test one user on every kind of device first (--user): after this FreeRADIUS checks these users with PAP only.
"""
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.radius.services import cleartext_users, hash_cleartext_passwords


class Command(BaseCommand):
    help = "Store clear-text RADIUS passwords as salted SHA-256 (same passwords; cannot be undone)"

    def add_arguments(self, parser):
        parser.add_argument("--user", action="append", default=[], help="only this user (repeat for more)")
        parser.add_argument("--yes", action="store_true", help="do not ask before changing")

    def handle(self, *args, **opts):
        users = opts["user"]
        if not users and settings.RADIUS_PASSWORD_MODE != "ssha2":
            raise CommandError("Set RADIUS_PASSWORD_MODE=ssha2 in .env and restart VAULT first "
                               "(sudo systemctl restart vault), or new passwords would be stored in clear text again. "
                               "To test one user before that, use --user NAME.")
        todo = cleartext_users(users)
        if not todo:
            self.stdout.write(self.style.SUCCESS("Nothing to do: no password is stored in clear text."))
            return
        self.stdout.write(f"{len(todo)} user(s) with a clear-text password: {', '.join(todo[:20])}"
                          + (f" and {len(todo) - 20} more" if len(todo) > 20 else ""))
        self.stdout.write("They keep the same password. This cannot be undone, and these users can then log in "
                          "with PAP only (SSH / Telnet logins on Cisco, Huawei, Juniper, FortiGate use PAP).")
        if not opts["yes"] and input("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
            raise CommandError("Stopped, nothing changed.")
        done = hash_cleartext_passwords(todo)
        self.stdout.write(self.style.SUCCESS(f"Done: {len(done)} password(s) now stored as salted SHA-256."))
