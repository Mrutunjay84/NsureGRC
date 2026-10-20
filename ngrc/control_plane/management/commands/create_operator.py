"""Bootstrap a platform operator (there is no self-registration). The password is read from the environment variable named
by --password-env or prompted for; it is never accepted on the command line (shell history / process list)."""
import getpass
import os

from django.core.management.base import BaseCommand, CommandError

from ngrc.authn.passwords import PolicyViolation
from ngrc.control_plane.operators import create_operator


class Command(BaseCommand):
    help = "Create a platform operator account (WebAuthn is enrolled at first sign-in)."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True)
        parser.add_argument("--name", required=True)
        parser.add_argument("--role", action="append", required=True,
                            choices=["platform_admin", "platform_security", "platform_curator", "platform_support"])
        parser.add_argument("--password-env", help="name of an environment variable holding the initial password")

    def handle(self, *args, **o):
        pw = os.environ.get(o["password_env"], "") if o["password_env"] else getpass.getpass("Initial password: ")
        try:
            op = create_operator(o["email"], o["name"], pw, o["role"])
        except (PolicyViolation, ValueError) as exc:
            raise CommandError(f"cannot create operator: {exc}") from exc
        self.stdout.write(f"created operator {op.id} with roles {', '.join(sorted(o['role']))}")
