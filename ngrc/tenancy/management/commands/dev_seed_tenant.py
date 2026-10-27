"""DEV ONLY (D-P6-001). There is no self-service signup anywhere in this application (confirmed: tenant
provisioning is an operator/ops action, `plt_provision_tenant`; the first account normally arrives via the
invitation-accept flow). For local UI development there is nothing to click through to get a first
account, so this command creates one directly - the same two steps `tests/conftest.py`'s `provision_tenant`/
`make_account`/`add_member` fixtures already perform for the test suite, just as a real, runnable command
instead of a pytest fixture. MFA (TOTP) is intentionally NOT pre-enrolled here - the login UI's own
enrollment screen is what should be exercised on first use. Run with NGRC_PLANE=all (same as the test
suite) - it needs both the "ops" and "owner" DB connections, which the customer/operator planes don't wire
up individually."""
import json
import secrets

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connections, transaction

from ngrc.authz import permissions as perm
from ngrc.iam import services as iam_services


class Command(BaseCommand):
    help = "DEV ONLY: create a tenant + an owner account with no MFA enrolled yet (enroll via the login UI)."

    def add_arguments(self, parser):
        parser.add_argument("--slug", default="devco")
        parser.add_argument("--email", default=None, help="defaults to owner@<slug>.example")
        parser.add_argument("--password", default="Dev-Password-1234!")

    def handle(self, *args, **o):
        if settings.NGRC_ENV != "dev":
            raise CommandError("refusing to run outside NGRC_ENV=dev")
        slug = o["slug"]
        email = o["email"] or f"owner@{slug}.example"
        system_roles = [{"key": k, "name": r["name"], "permissions": r["permissions"]}
                        for k, r in perm.SYSTEM_ROLES.items()]
        with connections["ops"].cursor() as cur:
            cur.execute("SELECT 1 FROM plt_tenant WHERE slug = %s", [slug])
            if cur.fetchone():
                raise CommandError(f"tenant '{slug}' already exists - pick a different --slug")
            cur.execute("SELECT plt_provision_tenant(%s,%s,%s,%s, now() + interval '7 days', %s::jsonb)",
                        [slug, slug.upper(), email, secrets.token_hex(32), json.dumps(system_roles)])
            tenant_id = cur.fetchone()[0]

        account = iam_services.create_account(email, o["password"], "Dev Owner", verified=True)

        with transaction.atomic(using="owner"), connections["owner"].cursor() as cur:
            cur.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_id)])
            cur.execute("SELECT id FROM ten_role WHERE key = 'owner' AND tenant_id = %s", [str(tenant_id)])
            role_id = cur.fetchone()[0]
            cur.execute(
                "INSERT INTO ten_membership (id, tenant_id, principal_id, role_id, kind, status, created_at) "
                "VALUES (gen_random_uuid(), %s, %s, %s, 'member', 'active', now())",
                [str(tenant_id), str(account.id), str(role_id)],
            )

        self.stdout.write(self.style.SUCCESS(
            f"tenant '{slug}' ({tenant_id}) + owner account {email} / {o['password']} ready - "
            "log in and enroll TOTP via the UI"
        ))
