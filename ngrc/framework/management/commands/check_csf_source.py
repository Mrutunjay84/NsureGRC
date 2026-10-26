"""Check the NIST CSF 2.0 source for changes and, if changed, build a new DRAFT version (D-P2-002).
Never publishes - a curator reviews and calls `services.publish_version` separately.

Runner-agnostic, like `audit_verify`/`audit_seal`: how this gets scheduled (cron, a CronJob, a GitHub
Actions scheduled workflow) is a deployment choice, not decided here.

  check_csf_source                              one pass against the existing "nist-csf-2.0" Framework
  check_csf_source --create-framework            also creates the Framework catalog row if missing
  check_csf_source --framework-urn <urn>         check a different Framework row's registered source
"""
from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from ngrc.framework import nist_csf
from ngrc.framework.models import Framework

DEFAULT_FRAMEWORK_URN = "nist-csf-2-0"


class Command(BaseCommand):
    help = "Check the NIST CSF 2.0 source registry for changes and draft a new version if changed."

    def add_arguments(self, parser):
        parser.add_argument("--framework-urn", default=DEFAULT_FRAMEWORK_URN)
        parser.add_argument("--create-framework", action="store_true",
                             help="create the Framework catalog row if it does not exist yet")

    def handle(self, *args, **o):
        urn = o["framework_urn"]
        framework = Framework.objects.using("catalog").filter(urn=urn).first()
        if framework is None:
            if not o["create_framework"]:
                raise CommandError(
                    f"no Framework with urn={urn!r} - pass --create-framework to create it, "
                    "or create it as a deliberate curator action first"
                )
            framework = Framework.objects.using("catalog").create(
                urn=urn, name="NIST Cybersecurity Framework", authority="National Institute of Standards and Technology"
            )
            self.stdout.write(f"created framework {urn}")
        version = nist_csf.check_csf_source(framework, created_by=None)
        if version is None:
            self.stdout.write("no change since last check")
            return
        count = version.requirements.count()
        self.stdout.write(f"drafted version {version.version_label} ({count} requirements) - NOT published")
