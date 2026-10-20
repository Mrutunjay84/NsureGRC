"""Issue chained, signed audit checkpoints (heartbeat included). Intended process plane: NGRC_PLANE=audit_seal (one database role: ngrc_audit_sealer).

  audit_seal                 one pass
  audit_seal --loop          worker: one pass every AUDIT_CHECKPOINT_INTERVAL_S (the heartbeat that makes a missing newest checkpoint visible)
"""
import time

from django.conf import settings
from django.core.management.base import BaseCommand

from ngrc.audit import sealer


class Command(BaseCommand):
    help = "Seal audit streams into signed, chained checkpoints."

    def add_arguments(self, parser):
        parser.add_argument("--loop", action="store_true")

    def handle(self, *args, **o):
        while True:
            sealed = sealer.seal_all()
            self.stdout.write(f"sealed {len(sealed)} checkpoint(s)")
            if not o["loop"]:
                return
            time.sleep(settings.AUDIT_CHECKPOINT_INTERVAL_S)  # pragma: no cover
