"""Run the scheduled audit verification (F-AUD-007). Intended process plane: NGRC_PLANE=audit_verify (one database role: ngrc_audit_verifier).

  audit_verify                       one full run; exit code 1 if any stream has a violation
  audit_verify --mode incremental    verify only what is new since each stream's last successful run (all checkpoints and anchors still checked)
  audit_verify --check-freshness     the WATCHDOG: exit 1 (and alert) if no verification was recorded recently; run it from a SEPARATE schedule
  audit_verify --loop --interval 600 worker: incremental runs every interval, a full run every --full-every runs
"""
import time

from django.core.management.base import BaseCommand

from ngrc.audit import scheduler


class Command(BaseCommand):
    help = "Verify the audit hash chains and checkpoints (independent verifier identity)."

    def add_arguments(self, parser):
        parser.add_argument("--mode", choices=["full", "incremental"], default="full")
        parser.add_argument("--check-freshness", action="store_true")
        parser.add_argument("--loop", action="store_true")
        parser.add_argument("--interval", type=int, default=600, help="seconds between runs in --loop mode")
        parser.add_argument("--full-every", type=int, default=12, help="in --loop mode, every Nth run is a full run")

    def handle(self, *args, **o):
        if o["check_freshness"]:
            ok = scheduler.check_verification_freshness()
            self.stdout.write("verification is fresh" if ok else "VERIFICATION OVERDUE")
            raise SystemExit(0 if ok else 1)
        if not o["loop"]:
            s = scheduler.run_scheduled_verification(o["mode"])
            self.stdout.write(f"{s.mode}: {s.streams_checked} stream(s), {s.violations} with violations, completeness {s.completeness}")
            raise SystemExit(s.exit_code)
        n = 0
        while True:  # pragma: no cover - long-running worker
            mode = "full" if n % max(o["full_every"], 1) == 0 else "incremental"
            s = scheduler.run_scheduled_verification(mode)
            self.stdout.write(f"{s.mode}: {s.streams_checked} stream(s), {s.violations} with violations")
            n += 1
            time.sleep(o["interval"])
