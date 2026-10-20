"""Malware-scan interface for evidence (D-P0-007 s5, amendment A5: files are downloadable only after a CLEAN scan).

`DevEicarScanner` is a DEV-ONLY stand-in: it detects only the industry-standard EICAR *test* string and is **not** a malware scanner. No scanning
engine has been selected (open item O-11); `config.settings.prod` refuses to start with this backend. Its job in development is to exercise the
quarantine state machine end to end.
"""
from __future__ import annotations

from typing import NamedTuple

from django.conf import settings

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class ScanResult(NamedTuple):
    verdict: str   # clean | infected | error
    detail: str


class DevEicarScanner:
    dev_only = True

    def scan(self, chunks) -> ScanResult:
        tail = b""
        for c in chunks:
            window = tail + c
            if EICAR in window:
                return ScanResult("infected", "EICAR test signature")
            tail = window[-(len(EICAR) - 1):]
        return ScanResult("clean", "no signature matched (dev scanner: NOT a malware engine)")


def get_scanner():
    if getattr(settings, "EVIDENCE_SCANNER_BACKEND", "") == "dev_eicar":
        return DevEicarScanner()
    raise RuntimeError("no malware scanner is configured (open item O-11)")
