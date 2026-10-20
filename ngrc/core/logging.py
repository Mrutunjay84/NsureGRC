"""Redacting log filter and JSON formatter (D-P0-007 s2: Restricted data never appears in logs)."""
from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

_SENSITIVE_KEYS = r"(password|passwd|secret|token|authorization|cookie|api[_-]?key|otp|code|signature|set-cookie|csrf)"
_KV = re.compile(rf"(?i)({_SENSITIVE_KEYS}[\"']?\s*[:=]\s*[\"']?)([^\s\"',;&}}]+)")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9_-]{40,}\b")
REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _KV.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    return _LONG_TOKEN.sub(REDACTED, text)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(record.getMessage())
            record.args = ()
            if record.exc_info and record.exc_info[1] is not None:
                # keep the exception type, drop its message (may embed SQL/values)
                record.exc_text = f"{record.exc_info[0].__name__}: {REDACTED}"
                record.exc_info = None
        except Exception:  # never let logging break a request
            record.msg = REDACTED
            record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_text:
            payload["exc"] = record.exc_text
        return json.dumps(payload, separators=(",", ":"))
