"""Production settings validation (D-P0-002: "verify security-critical defaults, don't assume them").

`validate_settings` is a pure function so it can be unit-tested with deliberately insecure inputs.
It returns a list of violations; production startup raises if the list is non-empty.
"""
from __future__ import annotations

from collections.abc import Mapping

# OWASP Password Storage Cheat Sheet minimum Argon2id configurations: (memory KiB, iterations, parallelism)
ARGON2_OWASP_FLOORS = [(47104, 1, 1), (19456, 2, 1), (12288, 3, 1), (9216, 4, 1), (7168, 5, 1)]


def argon2_meets_floor(memory_kib: int, time_cost: int, parallelism: int) -> bool:
    """True if the parameters are at least as strong as one OWASP-listed equivalent configuration."""
    return parallelism >= 1 and any(memory_kib >= m and time_cost >= t for (m, t, _p) in ARGON2_OWASP_FLOORS)


def validate_settings(cfg: Mapping) -> list[str]:
    v: list[str] = []
    if cfg.get("NGRC_ENV") != "prod":
        v.append("NGRC_ENV must be 'prod'")
    if cfg.get("DEBUG"):
        v.append("DEBUG must be False")
    if cfg.get("NGRC_PLANE") not in {"customer", "operator", "migrate"}:
        v.append("NGRC_PLANE must be customer, operator or migrate (not 'all')")
    hosts = cfg.get("ALLOWED_HOSTS") or []
    if not hosts or "*" in hosts:
        v.append("ALLOWED_HOSTS must be an explicit non-empty list without '*'")
    secret = cfg.get("SECRET_KEY") or ""
    if len(secret) < 50:
        v.append("SECRET_KEY too short")
    for flag in ("SECURE_SSL_REDIRECT", "CSRF_COOKIE_SECURE", "SESSION_COOKIE_SECURE", "CSRF_COOKIE_HTTPONLY",
                 "SECURE_CONTENT_TYPE_NOSNIFF"):
        if cfg.get(flag) is not True:
            v.append(f"{flag} must be True")
    if (cfg.get("SECURE_HSTS_SECONDS") or 0) < 31536000:
        v.append("SECURE_HSTS_SECONDS must be at least one year")
    if cfg.get("X_FRAME_OPTIONS") != "DENY":
        v.append("X_FRAME_OPTIONS must be DENY")
    if cfg.get("USE_X_FORWARDED_HOST"):
        v.append("USE_X_FORWARDED_HOST must be False")
    if not str(cfg.get("CSRF_COOKIE_NAME", "")).startswith("__Host-"):
        v.append("CSRF cookie must use the __Host- prefix")
    origins = cfg.get("CSRF_TRUSTED_ORIGINS") or []
    if not origins or any(not o.startswith("https://") for o in origins):
        v.append("CSRF_TRUSTED_ORIGINS must be explicit https origins")
    wa = cfg.get("WEBAUTHN_ALLOWED_ORIGINS") or []
    if not wa or any(not o.startswith("https://") for o in wa):
        v.append("WEBAUTHN_ALLOWED_ORIGINS must be explicit https origins")
    if not str(cfg.get("PUBLIC_BASE_URL", "")).startswith("https://"):
        v.append("PUBLIC_BASE_URL must be https")
    ph = cfg.get("PASSWORD_HASHING") or {}
    if not argon2_meets_floor(ph.get("memory_cost_kib", 0), ph.get("time_cost", 0), ph.get("parallelism", 0)):
        v.append("Argon2id parameters below OWASP minimum floor")
    for alias, db in (cfg.get("DATABASES") or {}).items():
        if (db.get("OPTIONS") or {}).get("sslmode") not in {"verify-full", "verify-ca"}:
            v.append(f"database '{alias}' must use sslmode verify-full/verify-ca")
        if db.get("USER") in {"postgres"}:
            v.append(f"database '{alias}' must not use a superuser role")
        if not db.get("PASSWORD"):
            v.append(f"database '{alias}' has no password")
    if cfg.get("AUDIT_SIGNER_BACKEND") == "dev_file":
        v.append("AUDIT_SIGNER_BACKEND 'dev_file' is DEV-ONLY (production KMS signer is open item O-4)")
    if cfg.get("KEY_PROVIDER") == "local":
        v.append("KEY_PROVIDER 'local' is DEV-ONLY (production KMS is open item O-4)")
    if "django.contrib.admin" in (cfg.get("INSTALLED_APPS") or []):
        v.append("django.contrib.admin must not be installed")
    return v
