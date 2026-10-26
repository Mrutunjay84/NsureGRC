"""NsureGRC base settings: secure by default (D-P0-002, D-P0-008).

Rules:
* No secret has a default value. Missing required secrets raise ImproperlyConfigured.
* Production-grade flags are the DEFAULT here; dev/test relax only what they must, explicitly.
* One Django project, "planes" selected by NGRC_PLANE (customer | operator | migrate | audit_verify | audit_seal | all[test only]).
  A process only receives the DB credentials of the roles its plane needs (D-P0-009 s3).
"""
from __future__ import annotations

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def env(name: str, default: str | None = None, *, required: bool = False) -> str | None:
    value = os.environ.get(name, default)
    if required and not value:
        raise ImproperlyConfigured(f"Required environment variable {name} is not set")
    return value


def env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


NGRC_ENV = env("NGRC_ENV", "prod")  # prod | dev | test  (unknown => treated as prod by validators)
NGRC_PLANE = env("NGRC_PLANE", "customer")  # customer | operator | migrate | audit_verify | audit_seal | all
if NGRC_PLANE not in {"customer", "operator", "migrate", "audit_verify", "audit_seal", "all"}:
    raise ImproperlyConfigured("NGRC_PLANE must be customer, operator, migrate, audit_verify, audit_seal or all")

DEBUG = False  # never read from the environment in base; dev may opt in explicitly in dev.py
SECRET_KEY = env("NGRC_SECRET_KEY", required=True)
if len(SECRET_KEY) < 50:
    raise ImproperlyConfigured("NGRC_SECRET_KEY must be at least 50 characters of random data")

ALLOWED_HOSTS = [h.strip() for h in env("NGRC_ALLOWED_HOSTS", "", required=False).split(",") if h.strip()]
if "*" in ALLOWED_HOSTS:
    raise ImproperlyConfigured("Wildcard ALLOWED_HOSTS is not permitted")

# --------------------------------------------------------------------------------------------------
# Applications. Deliberately NOT installed: django.contrib.admin/auth/sessions/messages/staticfiles.
# Authentication, sessions and CSRF-token delivery are NsureGRC's own (D-P0-008).
# --------------------------------------------------------------------------------------------------
INSTALLED_APPS = [
    "rest_framework",
    "ngrc.core",
    "ngrc.control_plane",
    "ngrc.iam",
    "ngrc.tenancy",
    "ngrc.evidence",
    "ngrc.authz",
    "ngrc.audit",
    "ngrc.framework",
    "ngrc.controls",
    "ngrc.risk",
    "ngrc.governance",
    "ngrc.compliance_audit",
    "ngrc.privacy",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "ngrc.core.middleware.RequestIdMiddleware",
    "ngrc.core.middleware.SecurityHeadersMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "ngrc.authn.middleware.SessionAuthMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
TIME_ZONE = "UTC"
LANGUAGE_CODE = "en"
APPEND_SLASH = False

# --------------------------------------------------------------------------------------------------
# Database: one physical database, one connection pool/alias per least-privilege role (C-5, D-P0-009).
# --------------------------------------------------------------------------------------------------
_DB_ROLES = {
    # alias: (postgres role, password env var)
    "default": ("ngrc_app", "NGRC_DB_APP_PASSWORD"),
    "autonomous": ("ngrc_app", "NGRC_DB_APP_PASSWORD"),  # separate connection => independent transaction
    "auth": ("ngrc_auth", "NGRC_DB_AUTH_PASSWORD"),
    "ops": ("ngrc_ops", "NGRC_DB_OPS_PASSWORD"),
    "owner": ("ngrc_owner", "NGRC_DB_OWNER_PASSWORD"),
    "audit_reader": ("ngrc_audit_reader_platform", "NGRC_DB_AUDIT_READER_PASSWORD"),
    "audit_sealer": ("ngrc_audit_sealer", "NGRC_DB_AUDIT_SEALER_PASSWORD"),
    "audit_verifier": ("ngrc_audit_verifier", "NGRC_DB_AUDIT_VERIFIER_PASSWORD"),
    "catalog": ("ngrc_catalog_publisher", "NGRC_DB_CATALOG_PASSWORD"),  # CAT/PLT writer (D-P2-001)
}
_PLANE_ALIASES = {
    "customer": ["default", "autonomous", "auth"],
    # The operator plane also serves support-session reads through ngrc_app, only after a grant check (D-P0-005 s3).
    # `catalog` is here (not on `customer`) because framework authoring/publish is a Platform Curator action (D-P2-001).
    "operator": ["default", "autonomous", "ops", "audit_reader", "catalog"],
    "migrate": ["owner"],
    # audit worker processes: exactly ONE database role each (verifier: read-only + run records; sealer: head read + checkpoint insert)
    "audit_verify": ["audit_verifier"],
    "audit_seal": ["audit_sealer"],
    "all": list(_DB_ROLES),
}
DB_NAME = env("NGRC_DB_NAME", "ngrc_dev")
_SSLMODE = env("NGRC_DB_SSLMODE", "prefer" if NGRC_ENV in {"dev", "test"} else "verify-full")


def _db_config(alias: str) -> dict:
    role, pw_var = _DB_ROLES[alias]
    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": DB_NAME,
        "USER": role,
        "PASSWORD": env(pw_var, required=True),
        "HOST": env("NGRC_DB_HOST", "127.0.0.1"),
        "PORT": env("NGRC_DB_PORT", "5432"),
        "CONN_MAX_AGE": 0,  # no connection reuse: removes any chance of session-state leakage between requests
        "ATOMIC_REQUESTS": False,  # tenant transactions are opened explicitly with tenant context
        "OPTIONS": {"sslmode": _SSLMODE},
    }


if NGRC_PLANE == "migrate":
    DATABASES = {"default": _db_config("owner"), "owner": _db_config("owner")}
elif NGRC_PLANE in {"audit_verify", "audit_seal"}:
    _w = _PLANE_ALIASES[NGRC_PLANE][0]  # Django needs a `default`; here it IS the worker role (nothing routes models to it)
    DATABASES = {"default": _db_config(_w), _w: _db_config(_w)}
else:
    DATABASES = {alias: _db_config(alias) for alias in _PLANE_ALIASES[NGRC_PLANE]}

DATABASE_ROUTERS = ["ngrc.core.db_router.ClassRouter"]

# --------------------------------------------------------------------------------------------------
# Passwords / authentication (D-P0-008). Values are NsureGRC baseline unless the ADR marks [STD].
# --------------------------------------------------------------------------------------------------
PASSWORD_HASHING = {
    # RFC 9106 second-recommended profile as the starting target; MUST be benchmarked on production hardware (ADR s3).
    "time_cost": env_int("NGRC_ARGON2_TIME_COST", 3),
    "memory_cost_kib": env_int("NGRC_ARGON2_MEMORY_KIB", 65536),
    "parallelism": env_int("NGRC_ARGON2_PARALLELISM", 4),
}
PASSWORD_POLICY = {
    "min_length": 12,
    "max_length": 128,
    "blocklist_path": env("NGRC_PASSWORD_BLOCKLIST", str(BASE_DIR / "ngrc" / "authn" / "data" / "blocklist_seed.txt")),
}
AUTH_THROTTLE = {
    # D-P0-008 s4 as amended by D-P1-001 (DEF-15): progressive back-off only. There is NO hard-stop to `recovery_required` while the
    # unlock/recovery workflow (F-ATH-015) does not exist. Values are NsureGRC baseline numbers pending approval, not standard-derived.
    "account_free_failures": 5,  # back-off starts at the 5th consecutive failure
    "account_base_delay_s": 60,
    "account_max_delay_s": 900,
    "ip_window_s": 60,
    "ip_max_attempts": 20,
    "suspicious_distinct_sources": 3,  # distinct source addresses failing against ONE account within the window => alert
    "suspicious_window_s": 3600,
    # stricter parameters for privileged operator accounts (platform realm)
    "operator_account_free_failures": 3,
    "operator_account_base_delay_s": 120,
    "operator_account_max_delay_s": 3600,
    "operator_suspicious_distinct_sources": 2,
    "operator_suspicious_window_s": 7200,
}
SESSION_POLICY = {
    # (idle seconds, absolute seconds)  -- NsureGRC baseline, not NIST-derived (ADR s8)
    "standard": (30 * 60, 12 * 3600),
    "privileged": (15 * 60, 8 * 3600),
    "operator": (15 * 60, 8 * 3600),
    "pending_mfa": (10 * 60, 10 * 60),
}
STEP_UP_T1_WINDOW_S = 10 * 60
EMAIL_VERIFY_TTL_S = 24 * 3600
PASSWORD_RESET_TTL_S = 30 * 60
INVITATION_TTL_S = 7 * 24 * 3600
WEBAUTHN_CHALLENGE_TTL_S = 5 * 60
WEBAUTHN_RP_ID = env("NGRC_WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_RP_NAME = "NsureGRC"
WEBAUTHN_ALLOWED_ORIGINS = [o for o in env("NGRC_WEBAUTHN_ORIGINS", "https://localhost").split(",") if o]
PUBLIC_BASE_URL = env("NGRC_PUBLIC_BASE_URL", "https://localhost")  # used in emails; NEVER derived from Host header

# Support access (D-P0-005 s3-4)
SUPPORT_GRANT_DEFAULT_MINUTES = 240
SUPPORT_GRANT_MAX_MINUTES = 480
BREAK_GLASS_MAX_MINUTES = 120

# Cryptographic material: injected, never defaulted (D-P0-007 s3). KMS integration is open item O-4.
FIELD_ENCRYPTION_KEY = env("NGRC_FIELD_ENCRYPTION_KEY", required=True)  # base64 32 bytes; DEV-ONLY local key provider
TOKEN_PEPPER = env("NGRC_TOKEN_PEPPER", required=True)  # HMAC key for recovery-code hashing
ALERT_SINKS = ["log"]  # delivery to a pager/SIEM is NOT IMPLEMENTED (O-4); see ngrc/audit/alerts.py
AUDIT_SIGNER_BACKEND = env("NGRC_AUDIT_SIGNER", "dev_file")  # dev_file is DEV-ONLY; prod requires 'kms' (NOT IMPLEMENTED, O-4)
AUDIT_SIGNER_KEY_PATH = env("NGRC_AUDIT_SIGNER_KEY_PATH", "")
AUDIT_CHECKPOINT_EXPORT_DIR = env("NGRC_AUDIT_EXPORT_DIR", "")  # dev: local dir. prod: WORM sink (NOT IMPLEMENTED, O-4)

# --------------------------------------------------------------------------------------------------
# HTTP security
# --------------------------------------------------------------------------------------------------
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = False  # preload is a deliberate, irreversible-ish decision; not enabled by default
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
SECURE_PROXY_SSL_HEADER = None  # set explicitly (and only) when behind a trusted TLS-terminating proxy
USE_X_FORWARDED_HOST = False

CSRF_COOKIE_NAME = "__Host-ngrc-csrf"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True  # token is delivered via GET /api/v1/auth/csrf/, not read from the cookie by JS
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_PATH = "/"
CSRF_HEADER_NAME = "HTTP_X_CSRFTOKEN"
CSRF_TRUSTED_ORIGINS = [o for o in env("NGRC_CSRF_TRUSTED_ORIGINS", "").split(",") if o]
CSRF_USE_SESSIONS = False

CUSTOMER_COOKIE_NAME = "__Host-ngrc-sid"
OPERATOR_COOKIE_NAME = "__Host-ngrc-ops-sid"
SESSION_COOKIE_SECURE = True  # used by our own cookie writer
SESSION_COOKIE_SAMESITE = "Lax"

DATA_UPLOAD_MAX_MEMORY_SIZE = 1_048_576  # 1 MiB for JSON API bodies; file uploads are a later phase
FILE_UPLOAD_MAX_MEMORY_SIZE = 0

# CORS: default deny (no CORS middleware installed). An allow-list is introduced by explicit ADR when needed.

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["ngrc.authz.drf_defaults.NgrcSessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["ngrc.authz.drf_defaults.DenyAll"],  # fail closed: every view must declare a policy
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["ngrc.core.parsers.StrictJSONParser"],  # no form posts, no multipart in Phase 1
    "UNAUTHENTICATED_USER": None,
    "UNAUTHENTICATED_TOKEN": None,  # nosec B105
    "EXCEPTION_HANDLER": "ngrc.authz.drf_defaults.exception_handler",
    "DEFAULT_THROTTLE_CLASSES": [],
    "TEST_REQUEST_DEFAULT_FORMAT": "json",
    "URL_FORMAT_OVERRIDE": None,
}

# --------------------------------------------------------------------------------------------------
# Logging: structured, secret-redacting, no request bodies (D-P0-007).
# --------------------------------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"redact": {"()": "ngrc.core.logging.RedactingFilter"}},
    "formatters": {"json": {"()": "ngrc.core.logging.JsonFormatter"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "filters": ["redact"], "formatter": "json"}},
    "root": {"handlers": ["console"], "level": env("NGRC_LOG_LEVEL", "INFO")},
    "loggers": {"django.db.backends": {"level": "WARNING"}},
}


# Audit checkpoint continuity / completeness (H-11, docs/AUDIT_COMPLETENESS.md). NsureGRC BASELINE values pending approval; the interval
# follows the D-P0-006 s5 proposal (<= 5 minutes). Max age = three missed heartbeats.
AUDIT_CHECKPOINT_INTERVAL_S = env_int("NGRC_AUDIT_CHECKPOINT_INTERVAL_S", 300)
AUDIT_CHECKPOINT_MAX_AGE_S = env_int("NGRC_AUDIT_CHECKPOINT_MAX_AGE_S", 900)
AUDIT_EXPORT_GRACE_S = 120                 # a fresh DB checkpoint may legitimately lack its external copy for this long
AUDIT_CLOCK_SKEW_TOLERANCE_S = 300         # checkpoints of one stream may not be dated earlier than their predecessor by more than this
AUDIT_SINK_IMMUTABLE = False               # True only when the external sink is a WORM store (NOT IMPLEMENTED, open item O-4)
AUDIT_VERIFY_MAX_AGE_HOURS = env_int("NGRC_AUDIT_VERIFY_MAX_AGE_HOURS", 6)   # BASELINE pending Platform Security approval; watchdog threshold
AUDIT_REQUIRE_EXTERNAL_COPY = False        # prod: True (validated). Dev has only a local, rewritable sink
AUDIT_REQUIRE_COMPLETENESS = False         # prod: True (validated): a run without any independent anchor then FAILS instead of passing silently
AUDIT_PUBLIC_KEYS = {}                     # key id -> hex raw Ed25519 public key; the verifier never needs a private key

# Lost-factor recovery (D-P0-008 s7.4, F-ATH-015). BASELINE values pending approval, not standard-derived.
RECOVERY_COOLING_OFF_S = env_int("NGRC_RECOVERY_COOLING_OFF_S", 24 * 3600)   # ADR BASELINE: 24 h between approval and completion (DB floor: 1 h)
RECOVERY_ENROLMENT_WINDOW_S = env_int("NGRC_RECOVERY_ENROLMENT_WINDOW_S", 1800)  # after a completed recovery only the completing session may enrol (BASELINE)
RECOVERY_REQUEST_TTL_S = 7 * 24 * 3600                                       # an unfinished request expires

# Evidence (D-P0-007 s5, decision C-6). The local store and the EICAR scanner are DEV-ONLY stand-ins: production refuses to start with them
# (hosting/object store = open item O-4, malware engine = O-11). The size limit is a BASELINE pending approval.
EVIDENCE_STORE_BACKEND = env("NGRC_EVIDENCE_STORE", "local_dev" if NGRC_ENV in {"dev", "test"} else "")
EVIDENCE_STORE_DIR = env("NGRC_EVIDENCE_STORE_DIR", str(BASE_DIR / "var" / "evidence"))
EVIDENCE_SCANNER_BACKEND = env("NGRC_EVIDENCE_SCANNER", "dev_eicar" if NGRC_ENV in {"dev", "test"} else "")
EVIDENCE_MAX_BYTES = env_int("NGRC_EVIDENCE_MAX_BYTES", 25 * 1024 * 1024)
SEARCH_MAX_QUERY_CHARS = 200
SEARCH_MAX_RESULTS = 25
