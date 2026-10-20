"""Test settings. TEST-ONLY. Differences from base are limited to cost parameters, local origins and the locmem mail backend."""
import os
import secrets

from ._devenv import load_dev_env

load_dev_env()
os.environ["NGRC_ENV"] = "test"
os.environ["NGRC_PLANE"] = "all"
os.environ.setdefault("NGRC_ALLOWED_HOSTS", "testserver,localhost")
# Per-run random key when none is provided: no static secret exists in the repository.
os.environ.setdefault("NGRC_SECRET_KEY", secrets.token_urlsafe(64))
os.environ.setdefault("NGRC_FIELD_ENCRYPTION_KEY", secrets.token_urlsafe(32))
os.environ.setdefault("NGRC_TOKEN_PEPPER", secrets.token_urlsafe(32))
os.environ["NGRC_DB_NAME"] = os.environ.get("NGRC_DB_TEST_NAME", "ngrc_test")

from .base import *  # noqa: E402,F403

DEBUG = False
SECURE_SSL_REDIRECT = False  # tests send https via the client; redirect logic is covered by the settings validator test
KEY_PROVIDER = "local"
CSRF_TRUSTED_ORIGINS = ["https://testserver"]
WEBAUTHN_RP_ID = "testserver"
WEBAUTHN_ALLOWED_ORIGINS = ["https://testserver"]
PUBLIC_BASE_URL = "https://testserver"
ALLOWED_HOSTS = ["testserver", "localhost"]

# Argon2 at the OWASP *floor* (never below it) so the suite stays fast; production target is in base.py.
PASSWORD_HASHING = {"time_cost": 2, "memory_cost_kib": 19456, "parallelism": 1}

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
