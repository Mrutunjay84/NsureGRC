"""Insecure-configuration tests: production settings must refuse to start with weak or dev-only settings; planes get only their
own database credentials; unsafe Django features are not installed."""
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from django.conf import settings

from config.settings.validators import validate_settings

pytestmark = pytest.mark.security
ROOT = Path(__file__).resolve().parent.parent

SECURE = {
    "NGRC_ENV": "prod", "DEBUG": False, "NGRC_PLANE": "customer", "ALLOWED_HOSTS": ["app.example.test"], "SECRET_KEY": "k" * 64,
    "SECURE_SSL_REDIRECT": True, "CSRF_COOKIE_SECURE": True, "SESSION_COOKIE_SECURE": True, "CSRF_COOKIE_HTTPONLY": True,
    "SECURE_CONTENT_TYPE_NOSNIFF": True, "SECURE_HSTS_SECONDS": 31536000, "X_FRAME_OPTIONS": "DENY", "USE_X_FORWARDED_HOST": False,
    "CSRF_COOKIE_NAME": "__Host-ngrc-csrf", "CSRF_TRUSTED_ORIGINS": ["https://app.example.test"],
    "WEBAUTHN_ALLOWED_ORIGINS": ["https://app.example.test"], "PUBLIC_BASE_URL": "https://app.example.test",
    "PASSWORD_HASHING": {"time_cost": 3, "memory_cost_kib": 65536, "parallelism": 4},
    "DATABASES": {"default": {"USER": "ngrc_app", "PASSWORD": "x", "OPTIONS": {"sslmode": "verify-full"}}},
    "AUDIT_SIGNER_BACKEND": "kms", "KEY_PROVIDER": "kms", "INSTALLED_APPS": ["rest_framework", "ngrc.core"], "NGRC_MFA_REQUIRED": True,
    "AUDIT_REQUIRE_EXTERNAL_COPY": True, "AUDIT_REQUIRE_COMPLETENESS": True, "AUDIT_SINK_IMMUTABLE": True,
    "EVIDENCE_STORE_BACKEND": "object_store", "EVIDENCE_SCANNER_BACKEND": "engine",
}


def test_a_fully_secure_configuration_passes():
    assert validate_settings(SECURE) == []


@pytest.mark.parametrize("key,bad,fragment", [
    ("NGRC_ENV", "dev", "NGRC_ENV"), ("DEBUG", True, "DEBUG"), ("NGRC_PLANE", "all", "NGRC_PLANE"), ("ALLOWED_HOSTS", [], "ALLOWED_HOSTS"),
    ("ALLOWED_HOSTS", ["*"], "ALLOWED_HOSTS"), ("SECRET_KEY", "short", "SECRET_KEY"), ("SECURE_SSL_REDIRECT", False, "SECURE_SSL_REDIRECT"),
    ("CSRF_COOKIE_SECURE", False, "CSRF_COOKIE_SECURE"), ("SESSION_COOKIE_SECURE", False, "SESSION_COOKIE_SECURE"),
    ("CSRF_COOKIE_HTTPONLY", False, "CSRF_COOKIE_HTTPONLY"), ("SECURE_CONTENT_TYPE_NOSNIFF", False, "NOSNIFF"),
    ("SECURE_HSTS_SECONDS", 0, "HSTS"), ("X_FRAME_OPTIONS", "SAMEORIGIN", "X_FRAME_OPTIONS"), ("USE_X_FORWARDED_HOST", True, "X_FORWARDED"),
    ("CSRF_COOKIE_NAME", "csrftoken", "__Host-"), ("CSRF_TRUSTED_ORIGINS", ["http://app.example.test"], "CSRF_TRUSTED_ORIGINS"),
    ("CSRF_TRUSTED_ORIGINS", [], "CSRF_TRUSTED_ORIGINS"), ("WEBAUTHN_ALLOWED_ORIGINS", ["http://x"], "WEBAUTHN"),
    ("PUBLIC_BASE_URL", "http://app.example.test", "PUBLIC_BASE_URL"),
    ("PASSWORD_HASHING", {"time_cost": 1, "memory_cost_kib": 1024, "parallelism": 1}, "Argon2id"),
    ("AUDIT_SIGNER_BACKEND", "dev_file", "dev_file"), ("KEY_PROVIDER", "local", "local"),
    ("NGRC_MFA_REQUIRED", False, "NGRC_MFA_REQUIRED"),
    ("INSTALLED_APPS", ["django.contrib.admin"], "admin"),
    ("AUDIT_REQUIRE_EXTERNAL_COPY", False, "AUDIT_REQUIRE_EXTERNAL_COPY"), ("AUDIT_REQUIRE_COMPLETENESS", False, "AUDIT_REQUIRE_COMPLETENESS"),
    ("AUDIT_SINK_IMMUTABLE", False, "AUDIT_SINK_IMMUTABLE"), ("EVIDENCE_STORE_BACKEND", "local_dev", "EVIDENCE_STORE_BACKEND"),
    ("EVIDENCE_SCANNER_BACKEND", "dev_eicar", "EVIDENCE_SCANNER_BACKEND"),
])
def test_each_insecure_setting_is_detected(key, bad, fragment):
    cfg = copy.deepcopy(SECURE)
    cfg[key] = bad
    problems = validate_settings(cfg)
    assert problems and any(fragment.lower() in p.lower() for p in problems), problems


def test_insecure_database_settings_are_detected():
    for opts, user, pw, frag in (({"sslmode": "prefer"}, "ngrc_app", "x", "sslmode"), ({"sslmode": "disable"}, "ngrc_app", "x", "sslmode"),
                                 ({"sslmode": "verify-full"}, "postgres", "x", "superuser"), ({"sslmode": "verify-full"}, "ngrc_app", "", "password")):
        cfg = copy.deepcopy(SECURE)
        cfg["DATABASES"] = {"default": {"USER": user, "PASSWORD": pw, "OPTIONS": opts}}
        assert any(frag in p for p in validate_settings(cfg)), (opts, user)


def _env(**over):
    env = {k: v for k, v in os.environ.items() if not k.startswith("NGRC_") and k != "DJANGO_SETTINGS_MODULE"}
    env.update({"NGRC_SECRET_KEY": "s" * 64, "NGRC_FIELD_ENCRYPTION_KEY": "A" * 43, "NGRC_TOKEN_PEPPER": "p" * 40,
                "NGRC_ALLOWED_HOSTS": "app.example.test", "NGRC_CSRF_TRUSTED_ORIGINS": "https://app.example.test",
                "NGRC_WEBAUTHN_ORIGINS": "https://app.example.test", "NGRC_PUBLIC_BASE_URL": "https://app.example.test",
                "NGRC_DB_APP_PASSWORD": "x", "NGRC_DB_AUTH_PASSWORD": "x", "NGRC_DB_OPS_PASSWORD": "x", "NGRC_DB_OWNER_PASSWORD": "x",
                "NGRC_DB_AUDIT_READER_PASSWORD": "x", "NGRC_DB_AUDIT_SEALER_PASSWORD": "x", "NGRC_DB_AUDIT_VERIFIER_PASSWORD": "x",
                "NGRC_DB_CATALOG_PASSWORD": "x",
                "NGRC_ENV": "prod", "NGRC_PLANE": "customer", "PYTHONIOENCODING": "utf-8"})
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


def _run(code: str, module: str, **over):
    env = _env(DJANGO_SETTINGS_MODULE=module, **over)
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)  # noqa: S603


def test_production_settings_refuse_to_start_while_dev_only_components_are_the_only_ones_available():
    r = _run("import django; django.setup()", "config.settings.prod")
    assert r.returncode != 0
    assert "Insecure production configuration" in r.stderr
    # the refusal is specifically about the unimplemented production key/audit backends (open item O-4), not an accident
    assert "AUDIT_SIGNER_BACKEND" in r.stderr and "DEV-ONLY" in r.stderr


@pytest.mark.parametrize("missing", ["NGRC_SECRET_KEY", "NGRC_FIELD_ENCRYPTION_KEY", "NGRC_TOKEN_PEPPER", "NGRC_DB_APP_PASSWORD"])
def test_missing_required_secrets_stop_startup_and_nothing_has_a_default(missing):
    r = _run("import django; django.setup()", "config.settings.base", **{missing: None})
    assert r.returncode != 0 and "ImproperlyConfigured" in r.stderr and missing in r.stderr


def test_weak_secret_key_and_wildcard_hosts_stop_startup():
    r = _run("import django; django.setup()", "config.settings.base", NGRC_SECRET_KEY="tooshort")
    assert r.returncode != 0 and "SECRET_KEY" in r.stderr
    r = _run("import django; django.setup()", "config.settings.base", NGRC_ALLOWED_HOSTS="*")
    assert r.returncode != 0 and "Wildcard" in r.stderr
    r = _run("import django; django.setup()", "config.settings.base", NGRC_PLANE="everything")
    assert r.returncode != 0 and "NGRC_PLANE" in r.stderr


@pytest.mark.parametrize("plane,expected", [("customer", {"default", "autonomous", "auth"}),
                                            ("operator", {"default", "autonomous", "ops", "audit_reader", "catalog"}), ("migrate", {"default", "owner"}),
                                            ("audit_verify", {"default", "audit_verifier"}), ("audit_seal", {"default", "audit_sealer"})])
def test_each_process_plane_receives_only_its_own_database_roles(plane, expected):
    code = "from django.conf import settings; import json; print(json.dumps(sorted(settings.DATABASES)))"
    over = {"NGRC_PLANE": plane}
    # a customer-plane process is started WITHOUT the other planes' credentials: it must still boot, proving it never needs them
    if plane == "customer":
        over.update({k: None for k in ("NGRC_DB_OPS_PASSWORD", "NGRC_DB_OWNER_PASSWORD", "NGRC_DB_AUDIT_READER_PASSWORD",
                                       "NGRC_DB_AUDIT_SEALER_PASSWORD", "NGRC_DB_AUDIT_VERIFIER_PASSWORD")})
    r = _run(code, "config.settings.base", **over)
    assert r.returncode == 0, r.stderr
    assert set(json.loads(r.stdout)) == expected


def test_operator_plane_requires_the_catalog_role_password():
    """D-P2-001: the operator plane is the only one that loads `catalog` (ngrc_catalog_publisher)."""
    r = _run("import django; django.setup()", "config.settings.base", NGRC_PLANE="operator", NGRC_DB_CATALOG_PASSWORD=None)
    assert r.returncode != 0 and "ImproperlyConfigured" in r.stderr and "NGRC_DB_CATALOG_PASSWORD" in r.stderr


def test_runtime_roles_in_database_settings_are_not_privileged():
    for alias, db in settings.DATABASES.items():
        assert db["USER"] not in {"postgres", "root"}, alias
        assert db["USER"].startswith("ngrc_"), alias
        assert db["CONN_MAX_AGE"] == 0 and db["ATOMIC_REQUESTS"] is False, alias  # no connection reuse, explicit tenant transactions
    assert settings.DATABASES["default"]["USER"] == settings.DATABASES["autonomous"]["USER"] == "ngrc_app"
    assert settings.DATABASES["auth"]["USER"] == "ngrc_auth" and settings.DATABASES["ops"]["USER"] == "ngrc_ops"
    assert settings.DATABASES["owner"]["USER"] == "ngrc_owner"


def test_django_baseline_features_are_not_installed():
    apps = " ".join(settings.INSTALLED_APPS)
    for banned in ("django.contrib.admin", "django.contrib.auth", "django.contrib.sessions", "django.contrib.messages",
                   "django.contrib.staticfiles", "django.contrib.contenttypes"):
        assert banned not in apps, banned
    mw = settings.MIDDLEWARE
    assert "django.middleware.csrf.CsrfViewMiddleware" in mw and "django.middleware.security.SecurityMiddleware" in mw
    assert "django.middleware.clickjacking.XFrameOptionsMiddleware" in mw
    assert mw.index("django.middleware.security.SecurityMiddleware") < mw.index("ngrc.authn.middleware.SessionAuthMiddleware")
    assert settings.DEBUG is False and settings.APPEND_SLASH is False


def test_http_security_settings_are_secure_by_default():
    assert settings.CSRF_COOKIE_NAME.startswith("__Host-") and settings.CSRF_COOKIE_SECURE and settings.CSRF_COOKIE_HTTPONLY
    assert settings.CUSTOMER_COOKIE_NAME.startswith("__Host-") and settings.OPERATOR_COOKIE_NAME.startswith("__Host-")
    assert settings.SECURE_HSTS_SECONDS >= 31536000 and settings.SECURE_CONTENT_TYPE_NOSNIFF
    assert settings.USE_X_FORWARDED_HOST is False and settings.SECURE_PROXY_SSL_HEADER is None
    assert settings.ALLOWED_HOSTS and "*" not in settings.ALLOWED_HOSTS
    assert settings.DATA_UPLOAD_MAX_MEMORY_SIZE <= 1_048_576 and settings.FILE_UPLOAD_MAX_MEMORY_SIZE == 0
    assert not hasattr(settings, "CORS_ALLOW_ALL_ORIGINS") and "corsheaders" not in " ".join(settings.INSTALLED_APPS)


def test_dev_only_markers_are_explicit():
    """Dev-only stand-ins must announce themselves so nobody mistakes them for production controls."""
    from ngrc.audit.signer import DevFileSigner, get_signer
    from ngrc.core import crypto

    assert DevFileSigner.dev_only is True
    assert settings.KEY_PROVIDER == "local" and "DEV-ONLY" in (crypto.__doc__ or "")
    assert "DEV/TEST ONLY" in sys.modules[DevFileSigner.__module__].__doc__
    settings.AUDIT_SIGNER_BACKEND = "kms"
    try:
        with pytest.raises(NotImplementedError):
            get_signer()
    finally:
        settings.AUDIT_SIGNER_BACKEND = "dev_file"


def test_no_test_only_code_ships_in_the_application_package():
    assert not (ROOT / "ngrc" / "testkit").exists()
    assert "testserver" not in " ".join(_prod_like_hosts())


def _prod_like_hosts():
    r = _run("from django.conf import settings; print(','.join(settings.ALLOWED_HOSTS))", "config.settings.base", NGRC_PLANE="migrate")
    return r.stdout.strip().split(",")


def test_signing_key_and_env_files_are_gitignored():
    ig = (ROOT / ".gitignore").read_text()
    for pattern in (".env", "*.pem", "*.key", "secrets/"):
        assert pattern in ig
    di = (ROOT / ".dockerignore").read_text()
    assert ".env" in di and "*.pem" in di
