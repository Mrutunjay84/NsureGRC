"""Development settings. DEV-ONLY: relaxes TLS redirect/HSTS for localhost; keeps every other control on."""
from ._devenv import load_dev_env

load_dev_env()
import os  # noqa: E402

os.environ.setdefault("NGRC_ENV", "dev")
os.environ.setdefault("NGRC_ALLOWED_HOSTS", "localhost,127.0.0.1")

from .base import *  # noqa: E402,F403
from .base import env_bool  # noqa: E402

DEBUG = env_bool("NGRC_DEBUG", False)
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
KEY_PROVIDER = "local"  # DEV-ONLY local key provider (not KMS)
CSRF_TRUSTED_ORIGINS = ["https://localhost", "https://127.0.0.1",
                        "https://localhost:5173", "https://127.0.0.1:5173"]  # Vite dev server (D-P6-001)
