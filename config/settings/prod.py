"""Production settings. Refuses to start unless every validator passes (config/settings/validators.py).

NOTE (honest status): production start-up is currently IMPOSSIBLE by design, because the production KMS key provider and
audit-signing/WORM backends are not implemented (open item O-4). This is intended: dev-only stand-ins can never run here.
"""
from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F403
from .validators import validate_settings

KEY_PROVIDER = "kms"  # NOT IMPLEMENTED (O-4)
_violations = validate_settings({k: v for k, v in globals().items() if k.isupper() or k.startswith("NGRC")})
if _violations:
    raise ImproperlyConfigured("Insecure production configuration: " + "; ".join(_violations))
