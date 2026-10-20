"""Identity realms: the customer store (idn_*, connection `auth`) and the platform operator store (plt_operator_*,
connection `ops`) are separate (D-P0-005 s1). Services take a Realm so the same hardened code serves both."""
from __future__ import annotations

import importlib
from dataclasses import dataclass

from django.conf import settings


@dataclass(frozen=True)
class Realm:
    name: str
    db: str
    cookie_setting: str
    models_module: str
    model_names: dict
    factors: frozenset[str]
    throttle_prefix: str  # settings.AUTH_THROTTLE key prefix
    event_prefix: str  # audit action prefix for pre-tenant events
    path_prefix: str

    def _m(self, key):
        return getattr(importlib.import_module(self.models_module), self.model_names[key])

    @property
    def Account(self):  # noqa: N802
        return self._m("account")

    @property
    def Session(self):  # noqa: N802
        return self._m("session")

    @property
    def WebAuthn(self):  # noqa: N802
        return self._m("webauthn")

    @property
    def Throttle(self):  # noqa: N802
        return self._m("throttle")

    @property
    def cookie_name(self) -> str:
        return getattr(settings, self.cookie_setting)


CUSTOMER = Realm(
    name="customer", db="auth", cookie_setting="CUSTOMER_COOKIE_NAME", models_module="ngrc.iam.models",
    model_names={"account": "Account", "session": "Session", "webauthn": "WebAuthnCredential", "throttle": "Throttle"},
    factors=frozenset({"totp", "webauthn", "recovery"}), throttle_prefix="", event_prefix="auth", path_prefix="/api/",
)
OPERATOR = Realm(
    name="operator", db="ops", cookie_setting="OPERATOR_COOKIE_NAME", models_module="ngrc.control_plane.models",
    model_names={"account": "OperatorAccount", "session": "OperatorSession", "webauthn": "OperatorWebAuthnCredential",
                 "throttle": "OperatorThrottle"},
    factors=frozenset({"webauthn"}), throttle_prefix="operator_", event_prefix="platform.operator", path_prefix="/ops/",
)


def realm_for_path(path: str) -> Realm:
    return OPERATOR if path.startswith("/ops/") else CUSTOMER
