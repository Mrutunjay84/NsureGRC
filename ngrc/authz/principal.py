from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Principal:
    """The authenticated caller, built from a server-side session by SessionAuthMiddleware. `is_authenticated` is for DRF."""

    kind: str  # 'customer' | 'operator'
    account_id: uuid.UUID
    session_id: uuid.UUID
    stage: str  # password_ok | enroll_mfa | active
    email: str
    tenant_id: uuid.UUID | None  # customer: tenant chosen in the session; operator: tenant of the active support grant
    session_ref: str  # short hash of the session token for audit correlation (never the token)
    mfa_at: datetime | None = None
    step_up_at: datetime | None = None
    step_up_method: str = ""
    auth_methods: tuple[str, ...] = ()
    operator_roles: frozenset[str] = frozenset()
    grant_id: uuid.UUID | None = None
    extra: dict = field(default_factory=dict, compare=False, hash=False)

    is_authenticated = True

    @property
    def actor_type(self) -> str:
        return "operator" if self.kind == "operator" else "user"
