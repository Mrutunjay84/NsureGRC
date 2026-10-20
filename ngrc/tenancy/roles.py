"""Tenant role / membership helpers shared by views and the auth service."""
from __future__ import annotations

import re

from django.db import connections

from ngrc.authz import permissions as perm
from ngrc.core.context import principal_context

RESERVED_KEYS = frozenset({"owner", "admin", "member"})
KEY_RE = re.compile(r"[a-z][a-z0-9-]{1,62}")  # use fullmatch: "$" would accept a trailing newline


class RoleError(Exception):
    def __init__(self, code: str, http: int = 400):
        super().__init__(code)
        self.code, self.http = code, http


def clean_permissions(perms, caller_permissions: frozenset[str]) -> list[str]:
    """Validate a permission list: known tenant permissions only, and NEVER more than the caller holds (no escalation)."""
    if not isinstance(perms, list) or not all(isinstance(p, str) for p in perms):
        raise RoleError("invalid_permissions")
    uniq = sorted(set(perms))
    for p in uniq:
        definition = perm.get(p)
        if definition is None or definition.realm != "tenant":
            raise RoleError("unknown_permission")
    if not set(uniq) <= set(caller_permissions):
        raise RoleError("privilege_escalation", 403)
    return uniq


def role_key_for(tenant_id, role_id, account_id) -> str:
    """Role key for an audit detail, read through the auth connection under the member's own principal context."""
    with principal_context(account_id, using="auth"), connections["auth"].cursor() as cur:
        cur.execute("SELECT key FROM ten_role WHERE id = %s::uuid AND tenant_id = %s::uuid", [str(role_id), str(tenant_id)])
        row = cur.fetchone()
    return (row[0] if row else "unknown")[:64]


def revoke_member_sessions(principal_id, reason: str) -> int:
    """End a member's sessions bound to the CURRENT tenant (SECURITY DEFINER fn; needs tenant context)."""
    with connections["default"].cursor() as cur:
        cur.execute("SELECT idn_revoke_tenant_sessions(%s::uuid, %s)", [str(principal_id), reason])
        return cur.fetchone()[0]
