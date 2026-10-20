"""Tenant administration API. Every handler runs inside a tenant-bound transaction (RLS) with the audit unit of work;
mutations require an explicit permission, recent step-up, and obey the no-escalation rule."""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.db import IntegrityError, connections, transaction
from rest_framework import serializers
from rest_framework.response import Response

from ngrc.audit import service as audit
from ngrc.authn.flow import normalize_email
from ngrc.authz import permissions as perm
from ngrc.authz.drf import NgrcAPIView, Policy
from ngrc.authz.policy import resolve_tenant_authz
from ngrc.control_plane.models import Tenant
from ngrc.core import clock
from ngrc.core.crypto import hash_token, keyed_identifier_hash, new_token
from ngrc.iam.models import Profile

from .models import Membership, TenantRole
from .roles import KEY_RE, RESERVED_KEYS, RoleError, clean_permissions, revoke_member_sessions


def _err(code: str, http: int = 400) -> Response:
    return Response({"error": code}, status=http)


def _role_json(r: TenantRole) -> dict:
    return {"id": str(r.id), "key": r.key, "name": r.name, "permissions": r.permissions, "is_system": r.is_system}


class MeView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "tenant.view")

    def get(self, request):
        ta = resolve_tenant_authz(request.user)
        t = Tenant.objects.using("default").get(id=request.user.tenant_id)
        return Response({"tenant": {"id": str(t.id), "slug": t.slug, "name": t.name}, "role": ta.role_key,
                         "permissions": sorted(ta.permissions), "kind": ta.kind})


# ---------------------------------------------------------------------------------------------- roles
class RoleSerializer(serializers.Serializer):
    key = serializers.CharField(max_length=64)
    name = serializers.CharField(max_length=100)
    permissions = serializers.ListField(child=serializers.CharField(max_length=64), max_length=64)


class RolePatchSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100, required=False)
    permissions = serializers.ListField(child=serializers.CharField(max_length=64), max_length=64, required=False)


class RoleListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "tenant.roles.read")

    def get(self, request):
        return Response({"roles": [_role_json(r) for r in TenantRole.objects.order_by("key")]})

    def post(self, request):
        self.require(request, "tenant.roles.manage", step_up="T1")
        d = RoleSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        key = d.validated_data["key"]
        if not KEY_RE.fullmatch(key) or key in RESERVED_KEYS:
            return _err("invalid_key")
        ta = resolve_tenant_authz(request.user)
        try:
            perms = clean_permissions(d.validated_data["permissions"], ta.permissions)
        except RoleError as e:
            if e.http == 403:
                self.deny(request, "tenant.roles.manage", e.code)
            return _err(e.code, e.http)
        try:
            with transaction.atomic(using="default"):
                r = TenantRole.objects.create(key=key, name=d.validated_data["name"], permissions=perms, is_system=False)
        except IntegrityError:
            return _err("role_exists", 409)
        audit.record("tenant.role.created", actor_id=request.user.account_id, object_type="role", object_id=str(r.id),
                     details={"role_key": key, "permissions": perms})
        return Response(_role_json(r), status=201)


class RoleDetailView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "tenant.roles.read")

    def _get(self, pk):
        return TenantRole.objects.filter(pk=pk).first()

    def get(self, request, pk):
        r = self._get(pk)
        return Response(_role_json(r)) if r else _err("not_found", 404)

    def patch(self, request, pk):
        self.require(request, "tenant.roles.manage", step_up="T1")
        r = self._get(pk)
        if r is None:
            return _err("not_found", 404)
        if r.is_system:
            self.deny(request, "tenant.roles.manage", "system_role_immutable")
        d = RolePatchSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        ta = resolve_tenant_authz(request.user)
        added, removed = [], []
        if "permissions" in d.validated_data:
            try:
                new = clean_permissions(d.validated_data["permissions"], ta.permissions)
            except RoleError as e:
                if e.http == 403:
                    self.deny(request, "tenant.roles.manage", e.code)
                return _err(e.code, e.http)
            added, removed = sorted(set(new) - set(r.permissions)), sorted(set(r.permissions) - set(new))
            r.permissions = new
        if "name" in d.validated_data:
            r.name = d.validated_data["name"]
        r.save()
        if removed:  # permission reduction ends affected members' sessions (D-P0-008 s9)
            for m in Membership.objects.filter(role_id=r.id):
                revoke_member_sessions(m.principal_id, "role_permissions_reduced")
        audit.record("tenant.role.updated", actor_id=request.user.account_id, object_type="role", object_id=str(r.id),
                     details={"role_key": r.key, "added": added, "removed": removed})
        return Response(_role_json(r))

    def delete(self, request, pk):
        self.require(request, "tenant.roles.manage", step_up="T1")
        r = self._get(pk)
        if r is None:
            return _err("not_found", 404)
        if r.is_system:
            self.deny(request, "tenant.roles.manage", "system_role_immutable")
        if Membership.objects.filter(role_id=r.id).exists():
            return _err("role_in_use", 409)
        key = r.key
        r.delete()
        audit.record("tenant.role.deleted", actor_id=request.user.account_id, object_type="role", object_id=str(pk),
                     details={"role_key": key})
        return Response(status=204)


# ---------------------------------------------------------------------------------------------- members
def _member_json(m: Membership, profile: Profile | None, role: TenantRole | None) -> dict:
    return {"id": str(m.id), "principal_id": str(m.principal_id), "email": profile.email if profile else None,
            "display_name": profile.display_name if profile else None, "role_id": str(m.role_id),
            "role_key": role.key if role else None, "kind": m.kind, "status": m.status,
            "expires_at": m.expires_at.isoformat() if m.expires_at else None}


class MemberListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "tenant.members.read")

    def get(self, request):
        members = list(Membership.objects.order_by("created_at"))
        profiles = {p.id: p for p in Profile.objects.using("default").filter(id__in=[m.principal_id for m in members])}
        roles = {r.id: r for r in TenantRole.objects.all()}
        return Response({"members": [_member_json(m, profiles.get(m.principal_id), roles.get(m.role_id)) for m in members]})


class MemberPatchSerializer(serializers.Serializer):
    role_id = serializers.UUIDField(required=False)
    status = serializers.ChoiceField(choices=["active", "suspended"], required=False)


class MemberDetailView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "tenant.members.read")

    def get(self, request, pk):
        m = Membership.objects.filter(pk=pk).first()
        if m is None:
            return _err("not_found", 404)
        p = Profile.objects.using("default").filter(id=m.principal_id).first()
        return Response(_member_json(m, p, TenantRole.objects.filter(id=m.role_id).first()))

    def patch(self, request, pk):
        self.require(request, "tenant.members.manage", step_up="T1")
        m = Membership.objects.filter(pk=pk).first()
        if m is None:
            return _err("not_found", 404)
        d = MemberPatchSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        ta = resolve_tenant_authz(request.user)
        if m.principal_id == request.user.account_id:
            self.deny(request, "tenant.members.manage", "self_modification")
        cur_role = TenantRole.objects.filter(id=m.role_id).first()
        if cur_role is None or not set(cur_role.permissions) <= set(ta.permissions):
            self.deny(request, "tenant.members.manage", "target_outranks_caller")   # cannot modify someone above you
        reduced = False
        from_role = cur_role.key
        if "role_id" in d.validated_data:
            new_role = TenantRole.objects.filter(id=d.validated_data["role_id"]).first()
            if new_role is None:
                return _err("role_not_found", 404)
            if not set(new_role.permissions) <= set(ta.permissions):
                self.deny(request, "tenant.members.manage", "privilege_escalation")
            reduced = reduced or not set(cur_role.permissions) <= set(new_role.permissions)
            m.role_id = new_role.id
        status_changed = False
        if "status" in d.validated_data and d.validated_data["status"] != m.status:
            m.status, status_changed = d.validated_data["status"], True
            reduced = reduced or m.status == "suspended"
        try:
            with transaction.atomic(using="default"):
                m.save()
        except IntegrityError:
            return _err("last_owner", 409)
        except Exception as exc:  # DB guard trigger (last Owner) surfaces as a DatabaseError subclass
            if "last active tenant Owner" in str(exc):
                return _err("last_owner", 409)
            raise
        if reduced:
            revoke_member_sessions(m.principal_id, "membership_reduced")
        new_key = TenantRole.objects.get(id=m.role_id).key
        if new_key != from_role:
            audit.record("tenant.member.role_changed", actor_id=request.user.account_id, object_type="membership",
                         object_id=str(m.id), details={"from_role": from_role, "to_role": new_key})
        if status_changed:
            audit.record("tenant.member.status_changed", actor_id=request.user.account_id, object_type="membership",
                         object_id=str(m.id), details={"status": m.status})
        return Response(_member_json(m, None, None))


# ---------------------------------------------------------------------------------------------- invitations
class InvitationCreateSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    role_id = serializers.UUIDField()
    kind = serializers.ChoiceField(choices=["member", "external_party", "external_auditor"], default="member")
    membership_expires_at = serializers.DateTimeField(required=False, allow_null=True)


class InvitationListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "tenant.invitations.manage")

    def get(self, request):
        with connections["default"].cursor() as cur:
            cur.execute("SELECT * FROM idn_list_invitations()")
            rows = cur.fetchall()
        return Response({"invitations": [
            {"id": str(r[0]), "email": r[1], "role_id": str(r[2]), "kind": r[3], "created_at": r[4].isoformat(),
             "expires_at": r[5].isoformat(), "accepted": r[6] is not None, "revoked": r[7] is not None} for r in rows]})

    def post(self, request):
        self.require(request, "tenant.invitations.manage", step_up="T1")
        d = InvitationCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        v = d.validated_data
        role = TenantRole.objects.filter(id=v["role_id"]).first()
        if role is None:
            return _err("role_not_found", 404)
        ta = resolve_tenant_authz(request.user)
        if not set(role.permissions) <= set(ta.permissions):
            self.deny(request, "tenant.invitations.manage", "privilege_escalation")
        now = clock.now()
        exp = v.get("membership_expires_at")
        if v["kind"] == "external_auditor" and exp is None:
            return _err("expiry_required")
        if exp is not None and not (now < exp <= now + timedelta(days=365)):
            return _err("invalid_expiry")
        raw = new_token()
        email = normalize_email(v["email"])
        with connections["default"].cursor() as cur:
            cur.execute("SELECT idn_create_invitation(%s::uuid,%s,%s::uuid,%s,%s,%s,%s)",
                        [str(request.user.tenant_id), email, str(role.id), v["kind"], exp, hash_token(raw),
                         now + timedelta(seconds=settings.INVITATION_TTL_S)])
            inv_id = cur.fetchone()[0]
        send_mail("You have been invited to NsureGRC",
                  f"Accept your invitation: {settings.PUBLIC_BASE_URL}/accept-invitation#token={raw}\nThis link expires in 7 days.",
                  None, [email], fail_silently=False)
        audit.record("tenant.invitation.created", actor_id=request.user.account_id, object_type="invitation",
                     object_id=str(inv_id), details={"invitee_hash": keyed_identifier_hash(email), "role_key": role.key,
                                                    "kind": v["kind"]})
        return Response({"id": str(inv_id)}, status=201)  # the token is never returned by the API


class InvitationDetailView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "tenant.invitations.manage")

    def delete(self, request, pk):
        self.require(request, "tenant.invitations.manage", step_up="T1")
        with connections["default"].cursor() as cur:
            cur.execute("SELECT idn_revoke_invitation(%s::uuid)", [str(pk)])
            ok = cur.fetchone()[0]
        if not ok:
            return _err("not_found", 404)
        audit.record("tenant.invitation.revoked", actor_id=request.user.account_id, object_type="invitation", object_id=str(pk))
        return Response(status=204)


# ---------------------------------------------------------------------------------------------- support access (tenant side)
def _grants():
    with connections["default"].cursor() as cur:
        cur.execute("SELECT * FROM plt_list_grants_for_tenant()")
        cols = [c.name for c in cur.description]
        return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


def _grant_json(g: dict) -> dict:
    out = {k: (v.isoformat() if hasattr(v, "isoformat") else (str(v) if k == "id" else v)) for k, v in g.items()}
    return out


class SupportGrantListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "tenant.support.read")

    def get(self, request):
        return Response({"grants": [_grant_json(g) for g in _grants()]})


class SupportConsentSerializer(serializers.Serializer):
    restricted_class = serializers.BooleanField(required=False, default=False)


class _SupportDecisionView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "tenant.support.read")
    action = ""

    def post(self, request, pk):
        self.require(request, "tenant.support.consent", step_up="T1")
        grant = next((g for g in _grants() if str(g["id"]) == str(pk)), None)
        if grant is None:
            return _err("not_found", 404)
        restricted = False
        if self.action == "consent":
            d = SupportConsentSerializer(data=request.data or {})
            d.is_valid(raise_exception=True)
            restricted = d.validated_data["restricted_class"]
        try:
            with transaction.atomic(using="default"), connections["default"].cursor() as cur:
                cur.execute("SELECT plt_grant_tenant_decide(%s::uuid, %s, %s)", [str(pk), self.action, restricted])
        except Exception as exc:  # noqa: BLE001 - function raises 42501 for illegal transitions / non-owners
            if "only a tenant Owner" in str(exc):
                self.deny(request, "tenant.support.consent", "not_an_owner")
            return _err("illegal_transition", 409)
        uid = request.user.account_id
        if self.action == "consent":
            audit.record("tenant.support.consented", actor_id=uid, object_type="support_grant", object_id=str(pk),
                         details={"profile": grant["profile"], "restricted": restricted})
            audit.record_platform("platform.support.consented", actor_id=uid, object_type="support_grant",
                                  object_id=str(pk), details={"restricted": restricted})
        elif self.action == "deny":
            audit.record("tenant.support.denied", actor_id=uid, object_type="support_grant", object_id=str(pk))
            audit.record_platform("platform.support.denied", actor_id=uid, object_type="support_grant", object_id=str(pk))
        else:
            audit.record("tenant.support.revoked", actor_id=uid, object_type="support_grant", object_id=str(pk))
            audit.record_platform("platform.support.ended", actor_id=uid, object_type="support_grant", object_id=str(pk),
                                  details={"by": "tenant", "state": "revoked"})
        return Response({"status": "ok"})


class SupportConsentView(_SupportDecisionView):
    action = "consent"


class SupportDenyView(_SupportDecisionView):
    action = "deny"


class SupportRevokeView(_SupportDecisionView):
    action = "revoke"


# ---------------------------------------------------------------------------------------------- audit trail (tenant stream)
_EVENTS_SQL = """SELECT seq, occurred_at, actor_type, actor_id::text, on_behalf_of_grant::text, action, object_type, object_id,
  result, reason_code, details::text, encode(hash, 'hex') FROM audit.tenant_event
  WHERE tenant_id = ngrc_current_tenant() AND seq > %s ORDER BY seq LIMIT %s"""


def _event_json(r) -> dict:
    return {"seq": r[0], "occurred_at": r[1].isoformat(), "actor_type": r[2], "actor_id": r[3], "support_grant": r[4],
            "action": r[5], "object_type": r[6], "object_id": r[7], "result": r[8], "reason_code": r[9],
            "details": json.loads(r[10]), "hash": r[11]}


class AuditEventsView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "audit.read")

    def get(self, request):
        try:
            after = max(0, int(request.query_params.get("after_seq", 0)))
            limit = min(500, max(1, int(request.query_params.get("limit", 100))))
        except ValueError:
            return _err("invalid_request")
        with connections["default"].cursor() as cur:
            cur.execute(_EVENTS_SQL, [after, limit])
            rows = cur.fetchall()
        audit.record("audit.read", actor_id=request.user.account_id, details={"count": len(rows)})
        return Response({"events": [_event_json(r) for r in rows]})


class AuditExportView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "audit.export", step_up="T1")

    def get(self, request):
        with connections["default"].cursor() as cur:
            cur.execute(_EVENTS_SQL, [0, 10000])
            rows = cur.fetchall()
            cur.execute("SELECT seq, encode(head_hash,'hex'), issued_at, key_id, algorithm, encode(signature,'hex') "
                        "FROM audit.checkpoint ORDER BY seq")
            cps = cur.fetchall()
        pub = None
        try:
            from ngrc.audit.signer import get_signer

            pub = get_signer().public_key_raw().hex()
        except Exception:  # noqa: BLE001 - signer not configured in this process
            pub = None
        audit.record("audit.export", actor_id=request.user.account_id, details={"count": len(rows)})
        body = {"format": "ngrc-audit-export-v1", "tenant_id": str(request.user.tenant_id),
                "events": [_event_json(r) for r in rows],
                "checkpoints": [{"seq": c[0], "head_hash": c[1], "issued_at": c[2].isoformat(), "key_id": c[3],
                                 "algorithm": c[4], "signature": c[5]} for c in cps],
                "signing_public_key_hex": pub,
                "verification": "Recompute each event hash with the documented construction (NGRC-AUDIT-v1), check prev_hash "
                                "linkage from the genesis hash, then verify checkpoint signatures against the signing key."}
        body["sha256"] = hashlib.sha256(json.dumps(body["events"], sort_keys=True).encode()).hexdigest()
        return Response(body)


_ = perm  # catalogue import side effects (registration) must happen before urls are loaded


# ------------------------------------------------------------------------------------ lost-factor recovery approvals (F-ATH-015)
def _recovery_requests() -> list[dict]:
    cols = ("id", "account_id", "display_name", "email", "kind", "state", "created_at", "expires_at", "approved_at", "cooling_until")
    with connections["default"].cursor() as cur:
        cur.execute("SELECT id, account_id, display_name, email, kind, state, created_at, expires_at, approved_at, cooling_until "
                    "FROM idn_recovery_tenant_list()")
        return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


class RecoveryListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "tenant.recovery.approve")

    def get(self, request):
        return Response({"requests": [{"id": str(r["id"]), "member": r["display_name"] or r["email"], "email": r["email"], "kind": r["kind"],
                                       "state": r["state"], "created_at": r["created_at"].isoformat(), "expires_at": r["expires_at"].isoformat(),
                                       "cooling_until": r["cooling_until"].isoformat() if r["cooling_until"] else None}
                                      for r in _recovery_requests()]})


class _RecoveryDecisionView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "tenant.recovery.approve", step_up="T1")
    action = ""

    def post(self, request, pk):
        from ngrc.iam import services as idn

        req = next((r for r in _recovery_requests() if str(r["id"]) == str(pk)), None)
        if req is None:
            return _err("not_found", 404)
        try:
            with transaction.atomic(using="default"), connections["default"].cursor() as cur:
                cur.execute("SELECT account_id, cooling_until FROM idn_recovery_tenant_decide(%s::uuid, %s)", [str(pk), self.action])
                account_id, cooling_until = cur.fetchone()
        except Exception as exc:  # noqa: BLE001 - the function raises 42501 for self-approval, wrong state, non-admins
            if "own recovery" in str(exc):
                self.deny(request, "tenant.recovery.approve", "self_approval")
            return _err("illegal_transition", 409)
        uid = request.user.account_id
        name = "auth.recovery.approved" if self.action == "approve" else "auth.recovery.denied"
        audit.record(name, actor_id=uid, object_type="recovery_request", object_id=str(pk), details={"kind": req["kind"]})
        audit.record_platform(name, actor_id=uid, object_type="recovery_request", object_id=str(pk), details={"kind": req["kind"]})
        target = idn.Account.objects.using("auth").filter(pk=account_id).first()
        if target is not None:
            if self.action == "approve":
                idn.send_notice(target, "Your NsureGRC sign-in recovery was approved",
                                f"A tenant administrator approved your recovery. You can complete it after {cooling_until.isoformat()}. "
                                "If you did not ask for this, cancel it now with the link in the earlier e-mail, or sign in and cancel it from your account.")
            else:
                idn.send_notice(target, "Your NsureGRC sign-in recovery was declined", "A tenant administrator declined your recovery request.")
        return Response({"status": "ok", "cooling_until": cooling_until.isoformat() if self.action == "approve" else None})


class RecoveryApproveView(_RecoveryDecisionView):
    action = "approve"


class RecoveryDenyView(_RecoveryDecisionView):
    action = "deny"
