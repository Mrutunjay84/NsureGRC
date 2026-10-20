"""P2-4 / H-01: tighten `plt_support_grant_guard` so the database is at least as strict as the application.

Weaknesses found when the Phase 1 trigger was re-reviewed (each has a regression test in tests/test_support_grant_db_guard.py):

1. INSERT accepted `platform_admin` as requester; the application (DEF-07) and D-P0-005 allow only Platform Support. Requester must
   now hold `platform_support` AND be an active account (a disabled operator cannot open new requests).
2. The "same state" branch returned without checking anything, so `ngrc_ops` (which may UPDATE the decision/time columns) could,
   WITHOUT any state change, extend `expires_at` of an active grant, rewrite `activated_at`/`approved_at`/`ended_at`, or plant an
   unvalidated approver. Because `audit.append_tenant_event` trusts `plt_support_access_grant.expires_at` to accept `support.action`
   events, an extended expiry also widened the window in which the tenant audit stream accepts operator actions.
   Rules now: the decision/time columns are write-once; `expires_at` may only move EARLIER while the grant is active; every value is
   set only together with its matching transition (the single same-state write that remains is the recorded FIRST break-glass
   approval, which is validated in full).
3. INSERT did not reject pre-set `approved_at`, `consented_at`, `ended_at`, `ended_by_type`, a non-array `scope`, or a scope on the
   metadata-only profile.
4. Approvers / requester were checked for the ROLE only. Accounts must be `active`, and the requester must still hold
   `platform_support` when the grant is activated.
5. Consent columns could change on any transition by the owner role; they now change only on approved -> tenant_consented.

Replaces the function body only (CREATE OR REPLACE): trigger, grants and column privileges are unchanged.
"""
from importlib import import_module

from django.db import migrations

_REQUESTER_OK = """EXISTS (SELECT 1 FROM plt_operator_role r JOIN plt_operator_account a ON a.id = r.operator_id
                   WHERE r.operator_id = {who} AND r.role = 'platform_support' AND a.status = 'active')"""
_HOLDS = """EXISTS (SELECT 1 FROM plt_operator_role r JOIN plt_operator_account a ON a.id = r.operator_id
                   WHERE r.operator_id = {who} AND r.role = '{role}' AND a.status = 'active')"""

GUARD_V2 = f"""CREATE OR REPLACE FUNCTION plt_support_grant_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v_max int;
  v_by_owner boolean := (current_user = 'ngrc_owner');   -- true only inside our SECURITY DEFINER functions
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'requested' THEN RAISE EXCEPTION 'grant must start in state requested' USING ERRCODE = '23514'; END IF;
    IF btrim(NEW.ticket_ref) = '' OR btrim(NEW.reason) = '' THEN
      RAISE EXCEPTION 'ticket reference and reason are mandatory' USING ERRCODE = '23514';
    END IF;
    v_max := CASE WHEN NEW.break_glass THEN 120 ELSE 480 END;
    IF NEW.duration_minutes < 1 OR NEW.duration_minutes > v_max THEN
      RAISE EXCEPTION 'duration outside permitted maximum' USING ERRCODE = '23514';
    END IF;
    IF NEW.approver_id IS NOT NULL OR NEW.second_approver_id IS NOT NULL OR NEW.consent_user_id IS NOT NULL
       OR NEW.activated_at IS NOT NULL OR NEW.expires_at IS NOT NULL OR NEW.restricted_class_consent
       OR NEW.approved_at IS NOT NULL OR NEW.consented_at IS NOT NULL OR NEW.ended_at IS NOT NULL OR NEW.ended_by_type <> '' THEN
      RAISE EXCEPTION 'approval/consent/activation/end fields must be empty on insert' USING ERRCODE = '23514';
    END IF;
    IF jsonb_typeof(NEW.scope::jsonb) IS DISTINCT FROM 'array'
       OR (NEW.profile = 'diagnostic_metadata' AND jsonb_array_length(NEW.scope::jsonb) > 0) THEN
      RAISE EXCEPTION 'scope must be a list and must be empty for the metadata-only profile' USING ERRCODE = '23514';
    END IF;
    IF NOT {_REQUESTER_OK.format(who="NEW.requester_id")} THEN
      RAISE EXCEPTION 'requester must be an active Platform Support operator' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;

  -- UPDATE: identity of the request is immutable
  IF NEW.id <> OLD.id OR NEW.subject_tenant_id <> OLD.subject_tenant_id OR NEW.requester_id <> OLD.requester_id
     OR NEW.ticket_ref <> OLD.ticket_ref OR NEW.reason <> OLD.reason OR NEW.profile <> OLD.profile
     OR NEW.scope::text <> OLD.scope::text OR NEW.duration_minutes <> OLD.duration_minutes
     OR NEW.break_glass <> OLD.break_glass OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'grant request fields are immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.state IN ('expired', 'revoked', 'denied') THEN
    RAISE EXCEPTION 'grant is in a terminal state' USING ERRCODE = '42501';
  END IF;
  -- consent columns change only inside the tenant-side SECURITY DEFINER functions, and only on approved -> tenant_consented
  IF (NEW.consent_user_id IS DISTINCT FROM OLD.consent_user_id OR NEW.consented_at IS DISTINCT FROM OLD.consented_at
      OR NEW.restricted_class_consent IS DISTINCT FROM OLD.restricted_class_consent)
     AND NOT (v_by_owner AND OLD.state = 'approved' AND NEW.state = 'tenant_consented') THEN
    RAISE EXCEPTION 'tenant consent can only be recorded by the tenant' USING ERRCODE = '42501';
  END IF;

  -- decision / time columns are write-once ...
  IF OLD.approver_id IS NOT NULL AND NEW.approver_id IS DISTINCT FROM OLD.approver_id THEN
    RAISE EXCEPTION 'approver cannot be changed' USING ERRCODE = '42501'; END IF;
  IF OLD.second_approver_id IS NOT NULL AND NEW.second_approver_id IS DISTINCT FROM OLD.second_approver_id THEN
    RAISE EXCEPTION 'second approver cannot be changed' USING ERRCODE = '42501'; END IF;
  IF OLD.approved_at IS NOT NULL AND NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
    RAISE EXCEPTION 'approval time cannot be changed' USING ERRCODE = '42501'; END IF;
  IF OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at THEN
    RAISE EXCEPTION 'activation time cannot be changed' USING ERRCODE = '42501'; END IF;
  -- ... except that an ACTIVE grant may be cut short (never extended)
  IF OLD.expires_at IS NOT NULL AND NEW.expires_at IS DISTINCT FROM OLD.expires_at
     AND NOT (OLD.state = 'active' AND NEW.state = 'active' AND NEW.expires_at IS NOT NULL AND NEW.expires_at < OLD.expires_at) THEN
    RAISE EXCEPTION 'expiry can only be shortened while the grant is active' USING ERRCODE = '42501'; END IF;

  -- ... and each is set only together with its matching transition
  IF (NEW.approver_id IS DISTINCT FROM OLD.approver_id OR NEW.approved_at IS DISTINCT FROM OLD.approved_at)
     AND NOT (OLD.state = 'requested' AND (NEW.state = 'approved' OR (NEW.state = 'requested' AND NEW.break_glass))) THEN
    RAISE EXCEPTION 'approval fields change only when the request is approved' USING ERRCODE = '42501'; END IF;
  IF NEW.second_approver_id IS DISTINCT FROM OLD.second_approver_id
     AND NOT (OLD.state = 'requested' AND NEW.state = 'approved' AND NEW.break_glass) THEN
    RAISE EXCEPTION 'second approver is recorded only with the break-glass approval' USING ERRCODE = '42501'; END IF;
  IF (NEW.activated_at IS DISTINCT FROM OLD.activated_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at)
     AND NOT (NEW.state = 'active' AND (OLD.state <> 'active' OR NEW.expires_at < OLD.expires_at)) THEN
    RAISE EXCEPTION 'activation fields change only when the grant is activated' USING ERRCODE = '42501'; END IF;
  IF (NEW.ended_at IS DISTINCT FROM OLD.ended_at OR NEW.ended_by_type IS DISTINCT FROM OLD.ended_by_type)
     AND NEW.state NOT IN ('denied', 'revoked', 'expired') THEN
    RAISE EXCEPTION 'end fields change only when the grant ends' USING ERRCODE = '42501'; END IF;

  -- whoever is recorded as (first) approver must be a different, active Platform Security operator
  IF NEW.approver_id IS DISTINCT FROM OLD.approver_id THEN
    IF NEW.approver_id IS NULL OR NEW.approved_at IS NULL THEN RAISE EXCEPTION 'approval incomplete' USING ERRCODE = '23514'; END IF;
    IF NEW.approver_id = NEW.requester_id THEN
      RAISE EXCEPTION 'requester cannot approve own request' USING ERRCODE = '42501'; END IF;
    IF NOT {_HOLDS.format(who="NEW.approver_id", role="platform_security")} THEN
      RAISE EXCEPTION 'approver must be an active Platform Security operator' USING ERRCODE = '42501'; END IF;
  END IF;

  IF NEW.state = OLD.state THEN
    RETURN NEW;   -- every remaining same-state change was constrained above (first break-glass approval, expiry cut)
  END IF;

  IF OLD.state = 'requested' AND NEW.state = 'approved' THEN
    IF NEW.approver_id IS NULL OR NEW.approved_at IS NULL THEN RAISE EXCEPTION 'approval incomplete' USING ERRCODE = '23514'; END IF;
    IF NEW.approver_id = NEW.requester_id THEN
      RAISE EXCEPTION 'requester cannot approve own request' USING ERRCODE = '42501'; END IF;
    IF NOT {_HOLDS.format(who="NEW.approver_id", role="platform_security")} THEN
      RAISE EXCEPTION 'approver must be an active Platform Security operator' USING ERRCODE = '42501'; END IF;
    IF NEW.break_glass THEN
      IF NEW.second_approver_id IS NULL OR NEW.second_approver_id IN (NEW.requester_id, NEW.approver_id) THEN
        RAISE EXCEPTION 'break-glass needs a distinct second approver' USING ERRCODE = '42501'; END IF;
      IF NOT {_HOLDS.format(who="NEW.second_approver_id", role="platform_admin")} THEN
        RAISE EXCEPTION 'second approver must be an active Platform Admin' USING ERRCODE = '42501'; END IF;
    ELSIF NEW.second_approver_id IS NOT NULL THEN
      RAISE EXCEPTION 'second approver only applies to break-glass' USING ERRCODE = '23514';
    END IF;
  ELSIF OLD.state = 'approved' AND NEW.state = 'tenant_consented' THEN
    IF NEW.break_glass THEN RAISE EXCEPTION 'break-glass grants skip tenant consent' USING ERRCODE = '42501'; END IF;
    IF NOT v_by_owner OR NEW.consent_user_id IS NULL OR NEW.consented_at IS NULL THEN
      RAISE EXCEPTION 'tenant consent must be recorded by the tenant' USING ERRCODE = '42501'; END IF;
  ELSIF (OLD.state = 'tenant_consented' AND NEW.state = 'active' AND NOT OLD.break_glass)
        OR (OLD.state = 'approved' AND NEW.state = 'active' AND OLD.break_glass) THEN
    IF NEW.activated_at IS NULL OR NEW.expires_at IS NULL THEN RAISE EXCEPTION 'activation incomplete' USING ERRCODE = '23514'; END IF;
    IF abs(extract(epoch FROM (NEW.activated_at - now()))) > 120 THEN
      RAISE EXCEPTION 'activation time must be current' USING ERRCODE = '23514'; END IF;
    IF NEW.expires_at <= NEW.activated_at
       OR NEW.expires_at > NEW.activated_at + (OLD.duration_minutes * interval '1 minute') THEN
      RAISE EXCEPTION 'expiry exceeds granted duration' USING ERRCODE = '23514'; END IF;
    IF NOT {_REQUESTER_OK.format(who="NEW.requester_id")} THEN
      RAISE EXCEPTION 'requester no longer holds Platform Support' USING ERRCODE = '42501'; END IF;
  ELSIF OLD.state = 'active' AND NEW.state IN ('expired', 'revoked') THEN
    IF NEW.ended_at IS NULL THEN RAISE EXCEPTION 'ended_at required' USING ERRCODE = '23514'; END IF;
  ELSIF OLD.state IN ('requested', 'approved', 'tenant_consented') AND NEW.state IN ('denied', 'revoked') THEN
    IF NEW.ended_at IS NULL THEN RAISE EXCEPTION 'ended_at required' USING ERRCODE = '23514'; END IF;
  ELSE
    RAISE EXCEPTION 'illegal grant transition % -> %', OLD.state, NEW.state USING ERRCODE = '42501';
  END IF;
  IF NEW.state IN ('denied', 'revoked', 'expired') AND NEW.ended_by_type = '' THEN
    RAISE EXCEPTION 'ended_by_type required' USING ERRCODE = '23514'; END IF;
  IF NEW.ended_by_type = 'tenant' AND NOT v_by_owner THEN
    RAISE EXCEPTION 'tenant-ended grants are recorded only via the tenant functions' USING ERRCODE = '42501'; END IF;
  RETURN NEW;
END $$"""



def _phase1_guard() -> str:
    """The Phase 1 function body, taken from migration 0002 (reverse only; it re-opens the weaknesses listed above)."""
    forward = import_module("ngrc.control_plane.migrations.0002_security").FORWARD
    return next(s for s in forward if s.startswith("CREATE FUNCTION plt_support_grant_guard()")).replace(
        "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)


class Migration(migrations.Migration):
    dependencies = [("control_plane", "0003_provision_invitation_kind")]
    operations = [migrations.RunSQL([GUARD_V2], reverse_sql=[_phase1_guard()])]
