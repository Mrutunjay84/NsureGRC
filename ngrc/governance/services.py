"""Policies, objectives and issues (D-P4-004).

All plain TEN writes (no new DB role). Callers must already be inside the target tenant's
`tenant_context()` and have checked `governance.manage` - services trust an already-authorized caller, same
convention as `ngrc.controls.services`/`ngrc.risk.services`.
"""
from __future__ import annotations

from ngrc.audit import service as audit

from .models import Issue, Objective, Policy


class GovernanceError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def create_policy(title: str, *, created_by, description: str = "", owner=None, effective_date=None,
                   next_review_date=None) -> Policy:
    policy = Policy.objects.create(
        title=title, description=description, owner=owner, effective_date=effective_date,
        next_review_date=next_review_date, created_by=created_by,
    )
    audit.record("governance.policy.created", actor_id=created_by, object_type="policy",
                 object_id=str(policy.id), details={})
    return policy


_ALLOWED_POLICY_TRANSITIONS: dict[str, set[str]] = {
    Policy.Status.DRAFT: {Policy.Status.ACTIVE},
    Policy.Status.ACTIVE: {Policy.Status.RETIRED},
    Policy.Status.RETIRED: {Policy.Status.ACTIVE},
}


def transition_policy(policy: Policy, new_status: str, *, actor_id) -> Policy:
    allowed = _ALLOWED_POLICY_TRANSITIONS.get(policy.status, set())
    if new_status not in allowed:
        raise GovernanceError(f"invalid_transition:{policy.status}->{new_status}")
    from_status = policy.status
    policy.status = new_status
    policy.save(update_fields=["status"])
    audit.record("governance.policy.transitioned", actor_id=actor_id, object_type="policy",
                 object_id=str(policy.id), details={"from_status": from_status, "to_status": new_status})
    return policy


def create_objective(title: str, *, created_by, description: str = "", owner=None, target_date=None) -> Objective:
    objective = Objective.objects.create(
        title=title, description=description, owner=owner, target_date=target_date, created_by=created_by,
    )
    audit.record("governance.objective.created", actor_id=created_by, object_type="objective",
                 object_id=str(objective.id), details={})
    return objective


_ALLOWED_OBJECTIVE_TRANSITIONS: dict[str, set[str]] = {
    Objective.Status.OPEN: {Objective.Status.ACHIEVED, Objective.Status.MISSED},
    Objective.Status.ACHIEVED: {Objective.Status.OPEN},
    Objective.Status.MISSED: {Objective.Status.OPEN},
}


def transition_objective(objective: Objective, new_status: str, *, actor_id) -> Objective:
    allowed = _ALLOWED_OBJECTIVE_TRANSITIONS.get(objective.status, set())
    if new_status not in allowed:
        raise GovernanceError(f"invalid_transition:{objective.status}->{new_status}")
    from_status = objective.status
    objective.status = new_status
    objective.save(update_fields=["status"])
    audit.record("governance.objective.transitioned", actor_id=actor_id, object_type="objective",
                 object_id=str(objective.id), details={"from_status": from_status, "to_status": new_status})
    return objective


def raise_issue(title: str, *, severity: str, created_by, description: str = "", owner=None, due_date=None) -> Issue:
    issue = Issue.objects.create(
        title=title, description=description, severity=severity, owner=owner, due_date=due_date,
        created_by=created_by,
    )
    audit.record("governance.issue.raised", actor_id=created_by, object_type="issue", object_id=str(issue.id),
                 details={"severity": severity})
    return issue


_ALLOWED_ISSUE_TRANSITIONS: dict[str, set[str]] = {
    Issue.Status.OPEN: {Issue.Status.IN_PROGRESS},
    Issue.Status.IN_PROGRESS: {Issue.Status.RESOLVED},
    Issue.Status.RESOLVED: {Issue.Status.CLOSED},
    Issue.Status.CLOSED: {Issue.Status.OPEN},
}


def transition_issue(issue: Issue, new_status: str, *, actor_id) -> Issue:
    """No verification gate on closing (D-P4-004) - unlike Finding, nothing in any spec document asks for
    one on Issue specifically."""
    allowed = _ALLOWED_ISSUE_TRANSITIONS.get(issue.status, set())
    if new_status not in allowed:
        raise GovernanceError(f"invalid_transition:{issue.status}->{new_status}")
    from_status = issue.status
    issue.status = new_status
    issue.save(update_fields=["status"])
    audit.record("governance.issue.transitioned", actor_id=actor_id, object_type="issue", object_id=str(issue.id),
                 details={"from_status": from_status, "to_status": new_status})
    return issue
