"""D-P4-004: policies, objectives and issues - each object's transition graph (including every reopen
edge), Issue's deliberate absence of a verification gate on closing, and tenant isolation."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.core.context import tenant_context
from ngrc.governance import services as gov_services
from ngrc.governance.models import Issue, Objective, Policy

pytestmark = pytest.mark.security


def test_create_and_transition_policy(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        policy = gov_services.create_policy("Access Control Policy", created_by=uuid.uuid4())
        uow.flush()
        assert policy.status == Policy.Status.DRAFT
        policy = gov_services.transition_policy(policy, Policy.Status.ACTIVE, actor_id=uuid.uuid4())
        assert policy.status == Policy.Status.ACTIVE
        policy = gov_services.transition_policy(policy, Policy.Status.RETIRED, actor_id=uuid.uuid4())
        assert policy.status == Policy.Status.RETIRED
        policy = gov_services.transition_policy(policy, Policy.Status.ACTIVE, actor_id=uuid.uuid4())
        assert policy.status == Policy.Status.ACTIVE


def test_policy_cannot_skip_draft_to_retired(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        policy = gov_services.create_policy("Access Control Policy", created_by=uuid.uuid4())
        uow.flush()
        with pytest.raises(gov_services.GovernanceError, match="invalid_transition"):
            gov_services.transition_policy(policy, Policy.Status.RETIRED, actor_id=uuid.uuid4())


def test_create_and_transition_objective(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        objective = gov_services.create_objective("Reduce critical findings by 50%", created_by=uuid.uuid4())
        uow.flush()
        assert objective.status == Objective.Status.OPEN
        objective = gov_services.transition_objective(objective, Objective.Status.ACHIEVED, actor_id=uuid.uuid4())
        assert objective.status == Objective.Status.ACHIEVED
        objective = gov_services.transition_objective(objective, Objective.Status.OPEN, actor_id=uuid.uuid4())
        assert objective.status == Objective.Status.OPEN


def test_objective_can_be_missed_and_reopened(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        objective = gov_services.create_objective("Reduce critical findings by 50%", created_by=uuid.uuid4())
        uow.flush()
        objective = gov_services.transition_objective(objective, Objective.Status.MISSED, actor_id=uuid.uuid4())
        assert objective.status == Objective.Status.MISSED
        objective = gov_services.transition_objective(objective, Objective.Status.OPEN, actor_id=uuid.uuid4())
        assert objective.status == Objective.Status.OPEN


def test_raise_and_transition_issue_through_close_with_no_verification_gate(tenant_a):
    """D-P4-004: unlike Finding, Issue's close needs no prior verification state."""
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        issue = gov_services.raise_issue("Vendor contract renewal overdue", severity=Issue.Severity.MEDIUM,
                                          created_by=uuid.uuid4())
        uow.flush()
        assert issue.status == Issue.Status.OPEN
        issue = gov_services.transition_issue(issue, Issue.Status.IN_PROGRESS, actor_id=uuid.uuid4())
        issue = gov_services.transition_issue(issue, Issue.Status.RESOLVED, actor_id=uuid.uuid4())
        issue = gov_services.transition_issue(issue, Issue.Status.CLOSED, actor_id=uuid.uuid4())
        assert issue.status == Issue.Status.CLOSED
        issue = gov_services.transition_issue(issue, Issue.Status.OPEN, actor_id=uuid.uuid4())
        assert issue.status == Issue.Status.OPEN


def test_issue_cannot_skip_in_progress(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        issue = gov_services.raise_issue("Vendor contract renewal overdue", severity=Issue.Severity.LOW,
                                          created_by=uuid.uuid4())
        uow.flush()
        with pytest.raises(gov_services.GovernanceError, match="invalid_transition"):
            gov_services.transition_issue(issue, Issue.Status.RESOLVED, actor_id=uuid.uuid4())


def test_a_tenant_cannot_see_another_tenants_governance_records(tenant_a, tenant_b):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        policy = gov_services.create_policy("Access Control Policy", created_by=uuid.uuid4())
        objective = gov_services.create_objective("Reduce critical findings by 50%", created_by=uuid.uuid4())
        issue = gov_services.raise_issue("Vendor contract renewal overdue", severity=Issue.Severity.LOW,
                                          created_by=uuid.uuid4())
        uow.flush()
        policy_id, objective_id, issue_id = policy.id, objective.id, issue.id
    with tenant_context(tenant_b.id):
        assert not Policy.objects.filter(id=policy_id).exists()
        assert not Objective.objects.filter(id=objective_id).exists()
        assert not Issue.objects.filter(id=issue_id).exists()
