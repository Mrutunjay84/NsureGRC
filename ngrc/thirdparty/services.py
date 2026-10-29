"""Third Parties (D-P7-001). All plain TEN writes (no new DB role). Callers must already be inside the
target tenant's `tenant_context()` and have checked `third_party.manage` - services trust an
already-authorized caller, same convention as `ngrc.governance.services`."""
from __future__ import annotations

from ngrc.audit import service as audit

from .models import ThirdPartyAssessment, ThirdPartyEntity, ThirdPartyRepresentative, ThirdPartySolution


class ThirdPartyError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def create_entity(name: str, *, category: str, criticality: str, created_by, description: str = "") -> ThirdPartyEntity:
    entity = ThirdPartyEntity.objects.create(
        name=name, category=category, criticality=criticality, description=description, created_by=created_by,
    )
    audit.record("third_party.entity.created", actor_id=created_by, object_type="third_party_entity",
                 object_id=str(entity.id), details={})
    return entity


def create_representative(entity: ThirdPartyEntity, name: str, email: str, *, created_by, role: str = "",
                          phone: str = "") -> ThirdPartyRepresentative:
    rep = ThirdPartyRepresentative.objects.create(
        entity=entity, name=name, email=email, role=role, phone=phone, created_by=created_by,
    )
    audit.record("third_party.representative.created", actor_id=created_by, object_type="third_party_representative",
                 object_id=str(rep.id), details={})
    return rep


def create_solution(entity: ThirdPartyEntity, name: str, *, created_by, description: str = "",
                    data_classification_note: str = "") -> ThirdPartySolution:
    sol = ThirdPartySolution.objects.create(
        entity=entity, name=name, description=description, data_classification_note=data_classification_note,
        created_by=created_by,
    )
    audit.record("third_party.solution.created", actor_id=created_by, object_type="third_party_solution",
                 object_id=str(sol.id), details={})
    return sol


def create_assessment(entity: ThirdPartyEntity, *, created_by, solution: ThirdPartySolution | None = None,
                      scope: str = "", risk_rating: str = "", assessor=None, started_at=None) -> ThirdPartyAssessment:
    if solution is not None and solution.entity_id != entity.id:
        raise ThirdPartyError("solution_entity_mismatch")
    a = ThirdPartyAssessment.objects.create(
        entity=entity, solution=solution, scope=scope, risk_rating=risk_rating, assessor=assessor,
        started_at=started_at, created_by=created_by,
    )
    audit.record("third_party.assessment.created", actor_id=created_by, object_type="third_party_assessment",
                 object_id=str(a.id), details={})
    return a


_ALLOWED_ASSESSMENT_TRANSITIONS: dict[str, set[str]] = {
    ThirdPartyAssessment.Status.DRAFT: {ThirdPartyAssessment.Status.IN_PROGRESS},
    ThirdPartyAssessment.Status.IN_PROGRESS: {ThirdPartyAssessment.Status.COMPLETED},
    ThirdPartyAssessment.Status.COMPLETED: {ThirdPartyAssessment.Status.DRAFT},
}


def transition_assessment(assessment: ThirdPartyAssessment, new_status: str, *, actor_id,
                          completed_at=None) -> ThirdPartyAssessment:
    allowed = _ALLOWED_ASSESSMENT_TRANSITIONS.get(assessment.status, set())
    if new_status not in allowed:
        raise ThirdPartyError(f"invalid_transition:{assessment.status}->{new_status}")
    from_status = assessment.status
    assessment.status = new_status
    update_fields = ["status"]
    if new_status == ThirdPartyAssessment.Status.COMPLETED:
        assessment.completed_at = completed_at
        update_fields.append("completed_at")
    assessment.save(update_fields=update_fields)
    audit.record("third_party.assessment.transitioned", actor_id=actor_id, object_type="third_party_assessment",
                 object_id=str(assessment.id), details={"from_status": from_status, "to_status": new_status})
    return assessment
