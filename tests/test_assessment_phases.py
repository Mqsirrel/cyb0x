import pytest
from synapse.models import TargetStatus, ChecklistStatus, ProofType
from synapse.assessment.engine import evaluate_phase_progress, PhaseProgress, PhaseStatus, NextAction
from synapse.methodology.profile import MethodologyProfile, PhaseDefinition, PrerequisiteCondition
from synapse.db.repository import DatabaseRepository


def build_profile():
    """Linear spine: recon -> enum -> exploit -> privesc, with a foothold jump."""
    return MethodologyProfile(
        id="ejptv2",
        name="eJPTv2",
        phases=[
            PhaseDefinition(id="recon", name="Recon", order=1, checklist_categories=["recon"]),
            PhaseDefinition(
                id="enum", name="Enum", order=2,
                checklist_categories=["enum"], depends_on=["recon"],
            ),
            PhaseDefinition(
                id="exploit", name="Exploit", order=3,
                checklist_categories=["exploit"], depends_on=["enum"],
                prerequisites=[
                    PrerequisiteCondition(condition_type="target_status", value="foothold"),
                    PrerequisiteCondition(condition_type="evidence_type", value="user_flag"),
                ],
            ),
            PhaseDefinition(
                id="privesc", name="PrivEsc", order=4,
                checklist_categories=["privesc"], depends_on=["exploit"],
                prerequisites=[
                    PrerequisiteCondition(condition_type="target_status", value="foothold"),
                    PrerequisiteCondition(condition_type="evidence_type", value="user_flag"),
                ],
            ),
        ],
    )


def test_phase_evaluation():
    repo = DatabaseRepository(":memory:")
    target = repo.add_or_get_target("10.0.0.1")

    svc = repo.add_or_update_service(target.id, 80)
    repo.add_checklist_item(svc.id, "Nmap scan", category="recon", status=ChecklistStatus.CHECKED)
    repo.add_checklist_item(svc.id, "Dirb", category="enum", status=ChecklistStatus.TODO)

    target = repo.get_target_by_id(target.id)

    progress = evaluate_phase_progress(target, build_profile(), repo.list_evidence(target.id))
    assert "recon" in progress
    assert progress["recon"].phase_status == PhaseStatus.COMPLETED
    assert "Nmap scan" in progress["recon"].completed_checks

    assert progress["enum"].phase_status == PhaseStatus.NOT_STARTED
    assert "Dirb" in progress["enum"].pending_checks
    assert len(progress["enum"].recommended_actions) > 0
    assert progress["enum"].recommended_actions[0].kind == "enum"


def test_nonlinear_transition():
    repo = DatabaseRepository(":memory:")
    target = repo.add_or_get_target("10.0.0.2")
    # Mark target as foothold and capture the user flag: privesc unlocks even
    # though no exploit/privesc checks exist yet.
    repo.update_target_status(target.id, TargetStatus.FOOTHOLD)
    repo.add_evidence(target.id, "User Flag", proof_type=ProofType.USER_FLAG)

    target = repo.get_target_by_id(target.id)

    progress = evaluate_phase_progress(target, build_profile(), repo.list_evidence(target.id))
    assert progress["privesc"].phase_status != PhaseStatus.BLOCKED


def test_blocked_phase():
    repo = DatabaseRepository(":memory:")
    target = repo.add_or_get_target("10.0.0.3")
    svc = repo.add_or_update_service(target.id, 22)
    repo.add_checklist_item(svc.id, "SSH enum", category="recon", status=ChecklistStatus.TODO)
    target = repo.get_target_by_id(target.id)

    profile = MethodologyProfile(
        id="tiny",
        name="Tiny",
        phases=[
            PhaseDefinition(id="recon", name="Recon", order=1, checklist_categories=["recon"]),
            PhaseDefinition(id="enum", name="Enum", order=2, checklist_categories=["enum"], depends_on=["recon"]),
        ],
    )
    progress = evaluate_phase_progress(target, profile, [])
    assert progress["recon"].phase_status == PhaseStatus.NOT_STARTED
    assert progress["enum"].phase_status == PhaseStatus.BLOCKED
