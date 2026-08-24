"""Guided methodology workflow: phase routing, gating, and branch jumps.

Covers evaluate_phase_progress over MethodologyProfile objects:
- checklist_categories routing (data-driven, first-phase-wins)
- depends_on blocking + blocked_reason
- prerequisites as non-linear unlock branches (target_status / evidence_type)
- evidence_required completion gates
"""

import pytest

from synapse.assessment.engine import (
    NextAction,
    PhaseProgress,
    PhaseStatus,
    evaluate_phase_progress,
)
from synapse.db.repository import DatabaseRepository
from synapse.methodology.engine import MethodologyEngine
from synapse.methodology.profile import (
    MethodologyProfile,
    PhaseDefinition,
    PrerequisiteCondition,
)
from synapse.models import (
    ChecklistStatus,
    Evidence,
    ProofType,
    TargetStatus,
)


def make_profile(**phase_kwargs) -> MethodologyProfile:
    """Builds a small linear profile: recon -> enum -> exploit -> privesc."""
    defaults = [
        dict(id="recon", name="Recon", order=1, checklist_categories=["recon"]),
        dict(
            id="enum", name="Enumeration", order=2, checklist_categories=["enum"],
            depends_on=["recon"],
        ),
        dict(
            id="exploit", name="Exploitation", order=3, checklist_categories=["exploit"],
            depends_on=["enum"], evidence_required=["user_flag"],
            prerequisites=[
                PrerequisiteCondition(condition_type="evidence_type", value="user_flag"),
                PrerequisiteCondition(condition_type="target_status", value="foothold"),
            ],
        ),
        dict(
            id="privesc", name="PrivEsc", order=4, checklist_categories=["privesc"],
            depends_on=["exploit"],
            prerequisites=[
                PrerequisiteCondition(condition_type="target_status", value="foothold"),
            ],
        ),
    ]
    phases = [PhaseDefinition(**{**d, **phase_kwargs.get(d["id"], {})}) for d in defaults]
    return MethodologyProfile(id="test", name="Test Profile", phases=phases)


def evidence_of(proof_type: ProofType, title: str = "Flag") -> Evidence:
    return Evidence(target_id=1, proof_type=proof_type, title=title)


@pytest.fixture
def repo():
    return DatabaseRepository(":memory:")


def test_checks_route_by_category(repo):
    t = repo.add_or_get_target("10.0.0.1")
    svc = repo.add_or_update_service(t.id, 80, "tcp", "http")
    repo.add_checklist_item(svc.id, "Ping sweep", category="recon", status=ChecklistStatus.CHECKED)
    repo.add_checklist_item(svc.id, "Dirb", category="enum", status=ChecklistStatus.TODO)
    target = repo.get_target_by_id(t.id)

    progress = evaluate_phase_progress(target, make_profile(), [])
    assert progress["recon"].completed_checks == ["Ping sweep"]
    assert progress["enum"].pending_checks == ["Dirb"]
    # Categories no phase claims are simply not part of the guided view.
    assert all(p.total_checks == 0 for pid, p in progress.items() if pid not in ("recon", "enum"))


def test_dependency_blocking_with_reason(repo):
    t = repo.add_or_get_target("10.0.0.2")
    svc = repo.add_or_update_service(t.id, 22, "tcp", "ssh")
    repo.add_checklist_item(svc.id, "SSH enum", category="enum", status=ChecklistStatus.TODO)
    target = repo.get_target_by_id(t.id)

    progress = evaluate_phase_progress(target, make_profile(), [])
    assert progress["exploit"].phase_status == PhaseStatus.BLOCKED
    assert "enum" in progress["exploit"].blocked_reason
    # Exploit carries an evidence_required gate (user_flag), so even once its
    # checks resolve it stays incomplete — and transitively blocks privesc.
    assert progress["privesc"].phase_status == PhaseStatus.BLOCKED


def test_recommended_actions_carry_rationale_and_context(repo):
    t = repo.add_or_get_target("10.0.0.3")
    svc = repo.add_or_update_service(t.id, 445, "tcp", "smb")
    repo.add_checklist_item(svc.id, "Null session", category="enum", status=ChecklistStatus.FINDING)
    repo.add_checklist_item(svc.id, "Share dump", category="enum", status=ChecklistStatus.TODO)
    target = repo.get_target_by_id(t.id)

    progress = evaluate_phase_progress(target, make_profile(), [])
    actions = progress["enum"].recommended_actions
    kinds = {a.kind for a in actions}
    assert "exploit" in kinds  # finding surfaces an exploit action...
    assert any(a.rationale for a in actions)  # ...and every action says why
    exploit_action = next(a for a in actions if a.kind == "exploit")
    assert exploit_action.port == 445


def test_evidence_required_gates_completion(repo):
    t = repo.add_or_get_target("10.0.0.4")
    svc = repo.add_or_update_service(t.id, 22, "tcp", "ssh")
    repo.add_checklist_item(svc.id, "SSH login", category="exploit", status=ChecklistStatus.CHECKED)
    target = repo.get_target_by_id(t.id)

    # Checks resolved but user_flag not captured: exploitation stays open.
    progress = evaluate_phase_progress(target, make_profile(), [])
    assert progress["exploit"].phase_status == PhaseStatus.IN_PROGRESS

    # Capturing the flag completes the phase.
    progress = evaluate_phase_progress(target, make_profile(), [evidence_of(ProofType.USER_FLAG)])
    assert progress["exploit"].phase_status == PhaseStatus.COMPLETED
    assert progress["exploit"].evidence == ["Flag"]


def test_prerequisite_jumps_the_queue_nonlinearly(repo):
    """Foothold status unlocks privesc even though its dependency is blocked."""
    profile = MethodologyProfile(
        id="jump",
        name="Jump",
        phases=[
            PhaseDefinition(id="enum", name="Enum", order=1, checklist_categories=["enum"]),
            PhaseDefinition(
                id="privesc", name="PrivEsc", order=2, checklist_categories=["privesc"],
                depends_on=["enum"],
                prerequisites=[
                    PrerequisiteCondition(condition_type="target_status", value="foothold"),
                ],
            ),
        ],
    )
    t = repo.add_or_get_target("10.0.0.5")
    svc = repo.add_or_update_service(t.id, 3389, "tcp", "rdp")
    repo.add_checklist_item(svc.id, "SSH enum", category="enum", status=ChecklistStatus.TODO)
    repo.add_checklist_item(svc.id, "WinPEAS", category="privesc", status=ChecklistStatus.TODO)
    target = repo.get_target_by_id(t.id)

    # Discovered: privesc is gated behind the unfinished enum phase.
    progress = evaluate_phase_progress(target, profile, [])
    assert progress["privesc"].phase_status == PhaseStatus.BLOCKED

    # Foothold satisfies the prerequisite: privesc jumps the queue.
    repo.update_target_status(t.id, TargetStatus.FOOTHOLD)
    target = repo.get_target_by_id(t.id)
    progress = evaluate_phase_progress(target, profile, [])
    assert progress["privesc"].phase_status == PhaseStatus.NOT_STARTED
    assert progress["enum"].phase_status == PhaseStatus.NOT_STARTED


def test_pwned_keeps_foothold_gates_open(repo):
    t = repo.add_or_get_target("10.0.0.6")
    repo.update_target_status(t.id, TargetStatus.PWNED)
    target = repo.get_target_by_id(t.id)
    progress = evaluate_phase_progress(target, make_profile(), [])
    assert progress["privesc"].phase_status != PhaseStatus.BLOCKED


def test_bundled_profiles_load_and_are_well_formed():
    engine = MethodologyEngine()
    profiles = engine.get_available_profiles()
    ids = {p.id for p in profiles}
    assert {"ejptv2", "network_pentest", "web_pentest", "htb_lab"} <= ids

    for profile in profiles:
        phase_ids = [p.id for p in profile.phases]
        assert len(phase_ids) == len(set(phase_ids)), f"{profile.id}: duplicate phase ids"
        for p in profile.phases:
            for dep in p.depends_on:
                assert dep in phase_ids, f"{profile.id}/{p.id}: unknown dependency {dep}"
        # No eJPT-specific behavior may leak into evaluation: every profile is
        # plain data with categories partitioned across its own phases.
        claimed = [c for p in profile.phases for c in p.checklist_categories]
        assert len(claimed) == len(set(claimed)), f"{profile.id}: category claimed twice"


def _owner_of(profile: MethodologyProfile, category: str):
    return next(
        (p for p in profile.ordered_phases() if category in (p.checklist_categories or [])),
        None,
    )


@pytest.mark.parametrize("profile_id", ["ejptv2", "network_pentest", "web_pentest", "htb_lab"])
def test_bundled_profile_sequential_completion(profile_id):
    """Each bundled profile walks a target through recon→enum→vuln→exploit."""
    engine = MethodologyEngine()
    profile = engine.profile_loader.get_profile(profile_id)
    repo = DatabaseRepository(":memory:")
    t = repo.add_or_get_target("10.10.10.10")
    svc = repo.add_or_update_service(t.id, 80, "tcp", "http")
    for cat in ("recon", "enum", "vuln_check"):
        repo.add_checklist_item(svc.id, f"Check {cat}", category=cat, status=ChecklistStatus.TODO)

    def evaluate():
        return evaluate_phase_progress(
            repo.get_target_by_id(t.id), profile, repo.list_evidence(t.id)
        )

    # Fresh target: first phase pending, downstream phases blocked.
    progress = evaluate()
    first = profile.ordered_phases()[0]
    assert progress[first.id].pending_checks
    assert any(p.phase_status == PhaseStatus.BLOCKED for p in progress.values())

    # Resolving recon + enum + vuln checks unblocks and completes those phases.
    for cat in ("recon", "enum", "vuln_check"):
        owner = _owner_of(profile, cat)
        if owner is None:
            continue
        target = repo.get_target_by_id(t.id)
        for c in [c for s in target.services for c in s.checklists if c.category == cat]:
            repo.update_checklist_status(c.id, ChecklistStatus.CHECKED)

    progress = evaluate()
    for pid in ("target_mapping", "host_discovery", "port_scan"):
        if pid in progress:
            assert progress[pid].phase_status == PhaseStatus.COMPLETED

    # Exploitation is unlocked (deps complete) but gated on user_flag evidence.
    exploit_phase = _owner_of(profile, "exploit")
    if exploit_phase and exploit_phase.evidence_required:
        repo.add_checklist_item(svc.id, "Run exploit", category="exploit", status=ChecklistStatus.CHECKED)
        progress = evaluate()
        assert progress[exploit_phase.id].phase_status == PhaseStatus.IN_PROGRESS
        assert progress[exploit_phase.id].evidence == []

        repo.add_evidence(t.id, title="user.txt", proof_type=ProofType.USER_FLAG)
        repo.update_target_status(t.id, TargetStatus.FOOTHOLD)
        progress = evaluate()
        assert progress[exploit_phase.id].phase_status == PhaseStatus.COMPLETED
