"""Full guided-workflow simulation: target to completion under a methodology.

Drives a realistic single-box engagement through the repository while asserting
phase transitions from the deterministic engine at every step:

target → recon → enumeration → finding (vuln assessment) → exploitation
       → post-exploitation/privilege escalation → verification & completion

Uses the bundled htb_lab profile (flag-gated phases exercise the evidence
gates) and verifies the nonlinear branch: foothold status unlocks privesc
before every exploit check is resolved.
"""

import pytest

from synapse.assessment.engine import PhaseStatus, evaluate_phase_progress
from synapse.db.repository import DatabaseRepository
from synapse.methodology.engine import MethodologyEngine
from synapse.models import ChecklistStatus, CredentialType, ProofType, TargetStatus


@pytest.fixture
def env(tmp_path):
    repo = DatabaseRepository(tmp_path / "guided_sim.db")
    engine = MethodologyEngine()
    profile = engine.profile_loader.get_profile("htb_lab")
    assert profile is not None
    return repo, profile


def evaluate(repo, profile):
    """Re-evaluates phase progress for the simulated box."""
    target = repo.get_target_by_ip("10.10.11.7")
    return evaluate_phase_progress(target, profile, repo.list_evidence(target.id))


def test_full_guided_assessment(env):
    repo, profile = env
    t = repo.add_or_get_target("10.10.11.7", hostname="craft.htb")

    # --- Target added: recon owns the plan; everything downstream blocked ---
    svc_http = repo.add_or_update_service(t.id, 80, "tcp", "http")
    repo.add_checklist_item(svc_http.id, "Top-1000 port scan", category="recon", status=ChecklistStatus.TODO)
    progress = evaluate(repo, profile)
    assert progress["port_scan"].phase_status == PhaseStatus.NOT_STARTED
    assert len(progress["port_scan"].recommended_actions) == 1  # pending check w/ rationale
    assert progress["service_enum"].phase_status == PhaseStatus.BLOCKED
    assert progress["root_flag"].blocked_reason

    # --- Recon resolved: enum unblocks and becomes the active objective ---
    target = repo.get_target_by_id(t.id)
    for c in [c for s in target.services for c in s.checklists if c.category == "recon"]:
        repo.update_checklist_status(c.id, ChecklistStatus.CHECKED)
    progress = evaluate(repo, profile)
    assert progress["port_scan"].phase_status == PhaseStatus.COMPLETED
    assert progress["service_enum"].phase_status == PhaseStatus.NOT_STARTED

    # --- Enumeration: findings appear; vuln research unblocks ---
    svc_smb = repo.add_or_update_service(t.id, 445, "tcp", "microsoft-ds")
    repo.add_checklist_item(svc_http.id, "Content discovery (ffuf)", category="enum", status=ChecklistStatus.CHECKED)
    repo.add_checklist_item(svc_smb.id, "Null session enumeration", category="enum", status=ChecklistStatus.FINDING)
    progress = evaluate(repo, profile)
    assert progress["service_enum"].findings == ["Null session enumeration"]
    assert any(a.kind == "exploit" for a in progress["service_enum"].recommended_actions)
    assert progress["vulnerability_research"].phase_status == PhaseStatus.NOT_STARTED

    # --- Vulnerability assessment confirms the vector; exploitation unlocks ---
    repo.add_checklist_item(svc_http.id, "Version vs CVE match (http)", category="vuln_check", status=ChecklistStatus.DEAD_END)
    repo.add_checklist_item(svc_smb.id, "SMBv1 MS17-010 probe", category="vuln_check", status=ChecklistStatus.FINDING)
    repo.update_checklist_status(
        repo.get_checklists_by_service(svc_smb.id)[1].id, ChecklistStatus.FINDING
    )
    progress = evaluate(repo, profile)
    assert progress["port_scan"].phase_status == PhaseStatus.COMPLETED
    assert progress["service_enum"].phase_status == PhaseStatus.COMPLETED
    assert progress["foothold_user_flag"].phase_status != PhaseStatus.BLOCKED

    # --- Exploitation: checks resolve, but user flag gate holds it open ---
    repo.add_checklist_item(svc_smb.id, "Exploit SMB vulnerability", category="exploit", status=ChecklistStatus.RUNNING)
    progress = evaluate(repo, profile)
    assert progress["foothold_user_flag"].running_checks == ["Exploit SMB vulnerability"]
    resume_actions = [a for a in progress["foothold_user_flag"].recommended_actions if a.kind == "resume"]
    assert resume_actions and "RUNNING" in resume_actions[0].rationale

    repo.update_checklist_status(
        repo.get_checklists_by_service(svc_smb.id)[2].id, ChecklistStatus.FINDING
    )
    progress = evaluate(repo, profile)
    # All exploit checks resolved (as finding), yet no user.txt captured:
    # phase remains IN_PROGRESS with a capture-proof recommendation.
    assert not progress["foothold_user_flag"].pending_checks
    assert progress["foothold_user_flag"].phase_status == PhaseStatus.IN_PROGRESS
    assert any("user_flag" in a.title for a in progress["foothold_user_flag"].recommended_actions)

    # --- Foothold achieved: flag captured + status raised → privesc branch opens ---
    repo.add_evidence(t.id, title="user.txt", proof_type=ProofType.USER_FLAG, service_id=svc_smb.id)
    repo.record_credential_test(
        repo.add_credential("svc_backup", "Summer2024!", CredentialType.PASSWORD, target_id=t.id).id,
        t.ip, "smb", valid=True,
    )
    repo.update_target_status(t.id, TargetStatus.FOOTHOLD)
    progress = evaluate(repo, profile)
    assert progress["foothold_user_flag"].phase_status == PhaseStatus.COMPLETED
    assert progress["privilege_escalation"].phase_status != PhaseStatus.BLOCKED

    # --- Post-exploitation: privesc checks run and complete ---
    repo.add_checklist_item(svc_smb.id, "winPEAS sweep", category="privesc", status=ChecklistStatus.CHECKED)
    repo.add_checklist_item(svc_smb.id, "AlwaysInstallElevated check", category="privesc", status=ChecklistStatus.FINDING)
    progress = evaluate(repo, profile)
    assert progress["privilege_escalation"].findings == ["AlwaysInstallElevated check"]
    # Required proof attaches to the phase that declares it (foothold/user flag).
    assert progress["foothold_user_flag"].evidence == ["user.txt"]
    # root_flag phase still gated on root proof.
    assert progress["root_flag"].phase_status == PhaseStatus.IN_PROGRESS
    assert any("root_flag" in a.title for a in progress["root_flag"].recommended_actions)

    # --- Completion: root flag captured, host pwned, every phase closes ---
    repo.add_evidence(t.id, title="proof.txt", proof_type=ProofType.ROOT_FLAG)
    repo.update_target_status(t.id, TargetStatus.PWNED)
    progress = evaluate(repo, profile)
    statuses = {pid: p.phase_status for pid, p in progress.items()}
    assert all(s == PhaseStatus.COMPLETED for s in statuses.values()), statuses
    assert progress["root_flag"].evidence == ["proof.txt"]

    # Dead ends were tracked along the way without breaking completion.
    assert progress["vulnerability_research"].dead_ends == ["Version vs CVE match (http)"]


def test_simulation_remains_deterministic(env):
    """Same workspace state twice → identical phase evaluation (no drift)."""
    repo, profile = env
    t = repo.add_or_get_target("10.10.11.7")
    svc = repo.add_or_update_service(t.id, 22, "tcp", "ssh")
    repo.add_checklist_item(svc.id, "ssh-audit", category="enum", status=ChecklistStatus.TODO)
    first = evaluate(repo, profile)
    second = evaluate(repo, profile)
    assert {k: v.phase_status for k, v in first.items()} == {k: v.phase_status for k, v in second.items()}
