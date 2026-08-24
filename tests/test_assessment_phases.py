import pytest
from datetime import datetime, timezone
from synapse.models import Target, TargetStatus, Service, ServiceStatus, ChecklistItem, ChecklistStatus, Evidence, ProofType
from synapse.assessment.engine import evaluate_phase_progress, PhaseProgress, PhaseStatus, NextAction
from synapse.db.repository import DatabaseRepository

def test_phase_evaluation():
    repo = DatabaseRepository(":memory:")
    target = repo.add_or_get_target("10.0.0.1")
    
    svc = repo.add_or_update_service(target.id, 80)
    chk1 = repo.add_checklist_item(svc.id, "Nmap scan", category="recon", status=ChecklistStatus.CHECKED)
    chk2 = repo.add_checklist_item(svc.id, "Dirb", category="enum", status=ChecklistStatus.TODO)
    
    target = repo.get_target_by_id(target.id)
    
    profile = {
        "id": "ejptv2",
        "phases": [
            {"id": "recon", "depends_on": []},
            {"id": "enum", "depends_on": ["recon"]},
            {"id": "exploit", "depends_on": ["enum"]},
            {"id": "privesc", "depends_on": ["exploit"]},
        ]
    }
    
    progress = evaluate_phase_progress(target, profile, repo)
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
    # Mark target as foothold to trigger privesc jump
    repo.update_target_status(target.id, TargetStatus.FOOTHOLD)
    # Add flag
    repo.add_evidence(target.id, "User Flag", proof_type=ProofType.USER_FLAG)
    
    target = repo.get_target_by_id(target.id)
    profile = {
        "phases": [
            {"id": "recon", "depends_on": []},
            {"id": "enum", "depends_on": ["recon"]},
            {"id": "exploit", "depends_on": ["enum"]},
            {"id": "privesc", "depends_on": ["exploit"]},
        ]
    }
    
    progress = evaluate_phase_progress(target, profile, repo)
    assert progress["privesc"].phase_status == PhaseStatus.IN_PROGRESS
    assert len(progress["privesc"].evidence) == 1

def test_blocked_phase():
    repo = DatabaseRepository(":memory:")
    target = repo.add_or_get_target("10.0.0.3")
    svc = repo.add_or_update_service(target.id, 22)
    chk = repo.add_checklist_item(svc.id, "SSH enum", category="recon", status=ChecklistStatus.TODO)
    target = repo.get_target_by_id(target.id)
    profile = {
        "phases": [
            {"id": "recon", "depends_on": []},
            {"id": "enum", "depends_on": ["recon"]}
        ]
    }
    progress = evaluate_phase_progress(target, profile, repo)
    assert progress["recon"].phase_status == PhaseStatus.NOT_STARTED
    assert progress["enum"].phase_status == PhaseStatus.BLOCKED
