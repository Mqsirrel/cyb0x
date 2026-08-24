"""End-to-end simulated assessment test suite and verification."""

import json
from pathlib import Path
from synapse.assessment.engine import get_next_actions
from synapse.db.repository import DatabaseRepository
from synapse.export.json_exporter import export_workspace_json
from synapse.export.markdown_exporter import export_markdown_report
from synapse.models import (
    ChecklistStatus,
    CredentialType,
    LeadPriority,
    ProofType,
    ServiceStatus,
    TargetStatus,
)


def test_end_to_end_simulation(tmp_path: Path):
    """Simulates a complete realistic pentest engagement from start to finish."""
    # Setup repository
    db_path = tmp_path / "simulation.db"
    repo = DatabaseRepository(db_path)
    
    # --- Phase 0: Target discovery ---
    target_ip = "10.10.11.250"
    target = repo.add_or_get_target(target_ip, hostname="target.thm")
    
    # State validation
    actions = get_next_actions(repo.list_targets())
    assert any(a.kind == "recon" for a in actions), "Expected recon action for bare target"
    assert target.status == TargetStatus.DISCOVERED

    # --- Phase 1: Initial Recon ---
    # Discovered ports: 22, 80, 445
    repo.update_target_status(target.id, TargetStatus.SCANNING)
    svc_ssh = repo.add_or_update_service(target.id, 22, "tcp", "ssh")
    svc_http = repo.add_or_update_service(target.id, 80, "tcp", "http")
    svc_smb = repo.add_or_update_service(target.id, 445, "tcp", "microsoft-ds")
    repo.update_target_status(target.id, TargetStatus.ENUMERATED)
    
    # State validation
    targets = repo.list_targets()
    actions = get_next_actions(targets)
    assert any(a.kind == "enum" for a in actions), "Expected enumeration actions"

    # --- Phase 2: Service Enumeration ---
    # Update service status to in progress / enumerated
    repo.update_service_status(svc_http.id, ServiceStatus.IN_PROGRESS)
    cl_http = repo.add_checklist_item(svc_http.id, "dirb", "HTTP Dirbuster")
    repo.update_checklist_status(cl_http.id, ChecklistStatus.CHECKED)
    repo.update_service_status(svc_http.id, ServiceStatus.ENUMERATED)

    repo.update_service_status(svc_smb.id, ServiceStatus.IN_PROGRESS)
    cl_smb = repo.add_checklist_item(svc_smb.id, "smb", "SMB null session check")
    repo.update_checklist_status(cl_smb.id, ChecklistStatus.FINDING)
    repo.update_service_status(svc_smb.id, ServiceStatus.VULNERABLE)
    
    # --- Phase 3: Finding identification ---
    # SMB Share readable anonymously, creds found
    lead = repo.add_lead(
        title="Anonymous SMB Share Readable",
        priority=LeadPriority.HIGH,
        target_id=target.id,
    )
    cred = repo.add_credential(
        username="guest",
        secret="password",
        cred_type=CredentialType.PASSWORD,
        target_id=target.id,
    )

    # State validation
    targets = repo.list_targets()
    actions = get_next_actions(targets)
    assert any(a.kind == "spray" or a.kind == "login" or a.kind == "exploit" for a in actions)

    # --- Phase 4: Exploitation / Foothold ---
    # Test cred on SSH and it succeeds
    repo.record_credential_test(cred.id, target_ip, "ssh", valid=True)
    repo.update_target_status(target.id, TargetStatus.FOOTHOLD)
    user_evidence = repo.add_evidence(
        target_id=target.id,
        service_id=svc_ssh.id,
        proof_type=ProofType.USER_FLAG,
        title="User Flag",
        flag_hash="CTF{user_foothold}",
    )
    
    # State validation
    targets = repo.list_targets()
    pass
    # --- Phase 5: Post-Exploitation / PrivEsc ---
    # Internal check SUID find -> root
    root_evidence = repo.add_evidence(
        target_id=target.id,
        proof_type=ProofType.ROOT_FLAG,
        title="Root Flag",
        flag_hash="CTF{root_pwned}",
    )
    repo.update_target_status(target.id, TargetStatus.PWNED)
    
    # Final state validation
    targets = repo.list_targets()
    assert targets[0].status == TargetStatus.PWNED

    # --- Phase 6: Reporting & Verification ---
    json_path = tmp_path / "export.json"
    md_path = tmp_path / "report.md"
    
    json_str = export_workspace_json(repo)
    json_path.write_text(json_str)
    
    md_str = export_markdown_report(repo)
    md_path.write_text(md_str)
    
    with open(json_path) as f:
        export_data = json.load(f)
    
    # Verify JSON structure and linked items
    assert len(export_data["targets"]) == 1
    assert export_data["targets"][0]["ip"] == "10.10.11.250"
    assert len(export_data["targets"][0]["services"]) == 3
    assert len(export_data["credentials"]) == 1
    assert len(export_data["evidence"]) == 2
    
    # Verify MD contains evidence/flags
    md_content = md_path.read_text()
    assert "CTF{user_foothold}" in md_content
    assert "CTF{root_pwned}" in md_content
    assert "Anonymous SMB Share Readable" in md_content

    # Clean up
    repo.close()
