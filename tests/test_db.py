"""Unit tests for SQLite database repository."""

import pytest
from synapse.db.repository import DatabaseRepository
from synapse.models import (
    ChecklistStatus,
    CredentialType,
    LeadPriority,
    LeadStatus,
    ProofType,
    ServiceStatus,
    TargetStatus,
)


@pytest.fixture
def repo():
    return DatabaseRepository(":memory:")


def test_target_crud(repo: DatabaseRepository):
    target = repo.add_or_get_target("10.10.11.10", hostname="web.local", os="Linux")
    assert target.id is not None
    assert target.ip == "10.10.11.10"
    assert target.hostname == "web.local"
    assert target.os == "Linux"
    assert target.status == TargetStatus.DISCOVERED

    # Update status
    updated = repo.update_target_status(target.id, TargetStatus.FOOTHOLD)
    assert updated is True

    fetched = repo.get_target_by_id(target.id)
    assert fetched is not None
    assert fetched.status == TargetStatus.FOOTHOLD

    # List targets
    targets = repo.list_targets()
    assert len(targets) == 1
    assert targets[0].ip == "10.10.11.10"

    # Delete
    deleted = repo.delete_target(target.id)
    assert deleted is True
    assert repo.get_target_by_id(target.id) is None


def test_service_and_checklist_crud(repo: DatabaseRepository):
    target = repo.add_or_get_target("10.10.11.20", os="Windows")
    svc = repo.add_or_update_service(
        target_id=target.id,
        port=445,
        protocol="tcp",
        name="smb",
        product="Microsoft-DS",
        version="Windows 10",
    )
    assert svc.id is not None
    assert svc.port == 445

    # Add checklist item
    item = repo.add_checklist_item(
        service_id=svc.id,
        title="Check Anonymous SMB Access",
        category="enum",
        command_template="netexec smb {IP} -u '' -p '' --shares",
    )
    assert item.id is not None
    assert item.status == ChecklistStatus.TODO

    # Update checklist status
    repo.update_checklist_status(item.id, ChecklistStatus.CHECKED, output_snippet="Readable share: /public")
    refreshed_item = repo.get_checklist_by_id(item.id)
    assert refreshed_item.status == ChecklistStatus.CHECKED
    assert "public" in refreshed_item.output_snippet

    # Verify services attached to target
    target_with_svc = repo.get_target_by_id(target.id)
    assert len(target_with_svc.services) == 1
    assert len(target_with_svc.services[0].checklists) == 1


def test_credentials_matrix(repo: DatabaseRepository):
    target = repo.add_or_get_target("10.10.11.30")
    cred = repo.add_credential(
        username="administrator",
        secret="Password123!",
        cred_type=CredentialType.PASSWORD,
        domain="CORP.LOCAL",
        service_scope="smb",
        target_id=target.id,
    )
    assert cred.id is not None
    assert cred.username == "administrator"

    # Record testing on other machines
    repo.record_credential_test(cred.id, "10.10.11.30", "smb", valid=True, admin=True)
    repo.record_credential_test(cred.id, "10.10.11.31", "ssh", valid=False, admin=False)

    refreshed = repo.get_credential_by_id(cred.id)
    assert "10.10.11.30" in refreshed.tested_targets
    assert refreshed.tested_targets["10.10.11.30"]["admin"] is True
    assert refreshed.tested_targets["10.10.11.31"]["valid"] is False


def test_leads_and_evidence(repo: DatabaseRepository):
    target = repo.add_or_get_target("10.10.11.40")

    # Add lead
    lead = repo.add_lead(
        title="Test LFI in search.php",
        description="Observed page param passing filenames",
        priority=LeadPriority.HIGH,
        status=LeadStatus.BACKLOG,
        target_id=target.id,
    )
    assert lead.id is not None

    # Update lead status
    repo.update_lead_status(lead.id, LeadStatus.CONFIRMED)
    assert repo.get_lead_by_id(lead.id).status == LeadStatus.CONFIRMED

    # Add evidence
    ev = repo.add_evidence(
        target_id=target.id,
        proof_type=ProofType.USER_FLAG,
        title="User Flag on 10.10.11.40",
        command="cat /home/user/user.txt",
        output="7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d",
        flag_hash="7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d",
    )
    assert ev.id is not None
    assert ev.flag_hash == "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d"

    # Verify global stats
    stats = repo.get_stats()
    assert stats["total_targets"] == 1
    assert stats["captured_flags"] == 1


def test_target_scope_toggle_and_merge_preservation(repo: DatabaseRepository):
    target = repo.add_or_get_target("10.10.11.50")
    assert target.in_scope is True

    assert repo.set_target_scope(target.id, False) is True
    fetched = repo.get_target_by_id(target.id)
    assert fetched.in_scope is False

    # Re-adding the same host must NOT silently re-scope it
    merged = repo.add_or_get_target("10.10.11.50", hostname="mail.corp.local")
    assert merged.in_scope is False
    assert merged.hostname == "mail.corp.local"

    # Explicit scope argument still wins on merge
    repo.add_or_get_target("10.10.11.50", in_scope=True)
    assert repo.get_target_by_id(target.id).in_scope is True


def test_evidence_checklist_relationship_roundtrip(repo: DatabaseRepository):
    target = repo.add_or_get_target("10.10.11.60")
    svc = repo.add_or_update_service(target.id, 22, "tcp", "ssh", "OpenSSH", "9.6p1")
    chk = repo.add_checklist_item(svc.id, title="SSH algo audit", command_template="ssh-audit {IP}")

    ev = repo.add_evidence(
        target_id=target.id,
        service_id=svc.id,
        checklist_id=chk.id,
        title="Output for: SSH algo audit",
        command="ssh-audit 10.10.11.60",
        output="ssh-rsa (rsa-sha2-256) weak",
    )
    fetched = repo.get_evidence_by_id(ev.id)
    assert fetched.checklist_id == chk.id
    assert fetched.service_id == svc.id

    listed = repo.list_evidence(target_id=target.id)
    assert any(e.checklist_id == chk.id for e in listed)


def test_credential_lifecycle_reset(repo: DatabaseRepository):
    t1 = repo.add_or_get_target("10.10.11.70")
    t2 = repo.add_or_get_target("10.10.11.71")
    cred = repo.add_credential("svc_acc", "pw123", target_id=t1.id)

    repo.record_credential_test(cred.id, "10.10.11.70", service="smb", valid=True, admin=True)
    repo.record_credential_test(cred.id, "10.10.11.71", valid=False)
    refreshed = repo.get_credential_by_id(cred.id)
    assert set(refreshed.tested_targets.keys()) == {"10.10.11.70", "10.10.11.70:smb", "10.10.11.71"}

    # Reset host .70 to untested (wipe host + compound keys, keep .71)
    remaining = {k: v for k, v in refreshed.tested_targets.items() if not str(k).startswith("10.10.11.70")}
    assert repo.update_credential_tested_targets(cred.id, remaining) is True

    final = repo.get_credential_by_id(cred.id)
    assert "10.10.11.70" not in final.tested_targets
    assert "10.10.11.71" in final.tested_targets


def test_refresh_service_state_derives_status_from_checklists(repo: DatabaseRepository):
    t = repo.add_or_get_target("10.10.11.80")
    svc = repo.add_or_update_service(t.id, 21, "tcp", "ftp")
    c1 = repo.add_checklist_item(svc.id, title="anon ftp")
    c2 = repo.add_checklist_item(svc.id, title="version hunt")

    # No checklists touched yet -> status untouched
    assert repo.refresh_service_state(svc.id).status == ServiceStatus.UNTESTED

    repo.update_checklist_status(c1.id, ChecklistStatus.RUNNING)
    assert repo.refresh_service_state(svc.id).status == ServiceStatus.IN_PROGRESS

    repo.update_checklist_status(c2.id, ChecklistStatus.FINDING)
    assert repo.refresh_service_state(svc.id).status == ServiceStatus.VULNERABLE

    repo.update_checklist_status(c1.id, ChecklistStatus.CHECKED)
    assert repo.refresh_service_state(svc.id).status == ServiceStatus.VULNERABLE

    repo.update_checklist_status(c2.id, ChecklistStatus.DEAD_END)
    assert repo.refresh_service_state(svc.id).status == ServiceStatus.ENUMERATED

    repo.update_checklist_status(c1.id, ChecklistStatus.DEAD_END)
    assert repo.refresh_service_state(svc.id).status == ServiceStatus.DEAD_END

    # Persisted, not just returned
    assert repo.get_service_by_id(svc.id).status == ServiceStatus.DEAD_END


def test_refresh_service_state_unknown_id_returns_none(repo: DatabaseRepository):
    assert repo.refresh_service_state(99999) is None
