"""Unit tests for report generation, Notion workspace, Obsidian vault exporter, and JSON backup/restore."""

import json
from pathlib import Path
import pytest
from synapse.db.repository import DatabaseRepository
from synapse.export.json_exporter import export_workspace_json, import_workspace_json
from synapse.export.markdown_exporter import export_markdown_report, export_obsidian_vault
from synapse.export.notion_exporter import export_notion_workspace
from synapse.models import ChecklistStatus, CredentialType, LeadPriority, ProofType, TargetStatus


@pytest.fixture
def populated_repo(tmp_path: Path):
    repo = DatabaseRepository(tmp_path / "test.db")
    t = repo.add_or_get_target("10.10.11.150", hostname="dc01.corp.local", os="Windows Server 2019")
    repo.update_target_status(t.id, TargetStatus.PWNED)

    svc = repo.add_or_update_service(t.id, 445, "tcp", "smb", "Microsoft-DS", "SMBv3")
    repo.add_checklist_item(
        service_id=svc.id,
        title="Check Anonymous Share Access",
        category="enum",
        command_template="netexec smb 10.10.11.150 -u '' -p '' --shares",
        status=ChecklistStatus.FINDING,
    )

    cred = repo.add_credential(
        username="administrator",
        secret="Password123!",
        cred_type=CredentialType.PASSWORD,
        domain="CORP.LOCAL",
        target_id=t.id,
    )
    repo.record_credential_test(cred.id, "10.10.11.150", "smb", valid=True, admin=True)

    repo.add_lead(
        title="Extract NTDS.dit hashes",
        description="Using secretsdump.py with administrator creds",
        priority=LeadPriority.CRITICAL,
        target_id=t.id,
    )

    repo.add_evidence(
        target_id=t.id,
        proof_type=ProofType.ROOT_FLAG,
        title="Domain Admin Compromise Flag",
        command="type C:\\Users\\Administrator\\Desktop\\proof.txt",
        output="aad3b435b51404eeaad3b435b51404ee",
        flag_hash="aad3b435b51404eeaad3b435b51404ee",
    )

    repo.add_pivot_route(
        name="Internal AD Enclave",
        jump_host_ip="10.10.11.150",
        target_subnet="172.16.10.0/24",
        tunnel_type="chisel_socks",
        local_bind="127.0.0.1:1080",
    )

    return repo


def test_markdown_report_export(populated_repo: DatabaseRepository):
    report_md = export_markdown_report(populated_repo)
    assert "# Penetration Testing Assessment Report" in report_md
    assert "10.10.11.150" in report_md
    assert "dc01.corp.local" in report_md
    assert "administrator" in report_md
    assert "Password123!" in report_md
    assert "aad3b435b51404eeaad3b435b51404ee" in report_md
    assert "172.16.10.0/24" in report_md


def test_notion_workspace_export(populated_repo: DatabaseRepository, tmp_path: Path):
    notion_dir = tmp_path / "notion_ws"
    export_notion_workspace(populated_repo, notion_dir)

    dashboard = (notion_dir / "SYNAPSE Assessment Workspace.md").read_text(encoding="utf-8")
    assert "# SYNAPSE Assessment Workspace" in dashboard
    assert "> 🎯 **Targets:**" in dashboard
    assert "10.10.11.150" in dashboard
    assert "[10.10.11.150 (dc01.corp.local)](Targets/10.10.11.150.md)" in dashboard

    target_page = (notion_dir / "Targets" / "10.10.11.150.md").read_text(encoding="utf-8")
    assert "# Target: 10.10.11.150" in target_page
    assert "Check Anonymous Share Access" in target_page
    assert "VULNERABILITY FINDING" in target_page

    assert (notion_dir / "Credentials.md").exists()
    assert (notion_dir / "Leads & Hypotheses.md").exists()
    assert (notion_dir / "Evidence & Flags.md").exists()
    assert (notion_dir / "Pivoting & Networks.md").exists()


def test_notion_path_traversal_protection(tmp_path: Path):
    repo = DatabaseRepository(":memory:")
    repo.add_or_get_target("../../escape_test_notion")
    notion_dir = tmp_path / "notion_vault"
    export_notion_workspace(repo, notion_dir)

    assert not (tmp_path / "escape_test_notion.md").exists()
    assert (notion_dir / "Targets" / "escape_test_notion.md").exists()


def test_obsidian_vault_export(populated_repo: DatabaseRepository, tmp_path: Path):
    vault_dir = tmp_path / "obsidian_vault"
    export_obsidian_vault(populated_repo, vault_dir)

    assert (vault_dir / "Dashboard.md").exists()
    assert (vault_dir / "Credentials.md").exists()
    assert (vault_dir / "Leads & Hypotheses.md").exists()
    assert (vault_dir / "Targets" / "10.10.11.150.md").exists()


def test_obsidian_vault_path_traversal_protection(tmp_path: Path):
    repo = DatabaseRepository(":memory:")
    repo.add_or_get_target("../../escape_test")
    vault_dir = tmp_path / "vault"
    export_obsidian_vault(repo, vault_dir)

    # Ensure no file was created outside vault_dir
    assert not (tmp_path / "escape_test.md").exists()
    assert (vault_dir / "Targets" / "escape_test.md").exists()


def test_json_backup_and_restore(populated_repo: DatabaseRepository, tmp_path: Path):
    json_str = export_workspace_json(populated_repo)
    data = json.loads(json_str)
    assert len(data["targets"]) == 1
    assert len(data["credentials"]) == 1
    assert len(data["leads"]) == 1
    assert len(data["evidence"]) == 1
    assert len(data["pivot_routes"]) == 1

    # Restore to a fresh database
    new_repo = DatabaseRepository(tmp_path / "new.db")
    counts = import_workspace_json(new_repo, json_str)
    assert counts["targets"] == 1
    assert counts["services"] == 1
    assert counts["checklists"] == 1
    assert counts["credentials"] == 1
    assert counts["leads"] == 1
    assert counts["evidence"] == 1
    assert counts["routes"] == 1


def test_json_import_resilience(tmp_path: Path):
    repo = DatabaseRepository(tmp_path / "resilient.db")
    malformed_json = '{"targets": [{"ip": "10.1.1.1"}, {"ip": "10.2.2.2", "services": [{"port": 80}, {"no_port": 123}]}]}'
    counts = import_workspace_json(repo, malformed_json)
    assert counts["targets"] == 2
    assert counts["services"] == 1
    assert len(repo.list_targets()) == 2
