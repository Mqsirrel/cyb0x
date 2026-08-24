"""Interactive User Simulation & End-to-End TUI State Machine Test Harness.

Simulates a real pentester/exam candidate using the Synapse TUI across all
primary workflows:
1. Navigation & Tree Selection
2. Cycling Methodology Statuses (Space)
3. Running Recipes & Capturing Proof Flags
4. Managing Credential Vault & Lateral Movement Matrix
5. Attack Hypotheses & Leads Queue
6. Pivoting & Route Sentinel
7. Exporting to Notion Workspace Bundle
8. Help Modal & Keyboard Ergonomics
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from rich.console import Console

from synapse.db.repository import DatabaseRepository
from synapse.methodology.engine import MethodologyEngine
from synapse.models import (
    ChecklistStatus,
    CredentialType,
    LeadPriority,
    LeadStatus,
    ProofType,
    ServiceStatus,
    TargetStatus,
)
from synapse.tui.app import SynapseTUI
from synapse.tui.modals.add_cred_modal import AddCredModal
from synapse.tui.modals.add_evidence_modal import AddEvidenceModal
from synapse.tui.modals.add_lead_modal import AddLeadModal
from synapse.tui.modals.add_target_modal import AddTargetModal
from synapse.tui.modals.export_modal import ExportModal
from synapse.tui.modals.help_modal import HelpModal
from synapse.tui.modals.runner_modal import OutputArea, RunnerModal
from synapse.tui.widgets.cred_matrix import CredentialMatrixWidget
from synapse.tui.widgets.evidence_view import EvidenceViewWidget
from synapse.tui.widgets.lead_board import LeadBoardWidget
from synapse.tui.widgets.pivot_view import PivotViewWidget
from synapse.tui.widgets.service_detail import ServiceDetailWidget
from synapse.tui.widgets.target_tree import TargetTreeWidget


def build_simulation_db(db_path: Path) -> DatabaseRepository:
    """Pre-populates database with an Active Directory + Linux CTF lab environment."""
    if db_path.exists():
        db_path.unlink()

    repo = DatabaseRepository(db_path)
    engine = MethodologyEngine()

    # Target 1: Windows Domain Controller (10.10.11.100 - DC01)
    dc = repo.add_or_get_target("10.10.11.100", hostname="DC01.CORP.LOCAL", os="Windows Server 2019")
    repo.update_target_status(dc.id, TargetStatus.PWNED)

    for port, name, prod, ver in [
        (53, "dns", "Simple DNS", "2019"),
        (88, "kerberos", "Microsoft Windows Kerberos", ""),
        (135, "msrpc", "Microsoft Windows RPC", ""),
        (139, "netbios-ssn", "Microsoft Windows netbios-ssn", ""),
        (389, "ldap", "Microsoft Windows Active Directory LDAP", "2019"),
        (445, "smb", "Windows Server 2019 Standard 17763", "SMBv3"),
        (5985, "winrm", "Microsoft HTTPAPI httpd", "2.0"),
    ]:
        svc = repo.add_or_update_service(dc.id, port, "tcp", name, prod, ver)
        for check in engine.get_checklists_for_service(svc):
            cmd = engine.render_command(check.get("command_template", ""), dc, svc)
            repo.add_checklist_item(
                service_id=svc.id,
                category=check.get("category", "enum"),
                title=check.get("title", ""),
                description=check.get("description", ""),
                command_template=cmd,
                status=ChecklistStatus.CHECKED if port == 445 else ChecklistStatus.TODO,
            )

    # Target 2: Linux Web App & Database (10.10.11.105 - web01)
    web = repo.add_or_get_target("10.10.11.105", hostname="web01.corp.local", os="Ubuntu Linux 22.04")
    repo.update_target_status(web.id, TargetStatus.FOOTHOLD)

    for port, name, prod, ver in [
        (22, "ssh", "OpenSSH", "8.9p1 Ubuntu"),
        (80, "http", "Apache httpd", "2.4.52"),
        (3306, "mysql", "MySQL", "8.0.35"),
        (8080, "http", "Apache Tomcat", "9.0.58"),
    ]:
        svc = repo.add_or_update_service(web.id, port, "tcp", name, prod, ver)
        for check in engine.get_checklists_for_service(svc):
            cmd = engine.render_command(check.get("command_template", ""), web, svc)
            status = ChecklistStatus.FINDING if port == 8080 else ChecklistStatus.TODO
            repo.add_checklist_item(
                service_id=svc.id,
                category=check.get("category", "enum"),
                title=check.get("title", ""),
                description=check.get("description", ""),
                command_template=cmd,
                status=status,
                remediation="Upgrade Tomcat to 9.0.83+ and disable manager console",
            )

    # Credentials
    c1 = repo.add_credential("administrator", "Winter2024!Pwn", CredentialType.PASSWORD, "CORP.LOCAL", "smb", dc.id)
    repo.record_credential_test(c1.id, "10.10.11.100", "smb", valid=True, admin=True)
    repo.record_credential_test(c1.id, "10.10.11.105", "ssh", valid=False, admin=False)

    c2 = repo.add_credential("svc_backup", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", CredentialType.NTLM_HASH, "CORP.LOCAL", "winrm", dc.id)
    repo.record_credential_test(c2.id, "10.10.11.100", "winrm", valid=True, admin=True)

    c3 = repo.add_credential("tomcat_admin", "tomcat_pass123", CredentialType.PASSWORD, "", "http-8080", web.id)
    repo.record_credential_test(c3.id, "10.10.11.105", "http", valid=True, admin=False)

    # Leads
    repo.add_lead(
        title="Exploit Tomcat Manager WAR Deployment",
        description="Credentials valid for manager-gui role on port 8080. Upload reverse shell WAR.",
        priority=LeadPriority.CRITICAL,
        status=LeadStatus.IN_PROGRESS,
        target_id=web.id,
    )
    repo.add_lead(
        title="DCSync Attack via Administrator Credentials",
        description="Run secretsdump.py with DA credentials against DC01.",
        priority=LeadPriority.HIGH,
        status=LeadStatus.BACKLOG,
        target_id=dc.id,
    )

    # Evidence
    repo.add_evidence(
        target_id=web.id,
        proof_type=ProofType.USER_FLAG,
        title="User Flag on web01.corp.local",
        command="cat /home/webdev/user.txt",
        output="4f8a3c9b2e1d0f7a6b5c4d3e2f1a0b9c",
        flag_hash="4f8a3c9b2e1d0f7a6b5c4d3e2f1a0b9c",
    )
    repo.add_evidence(
        target_id=dc.id,
        proof_type=ProofType.ROOT_FLAG,
        title="System Proof Flag on DC01",
        command="type C:\\Users\\Administrator\\Desktop\\proof.txt",
        output="9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
        flag_hash="9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
    )

    # Pivoting
    repo.add_pivot_route(
        name="Internal Corp Network Pivot",
        jump_host_ip="10.10.11.105",
        target_subnet="172.16.20.0/24",
        tunnel_type="ligolo_ng",
        local_bind="127.0.0.1:1080",
        notes="Routing via tun0 interface session with webdev account",
    )

    return repo


async def run_end_to_end_user_simulation():
    """Runs a complete headless test pilot simulating a user through all TUI workflows."""
    sim_dir = Path("/tmp/synapse_sim")
    sim_dir.mkdir(parents=True, exist_ok=True)
    db_path = sim_dir / "sim_engagement.db"

    repo = build_simulation_db(db_path)
    app = SynapseTUI(db_path=db_path)

    console = Console()
    console.print("[bold green]Starting Headless User Simulation on Synapse TUI...[/bold green]")

    async with app.run_test(size=(120, 36)) as pilot:
        # Step 1: Initial Workbench load
        await pilot.pause(0.1)
        tree = app.query_one("#target-tree", TargetTreeWidget)
        assert len(app.repo.list_targets()) == 2

        # Select first target in tree
        if tree.root.children:
            tree.root.children[0].expand()
        await pilot.pause(0.1)
        svg_bench = app.export_screenshot()
        (sim_dir / "sim_1_workbench.svg").write_text(svg_bench, encoding="utf-8")
        console.print("[cyan]✔ Step 1: Workbench & Tree Loaded & Captured[/cyan]")

        # Step 2: Tab Navigation to Credential Vault
        await pilot.press("2")
        await pilot.pause(0.1)
        svg_creds = app.export_screenshot()
        (sim_dir / "sim_2_creds.svg").write_text(svg_creds, encoding="utf-8")
        console.print("[cyan]✔ Step 2: Credential Vault Tab Viewed & Captured[/cyan]")

        # Step 3: Tab Navigation to Leads Board
        await pilot.press("3")
        await pilot.pause(0.1)
        svg_leads = app.export_screenshot()
        (sim_dir / "sim_3_leads.svg").write_text(svg_leads, encoding="utf-8")
        console.print("[cyan]✔ Step 3: Leads & Hypotheses Board Viewed & Captured[/cyan]")

        # Step 4: Tab Navigation to Evidence Ledger
        await pilot.press("4")
        await pilot.pause(0.1)
        svg_ev = app.export_screenshot()
        (sim_dir / "sim_4_evidence.svg").write_text(svg_ev, encoding="utf-8")
        console.print("[cyan]✔ Step 4: Evidence & Flag Ledger Viewed & Captured[/cyan]")

        # Step 5: Tab Navigation to Pivoting Sentinel
        await pilot.press("5")
        await pilot.pause(0.1)
        svg_pivots = app.export_screenshot()
        (sim_dir / "sim_5_pivots.svg").write_text(svg_pivots, encoding="utf-8")
        console.print("[cyan]✔ Step 5: Pivoting & Route Sentinel Viewed & Captured[/cyan]")

        # Step 6: Test Help Modal
        await pilot.press("question_mark")
        await pilot.pause(0.1)
        assert isinstance(app.screen, HelpModal)
        svg_help = app.export_screenshot()
        (sim_dir / "sim_6_help_modal.svg").write_text(svg_help, encoding="utf-8")
        await pilot.press("escape")
        await pilot.pause(0.1)
        console.print("[cyan]✔ Step 6: Help Modal Opened, Captured, and Dismissed[/cyan]")

        # Step 7: Test Export Modal to Notion Workspace
        await pilot.press("x")
        await pilot.pause(0.1)
        assert isinstance(app.screen, ExportModal)
        svg_export = app.export_screenshot()
        (sim_dir / "sim_7_export_modal.svg").write_text(svg_export, encoding="utf-8")
        await pilot.press("escape")
        await pilot.pause(0.1)
        console.print("[cyan]✔ Step 7: Export Modal Opened, Captured, and Dismissed[/cyan]")

        # Step 8: Runner Modal — ^R execution, result chips, flag strip, ^S save flow
        await pilot.press("1")
        await pilot.pause(0.1)
        runner_results: list = []
        runner = RunnerModal(
            command="echo '22/tcp open  ssh     OpenSSH 8.9p1' && echo CTF{sim_runner}",
            title="Simulation: Recipe Run",
            context="10.10.11.105 ▸ 22/tcp ssh",
        )
        await pilot.app.push_screen(runner, runner_results.append)
        await pilot.pause(0.1)
        assert isinstance(app.screen, RunnerModal)
        assert runner.query_one("#btn-save").disabled is True

        svg_runner_idle = app.export_screenshot()
        (sim_dir / "sim_8_runner_modal.svg").write_text(svg_runner_idle, encoding="utf-8")

        await pilot.press("ctrl+r")
        for _ in range(60):
            await pilot.pause(0.1)
            if not runner._run_in_flight:
                break
        await pilot.pause(0.2)

        chips_plain = runner.query_one("#result-chips").render().plain
        assert "EXIT 0" in chips_plain, chips_plain
        assert "1 FLAG" in chips_plain, chips_plain
        output_area = runner.query_one("#cmd-output", OutputArea)
        assert "22/tcp open" in output_area.text
        assert output_area._highlights, "syntax highlighting must be active"

        svg_runner_done = app.export_screenshot()
        (sim_dir / "sim_8b_runner_results.svg").write_text(svg_runner_done, encoding="utf-8")

        await pilot.press("ctrl+s")
        await pilot.pause(0.1)
        assert len(runner_results) == 1 and runner_results[0]["action"] == "save_evidence"
        console.print("[cyan]✔ Step 8: Runner Modal ^R/^S Flow, Chips & Highlighting Verified[/cyan]")

        # Return to workbench
        await pilot.press("1")
        await pilot.pause(0.1)

    console.print(f"[bold green]✔ All simulation steps completed successfully! Artifacts in {sim_dir}[/bold green]")


if __name__ == "__main__":
    asyncio.run(run_end_to_end_user_simulation())
