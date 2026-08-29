"""Adversarial stress-test harness for all modals across multiple viewport geometries."""

import pytest
import asyncio
from typing import List, Dict, Any
from textual.app import App, ComposeResult
from textual.widgets import Footer, Input, TextArea, DataTable, OptionList

from synapse.db.repository import DatabaseRepository
from synapse.models import (
    Target, Service, Credential, Lead, Evidence, PivotRoute,
    TargetStatus, SeverityLevel, LeadPriority, LeadStatus, ProofType, ServiceStatus, CredentialType
)
from synapse.assessment.engine import TargetSnapshot, NextAction, StuckReport, PhaseProgress, PhaseStatus
from synapse.methodology.profile import MethodologyProfile, PhaseDefinition

from synapse.tui.modals.add_cred_modal import AddCredModal
from synapse.tui.modals.add_evidence_modal import AddEvidenceModal
from synapse.tui.modals.add_lead_modal import AddLeadModal
from synapse.tui.modals.add_target_modal import AddTargetModal
from synapse.tui.modals.command_palette_modal import CommandPaletteModal
from synapse.tui.modals.export_modal import ExportModal
from synapse.tui.modals.guided_phase_modal import GuidedPhaseModal
from synapse.tui.modals.help_modal import HelpModal
from synapse.tui.modals.initial_recon_modal import InitialReconModal
from synapse.tui.modals.jump_modal import JumpModal
from synapse.tui.modals.profile_modal import ProfileModal
from synapse.tui.modals.runner_modal import RunnerModal
from synapse.tui.modals.scratchpad_modal import ScratchpadModal
from synapse.tui.modals.stuck_modal import StuckModal
from synapse.tui.modals.theme_modal import ThemeModal
from synapse.tui.modals.triage_modal import TriageModal
from synapse.tui.modals.workspace_modal import WorkspaceModal
from synapse.tui.app import SynapseTUI


def create_populated_repo() -> DatabaseRepository:
    repo = DatabaseRepository(":memory:")
    t1 = repo.add_or_get_target("10.10.11.10", hostname="dc01.corp.local", os="Linux")
    t2 = repo.add_or_get_target("10.10.11.11", hostname="web01.corp.local", os="Linux")
    repo.add_or_update_service(t1.id, 88, "tcp", "kerberos", "open", "Microsoft Windows Kerberos")
    repo.add_or_update_service(t1.id, 445, "tcp", "microsoft-ds", "open", "Windows Server 2022 SMB")
    repo.add_or_update_service(t2.id, 80, "tcp", "http", "open", "Apache httpd 2.4.52")
    repo.add_or_update_service(t2.id, 22, "tcp", "ssh", "open", "OpenSSH 8.9p1")
    repo.add_credential("Administrator", "Password123!", CredentialType.PASSWORD, target_id=t1.id, notes="Domain admin creds")
    repo.add_credential("svc_backup", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", CredentialType.NTLM_HASH, target_id=t1.id, notes="Service hash")
    repo.add_lead("AS-REP Roasting candidate found", description="Target svc_backup without preauth", priority=LeadPriority.HIGH, severity=SeverityLevel.HIGH, status=LeadStatus.BACKLOG, target_id=t1.id)
    repo.add_evidence(t1.id, "Initial Nmap Scan", proof_type=ProofType.COMMAND_OUTPUT, output="Open ports: 88, 445")
    repo.add_evidence(t1.id, "Domain Flag", proof_type=ProofType.ROOT_FLAG, output="HTB{c0rp_d0m41n_pwn3d}", flag_hash="HTB{c0rp_d0m41n_pwn3d}")
    repo.add_pivot_route("Pivot-1", "10.10.11.11", "172.16.10.0/24", tunnel_type="socks5", local_bind="127.0.0.1:1080", notes="SSH SOCKS5")
    return repo


def get_modal_instances(repo: DatabaseRepository) -> List[tuple[str, Any]]:
    profile = MethodologyProfile(
        id="ad-standard",
        name="Active Directory Standard",
        description="Standard Active Directory Assessment",
        phases=[
            PhaseDefinition(id="p0", name="Phase 0: Recon"),
            PhaseDefinition(id="p1", name="Phase 1: Enum"),
        ]
    )
    stuck_report = StuckReport(
        dead_end_services=["SMB (445)"],
        dead_end_checks=["Kerberoasting (no SPNs)"],
        untested_ports=["HTTP (80)", "Kerberos (88)"],
        unsprayed_credentials=["svc_backup"],
        stale_leads=["AS-REP roasting"],
        suggestions=[
            NextAction(priority=1, kind="enum", title="Investigate web application", rationale="Check Apache on port 80", target_ip="10.10.11.11", port=80)
        ]
    )
    stuck_report_clean = StuckReport(
        dead_end_services=[],
        dead_end_checks=[],
        untested_ports=["SSH (22)"],
        unsprayed_credentials=[],
        stale_leads=[],
        suggestions=[
            NextAction(priority=2, kind="spray", title="Test SSH password", rationale="Try root password", target_ip="10.10.11.11", port=22)
        ]
    )
    snapshots = [
        TargetSnapshot(ip="10.10.11.10", hostname="dc01.corp.local", status=TargetStatus.ENUMERATED, services_total=2, services_untested=1),
        TargetSnapshot(ip="10.10.11.11", hostname="web01.corp.local", status=TargetStatus.PWNED, services_total=2, flag_count=1),
    ]
    actions = [
        NextAction(priority=1, kind="enum", title="Enumerate LDAP on DC", rationale="Run bloodhound-python or ldapsearch", target_ip="10.10.11.10", port=389),
        NextAction(priority=2, kind="recon", title="Inspect web application", rationale="Check Apache on port 80", target_ip="10.10.11.11", port=80),
    ]
    recipes = [
        {"name": "TCP Top 1000 Fast Scan", "command_template": "nmap -sS -T4 -top-ports 1000 {target_ip}"},
        {"name": "Full TCP All-Ports Scan", "command_template": "nmap -p- -T4 {target_ip}"},
        {"name": "UDP Common Services Scan", "command_template": "nmap -sU -top-ports 100 {target_ip}"},
    ]

    return [
        ("AddCredModal", AddCredModal()),
        ("AddEvidenceModal_empty", AddEvidenceModal()),
        ("AddEvidenceModal_populated", AddEvidenceModal(target_ip="10.10.11.10")),
        ("AddLeadModal_empty", AddLeadModal()),
        ("AddLeadModal_populated", AddLeadModal(target_id=1, target_ip="10.10.11.10")),
        ("AddTargetModal", AddTargetModal()),
        ("CommandPaletteModal", CommandPaletteModal()),
        ("ExportModal", ExportModal()),
        ("GuidedPhaseModal_no_profile", GuidedPhaseModal()),
        ("GuidedPhaseModal_with_profile", GuidedPhaseModal(profile=profile, progress={"p0": PhaseProgress("p0", completed_checks=["check1"], pending_checks=["check2"])})),
        ("HelpModal", HelpModal()),
        ("InitialReconModal", InitialReconModal("10.10.11.10", recipes)),
        ("JumpModal", JumpModal(repo)),
        ("ProfileModal", ProfileModal([profile], active_profile="ad-standard")),
        ("RunnerModal_idle", RunnerModal(command="nmap -sV -sC 10.10.11.10", target_id=1)),
        ("ScratchpadModal", ScratchpadModal(repo, "default")),
        ("StuckModal_stuck", StuckModal(stuck_report)),
        ("StuckModal_clean", StuckModal(stuck_report_clean)),
        ("ThemeModal", ThemeModal("claudish")),
        ("TriageModal_focused", TriageModal(snapshots, actions, focus_ip="10.10.11.10")),
        ("TriageModal_unfocused", TriageModal(snapshots, actions, focus_ip=None)),
        ("WorkspaceModal", WorkspaceModal("default")),
    ]


class ModalHostApp(App):
    """Host App for testing individual modal screens."""
    CSS = """
    Screen {
        background: #211E1B;
    }
    """


@pytest.mark.asyncio
@pytest.mark.parametrize("viewport", [(80, 24), (120, 36), (160, 45)])
async def test_all_modals_geometry_across_viewports(viewport):
    w, h = viewport
    repo = create_populated_repo()
    modals = get_modal_instances(repo)

    for name, modal in modals:
        app = ModalHostApp()
        async with app.run_test(size=(w, h)) as pilot:
            await app.push_screen(modal)
            await pilot.pause(0.05)

            # Query the dialog container
            dialog = modal.query_one("#dialog")
            dw = dialog.region.width
            dh = dialog.region.height
            dx = dialog.region.x
            dy = dialog.region.y

            # 1. Dialog must strictly fit within the screen viewport
            assert dw <= w, f"Modal {name} dialog width {dw} exceeds screen width {w}"
            assert dh <= h, f"Modal {name} dialog height {dh} exceeds screen height {h}"
            assert dx >= 0 and dx + dw <= w, f"Modal {name} horizontal bounds [{dx}, {dx+dw}] exceed screen width {w}"
            assert dy >= 0 and dy + dh <= h, f"Modal {name} vertical bounds [{dy}, {dy+dh}] exceed screen height {h}"

            # 2. Action bar buttons (if present) must fit within the dialog width
            action_buttons = modal.query("#action-buttons Button")
            if action_buttons:
                action_bar = modal.query_one("#action-bar")
                assert action_bar.region.width <= dw, f"Modal {name} action bar width {action_bar.region.width} exceeds dialog width {dw}"

            # 3. Modal must have valid non-zero dimensions
            assert dw > 0 and dh > 0, f"Modal {name} has zero dimensions: {dw}x{dh}"

            # Dismiss modal cleanly
            modal.dismiss(None)
            await pilot.pause(0.02)


@pytest.mark.asyncio
async def test_footer_80x24_no_wrapping_or_truncation():
    """Verify that SynapseTUI footer on 80x24 terminal shows all 8 buttons cleanly."""
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test(size=(80, 24)) as pilot:
        # Allow full layout and paint
        await pilot.pause(0.2)
        await pilot.press("1")
        await pilot.pause(0.1)

        footer = app.query_one(Footer)
        keys = list(footer.children)

        # Expected: exactly 8 curated shortcuts
        assert len(keys) == 8, f"Expected 8 footer keys, found {len(keys)}"

        # Measure individual button regions and total sum
        total_width = sum(k.region.width for k in keys)
        
        # Verify each key item has a positive width and valid text
        for i, key_widget in enumerate(keys):
            kw = key_widget.region.width
            kh = key_widget.region.height
            assert kw > 0, f"Key {i+1} has 0 width"
            # Footer height on a single row must be 1 (not wrapped onto multiple rows)
            assert kh == 1, f"Key {i+1} has height {kh}, expected single row (1)"

        assert total_width <= 80, f"Total footer width {total_width} exceeds 80 columns"
        assert 80 - total_width >= 0, "Footer overflows 80 columns"


@pytest.mark.asyncio
async def test_footer_across_all_tabs_80x24():
    """Verify that switching across all 5 tabs on 80x24 terminal keeps footer at exactly 8 buttons with no leakage."""
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.1)

        for tab_key in ["1", "2", "3", "4", "5"]:
            await pilot.press(tab_key)
            await pilot.pause(0.05)

            footer = app.query_one(Footer)
            keys = list(footer.children)
            total_width = sum(k.region.width for k in keys)

            assert len(keys) == 8, f"Tab {tab_key} leaked bindings into footer: {len(keys)} buttons"
            assert total_width <= 80, f"Tab {tab_key} footer width {total_width} > 80"


@pytest.mark.asyncio
async def test_modal_heavy_content_stress_80x24():
    """Adversarial stress test: modals populated with extreme, heavy payloads on 80x24."""
    repo = DatabaseRepository(":memory:")
    # Add 30 targets and 30 services
    for i in range(30):
        t = repo.add_or_get_target(f"10.10.12.{i+1}", hostname=f"heavy-host-{i}.corp.local", os="Linux")
        repo.add_or_update_service(t.id, 8080 + i, "tcp", "http-alt", "open", "Apache/2.4 Heavy Payload")

    # 1. Stress JumpModal with 30+ targets
    app = ModalHostApp()
    async with app.run_test(size=(80, 24)) as pilot:
        jump_modal = JumpModal(repo)
        await app.push_screen(jump_modal)
        await pilot.pause(0.05)
        d = jump_modal.query_one("#dialog")
        assert d.region.width <= 80 and d.region.height <= 24
        # Filter with input
        input_widget = jump_modal.query_one("#jump-input", Input)
        input_widget.value = "heavy-host"
        await pilot.pause(0.05)
        assert d.region.width <= 80 and d.region.height <= 24

    # 2. Stress RunnerModal with huge 2000-line output
    app = ModalHostApp()
    async with app.run_test(size=(80, 24)) as pilot:
        huge_cmd = "nmap -A -p- -T4 --script vuln " + " ".join(f"10.10.12.{i}" for i in range(10))
        runner_modal = RunnerModal(command=huge_cmd, target_id=1)
        await app.push_screen(runner_modal)
        await pilot.pause(0.05)
        out_area = runner_modal.query_one("#cmd-output", TextArea)
        out_area.text = "NMAP SCAN REPORT OUTPUT LINE\n" * 500
        await pilot.pause(0.05)
        d = runner_modal.query_one("#dialog")
        assert d.region.width <= 80 and d.region.height <= 24

    # 3. Stress ScratchpadModal with 500 lines of notes
    app = ModalHostApp()
    async with app.run_test(size=(80, 24)) as pilot:
        pad_modal = ScratchpadModal(repo, "heavy-lab")
        await app.push_screen(pad_modal)
        await pilot.pause(0.05)
        pad_area = pad_modal.query_one("#scratchpad-area", TextArea)
        pad_area.text = "# Pentest Notes\n" + "- Found endpoint /api/v1/auth\n" * 200
        await pilot.pause(0.05)
        d = pad_modal.query_one("#dialog")
        assert d.region.width <= 80 and d.region.height <= 24

    # 4. Stress TriageModal with 30 snapshots and 20 next actions
    heavy_snapshots = [
        TargetSnapshot(ip=f"10.10.12.{i}", hostname=f"node-{i}", status=TargetStatus.ENUMERATED, services_total=5, checks_total=10, checks_done=5)
        for i in range(25)
    ]
    heavy_actions = [
        NextAction(priority=i % 5, kind="enum", title=f"Action {i} on Target", rationale=f"Long detailed rationale for action {i} attacking port 80", target_ip=f"10.10.12.{i}", port=80)
        for i in range(20)
    ]
    app = ModalHostApp()
    async with app.run_test(size=(80, 24)) as pilot:
        triage_modal = TriageModal(heavy_snapshots, heavy_actions)
        await app.push_screen(triage_modal)
        await pilot.pause(0.05)
        d = triage_modal.query_one("#dialog")
        assert d.region.width <= 80 and d.region.height <= 24


@pytest.mark.asyncio
async def test_modal_interactive_escape_and_buttons():
    """Verify all modals dismiss cleanly on Escape key without hanging or layout errors."""
    repo = create_populated_repo()
    modals = get_modal_instances(repo)

    for name, modal in modals:
        app = ModalHostApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await app.push_screen(modal)
            await pilot.pause(0.05)
            # Press Escape
            await pilot.press("escape")
            await pilot.pause(0.05)
            # Verify modal was popped and screen is back to root
            assert len(app.screen_stack) == 1, f"Modal {name} did not dismiss on Escape"
