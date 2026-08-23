"""Unit and integration tests for Textual TUI interface."""

import pytest
from synapse.tui.app import SynapseTUI
from synapse.models import TargetStatus


@pytest.mark.asyncio
async def test_tui_initialization_and_mounting():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        # Verify default widgets are composed and mounted
        assert app.query_one("#tabs") is not None
        assert app.query_one("#target-tree") is not None
        assert app.query_one("#service-detail") is not None
        assert app.query_one("#cred-matrix") is not None
        assert app.query_one("#lead-board") is not None
        assert app.query_one("#evidence-view") is not None
        assert app.query_one("#pivot-view") is not None


@pytest.mark.asyncio
async def test_tui_target_and_checklist_flow():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        # Add target via repo
        target = app.repo.add_or_get_target("10.10.11.250", hostname="lab.local", os="Linux")
        svc = app.repo.add_or_update_service(target.id, 22, "tcp", "ssh", "OpenSSH", "8.9p1")
        app.repo.add_checklist_item(
            service_id=svc.id,
            title="SSH User Enumeration",
            category="enum",
            command_template="nmap --script ssh-run -p 22 10.10.11.250",
        )
        app.refresh_all_views()

        # Check stats banner
        stats_banner = app.query_one("#stats-banner")
        assert "10.10.11.250" not in stats_banner.render().plain  # Targets count is shown
        assert "Targets: 1" in stats_banner.render().plain

        # Select service
        detail = app.query_one("#service-detail")
        detail.display_service(target, svc)
        assert "Port 22/tcp" in detail.query_one("#service-header").render().plain


NMAP_RECON_OUTPUT = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.10.11.250
Host is up (0.012s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.52

Service detection performed. Nmap done: 1 IP address (1 host up) scanned in 3.2 seconds
"""


@pytest.mark.asyncio
async def test_tui_initial_recon_flow_ingests_services():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        # Bare target with no services -> the phase-0 dead end this feature fixes
        target = app.repo.add_or_get_target("10.10.11.250", hostname="lab.local", os="Linux")
        app.refresh_all_views()
        app.selected_target = target

        # Recon recipes are available and rendered for this target
        recipes = app.methodology.get_initial_recon_commands(app.repo.get_target_by_ip("10.10.11.250"))
        assert len(recipes) >= 3

        # Simulate a completed recon run whose output is standard Nmap text
        ingested = app._ingest_recon_output(
            app.repo.get_target_by_ip("10.10.11.250"), NMAP_RECON_OUTPUT
        )
        assert ingested == 2

        fresh = app.repo.get_target_by_ip("10.10.11.250")
        assert len(fresh.services) == 2
        ports = {s.port for s in fresh.services}
        assert ports == {22, 80}
        # Discovered services must flow through the normal recipe pipeline
        for s in fresh.services:
            assert s.checklists, f"No methodology checklists attached to port {s.port}"

        # Non-nmap output (e.g. ping) must not ingest anything
        assert app._ingest_recon_output(fresh, "PING 10.10.11.250 (10.10.11.250) 56(84) bytes of data.") == 0


@pytest.mark.asyncio
async def test_tui_recon_evidence_and_status_transition():
    from synapse.models import ProofType

    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.42")
        assert target.status == TargetStatus.DISCOVERED

        fresh = app.repo.get_target_by_ip("10.10.11.42")
        app.repo.add_evidence(
            target_id=fresh.id,
            proof_type=ProofType.COMMAND_OUTPUT,
            title="Initial Recon: Verify Host Reachability (ICMP)",
            command="ping -c 4 10.10.11.42",
            output="4 packets transmitted, 4 received",
        )
        if fresh.status == TargetStatus.DISCOVERED:
            app.repo.update_target_status(fresh.id, TargetStatus.SCANNING)

        refreshed = app.repo.get_target_by_ip("10.10.11.42")
        assert refreshed.status == TargetStatus.SCANNING
        assert len(app.repo.list_evidence()) == 1


@pytest.mark.asyncio
async def test_tui_initial_recon_modal_lists_recipes():
    from synapse.tui.modals.initial_recon_modal import InitialReconModal

    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.99")
        recipes = app.methodology.get_initial_recon_commands(target)

        modal = InitialReconModal(target_ip="10.10.11.99", recipes=recipes)
        await pilot.app.push_screen(modal, lambda r: None)
        await pilot.pause()

        table = modal.query_one("#recon-table")
        assert table.row_count >= 3
