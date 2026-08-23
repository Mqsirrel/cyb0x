"""Unit and integration tests for Textual TUI interface."""

import pytest
from textual.widgets import DataTable, TabbedContent
from synapse.tui.app import SynapseTUI
from synapse.assessment import get_next_actions
from synapse.models import ChecklistStatus, ProofType, ServiceStatus, TargetStatus


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

        # Check stats banner: counts always shown; state-aware NEXT hint may name targets
        stats_banner = app.query_one("#stats-banner")
        plain = stats_banner.render().plain
        assert "Targets: 1" in plain
        assert "Services: 1" in plain
        # Untested service exists -> engine must surface a concrete next action in the banner
        assert "NEXT:" in plain

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


@pytest.mark.asyncio
async def test_run_recipe_auto_routes_to_initial_recon_on_bare_target():
    """'r' on a fresh target (no service) must fall through to phase-0 recon."""
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.90")
        app.refresh_all_views()
        app.selected_target = target
        app.selected_service = None

        app.action_run_recipe()
        await pilot.pause()

        from synapse.tui.modals.initial_recon_modal import InitialReconModal
        assert isinstance(app.screen, InitialReconModal), "r must auto-route to Initial Recon"
        assert "10.10.11.90" in str(app.screen.target_ip)


@pytest.mark.asyncio
async def test_triage_modal_opens_with_state_and_actions():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.91")
        app.refresh_all_views()
        app.selected_target = target

        app.action_triage()
        await pilot.pause()

        from synapse.tui.modals.triage_modal import TriageModal
        assert isinstance(app.screen, TriageModal)
        modal = app.screen
        assert any(s.ip == "10.10.11.91" for s in modal.snapshots)
        # Bare target -> recon action must be present and first
        assert modal.actions[0].kind == "recon"

        state_text = modal.query_one("#state-block").render().plain
        assert "Known:" in state_text and "Tested:" in state_text
        actions_text = modal.query_one("#actions-block").render().plain
        assert "why:" in actions_text


@pytest.mark.asyncio
async def test_stuck_modal_detects_rabbit_hole():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.92")
        svc = app.repo.add_or_update_service(target.id, 3306, "tcp", "mysql")
        chk = app.repo.add_checklist_item(svc.id, title="default creds", command_template="x")
        app.repo.update_checklist_status(chk.id, ChecklistStatus.DEAD_END)
        app.repo.update_service_status(svc.id, ServiceStatus.DEAD_END)
        app.refresh_all_views()
        app.selected_target = target

        app.action_stuck_check()
        await pilot.pause()

        from synapse.tui.modals.stuck_modal import StuckModal
        assert isinstance(app.screen, StuckModal)
        report = app.screen.report
        assert report.dead_end_services, "dead-end service must be listed"
        assert report.is_stuck, "all-dead-end workspace is the rabbit-hole signature"
        plain = app.screen.query_one("#stuck-report-block").render().plain
        assert "Dead Ends" in plain


@pytest.mark.asyncio
async def test_scope_toggle_filters_tree_and_engine():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.93")
        app.refresh_all_views()
        app.selected_target = target
        assert target.in_scope is True

        app.action_toggle_scope()

        fresh = app.repo.get_target_by_ip("10.10.11.93")
        assert fresh.in_scope is False
        # Tree renders the out-of-scope marker on the target node label
        tree = app.query_one("#target-tree")
        node_label = str(tree.root.children[0].label)
        assert "OUT-OF-SCOPE" in str(node_label)

        # Engine must exclude the OOS host from suggestions
        actions = get_next_actions(*app._assessment_inputs())
        assert not [a for a in actions if a.target_ip == "10.10.11.93"]

        # Toggle back
        app.action_toggle_scope()
        assert app.repo.get_target_by_ip("10.10.11.93").in_scope is True


@pytest.mark.asyncio
async def test_credential_lifecycle_cycle_via_tui():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.94")
        cred = app.repo.add_credential("svc_sql", "sa_password", service_scope="mssql")
        app.selected_target = target
        app.query_one("#tabs", TabbedContent).active = "tab-creds"
        app.refresh_all_views()

        table = app.query_one("#cred-table", DataTable)
        table.move_cursor(row=0, column=0)
        assert app.screen is not None

        # untested -> valid
        app.action_mark_cred_tested()
        tested = app.repo.get_credential_by_id(cred.id).tested_targets
        assert tested["10.10.11.94"]["valid"] is True

        # valid -> invalid
        app.action_mark_cred_tested()
        tested = app.repo.get_credential_by_id(cred.id).tested_targets
        assert tested["10.10.11.94"]["valid"] is False

        # invalid -> untested (wiped for this host)
        app.action_mark_cred_tested()
        tested = app.repo.get_credential_by_id(cred.id).tested_targets
        assert "10.10.11.94" not in tested


@pytest.mark.asyncio
async def test_runner_evidence_links_back_to_checklist_item():
    """Evidence saved from a recipe run must carry the checklist relationship."""
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.95")
        svc = app.repo.add_or_update_service(target.id, 80, "tcp", "http", "nginx")
        chk = app.repo.add_checklist_item(svc.id, title="dirb scan", command_template="dirb http://{IP}")

        app.selected_target = app.repo.get_target_by_id(target.id)
        app.selected_service = app.repo.get_service_by_id(svc.id)

        app.repo.add_evidence(
            target_id=target.id,
            service_id=svc.id,
            checklist_id=chk.id,
            proof_type=ProofType.COMMAND_OUTPUT,
            title=f"Output for: {chk.title}",
            command="dirb http://10.10.11.95",
            output="+ http://10.10.11.95/admin",
        )
        app.refresh_all_views()

        evidence_list = app.repo.list_evidence()
        assert evidence_list[0].checklist_id == chk.id

        widget = app.query_one("#evidence-view")
        table = widget.query_one("#evidence-table", DataTable)
        row = table.get_row_at(0)
        # Column 2 = Service context, column 5 = Linked Check
        assert "80/tcp" in row[2]
        assert "dirb scan" in row[5]


@pytest.mark.asyncio
async def test_service_status_transitions_derive_from_checks():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.96")
        svc_obj = app.repo.add_or_update_service(target.id, 21, "tcp", "ftp")

        c1 = app.repo.add_checklist_item(svc_obj.id, title="anon ftp", command_template="x")
        c2 = app.repo.add_checklist_item(svc_obj.id, title="version hunt", command_template="y")

        app.selected_target = app.repo.get_target_by_id(target.id)
        app.selected_service = app.repo.get_service_by_id(svc_obj.id)

        from synapse.models import ServiceStatus as SS

        # One check running -> IN_PROGRESS
        app.repo.update_checklist_status(c1.id, ChecklistStatus.RUNNING)
        app.selected_service = app.repo.get_service_by_id(svc_obj.id)
        app._refresh_service_state(app.selected_service)
        assert app.repo.get_service_by_id(svc_obj.id).status == SS.IN_PROGRESS

        # Finding appears -> VULNERABLE wins
        app.repo.update_checklist_status(c2.id, ChecklistStatus.FINDING)
        app.selected_service = app.repo.get_service_by_id(svc_obj.id)
        app._refresh_service_state(app.selected_service)
        assert app.repo.get_service_by_id(svc_obj.id).status == SS.VULNERABLE

        # Everything resolved -> ENUMERATED
        app.repo.update_checklist_status(c1.id, ChecklistStatus.CHECKED)
        app.repo.update_checklist_status(c2.id, ChecklistStatus.CHECKED)
        app.selected_service = app.repo.get_service_by_id(svc_obj.id)
        app._refresh_service_state(app.selected_service)
        assert app.repo.get_service_by_id(svc_obj.id).status == SS.ENUMERATED

        # All dead ends -> DEAD_END
        app.repo.update_checklist_status(c1.id, ChecklistStatus.DEAD_END)
        app.repo.update_checklist_status(c2.id, ChecklistStatus.DEAD_END)
        app.selected_service = app.repo.get_service_by_id(svc_obj.id)
        app._refresh_service_state(app.selected_service)
        assert app.repo.get_service_by_id(svc_obj.id).status == SS.DEAD_END
