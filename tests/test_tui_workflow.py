"""Tests for the TUI Guided Workflow & Profile Modal interfaces."""

import pytest
from synapse.db.repository import DatabaseRepository
from synapse.models import ChecklistStatus
from synapse.tui.app import SynapseTUI
from synapse.tui.modals.profile_modal import ProfileModal
from synapse.tui.modals.guided_phase_modal import GuidedPhaseModal


@pytest.mark.asyncio
async def test_tui_profile_workflow():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        # Profile modal lists profiles from the loader, not a hardcoded set.
        await pilot.press("p")
        await pilot.pause(0.1)

        assert isinstance(app.screen, ProfileModal)
        modal = app.screen
        assert {p.id for p in modal.profiles} >= {"ejptv2", "network_pentest", "web_pentest", "htb_lab"}

        await pilot.press("escape")
        await pilot.pause(0.1)
        assert not isinstance(app.screen, ProfileModal)

        # Guided workflow modal opens cleanly even on an empty workspace.
        await pilot.press("g")
        await pilot.pause(0.1)
        assert isinstance(app.screen, GuidedPhaseModal)
        assert isinstance(app.screen.progress, dict)

        await pilot.press("escape")
        await pilot.pause(0.1)
        assert not isinstance(app.screen, GuidedPhaseModal)

        # Stats banner shows the active methodology name (default: eJPTv2).
        banner = app.query_one("#stats-banner")
        assert "eJPTv2" in str(banner.render())


@pytest.mark.asyncio
async def test_profile_selection_persists_and_updates_banner():
    repo = DatabaseRepository(":memory:")
    app = SynapseTUI(db_path=":memory:", repo=repo)
    async with app.run_test():
        # Simulate choosing web_pentest through the modal callback path.
        chosen = "web_pentest"
        assert app.methodology.set_active_profile(chosen)
        app.active_profile = chosen
        repo.set_metadata("active_profile_id", chosen)
        app.update_stats_banner()

        banner = app.query_one("#stats-banner")
        assert "Web Application Penetration Testing" in str(banner.render())

        # A fresh app instance restores the persisted selection.
        app2 = SynapseTUI(db_path=":memory:", repo=repo)
        assert app2.active_profile == "web_pentest"


@pytest.mark.asyncio
async def test_guided_modal_renders_live_phase_state():
    """Pending checks/findings from the workspace surface inside the modal."""
    repo = DatabaseRepository(":memory:")
    t = repo.add_or_get_target("10.10.10.99", hostname="lab.htb")
    svc = repo.add_or_update_service(t.id, 80, "tcp", "http")
    repo.add_checklist_item(svc.id, "Dirb scan", category="enum", status=ChecklistStatus.TODO)

    app = SynapseTUI(db_path=":memory:", repo=repo)
    async with app.run_test() as pilot:
        await pilot.press("g")
        await pilot.pause(0.1)
        assert isinstance(app.screen, GuidedPhaseModal)
        # The enum phase owns the pending Dirb check under every bundled profile.
        enum_progress = [p for p in app.screen.progress.values() if p.pending_checks]
        assert any("Dirb scan" in p.pending_checks for p in enum_progress)
