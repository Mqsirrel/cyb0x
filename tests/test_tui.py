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
