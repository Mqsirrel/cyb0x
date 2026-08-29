"""Deep usability and UI interaction tests for Synapse TUI."""

import pytest
from textual.widgets import TabbedContent, Tree

from synapse.db.repository import DatabaseRepository
from synapse.models import TargetStatus, ServiceStatus, ChecklistStatus
from synapse.tui.app import SynapseTUI
from synapse.tui.modals.command_palette_modal import CommandPaletteModal
from synapse.tui.modals.jump_modal import JumpModal
from synapse.tui.modals.scratchpad_modal import ScratchpadModal
from synapse.tui.modals.workspace_modal import WorkspaceModal
from synapse.tui.modals.theme_modal import ThemeModal
from synapse.tui.modals.help_modal import HelpModal
from synapse.tui.widgets.service_detail import ServiceDetailWidget


@pytest.mark.asyncio
async def test_tui_command_palette_flow():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        # Trigger command palette with action
        app.action_command_palette()
        await pilot.pause()

        assert isinstance(app.screen, CommandPaletteModal)
        # Select an action and press enter to dismiss
        await pilot.press("enter")
        await pilot.pause()
        assert not isinstance(app.screen, CommandPaletteModal)


@pytest.mark.asyncio
async def test_tui_jump_modal_flow():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.200", hostname="target.htb")
        svc = app.repo.add_or_update_service(target.id, 80, "tcp", "http", "nginx", "1.18.0")
        app.refresh_all_views()

        app.action_jump_to()
        await pilot.pause()

        assert isinstance(app.screen, JumpModal)
        await pilot.press("enter")
        await pilot.pause()
        assert not isinstance(app.screen, JumpModal)


@pytest.mark.asyncio
async def test_tui_scratchpad_flow():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        app.action_open_scratchpad()
        await pilot.pause()

        assert isinstance(app.screen, ScratchpadModal)
        modal = app.screen
        area = modal.query_one("#scratchpad-area")
        area.load_text("Discovered potential CVE on port 8080")

        # Save and close via escape
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, ScratchpadModal)

        # Verify saved in repo
        saved = app.repo.get_scratchpad()
        assert "CVE on port 8080" in saved


@pytest.mark.asyncio
async def test_tui_workspace_modal_flow():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        app.action_manage_workspaces()
        await pilot.pause()

        assert isinstance(app.screen, WorkspaceModal)
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, WorkspaceModal)


@pytest.mark.asyncio
async def test_tui_help_modal_flow():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        app.action_show_help()
        await pilot.pause()

        assert isinstance(app.screen, HelpModal)
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, HelpModal)


@pytest.mark.asyncio
async def test_tui_theme_modal_flow():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        app.action_select_theme()
        await pilot.pause()

        assert isinstance(app.screen, ThemeModal)
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, ThemeModal)


@pytest.mark.asyncio
async def test_tui_target_tree_navigation():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.201", hostname="dc.htb", os="Windows")
        svc = app.repo.add_or_update_service(target.id, 88, "tcp", "kerberos", "Kerberos", "5")
        app.refresh_all_views()

        detail = app.query_one("#service-detail", ServiceDetailWidget)

        # Emulate selecting target node
        snap = app._load_snapshot()
        detail.display_target_360(target, snap["credentials"], snap["evidence"])
        await pilot.pause()

        header_text = detail.query_one("#service-header").render().plain
        assert "TARGET 360° OVERVIEW" in header_text
        assert "10.10.11.201" in header_text

        # Emulate selecting service node
        detail.display_service(target, svc)
        await pilot.pause()

        header_text = detail.query_one("#service-header").render().plain
        assert "Port 88/tcp" in header_text

