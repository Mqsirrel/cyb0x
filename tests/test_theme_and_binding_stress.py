"""Milestone M1 Empirical Stress Tests: Theme Refresh & Binding Dispatch.

Author: Challenger 2 (Theme Refresh & Binding Dispatch Stress-Tester)
Focus:
1. Rapid theme switching (claudish, claudish-light, synapse, builtins) & contrast verification.
2. Complete verification of all 29 keybindings in SynapseTUI (especially hidden show=False bindings).
3. Concurrent modal / theme / tab stress and stability verification.
"""

from __future__ import annotations

import asyncio
import math
from typing import Tuple
import pytest
from rich.color import Color
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, TabbedContent

from synapse.db.repository import DatabaseRepository
from synapse.models import ChecklistStatus, CredentialType, LeadPriority, LeadStatus, TargetStatus
from synapse.tui.app import SynapseTUI
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
from synapse.tui.theme import (
    BACKGROUND,
    CLAUDISH_LIGHT_THEME,
    CLAUDISH_THEME,
    CREAM,
    DARK_CHARCOAL,
    ERROR_RED,
    KRAFT,
    MUTED,
    SAGE,
    SURFACE,
    SURFACE_RAISED,
    SYNAPSE_THEME,
    TERRACOTTA,
)


def _hex_to_rgb(hex_str: str) -> Tuple[int, int, int]:
    h = hex_str.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _relative_luminance(hex_str: str) -> float:
    """Calculates WCAG 2.1 relative luminance for a given hex color."""
    r, g, b = _hex_to_rgb(hex_str)
    channels = []
    for c in (r, g, b):
        sc = c / 255.0
        if sc <= 0.03928:
            channels.append(sc / 12.92)
        else:
            channels.append(math.pow((sc + 0.055) / 1.055, 2.4))
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def _contrast_ratio(hex1: str, hex2: str) -> float:
    """Calculates WCAG 2.1 contrast ratio between two hex colors."""
    l1 = _relative_luminance(hex1)
    l2 = _relative_luminance(hex2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


# =============================================================================
# 1. THEME REFRESH & CONTRAST STRESS TESTS
# =============================================================================

def test_theme_color_contrast_metrics():
    """Verify Claudish, Claudish-Light, and Synapse themes meet readability standards."""
    # Claudish Dark Theme
    fg_bg_dark = _contrast_ratio(CREAM, BACKGROUND)
    fg_surface_dark = _contrast_ratio(CREAM, SURFACE)
    fg_panel_dark = _contrast_ratio(CREAM, SURFACE_RAISED)
    muted_bg_dark = _contrast_ratio(MUTED, BACKGROUND)
    primary_bg_dark = _contrast_ratio(TERRACOTTA, BACKGROUND)
    sage_bg_dark = _contrast_ratio(SAGE, BACKGROUND)

    # Primary text on dark backgrounds must exceed WCAG AA 4.5:1 (actually >10:1 for Cream on Dark Charcoal)
    assert fg_bg_dark >= 10.0, f"Foreground-to-background contrast too low: {fg_bg_dark:.2f}:1"
    assert fg_surface_dark >= 8.0, f"Foreground-to-surface contrast too low: {fg_surface_dark:.2f}:1"
    assert fg_panel_dark >= 6.0, f"Foreground-to-panel contrast too low: {fg_panel_dark:.2f}:1"
    assert muted_bg_dark >= 4.5, f"Muted text contrast too low: {muted_bg_dark:.2f}:1"
    assert primary_bg_dark >= 3.0, f"Primary accent contrast too low: {primary_bg_dark:.2f}:1"
    assert sage_bg_dark >= 4.0, f"Sage accent contrast too low: {sage_bg_dark:.2f}:1"

    # Claudish Light Theme
    cl_fg = str(CLAUDISH_LIGHT_THEME.foreground)
    cl_bg = str(CLAUDISH_LIGHT_THEME.background)
    cl_surface = str(CLAUDISH_LIGHT_THEME.surface)
    cl_panel = str(CLAUDISH_LIGHT_THEME.panel)
    cl_muted = str(CLAUDISH_LIGHT_THEME.variables["text-muted"])

    fg_bg_light = _contrast_ratio(cl_fg, cl_bg)
    fg_surface_light = _contrast_ratio(cl_fg, cl_surface)
    muted_bg_light = _contrast_ratio(cl_muted, cl_bg)

    assert fg_bg_light >= 10.0, f"Light theme foreground-to-background contrast too low: {fg_bg_light:.2f}:1"
    assert fg_surface_light >= 9.0, f"Light theme foreground-to-surface contrast too low: {fg_surface_light:.2f}:1"
    assert muted_bg_light >= 4.0, f"Light theme muted text contrast too low: {muted_bg_light:.2f}:1"

    # Verify background polarity
    assert _relative_luminance(cl_bg) > 0.8, "Claudish Light background must have high luminance"
    assert _relative_luminance(BACKGROUND) < 0.05, "Claudish Dark background must have low luminance"


@pytest.mark.asyncio
async def test_rapid_theme_switching_stress_loop():
    """Stress test rapid switching between all themes without visual or state crash."""
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test(size=(120, 36)) as pilot:
        # Populate test data
        t = app.repo.add_or_get_target("10.10.11.100", hostname="stress.htb", os="Linux")
        svc = app.repo.add_or_update_service(t.id, 80, "tcp", "http", "nginx", "1.18.0")
        app.repo.add_checklist_item(svc.id, title="Test Check 1", category="enum", command_template="curl {IP}")
        app.repo.add_credential("admin", "p@ss", target_id=t.id)
        app.repo.add_lead(title="Stress Lead", priority=LeadPriority.HIGH, target_id=t.id)
        app.refresh_all_views()
        await pilot.pause(0.05)

        themes_to_cycle = ["claudish", "claudish-light", "synapse", "nord", "monokai", "gruvbox", "tokyo-night"]
        available = [th for th in themes_to_cycle if th in app.available_themes]
        assert len(available) >= 3

        # Execute 50 rapid theme transitions
        for i in range(50):
            target_theme = available[i % len(available)]
            app.theme = target_theme
            await pilot.pause(0.01)

            # Assert theme was applied and app remains healthy
            assert app.theme == target_theme
            assert app.current_theme.name == target_theme

            # Verify stats banner and views render without throwing exceptions
            banner_plain = app.query_one("#stats-banner").render().plain
            assert "Targets:" in banner_plain
            assert "stress.htb" in banner_plain or "10.10.11.100" in banner_plain or "Services:" in banner_plain

        # Settle back to default claudish
        app.theme = "claudish"
        await pilot.pause(0.05)
        assert app.theme == "claudish"


@pytest.mark.asyncio
async def test_theme_switching_with_active_modals():
    """Verify switching themes dynamically while modal screens are open."""
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test(size=(120, 36)) as pilot:
        t = app.repo.add_or_get_target("10.10.11.105")
        app.refresh_all_views()

        # 1. Open RunnerModal and switch theme
        runner = RunnerModal(command="echo test", title="Runner Theme Test")
        await app.push_screen(runner)
        await pilot.pause(0.05)
        assert isinstance(app.screen, RunnerModal)

        app.theme = "claudish-light"
        await pilot.pause(0.05)
        dialog = runner.query_one("#dialog")
        assert dialog.region.width <= 120 and dialog.region.height <= 36

        app.pop_screen()
        await pilot.pause(0.05)

        # 2. Open JumpModal and switch theme
        jump = JumpModal(app.repo)
        await app.push_screen(jump)
        await pilot.pause(0.05)
        assert isinstance(app.screen, JumpModal)

        app.theme = "synapse"
        await pilot.pause(0.05)
        dialog = jump.query_one("#dialog")
        assert dialog.region.width <= 120 and dialog.region.height <= 36

        app.pop_screen()
        await pilot.pause(0.05)

        # 3. Open CommandPaletteModal and switch theme
        palette = CommandPaletteModal()
        await app.push_screen(palette)
        await pilot.pause(0.05)
        assert isinstance(app.screen, CommandPaletteModal)

        app.theme = "claudish"
        await pilot.pause(0.05)
        dialog = palette.query_one("#dialog")
        assert dialog.region.width <= 120 and dialog.region.height <= 36

        app.pop_screen()
        await pilot.pause(0.05)


@pytest.mark.asyncio
async def test_theme_switching_during_tab_navigation():
    """Stress test tab switches interleaved with theme changes."""
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test(size=(120, 36)) as pilot:
        tabs = app.query_one("#tabs", TabbedContent)
        tab_ids = ["tab-workbench", "tab-creds", "tab-leads", "tab-evidence", "tab-pivots"]
        themes = ["claudish", "claudish-light", "synapse"]

        for iteration in range(15):
            tab_id = tab_ids[iteration % len(tab_ids)]
            theme = themes[iteration % len(themes)]

            tabs.active = tab_id
            app.theme = theme
            await pilot.pause(0.02)

            assert tabs.active == tab_id
            assert app.theme == theme


# =============================================================================
# 2. 29 KEYBINDINGS COMPREHENSIVE DISPATCH STRESS TESTS
# =============================================================================

def test_binding_registry_metadata():
    """Empirically inspect SynapseTUI.BINDINGS for exact counts and show flags."""
    bindings = SynapseTUI.BINDINGS
    assert len(bindings) == 30, f"Expected 30 total bindings, found {len(bindings)}"

    shown = [b for b in bindings if b.show is True]
    hidden = [b for b in bindings if b.show is False]

    assert len(shown) == 8, f"Expected 8 shown bindings, found {len(shown)}: {[b.key for b in shown]}"
    assert len(hidden) == 22, f"Expected 22 hidden bindings, found {len(hidden)}: {[b.key for b in hidden]}"

    expected_shown_keys = {"ctrl+k", "ctrl+p", "ctrl+l", "r", "full_stop", "T", "question_mark", "q"}
    actual_shown_keys = {b.key for b in shown}
    assert actual_shown_keys == expected_shown_keys, f"Mismatch in shown keys: {actual_shown_keys} != {expected_shown_keys}"


@pytest.mark.asyncio
async def test_footer_rendering_and_width_compliance():
    """Verify that footer only shows the 8 curated power bindings within 80 cols."""
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.1)
        footer = app.query_one(Footer)
        rendered_keys = list(footer.children)
        assert len(rendered_keys) == 8, f"Rendered footer keys count: {len(rendered_keys)}"
        total_width = sum(k.region.width for k in rendered_keys)
        assert total_width <= 80, f"Footer width ({total_width}) exceeded 80 cols"


@pytest.mark.asyncio
async def test_all_29_keybindings_dispatch_cleanly():
    """Press each of the 29 registered keys and verify direct action dispatch."""
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test(size=(120, 36)) as pilot:
        # Populate initial test state
        target = app.repo.add_or_get_target("10.10.11.222", hostname="dispatch.htb", os="Linux")
        svc = app.repo.add_or_update_service(target.id, 80, "tcp", "http")
        chk = app.repo.add_checklist_item(svc.id, title="Discovery Check", category="enum", command_template="nmap {IP}")
        cred = app.repo.add_credential("testuser", "secretpass", target_id=target.id)
        lead = app.repo.add_lead("SQLi Lead", priority=LeadPriority.MEDIUM, target_id=target.id)
        app.refresh_all_views()
        app.selected_target = target
        app.selected_service = svc
        await pilot.pause(0.1)

        # Helper to test modal-launching bindings
        async def assert_modal_binding(key: str, modal_cls: type):
            await pilot.press(key)
            await pilot.pause(0.05)
            assert isinstance(app.screen, modal_cls), f"Key '{key}' failed to open {modal_cls.__name__}"
            await pilot.press("escape")
            await pilot.pause(0.05)
            assert not isinstance(app.screen, modal_cls), f"Failed to dismiss {modal_cls.__name__}"

        # 1. ctrl+k (show=True) -> CommandPaletteModal
        await assert_modal_binding("ctrl+k", CommandPaletteModal)

        # 2. ctrl+p (show=True) -> JumpModal
        await assert_modal_binding("ctrl+p", JumpModal)

        # 3. ctrl+l (show=True) -> WorkspaceModal
        await assert_modal_binding("ctrl+l", WorkspaceModal)

        # 4. r (show=True) -> run_recipe (RunnerModal on selected checklist item)
        # Focus on checklist table first
        tabs = app.query_one("#tabs", TabbedContent)
        tabs.active = "tab-workbench"
        chk_table = app.query_one("#checklist-table", DataTable)
        chk_table.move_cursor(row=0, column=0)
        await pilot.pause(0.05)
        await assert_modal_binding("r", RunnerModal)

        # 5. full_stop / . (show=True) -> ScratchpadModal
        await assert_modal_binding("full_stop", ScratchpadModal)

        # 6. period (show=False) -> ScratchpadModal (alias)
        await assert_modal_binding("period", ScratchpadModal)

        # 7. T (show=True) -> ThemeModal
        await assert_modal_binding("T", ThemeModal)

        # 8. ctrl+t (show=False) -> ThemeModal (alias)
        await assert_modal_binding("ctrl+t", ThemeModal)

        # 9. question_mark / ? (show=True) -> HelpModal
        await assert_modal_binding("question_mark", HelpModal)

        # 10. f1 (show=False) -> HelpModal (alias)
        await assert_modal_binding("f1", HelpModal)

        # 11. a (show=False) -> AddTargetModal
        await assert_modal_binding("a", AddTargetModal)

        # 12. i (show=False) -> InitialReconModal
        await assert_modal_binding("i", InitialReconModal)

        # 13. n (show=False) -> TriageModal
        await assert_modal_binding("n", TriageModal)

        # 14. s (show=False) -> StuckModal
        await assert_modal_binding("s", StuckModal)

        # 15. o (show=False) -> toggle_scope
        orig_scope = app.selected_target.in_scope
        await pilot.press("o")
        await pilot.pause(0.05)
        assert app.repo.get_target_by_id(target.id).in_scope == (not orig_scope)
        await pilot.press("o")
        await pilot.pause(0.05)
        assert app.repo.get_target_by_id(target.id).in_scope == orig_scope

        # 16. c (show=False) -> AddCredModal
        await assert_modal_binding("c", AddCredModal)

        # 17. t (show=False) -> mark_cred_tested (on tab-creds)
        tabs.active = "tab-creds"
        await pilot.pause(0.05)
        cred_table = app.query_one("#cred-table", DataTable)
        cred_table.move_cursor(row=0, column=0)
        await pilot.press("t")
        await pilot.pause(0.05)
        tested_state = app.repo.get_credential_by_id(cred.id).tested_targets
        assert "10.10.11.222" in tested_state and tested_state["10.10.11.222"]["valid"] is True

        # 18. l (show=False) -> AddLeadModal
        await assert_modal_binding("l", AddLeadModal)

        # 19. e (show=False) -> AddEvidenceModal
        await assert_modal_binding("e", AddEvidenceModal)

        # 20. space (show=False) -> toggle_status
        tabs.active = "tab-workbench"
        await pilot.pause(0.05)
        chk_table = app.query_one("#checklist-table", DataTable)
        chk_table.move_cursor(row=0, column=0)
        orig_chk_status = app.repo.get_checklist_by_id(chk.id).status
        await pilot.press("space")
        await pilot.pause(0.05)
        new_chk_status = app.repo.get_checklist_by_id(chk.id).status
        assert new_chk_status != orig_chk_status

        # 21. x (show=False) -> ExportModal
        await assert_modal_binding("x", ExportModal)

        # 22. p (show=False) -> ProfileModal
        await assert_modal_binding("p", ProfileModal)

        # 23. g (show=False) -> GuidedPhaseModal
        await assert_modal_binding("g", GuidedPhaseModal)

        # 24-28. Tab switches: 1, 2, 3, 4, 5 (all show=False)
        await pilot.press("2")
        await pilot.pause(0.05)
        assert tabs.active == "tab-creds"

        await pilot.press("3")
        await pilot.pause(0.05)
        assert tabs.active == "tab-leads"

        await pilot.press("4")
        await pilot.pause(0.05)
        assert tabs.active == "tab-evidence"

        await pilot.press("5")
        await pilot.pause(0.05)
        assert tabs.active == "tab-pivots"

        await pilot.press("1")
        await pilot.pause(0.05)
        assert tabs.active == "tab-workbench"

        # 29. q (show=True) -> quit
        # Pressing 'q' causes app to exit
        await pilot.press("q")
        await pilot.pause(0.05)
        assert app.is_running is False


@pytest.mark.asyncio
async def test_binding_stress_fuzz_sequence():
    """Fuzz random rapid sequences of keybindings to verify zero deadlocks or crashes."""
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test(size=(120, 36)) as pilot:
        target = app.repo.add_or_get_target("10.10.11.230")
        app.refresh_all_views()

        keys_sequence = [
            "1", "2", "3", "4", "5", "1",
            "T", "escape",
            "ctrl+p", "escape",
            "ctrl+k", "escape",
            "question_mark", "escape",
            "full_stop", "escape",
            "n", "escape",
            "s", "escape",
            "p", "escape",
            "g", "escape",
            "x", "escape",
            "a", "escape",
            "c", "escape",
            "l", "escape",
            "e", "escape",
            "i", "escape",
            "2", "3", "1",
        ]

        for k in keys_sequence:
            await pilot.press(k)
            await pilot.pause(0.02)

        # App should still be healthy and responsive
        assert app.is_running is True
        assert not isinstance(app.screen, ModalScreen)
        assert app.query_one("#tabs", TabbedContent).active == "tab-workbench"
