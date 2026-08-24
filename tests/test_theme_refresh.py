"""Tests for the synapse theme refresh: palette, chips, modal anatomy, RunnerModal."""

import pytest

from synapse.models import ChecklistStatus, LeadPriority, LeadStatus, TargetStatus


@pytest.mark.asyncio
async def test_theme_activation_and_palette_variables():
    from synapse.tui.app import SynapseTUI
    from synapse.tui.theme import BACKGROUND, SURFACE, TERRACOTTA

    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        assert app.theme in ("claudish", "synapse")
        assert "dracula" not in app.available_themes
        assert "claudish" in app.available_themes
        assert str(app.current_theme.primary).lower() == TERRACOTTA.lower()
        assert app.current_theme.background == BACKGROUND
        assert app.current_theme.surface == SURFACE


def test_status_chips_cover_every_enum_member():
    from synapse.tui.theme import (
        checklist_chip,
        cred_test_chip,
        lead_priority_chip,
        lead_status_chip,
        service_status_chip,
        target_status_glyph,
        triage_chip,
    )

    for status in ChecklistStatus:
        markup = checklist_chip(status)
        assert "#D97757" in markup or "#8FA876" in markup or "#C4553B" in markup or "#D4A27F" in markup or "#A8A099" in markup

    for priority in LeadPriority:
        assert lead_priority_chip(priority).startswith("[")
    for status in LeadStatus:
        assert lead_status_chip(status).startswith("[")
    for value in ("untested", "in_progress", "enumerated", "vulnerable", "dead_end"):
        assert service_status_chip(value)
    for status in TargetStatus:
        assert target_status_glyph(status)

    assert triage_chip("RECON") == triage_chip("RECON")
    assert "10.0.0.9" in cred_test_chip("10.0.0.9", valid=True, admin=True)
    assert "(Admin)" in cred_test_chip("10.0.0.9", valid=True, admin=True)


@pytest.mark.asyncio
async def test_stats_banner_uses_glyphs_not_emojis():
    from synapse.tui.app import SynapseTUI

    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.250")
        svc = app.repo.add_or_update_service(target.id, 22, "tcp", "ssh")
        app.repo.add_checklist_item(svc.id, title="enum ssh", command_template="x")
        app.refresh_all_views()

        plain = app.query_one("#stats-banner").render().plain
        assert "Targets:" in plain and "Services:" in plain
        assert "NEXT:" in plain
        for emoji in ("🎯", "⚡", "🔑", "🚩"):
            assert emoji not in plain


@pytest.mark.asyncio
async def test_all_modals_follow_base_anatomy():
    from synapse.assessment.engine import StuckReport
    from synapse.tui.app import SynapseTUI
    from synapse.tui.modals.add_cred_modal import AddCredModal
    from synapse.tui.modals.add_evidence_modal import AddEvidenceModal
    from synapse.tui.modals.add_lead_modal import AddLeadModal
    from synapse.tui.modals.add_target_modal import AddTargetModal
    from synapse.tui.modals.base import SynapseModal
    from synapse.tui.modals.export_modal import ExportModal
    from synapse.tui.modals.help_modal import HelpModal
    from synapse.tui.modals.runner_modal import RunnerModal
    from synapse.tui.modals.stuck_modal import StuckModal
    from synapse.tui.modals.triage_modal import TriageModal

    app = SynapseTUI(db_path=":memory:")
    modals = [
        RunnerModal(command="echo hi", title="Run: x"),
        HelpModal(),
        ExportModal(),
        AddTargetModal(),
        AddCredModal(),
        AddLeadModal(),
        AddEvidenceModal(target_ip="10.10.11.1"),
        StuckModal(StuckReport(dead_end_services=["svc"])),
        TriageModal([], []),
    ]
    async with app.run_test(size=(120, 36)) as pilot:
        for modal in modals:
            assert isinstance(modal, SynapseModal), type(modal).__name__
            await pilot.app.push_screen(modal, lambda r: None)
            await pilot.pause()
            dialog = modal.query_one("#dialog")
            assert str(dialog.border_title).startswith("▸ "), type(modal).__name__
            assert modal.query_one("#action-bar") is not None
            assert modal.query_one("#key-hints") is not None
            assert len(modal.query("Button")) >= 1
            app.pop_screen()
            await pilot.pause()


def test_output_highlighter_nmap_ffuf_rustscan():
    from synapse.tui.output_syntax import compute_output_highlight

    nmap = (
        "Starting Nmap 7.94\n"
        "PORT   STATE SERVICE\n"
        "22/tcp open  ssh\n"
        "80/tcp filtered http\n"
        "443/tcp closed https\n"
        "Nmap done: 1 IP address (1 host up)"
    )
    result = compute_output_highlight(nmap)
    assert result.text == nmap
    keys = {k for spans in result.line_spans for _, _, k in spans}
    assert "syn.summary" in keys
    assert "syn.header" in keys
    assert "syn.state-open" in keys
    assert "syn.state-filtered" in keys
    assert "syn.state-closed" in keys

    ffuf = "[Status: 200, Size: 100] [Url: http://10.0.0.1/admin]"
    keys_ffuf = {k for spans in compute_output_highlight(ffuf).line_spans for _, _, k in spans}
    assert "syn.status-ok" in keys_ffuf
    assert "syn.url" in keys_ffuf

    rustscan = "Open 10.10.11.10:22"
    keys_rs = {k for spans in compute_output_highlight(rustscan).line_spans for _, _, k in spans}
    assert "syn.state-open" in keys_rs
    assert "syn.port" in keys_rs

    stderr_block = "out line\n[STDERR]\nerr happened"
    parsed = compute_output_highlight(stderr_block)
    assert [(0, 8, "syn.stderr-label")] == parsed.line_spans[1]
    assert parsed.line_spans[2][0][2] == "syn.stderr"

    flags = "CTF{abc} and e4d909c290d0fb1ca068ffaddf22cbd0"
    keys_flag = {k for spans in compute_output_highlight(flags).line_spans for _, _, k in spans}
    assert "syn.flag" in keys_flag


def test_output_highlighter_decodes_ansi_passthrough():
    from synapse.tui.output_syntax import compute_output_highlight, contains_ansi

    raw = "\x1b[32mOPEN\x1b[0m port \x1b[1;33mFILTERED\x1b[0m"
    assert contains_ansi(raw)
    result = compute_output_highlight(raw)
    assert "\x1b" not in result.text
    assert result.text == "OPEN port FILTERED"
    dyn_styles = [s for spans in result.line_spans for _, _, s in spans if s.startswith("dyn-")]
    assert dyn_styles, "ANSI colors must map to dynamic styles"


@pytest.mark.asyncio
async def test_runner_modal_run_flow_and_save_contract():
    from synapse.tui.app import SynapseTUI
    from synapse.tui.modals.runner_modal import OutputArea, RunnerModal

    app = SynapseTUI(db_path=":memory:")
    captured = []
    async with app.run_test(size=(120, 36)) as pilot:
        modal = RunnerModal(
            command="echo '22/tcp open  ssh' && echo CTF{flow}",
            title="Run: smoke",
            context="10.10.11.250 ▸ 445/tcp smb",
        )
        await pilot.app.push_screen(modal, captured.append)
        await pilot.pause()

        assert modal.query_one("#btn-save").disabled is True

        await pilot.press("ctrl+r")
        for _ in range(60):
            await pilot.pause(0.1)
            if not modal._run_in_flight:
                break
        await pilot.pause()

        chips = modal.query_one("#result-chips").render().plain
        assert "EXIT 0" in chips
        assert "1 FLAG" in chips
        assert "FLAG HIT" in modal.query_one("#flag-strip-text").render().plain
        assert modal.query_one("#btn-save").disabled is False

        out = modal.query_one("#cmd-output", OutputArea)
        assert "22/tcp open" in out.text and "CTF{flow}" in out.text
        assert out._highlights, "grammar highlight spans must be applied"

        await pilot.press("ctrl+s")
        await pilot.pause()

        assert len(captured) == 1
        res = captured[0]
        assert res["action"] == "save_evidence"
        assert "CTF{flow}" in res["output"]


@pytest.mark.asyncio
async def test_theme_modal_switcher():
    from synapse.tui.app import SynapseTUI
    from synapse.tui.modals.theme_modal import ThemeModal

    app = SynapseTUI(db_path=":memory:")
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.press("T")
        await pilot.pause(0.1)
        assert isinstance(app.screen, ThemeModal)

        # Select tokyo-night
        await pilot.press("down")
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert app.theme == "tokyo-night"

        # Switch back to claudish
        await pilot.press("T")
        await pilot.pause(0.1)
        await pilot.press("up")
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert app.theme == "claudish"
