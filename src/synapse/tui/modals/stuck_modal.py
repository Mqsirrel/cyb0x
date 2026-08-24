"""'I'm stuck' / rabbit-hole detection modal."""

from __future__ import annotations

from typing import List

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import ScrollableContainer
from textual.widgets import Static

from synapse.assessment.engine import NextAction, StuckReport
from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import ERROR_RED, KRAFT, MUTED, SAGE


class StuckModal(SynapseModal[None]):
    """Analyzes dead ends vs untouched surface and suggests concrete escape routes.

    Deliberately does NOT dump generic command lists: every suggestion is derived
    from actual workspace state (untested ports, un-sprayed creds, stale leads).
    """

    BINDINGS = [
        Binding("escape", "cancel", "Close"),
        Binding("q", "cancel", "Close", show=False),
        Binding("s", "cancel", "Close", show=False),
    ]

    GLYPH = "▸"
    TITLE = "STUCK — Rabbit-Hole Analysis"

    DEFAULT_CSS = """
    StuckModal #dialog {
        width: 100;
        height: 80%;
    }
    StuckModal #modal-body {
        height: 1fr;
    }
    #stuck-scroll {
        height: 1fr;
    }
    .section-title {
        margin-top: 1;
        text-style: bold;
        color: $warning;
    }
    """

    def __init__(self, report: StuckReport, **kwargs):
        verdict = (
            f"[bold {ERROR_RED}]Rabbit-hole signature detected[/]"
            if report.is_stuck
            else f"[bold {SAGE}]Not stuck — open avenues remain[/]"
        )
        super().__init__(context=verdict, **kwargs)
        self.report = report

    def _build_report_text(self) -> Text:
        txt = Text()
        r = self.report

        txt.append("Proven Dead Ends (stop digging here):\n", style=f"bold {ERROR_RED}")
        if r.dead_end_services or r.dead_end_checks:
            for tag in r.dead_end_services:
                txt.append(f"  ✖ {tag}\n")
            for tag in r.dead_end_checks:
                txt.append(f"  ✖ {tag}\n")
            txt.append("  Dead ends are data, not failure — they shrink the search space.\n", style=MUTED)
        else:
            txt.append("  None recorded. Nothing has been conclusively ruled out yet.\n", style=MUTED)

        txt.append("\nUntested Surface (dig here instead):\n", style=f"bold {SAGE}")
        if r.untested_ports:
            for tag in r.untested_ports[:12]:
                txt.append(f"  ○ {tag}\n")
            if len(r.untested_ports) > 12:
                txt.append(f"  … and {len(r.untested_ports) - 12} more\n", style=MUTED)
        else:
            txt.append("  Everything discovered has been touched.\n", style=MUTED)

        txt.append("\nUn-sprayed Credentials:\n", style=f"bold {KRAFT}")
        if r.unsprayed_credentials:
            for line in r.unsprayed_credentials[:8]:
                txt.append(f"  @ {line}\n")
        else:
            txt.append("  No credential is waiting to be tried on a new host.\n", style=MUTED)

        if r.stale_leads:
            txt.append("\nStale Hypotheses (confirm or reject):\n", style=KRAFT)
            for line in r.stale_leads[:6]:
                txt.append(f"  ✦ {line}\n")

        return txt

    def _build_escape_text(self) -> Text:
        txt = Text()
        if self.report.is_stuck:
            txt.append(
                "⚠ Rabbit-hole signature detected: dead ends exist and no untried surface remains "
                "in scope. Consider re-scoping ('o'), adding targets ('a'), or stepping back to "
                "recon with different techniques ('i').\n\n",
                style=f"bold {ERROR_RED}",
            )
        if not self.report.suggestions:
            txt.append("No escape routes found — the workspace may be complete or empty.\n", style=SAGE)
            return txt
        txt.append("Suggested Escapes (state-derived, not generic):\n", style=f"bold {KRAFT}")
        for i, act in enumerate(self.report.suggestions, 1):
            txt.append(f"  [{i}] {act.title}\n")
            txt.append(f"      why: {act.rationale}\n", style=MUTED)
        return txt

    def compose_body(self) -> ComposeResult:
        with ScrollableContainer(id="stuck-scroll"):
            yield Static(self._build_report_text(), id="stuck-report-block")
            yield Static(self._build_escape_text(), id="escape-block")

    def modal_buttons(self) -> List[ModalButton]:
        return [ModalButton("Back to Work", "btn-close", "primary")]

    def key_hints(self):
        return [("ESC", "Back"), ("Q", "Close")]
