"""'I'm stuck' / rabbit-hole detection modal."""

from __future__ import annotations

from typing import List

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import ScrollableContainer, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

from synapse.assessment.engine import NextAction, StuckReport


class StuckModal(ModalScreen[None]):
    """Analyzes dead ends vs untouched surface and suggests concrete escape routes.

    Deliberately does NOT dump generic command lists: every suggestion is derived
    from actual workspace state (untested ports, un-sprayed creds, stale leads).
    """

    BINDINGS = [
        Binding("escape", "cancel", "Close"),
        Binding("q", "cancel", "Close", show=False),
        Binding("s", "cancel", "Close", show=False),
    ]

    DEFAULT_CSS = """
    StuckModal {
        align: center middle;
    }
    #dialog {
        padding: 1 2;
        width: 100;
        height: 80%;
        border: thick red;
        background: $surface;
    }
    #stuck-scroll {
        height: 1fr;
        margin-top: 1;
    }
    .section-title {
        margin-top: 1;
        text-style: bold;
        color: $accent;
    }
    Button {
        margin-top: 1;
        align: center middle;
    }
    """

    def __init__(self, report: StuckReport, **kwargs):
        super().__init__(**kwargs)
        self.report = report

    def _build_report_text(self) -> Text:
        txt = Text()
        r = self.report

        txt.append("Proven Dead Ends (stop digging here):\n", style="bold red")
        if r.dead_end_services or r.dead_end_checks:
            for tag in r.dead_end_services:
                txt.append(f"  ✖ {tag}\n")
            for tag in r.dead_end_checks:
                txt.append(f"  ✖ {tag}\n")
            txt.append("  Dead ends are data, not failure — they shrink the search space.\n", style="dim")
        else:
            txt.append("  None recorded. Nothing has been conclusively ruled out yet.\n", style="dim")

        txt.append("\nUntested Surface (dig here instead):\n", style="bold green")
        if r.untested_ports:
            for tag in r.untested_ports[:12]:
                txt.append(f"  ○ {tag}\n")
            if len(r.untested_ports) > 12:
                txt.append(f"  … and {len(r.untested_ports) - 12} more\n", style="dim")
        else:
            txt.append("  Everything discovered has been touched.\n", style="dim")

        txt.append("\nUn-sprayed Credentials:\n", style="bold yellow")
        if r.unsprayed_credentials:
            for line in r.unsprayed_credentials[:8]:
                txt.append(f"  🔑 {line}\n")
        else:
            txt.append("  No credential is waiting to be tried on a new host.\n", style="dim")

        if r.stale_leads:
            txt.append("\nStale Hypotheses (confirm or reject):\n", style="yellow")
            for line in r.stale_leads[:6]:
                txt.append(f"  💡 {line}\n")

        return txt

    def _build_escape_text(self) -> Text:
        txt = Text()
        if self.report.is_stuck:
            txt.append(
                "⚠ Rabbit-hole signature detected: dead ends exist and no untried surface remains "
                "in scope. Consider re-scoping ('o'), adding targets ('a'), or stepping back to "
                "recon with different techniques ('i').\n\n",
                style="bold red",
            )
        if not self.report.suggestions:
            txt.append("No escape routes found — the workspace may be complete or empty.\n", style="green")
            return txt
        txt.append("Suggested Escapes (state-derived, not generic):\n", style="bold yellow")
        for i, act in enumerate(self.report.suggestions, 1):
            txt.append(f"  [{i}] {act.title}\n")
            txt.append(f"      why: {act.rationale}\n", style="dim")
        return txt

    def compose(self) -> ComposeResult:
        verdict = (
            "[bold red]You are in a rabbit hole.[/bold red]"
            if self.report.is_stuck
            else "[bold green]You are not stuck[/bold green] — open avenues remain."
        )
        with Vertical(id="dialog"):
            yield Label(f"[bold cyan]SYNAPSE // Rabbit-Hole Triage[/bold cyan] — {verdict}")
            with ScrollableContainer(id="stuck-scroll"):
                yield Static(self._build_report_text(), id="stuck-report-block")
                yield Static(self._build_escape_text(), id="escape-block")
            yield Button("Back to Work (Esc)", variant="primary", id="btn-close")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close":
            self.dismiss(None)
