"""State-aware triage modal: what is known, unknown, tested, and what to do next."""

from __future__ import annotations

from typing import List, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import ScrollableContainer
from textual.widgets import Static

from synapse.assessment.engine import NextAction, TargetSnapshot
from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import MUTED, SAGE, KRAFT, triage_chip


class TriageModal(SynapseModal[None]):
    """Answers: what do I know about this target, and what is the highest-value next move?"""

    BINDINGS = [
        Binding("escape", "cancel", "Close"),
        Binding("q", "cancel", "Close", show=False),
        Binding("n", "cancel", "Close", show=False),
    ]

    GLYPH = "▸"
    TITLE = "TRIAGE — State-Aware Situation Board"

    DEFAULT_CSS = """
    TriageModal #dialog {
        width: 100;
        height: 80%;
    }
    TriageModal #modal-body {
        height: 1fr;
    }
    #triage-scroll {
        height: 1fr;
    }
    .section-title {
        margin-top: 1;
        text-style: bold;
        color: $warning;
    }
    """

    def __init__(self, snapshots: List[TargetSnapshot], actions: List[NextAction],
                 focus_ip: Optional[str] = None, **kwargs):
        context = (
            f"Focus [bold {KRAFT}]{focus_ip}[/] · {len(snapshots)} target(s) assessed · "
            f"{len(actions)} open investigation(s)"
            if focus_ip
            else f"{len(snapshots)} target(s) assessed · {len(actions)} open investigation(s)"
        )
        super().__init__(context=context, **kwargs)
        self.snapshots = snapshots
        self.actions = actions
        self.focus_ip = focus_ip

    def _build_state_text(self) -> Text:
        txt = Text()
        ordered = sorted(
            self.snapshots,
            key=lambda s: (not s.in_scope, s.ip != self.focus_ip, s.ip),
        )
        for snap in ordered:
            scope_tag = "" if snap.in_scope else " [OUT-OF-SCOPE]"
            status_tag = f" [{snap.status.value.upper()}]"
            txt.append(f"{snap.label}{scope_tag}{status_tag}\n", style="bold")
            known = (
                f"services {snap.services_total}"
                f" (untested {snap.services_untested}, dead-end {snap.services_dead_end},"
                f" vulnerable {snap.services_vulnerable})"
            )
            planned = (
                f"checks {snap.checks_total}"
                f" (todo {snap.checks_todo}, running {snap.checks_running},"
                f" done {snap.checks_done}, findings {snap.checks_finding}, dead-end {snap.checks_dead_end})"
                if snap.checks_total
                else "no methodology checks generated yet"
            )
            extras = []
            if snap.valid_creds:
                extras.append(f"{snap.valid_creds} valid cred(s)")
            if snap.flag_count:
                extras.append(f"{snap.flag_count} flag(s)")
            extra_str = f"; {', '.join(extras)}" if extras else ""
            txt.append(f"    Known:     {known}\n")
            txt.append(f"    Tested:    {planned} — coverage {snap.coverage:.0%}{extra_str}\n")
            if snap.is_bare and snap.in_scope:
                txt.append("    Unknown:   attack surface not mapped — run initial recon ('i')\n", style=KRAFT)
            txt.append("\n")
        return txt

    def _build_actions_text(self) -> Text:
        txt = Text()
        if not self.actions:
            txt.append("No open investigations. Everything in scope is either resolved or pwned. GG.\n", style=SAGE)
            return txt
        for i, act in enumerate(self.actions, 1):
            chip = triage_chip(act.priority_label)
            txt.append("  ")
            txt.append(Text.from_markup(f"{chip}"))
            txt.append(f"  {act.title}\n")
            txt.append(f"       why: {act.rationale}\n", style=MUTED)
        return txt

    def compose_body(self) -> ComposeResult:
        with ScrollableContainer(id="triage-scroll"):
            yield Static(self._build_state_text(), id="state-block")
            yield Static(
                Text.from_markup("[bold]Highest-Value Next Investigations:[/bold]"),
                classes="section-title",
            )
            yield Static(self._build_actions_text(), id="actions-block")

    def modal_buttons(self) -> List[ModalButton]:
        return [ModalButton("Back to Workbench", "btn-close", "primary")]

    def key_hints(self):
        return [("ESC", "Back"), ("Q", "Close")]
