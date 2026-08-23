"""State-aware triage modal: what is known, unknown, tested, and what to do next."""

from __future__ import annotations

from typing import List, Optional

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import ScrollableContainer, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

from synapse.assessment.engine import NextAction, TargetSnapshot

_PRIORITY_STYLE = {
    "RECON": "bold white on #14507d",
    "EXPLOIT": "bold white on #801818",
    "ENUM": "bold black on #7da800",
    "SPRAY": "bold black on #c7a400",
    "RESUME": "bold yellow on #3b3014",
    "CLEANUP": "dim white on #262626",
}


class TriageModal(ModalScreen[None]):
    """Answers: what do I know about this target, and what is the highest-value next move?"""

    BINDINGS = [
        Binding("escape", "cancel", "Close"),
        Binding("q", "cancel", "Close", show=False),
        Binding("n", "cancel", "Close", show=False),
    ]

    DEFAULT_CSS = """
    TriageModal {
        align: center middle;
    }
    #dialog {
        padding: 1 2;
        width: 100;
        height: 80%;
        border: thick $primary;
        background: $surface;
    }
    #triage-scroll {
        height: 1fr;
        margin-top: 1;
    }
    .section-title {
        margin-top: 1;
        text-style: bold;
        color: $accent;
    }
    .snapshot-line {
        margin-left: 1;
    }
    Button {
        margin-top: 1;
        align: center middle;
    }
    """

    def __init__(self, snapshots: List[TargetSnapshot], actions: List[NextAction],
                 focus_ip: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
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
            txt.append(f"{snap.label}{scope_tag}{status_tag}\n", style="bold cyan")
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
                txt.append("    Unknown:   attack surface not mapped — run initial recon ('i')\n", style="yellow")
            txt.append("\n")
        return txt

    def _build_actions_text(self) -> Text:
        txt = Text()
        if not self.actions:
            txt.append("No open investigations. Everything in scope is either resolved or pwned. GG.\n", style="green")
            return txt
        for i, act in enumerate(self.actions, 1):
            style = _PRIORITY_STYLE.get(act.priority_label, "dim")
            txt.append("  ")
            txt.append(f"[{i}] {act.priority_label:^8}", style=style)
            txt.append(f"  {act.title}\n")
            txt.append(f"       why: {act.rationale}\n", style="dim")
        return txt

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[bold cyan]SYNAPSE // State-Aware Triage[/bold cyan]")
            with ScrollableContainer(id="triage-scroll"):
                yield Static(self._build_state_text(), id="state-block")
                yield Label("[bold yellow]Highest-Value Next Investigations:[/bold yellow]", classes="section-title")
                yield Static(self._build_actions_text(), id="actions-block")
            yield Button("Back to Workbench (Esc)", variant="primary", id="btn-close")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close":
            self.dismiss(None)
