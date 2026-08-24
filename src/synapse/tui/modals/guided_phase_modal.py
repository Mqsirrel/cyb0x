"""Guided workflow phase breakdown modal."""

from __future__ import annotations

from typing import List, Optional
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll, Horizontal, Vertical
from textual.widgets import TabbedContent, TabPane, Static
from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import TERRACOTTA, MUTED, SAGE, KRAFT, ERROR_RED
from synapse.tui.modals.profile_modal import PROFILES


class GuidedPhaseModal(SynapseModal[None]):
    """Dialog displaying complete assessment breakdown against the active methodology."""

    TITLE = "GUIDED WORKFLOW & METHODOLOGY BREAKDOWN"

    DEFAULT_CSS = """
    GuidedPhaseModal #dialog {
        width: 100;
        height: 35;
    }
    .phase-stats {
        layout: horizontal;
        height: 3;
        border-bottom: solid $panel;
        margin-bottom: 1;
        padding-top: 1;
    }
    .stat-box {
        width: 1fr;
        content-align: center middle;
    }
    .phase-details {
        height: auto;
        padding: 1;
    }
    """

    def __init__(self, active_profile: str = "network", stats: Optional[dict] = None):
        super().__init__()
        self.active_profile = active_profile
        self.stats = stats or {}

    def compose_body(self) -> ComposeResult:
        profile = next((p for p in PROFILES if p["id"] == self.active_profile), PROFILES[1])
        phases = [p.strip() for p in profile["phases"].split(",")]

        with TabbedContent():
            for i, phase in enumerate(phases):
                with TabPane(f"{i+1}. {phase}", id=f"tab-phase-{i}"):
                    with VerticalScroll():
                        # Stats row
                        with Horizontal(classes="phase-stats"):
                            yield Static(f"[{SAGE}]Completed:[/] 0", classes="stat-box")
                            yield Static(f"[{MUTED}]Pending:[/] 0", classes="stat-box")
                            yield Static(f"[{KRAFT}]Running:[/] 0", classes="stat-box")
                            yield Static(f"[{ERROR_RED}]Dead Ends:[/] 0", classes="stat-box")
                            yield Static(f"[bold {TERRACOTTA}]Findings:[/] 0", classes="stat-box")
                            yield Static(f"[bold]Evidence:[/] 0", classes="stat-box")

                        # Details
                        with Vertical(classes="phase-details"):
                            yield Static(f"[bold {TERRACOTTA}]Recommended Next Actions[/]\n\n"
                                         "No immediate actions recommended. Continue enumeration.\n\n"
                                         "[bold]Rationale:[/] Need more data to formulate hypotheses.", 
                                         id=f"phase-actions-{i}")

    def modal_buttons(self) -> List[ModalButton]:
        return [ModalButton("Close", "btn-cancel", "primary")]

    def key_hints(self):
        return [("ESC", "Close"), ("Q", "Close")]
