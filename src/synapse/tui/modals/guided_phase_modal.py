"""Guided workflow phase breakdown modal (live workspace state)."""

from __future__ import annotations

from typing import Dict, List, Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Static, TabbedContent, TabPane

from synapse.assessment.engine import PhaseProgress, PhaseStatus
from synapse.methodology.profile import MethodologyProfile
from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import ERROR_RED, KRAFT, MUTED, SAGE, TERRACOTTA

_STATUS_STYLES = {
    PhaseStatus.COMPLETED: (SAGE, "COMPLETED"),
    PhaseStatus.IN_PROGRESS: (KRAFT, "IN PROGRESS"),
    PhaseStatus.NOT_STARTED: (MUTED, "NOT STARTED"),
    PhaseStatus.BLOCKED: (ERROR_RED, "BLOCKED"),
}


def _status_markup(status: PhaseStatus) -> str:
    color, label = _STATUS_STYLES.get(status, (MUTED, status.value.upper()))
    return f"[bold {color}]{label}[/]"


class GuidedPhaseModal(SynapseModal[None]):
    """Per-phase breakdown of a target against the active methodology profile.

    Shows completed/pending/running checks, dead ends, findings, captured
    evidence, and rationale-backed recommended actions — all derived from
    the deterministic assessment engine.
    """

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

    def __init__(
        self,
        profile: Optional[MethodologyProfile] = None,
        progress: Optional[Dict[str, PhaseProgress]] = None,
        context: str = "",
    ):
        super().__init__()
        self.profile = profile
        self.progress = progress or {}
        self.modal_context = context or None

    def compose_body(self) -> ComposeResult:
        if self.profile is None:
            yield Static(
                f"[{MUTED}]No methodology profile active. Press 'p' to select one.[/]"
            )
            return

        with TabbedContent():
            for i, phase in enumerate(self.profile.ordered_phases()):
                prog = self.progress.get(phase.id, PhaseProgress(phase_id=phase.id))
                _, status_label = _STATUS_STYLES.get(prog.phase_status, (MUTED, prog.phase_status.value.upper()))
                with TabPane(f"{i + 1}. {phase.name} · {status_label}", id=f"tab-phase-{i}"):
                    with VerticalScroll():
                        with Horizontal(classes="phase-stats"):
                            yield Static(f"[{SAGE}]Completed:[/] {len(prog.completed_checks)}", classes="stat-box")
                            yield Static(f"[{MUTED}]Pending:[/] {len(prog.pending_checks)}", classes="stat-box")
                            yield Static(f"[{KRAFT}]Running:[/] {len(prog.running_checks)}", classes="stat-box")
                            yield Static(f"[{ERROR_RED}]Dead Ends:[/] {len(prog.dead_ends)}", classes="stat-box")
                            yield Static(f"[bold {TERRACOTTA}]Findings:[/] {len(prog.findings)}", classes="stat-box")
                            yield Static(f"[bold]Evidence:[/] {len(prog.evidence)}", classes="stat-box")

                        with Vertical(classes="phase-details"):
                            lines: List[str] = []
                            if prog.blocked_reason:
                                lines.append(f"[{ERROR_RED}]Blocked:[/] {prog.blocked_reason}\n")

                            if prog.findings:
                                lines.append(f"[bold {TERRACOTTA}]Findings[/]")
                                lines.extend(f" • {f}" for f in prog.findings)
                                lines.append("")
                            if prog.evidence:
                                lines.append("[bold]Evidence Captured[/]")
                                lines.extend(f" • {e}" for e in prog.evidence)
                                lines.append("")

                            if prog.recommended_actions:
                                lines.append(f"[bold {TERRACOTTA}]Recommended Next Actions[/]")
                                for action in prog.recommended_actions[:8]:
                                    lines.append(f" ▸ [bold]{action.title}[/]")
                                    lines.append(f"   [{MUTED}]Why: {action.rationale}[/]")
                                lines.append("")
                            elif not prog.blocked_reason:
                                lines.append(
                                    f"[{MUTED}]No pending actions in this phase."
                                    " Advance as findings allow.[/]"
                                )

                            if phase.description:
                                lines.append(f"[{MUTED}]{phase.description}[/]")

                            yield Static("\n".join(lines), id=f"phase-actions-{i}")

    def modal_buttons(self) -> List[ModalButton]:
        return [ModalButton("Close", "btn-cancel", "primary")]

    def key_hints(self):
        return [("ESC", "Close"), ("Q", "Close")]
