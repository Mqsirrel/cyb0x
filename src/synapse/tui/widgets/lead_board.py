"""Hypotheses and Leads Kanban/Queue widget."""

from __future__ import annotations

from typing import List
from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from synapse.models import Lead, LeadPriority, LeadStatus
from synapse.tui.widgets.table_utils import capture_cursor, restore_cursor


class LeadBoardWidget(Vertical):
    """Board tracking pentest hypotheses, attack ideas, and pending leads."""

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Attack Hypotheses & Leads Board[/bold cyan]", id="lead-header")
        yield Static("[dim]Prioritize leads and prevent rabbit-hole paralysis. Press Space to cycle status.[/dim]")
        table = DataTable(id="lead-table", cursor_type="row")
        table.add_columns("ID", "Priority", "Status", "Target", "Hypothesis / Lead Title", "Description")
        yield table

    def populate(self, leads: List[Lead]) -> None:
        table = self.query_one("#lead-table", DataTable)
        prev_cursor = capture_cursor(table)
        table.clear()

        priority_colors = {
            LeadPriority.CRITICAL: "[bold white on #801818] CRITICAL [/]",
            LeadPriority.HIGH: "[bold white on #662d18]   HIGH   [/]",
            LeadPriority.MEDIUM: "[bold white on #4d4414]  MEDIUM  [/]",
            LeadPriority.LOW: "[dim white on #262626]   LOW    [/]",
        }

        status_colors = {
            LeadStatus.BACKLOG: "[dim white on #1f1f1f]   BACKLOG   [/]",
            LeadStatus.IN_PROGRESS: "[bold yellow on #3b3014] ⟳ PROGRESS  [/]",
            LeadStatus.CONFIRMED: "[bold green on #143520] ✔ CONFIRMED [/]",
            LeadStatus.REJECTED: "[dim white on #1a1a1a] ✖ REJECTED  [/]",
        }

        for l in leads:
            p_str = priority_colors.get(l.priority, "[dim]MEDIUM[/dim]")
            s_str = status_colors.get(l.status, "[dim]BACKLOG[/dim]")
            desc_preview = l.description if len(l.description) <= 60 else l.description[:57] + "..."

            table.add_row(
                str(l.id),
                p_str,
                s_str,
                f"[cyan]{escape(l.target_ip or 'Global')}[/cyan]",
                f"[bold]{escape(l.title)}[/bold]",
                escape(desc_preview),
                key=str(l.id),
            )
        restore_cursor(table, prev_cursor)
