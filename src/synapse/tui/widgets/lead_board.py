"""Hypotheses and Leads Kanban/Queue widget."""

from __future__ import annotations

from typing import List
from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static, DataTable

from synapse.models import Lead, LeadPriority, LeadStatus


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
        table.clear()

        priority_colors = {
            LeadPriority.CRITICAL: "[bold red]CRITICAL[/bold red]",
            LeadPriority.HIGH: "[red]HIGH[/red]",
            LeadPriority.MEDIUM: "[yellow]MEDIUM[/yellow]",
            LeadPriority.LOW: "[dim]LOW[/dim]",
        }

        status_colors = {
            LeadStatus.BACKLOG: "[white]BACKLOG[/white]",
            LeadStatus.IN_PROGRESS: "[yellow]⟳ IN PROGRESS[/yellow]",
            LeadStatus.CONFIRMED: "[bold green]✔ CONFIRMED[/bold green]",
            LeadStatus.REJECTED: "[dim]✖ REJECTED[/dim]",
        }

        for l in leads:
            p_str = priority_colors.get(l.priority, "MEDIUM")
            s_str = status_colors.get(l.status, "BACKLOG")
            desc_preview = l.description if len(l.description) <= 60 else l.description[:57] + "..."

            table.add_row(
                str(l.id),
                p_str,
                s_str,
                escape(l.target_ip or "Global"),
                f"[bold]{escape(l.title)}[/bold]",
                escape(desc_preview),
                key=str(l.id),
            )
