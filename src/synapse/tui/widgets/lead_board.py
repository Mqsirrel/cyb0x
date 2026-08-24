"""Hypotheses and Leads Kanban/Queue widget."""

from __future__ import annotations

from typing import List
from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from synapse.models import Lead
from synapse.tui.theme import MUTED, TERRACOTTA, lead_priority_chip, lead_status_chip
from synapse.tui.widgets.table_utils import capture_cursor, restore_cursor


class LeadBoardWidget(Vertical):
    """Board tracking pentest hypotheses, attack ideas, and pending leads."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Attack Hypotheses & Leads Board[/bold]", id="lead-header")
        yield Static(f"[{MUTED}]Prioritize leads and prevent rabbit-hole paralysis. Press Space to cycle status.[/]")
        table = DataTable(id="lead-table", cursor_type="row")
        table.add_columns("ID", "Priority", "Status", "Target", "Hypothesis / Lead Title", "Description")
        yield table

    def populate(self, leads: List[Lead]) -> None:
        table = self.query_one("#lead-table", DataTable)
        prev_cursor = capture_cursor(table)
        table.clear()

        for l in leads:
            p_str = lead_priority_chip(l.priority)
            s_str = lead_status_chip(l.status)
            desc_preview = l.description if len(l.description) <= 60 else l.description[:57] + "..."

            table.add_row(
                str(l.id),
                p_str,
                s_str,
                f"[{TERRACOTTA}]{escape(l.target_ip or 'Global')}[/]",
                f"[bold]{escape(l.title)}[/bold]",
                escape(desc_preview),
                key=str(l.id),
            )
        restore_cursor(table, prev_cursor)
