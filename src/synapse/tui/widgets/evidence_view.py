"""Evidence, Flag Proofs, and Command Logs viewer widget."""

from __future__ import annotations

from typing import List
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static, DataTable

from synapse.models import Evidence


class EvidenceViewWidget(Vertical):
    """Table displaying captured proof flags, command evidence, and logs."""

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Evidence & Flag Proof Ledger[/bold cyan]", id="evidence-header")
        yield Static("[dim]Exam-compliant proof records, timestamps, commands, and flag hashes.[/dim]")
        table = DataTable(id="evidence-table", cursor_type="row")
        table.add_columns("ID", "Target", "Type", "Title / Context", "Flag Hash", "Command Executed", "Timestamp (UTC)")
        yield table

    def populate(self, evidence_list: List[Evidence]) -> None:
        table = self.query_one("#evidence-table", DataTable)
        table.clear()

        for ev in evidence_list:
            cmd_preview = ev.command if len(ev.command) <= 35 else ev.command[:32] + "..."
            flag_disp = f"[bold green]{ev.flag_hash}[/bold green]" if ev.flag_hash else "-"
            table.add_row(
                str(ev.id),
                ev.target_ip or "-",
                f"[magenta]{ev.proof_type.value}[/magenta]",
                f"[bold]{ev.title}[/bold]",
                flag_disp,
                f"[cyan]{cmd_preview}[/cyan]",
                ev.created_at.strftime("%Y-%m-%d %H:%M"),
                key=str(ev.id),
            )
