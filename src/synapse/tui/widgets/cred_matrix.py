"""Credential Vault & Lateral Movement Matrix widget."""

from __future__ import annotations

from typing import List
from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static, DataTable

from synapse.models import Credential


class CredentialMatrixWidget(Vertical):
    """Table of discovered credentials and cross-target testing status."""

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Credential Vault & Lateral Movement Matrix[/bold cyan]", id="cred-header")
        yield Static("[dim]Track discovered passwords, NTLM hashes, and Kerberos tickets across targets.[/dim]")
        table = DataTable(id="cred-table", cursor_type="row")
        table.add_columns("ID", "Domain", "Username", "Secret / Hash", "Type", "Scope", "Tested Targets / Admin Status")
        yield table

    def populate(self, credentials: List[Credential]) -> None:
        table = self.query_one("#cred-table", DataTable)
        table.clear()

        for c in credentials:
            tested_summary = []
            for tip, tdata in c.tested_targets.items():
                status_mark = "✔ (Pwn3d)" if tdata.get("admin") else ("✔" if tdata.get("valid") else "✖")
                tested_summary.append(f"{escape(str(tip))}:{status_mark}")
            tested_str = ", ".join(tested_summary) if tested_summary else "Untested"
            secret_disp = c.secret if len(c.secret) <= 30 else c.secret[:27] + "..."

            table.add_row(
                str(c.id),
                escape(c.domain or "-"),
                f"[bold]{escape(c.username)}[/bold]",
                f"[yellow]{escape(secret_disp)}[/yellow]",
                escape(c.cred_type.value),
                escape(c.service_scope or "general"),
                tested_str,
                key=str(c.id),
            )
