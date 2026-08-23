"""Credential Vault & Lateral Movement Matrix widget."""

from __future__ import annotations

from typing import List
from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

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
                if ":" in tip and tdata.get("service") and tip.endswith(f":{tdata.get('service')}"):
                    continue  # Skip redundant compound key in display
                if tdata.get("admin"):
                    status_mark = f"[bold white on #143520] {escape(str(tip))}:✔(Admin) [/]"
                elif tdata.get("valid"):
                    status_mark = f"[bold green] {escape(str(tip))}:✔ [/bold green]"
                else:
                    status_mark = f"[dim red] {escape(str(tip))}:✖ [/dim red]"
                tested_summary.append(status_mark)

            tested_str = " ".join(tested_summary) if tested_summary else "[dim]Untested[/dim]"
            secret_disp = c.secret if len(c.secret) <= 30 else c.secret[:27] + "..."

            table.add_row(
                str(c.id),
                escape(c.domain or "-"),
                f"[bold]{escape(c.username)}[/bold]",
                f"[yellow]{escape(secret_disp)}[/yellow]",
                f"[magenta]{escape(c.cred_type.value)}[/magenta]",
                escape(c.service_scope or "general"),
                tested_str,
                key=str(c.id),
            )
