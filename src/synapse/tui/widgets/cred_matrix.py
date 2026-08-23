"""Credential Vault & Lateral Movement Matrix widget."""

from __future__ import annotations

from typing import List, Optional
from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from synapse.models import Credential, Target


class CredentialMatrixWidget(Vertical):
    """Table of discovered credentials, cross-target testing status, and spray gaps."""

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Credential Vault & Lateral Movement Matrix[/bold cyan]", id="cred-header")
        yield Static(
            "[dim]Lifecycle per host: press 't' to cycle untested → valid → invalid for the selected target. "
            "⚠ column = in-scope hosts this credential has never touched.[/dim]"
        )
        table = DataTable(id="cred-table", cursor_type="row")
        table.add_columns("ID", "Domain", "Username", "Secret / Hash", "Type", "Scope", "Tested Targets / Admin Status", "⚠ Unsprayed Hosts")
        yield table

    def populate(self, credentials: List[Credential], targets: Optional[List[Target]] = None) -> None:
        targets = targets or []
        live_targets = [t for t in targets if t.in_scope]
        table = self.query_one("#cred-table", DataTable)
        table.clear()

        for c in credentials:
            tested_summary = []
            tested_hosts = set()
            for tip, tdata in c.tested_targets.items():
                if ":" in tip and tdata.get("service") and tip.endswith(f":{tdata.get('service')}"):
                    continue  # Skip redundant compound key in display
                host_ip = str(tip).split(":")[0]
                tested_hosts.add(host_ip)
                if tdata.get("admin"):
                    status_mark = f"[bold white on #143520] {escape(host_ip)}:✔(Admin) [/]"
                elif tdata.get("valid"):
                    status_mark = f"[bold green] {escape(host_ip)}:✔ [/bold green]"
                else:
                    status_mark = f"[dim red] {escape(host_ip)}:✖ [/dim red]"
                tested_summary.append(status_mark)

            tested_str = " ".join(tested_summary) if tested_summary else "[dim]Untested[/dim]"

            untested_hosts = [t.ip for t in live_targets if t.ip not in tested_hosts]
            if untested_hosts and any(
                isinstance(d, dict) and d.get("valid") for d in c.tested_targets.values()
            ):
                # Only flag spray gaps for creds that have proven valid somewhere
                preview = ", ".join(untested_hosts[:3]) + ("…" if len(untested_hosts) > 3 else "")
                spray_str = f"[bold yellow]{len(untested_hosts)}: {escape(preview)}[/bold yellow]"
            elif untested_hosts:
                spray_str = f"[dim]{len(untested_hosts)} untouched[/dim]"
            else:
                spray_str = "[green]full coverage[/green]"

            secret_disp = c.secret if len(c.secret) <= 30 else c.secret[:27] + "..."

            table.add_row(
                str(c.id),
                escape(c.domain or "-"),
                f"[bold]{escape(c.username)}[/bold]",
                f"[yellow]{escape(secret_disp)}[/yellow]",
                f"[magenta]{escape(c.cred_type.value)}[/magenta]",
                escape(c.service_scope or "general"),
                tested_str,
                spray_str,
                key=str(c.id),
            )
