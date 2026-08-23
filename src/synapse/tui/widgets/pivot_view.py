"""Pivot routes and SOCKS tunnel manager widget."""

from __future__ import annotations

from typing import List
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static, DataTable

from synapse.models import PivotRoute


class PivotViewWidget(Vertical):
    """Table of active pivot routes and proxychains configuration helpers."""

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Network Pivoting & Route Sentinel[/bold cyan]", id="pivot-header")
        yield Static("[dim]Multi-hop lab routing state, SOCKS5 bindings, and proxychains command prefixes.[/dim]")
        table = DataTable(id="pivot-table", cursor_type="row")
        table.add_columns("ID", "Route Name", "Jump Host IP", "Target Subnet", "Tunnel Type", "Local Bind", "Status")
        yield table

    def populate(self, routes: List[PivotRoute]) -> None:
        table = self.query_one("#pivot-table", DataTable)
        table.clear()

        for r in routes:
            st_color = "[green]ACTIVE[/green]" if r.status == "active" else f"[dim]{r.status.upper()}[/dim]"
            table.add_row(
                str(r.id),
                f"[bold]{r.name}[/bold]",
                r.jump_host_ip,
                f"[cyan]{r.target_subnet}[/cyan]",
                r.tunnel_type,
                r.local_bind,
                st_color,
                key=str(r.id),
            )
