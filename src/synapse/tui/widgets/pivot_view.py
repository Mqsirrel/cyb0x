"""Pivot routes and SOCKS tunnel manager widget."""

from __future__ import annotations

from typing import List
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static, DataTable

from synapse.models import PivotRoute
from synapse.tui.theme import MUTED, SAGE, TERRACOTTA


class PivotViewWidget(Vertical):
    """Table of active pivot routes and proxychains configuration helpers."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Network Pivoting & Route Sentinel[/bold]", id="pivot-header")
        yield Static(f"[{MUTED}]Multi-hop lab routing state, SOCKS5 bindings, and proxychains command prefixes.[/]")
        table = DataTable(id="pivot-table", cursor_type="row")
        table.add_columns("ID", "Route Name", "Jump Host IP", "Target Subnet", "Tunnel Type", "Local Bind", "Status")
        yield table

    def populate(self, routes: List[PivotRoute]) -> None:
        table = self.query_one("#pivot-table", DataTable)
        table.clear()

        for r in routes:
            st_color = f"[{SAGE}]ACTIVE[/]" if r.status == "active" else f"[{MUTED}]{r.status.upper()}[/]"
            table.add_row(
                str(r.id),
                f"[bold]{r.name}[/bold]",
                r.jump_host_ip,
                f"[{TERRACOTTA}]{r.target_subnet}[/]",
                r.tunnel_type,
                r.local_bind,
                st_color,
                key=str(r.id),
            )
