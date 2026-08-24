"""Credential Vault & Lateral Movement Matrix widget."""

from __future__ import annotations

from typing import List, Optional
from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from synapse.models import Credential, Target
from synapse.tui.theme import KRAFT, MUTED, SAGE, TERRACOTTA, cred_test_chip
from synapse.tui.widgets.table_utils import capture_cursor, restore_cursor


class CredentialMatrixWidget(Vertical):
    """Table of discovered credentials, cross-target testing status, and spray gaps."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Credential Vault & Lateral Movement Matrix[/bold]", id="cred-header")
        yield Static(
            f"[{MUTED}]Lifecycle per host: press 't' to cycle untested → valid → invalid for the selected target. "
            f"⚠ column = in-scope hosts this credential has never touched.[/]"
        )
        table = DataTable(id="cred-table", cursor_type="row")
        table.add_columns("ID", "Domain", "Username", "Secret / Hash", "Type", "Scope", "Tested Targets / Admin Status", "⚠ Unsprayed Hosts")
        yield table

    def populate(self, credentials: List[Credential], targets: Optional[List[Target]] = None) -> None:
        targets = targets or []
        live_targets = [t for t in targets if t.in_scope]
        table = self.query_one("#cred-table", DataTable)
        prev_cursor = capture_cursor(table)
        table.clear()

        for c in credentials:
            tested_summary = []
            tested_hosts = set()
            for tip, tdata in c.tested_targets.items():
                if ":" in tip and tdata.get("service") and tip.endswith(f":{tdata.get('service')}"):
                    continue  # Skip redundant compound key in display
                host_ip = str(tip).split(":")[0]
                tested_hosts.add(host_ip)
                tested_summary.append(cred_test_chip(host_ip, bool(tdata.get("valid")), bool(tdata.get("admin"))))

            tested_str = " ".join(tested_summary) if tested_summary else f"[{MUTED}]Untested[/]"

            untested_hosts = [t.ip for t in live_targets if t.ip not in tested_hosts]
            if untested_hosts and any(
                isinstance(d, dict) and d.get("valid") for d in c.tested_targets.values()
            ):
                preview = ", ".join(untested_hosts[:3]) + ("…" if len(untested_hosts) > 3 else "")
                spray_str = f"[bold {KRAFT}]{len(untested_hosts)}: {escape(preview)}[/]"
            elif untested_hosts:
                spray_str = f"[{MUTED}]{len(untested_hosts)} untouched[/]"
            else:
                spray_str = f"[{SAGE}]full coverage[/]"

            secret_disp = c.secret if len(c.secret) <= 30 else c.secret[:27] + "..."

            table.add_row(
                str(c.id),
                escape(c.domain or "-"),
                f"[bold]{escape(c.username)}[/bold]",
                f"[{KRAFT}]{escape(secret_disp)}[/]",
                f"[{TERRACOTTA}]{escape(c.cred_type.value)}[/]",
                escape(c.service_scope or "general"),
                tested_str,
                spray_str,
                key=str(c.id),
            )
        restore_cursor(table, prev_cursor)
