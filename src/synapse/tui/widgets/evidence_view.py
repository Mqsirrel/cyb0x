"""Evidence, Flag Proofs, and Command Logs viewer widget."""

from __future__ import annotations

from typing import Dict, List, Optional
from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static, DataTable

from synapse.models import ChecklistItem, Evidence, Service
from synapse.tui.theme import KRAFT, MUTED, SAGE, TERRACOTTA
from synapse.tui.widgets.table_utils import capture_cursor, restore_cursor


class EvidenceViewWidget(Vertical):
    """Table displaying captured proof flags and their full relational context.

    Every row links evidence back to its target, service (ip:port), and the
    methodology check that produced it — the audit trail for findings.
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold]Evidence & Flag Proof Ledger[/bold]", id="evidence-header")
        yield Static(f"[{MUTED}]Exam-compliant proof records with target/service/check relationships intact.[/]")
        table = DataTable(id="evidence-table", cursor_type="row")
        table.add_columns(
            "ID", "Target", "Service", "Type", "Title / Context", "Linked Check", "Flag Hash", "Command Executed", "Timestamp (UTC)"
        )
        yield table

    def populate(
        self,
        evidence_list: List[Evidence],
        services_map: Optional[Dict[int, Service]] = None,
        checks_map: Optional[Dict[int, ChecklistItem]] = None,
    ) -> None:
        services_map = services_map or {}
        checks_map = checks_map or {}
        table = self.query_one("#evidence-table", DataTable)
        prev_cursor = capture_cursor(table)
        table.clear()

        for ev in evidence_list:
            cmd_preview = ev.command if len(ev.command) <= 35 else ev.command[:32] + "..."
            flag_disp = f"[bold {SAGE}]{escape(ev.flag_hash)}[/]" if ev.flag_hash else "-"

            svc_disp = "-"
            if ev.service_id and ev.service_id in services_map:
                svc = services_map[ev.service_id]
                svc_disp = f"{svc.port}/{svc.protocol} {escape(svc.name)}"

            check_disp = f"[{MUTED}]-[/]"
            if ev.checklist_id and ev.checklist_id in checks_map:
                title = checks_map[ev.checklist_id].title
                check_disp = f"[{TERRACOTTA}]{escape(title[:40])}[/]"
            elif ev.title.startswith("Output for: "):
                # Legacy evidence saved before checklist linkage existed
                origin = ev.title[len("Output for: "):]
                check_disp = f"[{MUTED}]{escape(origin[:40])}[/]"

            table.add_row(
                str(ev.id),
                escape(ev.target_ip or "-"),
                svc_disp,
                f"[{KRAFT}]{escape(ev.proof_type.value)}[/]",
                f"[bold]{escape(ev.title[:45])}[/bold]",
                check_disp,
                flag_disp,
                f"[{TERRACOTTA}]{escape(cmd_preview)}[/]",
                ev.created_at.strftime("%Y-%m-%d %H:%M"),
                key=str(ev.id),
            )
        restore_cursor(table, prev_cursor)
