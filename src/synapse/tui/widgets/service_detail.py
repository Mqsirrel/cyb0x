"""Service detail & interactive methodology checklist widget."""

from __future__ import annotations

from typing import Optional
from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from synapse.models import ChecklistStatus, Service, Target
from synapse.tui.theme import ERROR_RED, KRAFT, MUTED, TERRACOTTA, checklist_chip, service_status_chip
from synapse.tui.widgets.table_utils import capture_cursor, restore_cursor


class ServiceDetailWidget(Vertical):
    """Main panel displaying service information and interactive checklist items."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.current_service: Optional[Service] = None
        self.current_target: Optional[Target] = None
        self.evidence_counts: dict = {}  # service_id -> linked evidence count

    def compose(self) -> ComposeResult:
        yield Static("[bold]Service & Methodology Checklist[/bold]", id="service-header")
        yield Static("", id="service-info")
        yield Static(f"[{KRAFT}]Interactive Action Items (Space to cycle status, 'r' to execute recipe):[/]", id="checklist-title")
        table = DataTable(id="checklist-table", cursor_type="row")
        table.add_columns("Status", "Category", "Action Item / Check", "Command Recipe")
        yield table

    def _coverage_line(self, service: Service) -> str:
        total = len(service.checklists)
        if total:
            done = sum(1 for c in service.checklists if c.status in (ChecklistStatus.CHECKED, ChecklistStatus.FINDING))
            dead = sum(1 for c in service.checklists if c.status == ChecklistStatus.DEAD_END)
            todo = sum(1 for c in service.checklists if c.status == ChecklistStatus.TODO)
            pct = int(round((done + dead) / total * 100))
            ev_count = self.evidence_counts.get(service.id, 0)
            ev_part = f" │ [bold]Evidence:[/bold] {ev_count} linked"
            return (
                f"[bold]Coverage:[/bold] {done + dead}/{total} ({pct}%)"
                f" │ [bold]Pending:[/bold] {todo}"
                f" │ [bold]Dead-ends:[/bold] {dead}{ev_part}\n"
            )
        return f"[{MUTED}]No methodology checks — run initial recon ('i') or re-ingest scan data.[/]\n"

    def display_service(self, target: Target, service: Service) -> None:
        self.current_target = target
        self.current_service = service

        header = self.query_one("#service-header", Static)
        safe_name = escape((service.name or "unknown").upper())
        safe_ip = escape(target.ip)
        header.update(
            f"[bold {TERRACOTTA}]Port {service.port}/{service.protocol} — {safe_name}[/] on [{MUTED}]{safe_ip}[/]"
        )

        info = self.query_one("#service-info", Static)
        prod_ver = f"{service.product} {service.version}".strip() or "Not specified"
        safe_prod_ver = escape(prod_ver)
        safe_os = escape(target.os or "Unknown")
        safe_host = escape(target.hostname or "None")
        scope_tag = "" if target.in_scope else f"[bold {ERROR_RED}] ⃠ OUT-OF-SCOPE[/]"
        banner_snippet = (
            f"\n[{MUTED}]Banner / Script Output:[/]\n{escape(service.banner[:300])}"
            if service.banner
            else ""
        )
        status_style = service_status_chip(service.status.value)
        info.update(
            f"[bold]Product/Version:[/bold] {safe_prod_ver} │ [bold]Status:[/bold] {status_style}{scope_tag}\n"
            f"{self._coverage_line(service)}"
            f"[bold]Target OS:[/bold] {safe_os} │ [bold]Hostname:[/bold] {safe_host}"
            f"{banner_snippet}"
        )

        table = self.query_one("#checklist-table", DataTable)
        prev_cursor = capture_cursor(table)
        table.clear()

        for item in service.checklists:
            st = checklist_chip(item.status)
            cmd_preview = item.command_template if len(item.command_template) <= 55 else item.command_template[:52] + "..."
            table.add_row(
                st,
                escape(item.category.upper()),
                escape(item.title),
                f"[{TERRACOTTA}]{escape(cmd_preview)}[/]",
                key=str(item.id),
            )
        restore_cursor(table, prev_cursor)

    def display_empty(self, message: str = "Select a target or service from the left sidebar.") -> None:
        header = self.query_one("#service-header", Static)
        header.update("[bold]Service & Methodology Checklist[/bold]")
        info = self.query_one("#service-info", Static)
        info.update(
            f"[{MUTED}]{escape(message)}[/]\n[{KRAFT}]Tip:[/] Press [bold]i[/bold] (or [bold]r[/bold]) "
            f"to launch Initial Reconnaissance on this target and discover its attack surface."
        )
        table = self.query_one("#checklist-table", DataTable)
        table.clear()
