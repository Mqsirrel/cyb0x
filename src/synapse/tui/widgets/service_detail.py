"""Service detail & interactive methodology checklist widget."""

from __future__ import annotations

from typing import Optional
from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from synapse.models import ChecklistStatus, Service, Target, TargetStatus
from synapse.tui.theme import (
    ERROR_RED,
    KRAFT,
    MUTED,
    SAGE,
    TERRACOTTA,
    checklist_chip,
    service_status_chip,
    target_status_chip,
)
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
            deferred = sum(1 for c in service.checklists if c.status == ChecklistStatus.DEFERRED)
            todo = sum(1 for c in service.checklists if c.status == ChecklistStatus.TODO)
            pct = int(round((done + dead + deferred) / total * 100))
            ev_count = self.evidence_counts.get(service.id, 0)
            ev_part = f" │ [bold]Evidence:[/bold] {ev_count} linked"
            defer_part = f" │ [bold]Deferred:[/bold] {deferred}" if deferred else ""
            return (
                f"[bold]Coverage:[/bold] {done + dead + deferred}/{total} ({pct}%)"
                f" │ [bold]Pending:[/bold] {todo}"
                f" │ [bold]Dead-ends:[/bold] {dead}{defer_part}{ev_part}\n"
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

        CATEGORY_ORDER = {"recon": 0, "enum": 1, "vuln_check": 2, "exploit": 3, "privesc": 4}
        ordered_checklists = sorted(
            service.checklists,
            key=lambda c: (CATEGORY_ORDER.get(c.category.lower(), 10), c.id or 0),
        )
        for item in ordered_checklists:
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

    def display_target_360(self, target: Target, credentials: list | None = None, evidence: list | None = None) -> None:
        """Renders the Target 360° unified operational overview card."""
        self.current_target = target
        self.current_service = None

        header = self.query_one("#service-header", Static)
        safe_ip = escape(target.ip)
        safe_host = f" ({escape(target.hostname)})" if target.hostname else ""
        header.update(f"[bold {TERRACOTTA}]TARGET 360° OVERVIEW[/] ▸ [bold]{safe_ip}[/bold]{safe_host}")

        info = self.query_one("#service-info", Static)
        safe_os = escape(target.os or "Unknown")
        status_tag = target_status_chip(target.status)
        scope_tag = "" if target.in_scope else f" [bold {ERROR_RED}]⃠ OUT-OF-SCOPE[/]"

        total_svcs = len(target.services)
        total_checks = sum(len(s.checklists) for s in target.services)
        done_checks = sum(sum(1 for c in s.checklists if c.status.value in ("checked", "finding", "dead_end", "deferred")) for s in target.services)
        findings_count = sum(sum(1 for c in s.checklists if c.status.value == "finding") for s in target.services)

        # Target-linked credentials
        creds = credentials or []
        valid_creds = [
            c.username for c in creds
            if any(isinstance(d, dict) and d.get("valid") and str(k).split(":")[0] == target.ip for k, d in c.tested_targets.items())
        ]
        cred_str = f"[{SAGE}]" + ", ".join(valid_creds[:4]) + f"[/{SAGE}]" if valid_creds else f"[{MUTED}]None confirmed[/{MUTED}]"

        cov_pct = int(round(done_checks / total_checks * 100)) if total_checks else 0

        info_text = (
            f"[bold]Status:[/bold] {status_tag}{scope_tag} │ [bold]OS:[/bold] {safe_os} │ [bold]Services:[/bold] {total_svcs} │ [bold]Findings:[/bold] [bold {ERROR_RED}]{findings_count}[/]\n"
            f"[bold]Methodology Coverage:[/bold] {done_checks}/{total_checks} ({cov_pct}%) │ [bold]Valid Access:[/bold] {cred_str}\n"
            f"[{MUTED}]Target Notes:[/] {escape(target.notes) if target.notes else '[dim]No notes recorded[/dim]'}"
        )
        info.update(info_text)

        title_lbl = self.query_one("#checklist-title", Static)
        table = self.query_one("#checklist-table", DataTable)
        prev_cursor = capture_cursor(table)
        table.clear()

        if total_svcs == 0:
            title_lbl.update(f"[{KRAFT}]Attack Surface Status:[/] No open ports recorded yet.")
            table.add_row(
                f"[bold {KRAFT}]UNSCANNED[/]",
                "-",
                "Phase 0 Reconnaissance",
                f"[{TERRACOTTA}]Press 'i' or 'r' to launch Initial Recon on {safe_ip}[/]",
            )
            return

        title_lbl.update(f"[{KRAFT}]Discovered Open Ports & Attack Surface (Select service in sidebar to inspect checks):[/]")

        for svc in target.services:
            st = service_status_chip(svc.status.value)
            prod_ver = f"{svc.product} {svc.version}".strip() or "-"
            checks_total = len(svc.checklists)
            checks_resolved = sum(1 for c in svc.checklists if c.status.value in ("checked", "finding", "dead_end"))
            cov_str = f"{checks_resolved}/{checks_total}" if checks_total else "0 checks"
            table.add_row(
                st,
                f"{svc.port}/{svc.protocol}",
                escape(svc.name.upper()),
                f"[{TERRACOTTA}]{escape(prod_ver)}[/] [dim]({cov_str})[/dim]",
                key=str(svc.id),
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

