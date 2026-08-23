"""Service detail & interactive methodology checklist widget."""

from __future__ import annotations

from typing import Optional
from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from synapse.models import ChecklistItem, ChecklistStatus, Service, Target


class ServiceDetailWidget(Vertical):
    """Main panel displaying service information and interactive checklist items."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.current_service: Optional[Service] = None
        self.current_target: Optional[Target] = None

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Service & Methodology Checklist[/bold cyan]", id="service-header")
        yield Static("", id="service-info")
        yield Static("[bold yellow]Interactive Action Items (Space to cycle status, 'r' to execute recipe):[/bold yellow]", id="checklist-title")
        table = DataTable(id="checklist-table", cursor_type="row")
        table.add_columns("Status", "Category", "Action Item / Check", "Command Recipe")
        yield table

    def display_service(self, target: Target, service: Service) -> None:
        self.current_target = target
        self.current_service = service

        header = self.query_one("#service-header", Static)
        safe_name = escape((service.name or "unknown").upper())
        safe_ip = escape(target.ip)
        header.update(f"[bold cyan]Port {service.port}/{service.protocol} — {safe_name}[/bold cyan] on [bold green]{safe_ip}[/bold green]")

        info = self.query_one("#service-info", Static)
        prod_ver = f"{service.product} {service.version}".strip() or "Not specified"
        safe_prod_ver = escape(prod_ver)
        safe_os = escape(target.os or "Unknown")
        safe_host = escape(target.hostname or "None")
        banner_snippet = f"\n[dim]Banner / Script Output:[/dim]\n{escape(service.banner[:300])}" if service.banner else ""
        info.update(
            f"[bold]Product/Version:[/bold] {safe_prod_ver} │ [bold]Status:[/bold] [{service.status.value.upper()}]\n"
            f"[bold]Target OS:[/bold] {safe_os} │ [bold]Hostname:[/bold] {safe_host}"
            f"{banner_snippet}"
        )

        table = self.query_one("#checklist-table", DataTable)
        table.clear()

        status_styles = {
            ChecklistStatus.TODO: "[dim white on #262626]   [ ] TODO  [/]",
            ChecklistStatus.RUNNING: "[bold yellow on #3b3014] ⟳ RUNNING [/]",
            ChecklistStatus.CHECKED: "[bold green on #143520] ✔ CHECKED [/]",
            ChecklistStatus.FINDING: "[bold bright_red on #421414] ★ FINDING [/]",
            ChecklistStatus.DEAD_END: "[dim white on #1a1a1a] ✖ DEAD-END[/]",
        }

        for item in service.checklists:
            st = status_styles.get(item.status, "[dim] [ ] TODO [/dim]")
            cmd_preview = item.command_template if len(item.command_template) <= 55 else item.command_template[:52] + "..."
            table.add_row(
                st,
                escape(item.category.upper()),
                escape(item.title),
                f"[cyan]{escape(cmd_preview)}[/cyan]",
                key=str(item.id),
            )

    def display_empty(self, message: str = "Select a target or service from the left sidebar.") -> None:
        header = self.query_one("#service-header", Static)
        header.update("[bold cyan]Service & Methodology Checklist[/bold cyan]")
        info = self.query_one("#service-info", Static)
        info.update(f"[dim]{escape(message)}[/dim]\n[yellow]Tip:[/yellow] Press [bold]i[/bold] to launch Initial Reconnaissance on this target and discover its attack surface.")
        table = self.query_one("#checklist-table", DataTable)
        table.clear()
