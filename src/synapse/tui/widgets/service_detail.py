"""Service detail & interactive methodology checklist widget."""

from __future__ import annotations

from typing import Optional
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal, ScrollableContainer
from textual.widgets import Static, DataTable, Label, Button

from synapse.models import Service, Target, ChecklistItem, ChecklistStatus


class ServiceDetailWidget(Vertical):
    """Main panel displaying service information and interactive checklist items."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.current_service: Optional[Service] = None
        self.current_target: Optional[Target] = None

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Service & Methodology Checklist[/bold cyan]", id="service-header")
        yield Static("", id="service-info")
        yield Static("[bold yellow]Interactive Methodology Action Items (Space/Enter to cycle status, 'r' to run recipe):[/bold yellow]", id="checklist-title")
        table = DataTable(id="checklist-table", cursor_type="row")
        table.add_columns("Status", "Category", "Action Item / Check", "Command Recipe")
        yield table

    def display_service(self, target: Target, service: Service) -> None:
        self.current_target = target
        self.current_service = service

        header = self.query_one("#service-header", Static)
        header.update(f"[bold cyan]Port {service.port}/{service.protocol} — {service.name.upper()}[/bold cyan] on [bold green]{target.ip}[/bold green]")

        info = self.query_one("#service-info", Static)
        prod_ver = f"{service.product} {service.version}".strip() or "Not specified"
        banner_snippet = f"\n[dim]Banner / Script Output:[/dim]\n{service.banner[:300]}" if service.banner else ""
        info.update(
            f"[bold]Product/Version:[/bold] {prod_ver} | [bold]Status:[/bold] [{service.status.value.upper()}]\n"
            f"[bold]Target OS:[/bold] {target.os} | [bold]Hostname:[/bold] {target.hostname or 'None'}"
            f"{banner_snippet}"
        )

        table = self.query_one("#checklist-table", DataTable)
        table.clear()

        status_styles = {
            ChecklistStatus.TODO: "[white]  [ ] TODO  [/white]",
            ChecklistStatus.RUNNING: "[yellow] ⟳ RUNNING [/yellow]",
            ChecklistStatus.CHECKED: "[green] ✔ CHECKED [/green]",
            ChecklistStatus.FINDING: "[bold red] ★ FINDING [/bold red]",
            ChecklistStatus.DEAD_END: "[dim] ✖ DEAD-END[/dim]",
        }

        for item in service.checklists:
            st = status_styles.get(item.status, "[ ] TODO")
            cmd_preview = item.command_template if len(item.command_template) <= 50 else item.command_template[:47] + "..."
            table.add_row(st, item.category, item.title, f"[cyan]{cmd_preview}[/cyan]", key=str(item.id))

    def display_empty(self, message: str = "Select a target or service from the left sidebar.") -> None:
        header = self.query_one("#service-header", Static)
        header.update("[bold cyan]Service & Methodology Checklist[/bold cyan]")
        info = self.query_one("#service-info", Static)
        info.update(f"[dim]{message}[/dim]")
        table = self.query_one("#checklist-table", DataTable)
        table.clear()
