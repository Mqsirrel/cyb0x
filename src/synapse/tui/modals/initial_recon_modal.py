"""Modal for launching host-level initial reconnaissance recipes (phase 0)."""

from __future__ import annotations

from typing import Dict, List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Label, Static


class InitialReconModal(ModalScreen[dict]):
    """Dialog listing host-level recon recipes for a target before any service is discovered.

    Dismisses with ``{"title": ..., "command": ...}`` so the app can hand the
    recipe to the standard RunnerModal, or ``None`` when cancelled.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    DEFAULT_CSS = """
    InitialReconModal {
        align: center middle;
    }
    #dialog {
        padding: 1 2;
        width: 90;
        height: auto;
        max-height: 80%;
        border: thick $primary;
        background: $surface;
    }
    #recon-hint {
        margin-top: 1;
        color: $text-muted;
    }
    #recon-table {
        height: auto;
        min-height: 8;
        margin-top: 1;
    }
    #buttons {
        margin-top: 1;
        align: right middle;
    }
    Button {
        margin-left: 2;
    }
    """

    def __init__(self, target_ip: str, recipes: List[Dict[str, str]], **kwargs):
        super().__init__(**kwargs)
        self.target_ip = target_ip
        self.recipes = [r for r in recipes if r.get("command_template")]

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(
                f"[bold cyan]Initial Reconnaissance — {escape(self.target_ip)}[/bold cyan]"
            )
            yield Static(
                "[dim]Phase 0 recipes for hosts with no discovered services yet. "
                "Nmap stdout is parsed automatically after execution to seed service recipes.[/dim]",
                id="recon-hint",
            )
            table = DataTable(id="recon-table", cursor_type="row")
            table.add_columns("Category", "Recon Check", "Command Recipe")
            yield table

            with Horizontal(id="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Run Selected", variant="warning", id="btn-run")

    def on_mount(self) -> None:
        table = self.query_one("#recon-table", DataTable)
        for idx, rc in enumerate(self.recipes):
            cmd = rc.get("command_template", "")
            preview = cmd if len(cmd) <= 60 else cmd[:57] + "..."
            table.add_row(
                escape((rc.get("category") or "recon").upper()),
                escape(rc.get("title", "")),
                f"[cyan]{escape(preview)}[/cyan]",
                key=str(idx),
            )

    def _selected_recipe(self) -> Optional[Dict[str, str]]:
        table = self.query_one("#recon-table", DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return None
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        try:
            return self.recipes[int(row_key)]
        except (ValueError, IndexError):
            return None

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        rc = self._selected_recipe()
        if rc:
            self.dismiss({"title": rc.get("title", ""), "command": rc.get("command_template", "")})

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
        elif event.button.id == "btn-run":
            rc = self._selected_recipe()
            if rc:
                self.dismiss({"title": rc.get("title", ""), "command": rc.get("command_template", "")})
