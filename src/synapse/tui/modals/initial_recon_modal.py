"""Modal for launching host-level initial reconnaissance recipes (phase 0)."""

from __future__ import annotations

from typing import Dict, List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Static

from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import MUTED, TERRACOTTA


class InitialReconModal(SynapseModal[dict]):
    """Dialog listing host-level recon recipes for a target before any service is discovered.

    Dismisses with ``{"title": ..., "command": ...}`` so the app can hand the
    recipe to the standard RunnerModal, or ``None`` when cancelled.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("enter", "run_selected", "Run Selected"),
    ]

    GLYPH = "▸"
    TITLE = "RECON — Phase-0 Host Reconnaissance"

    DEFAULT_CSS = """
    InitialReconModal #dialog {
        width: 96;
        height: auto;
        max-height: 85%;
    }
    #recon-scroll {
        height: auto;
        max-height: 100%;
        margin-top: 1;
    }
    #recon-hint {
        color: $text-muted;
    }
    #recon-table {
        height: auto;
        min-height: 8;
        margin-top: 1;
    }
    """

    def __init__(self, target_ip: str, recipes: List[Dict[str, str]], **kwargs):
        super().__init__(
            context=(
                f"Target [bold {TERRACOTTA}]{escape(target_ip)}[/] · "
                f"[{MUTED}]recipes seed methodology checklists automatically[/]"
            ),
            **kwargs,
        )
        self.target_ip = target_ip
        self.recipes = [r for r in recipes if r.get("command_template")]

    def compose_body(self) -> ComposeResult:
        with VerticalScroll(id="recon-scroll"):
            yield Static(
                "[dim]Phase 0 recipes for hosts with no discovered services yet. "
                "Nmap stdout is parsed automatically after execution to seed service recipes.[/dim]",
                id="recon-hint",
            )
            table = DataTable(id="recon-table", cursor_type="row")
            table.add_columns("Category", "Recon Check", "Command Recipe")
            yield table

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Cancel", "btn-cancel", "default"),
            ModalButton("Run Selected", "btn-run", "primary"),
        ]

    def key_hints(self):
        return [("ESC", "Cancel"), ("ENTER", "Run Selected")]

    def on_mount(self) -> None:
        table = self.query_one("#recon-table", DataTable)
        for idx, rc in enumerate(self.recipes):
            cmd = rc.get("command_template", "")
            preview = cmd if len(cmd) <= 60 else cmd[:57] + "..."
            table.add_row(
                escape((rc.get("category") or "recon").upper()),
                escape(rc.get("title", "")),
                f"[{TERRACOTTA}]{escape(preview)}[/]",
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

    def action_run_selected(self) -> None:
        rc = self._selected_recipe()
        if rc:
            self.dismiss({"title": rc.get("title", ""), "command": rc.get("command_template", "")})

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_run_selected()

    def on_modal_button(self, button_id: str) -> None:
        if button_id == "btn-run":
            self.action_run_selected()
