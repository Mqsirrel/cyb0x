"""Modal to configure and trigger report exports."""

from __future__ import annotations

from typing import List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import Input, Label, Select

from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import SAGE


class ExportModal(SynapseModal[dict]):
    """Dialog for exporting engagement reports."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    GLYPH = "▸"
    TITLE = "EXPORT — Engagement Report & Workspace"

    DEFAULT_CSS = """
    ExportModal #dialog {
        width: 72;
        height: auto;
    }
    """

    SUGGESTED_PATHS = {
        "notion": "./notion_workspace",
        "markdown": "./assessment_report.md",
        "obsidian": "./obsidian_vault",
        "json": "./workspace_backup.json",
    }

    def __init__(self, default_output: str = "./notion_workspace", **kwargs):
        super().__init__(**kwargs)
        self.default_output = default_output

    def compose_body(self) -> ComposeResult:
        yield Label("Export Format:", classes="field-label")
        yield Select(
            [
                ("Notion Workspace Bundle (Nested Pages & Callouts)", "notion"),
                ("Single-File Markdown (OffSec/eJPT format)", "markdown"),
                ("Obsidian Vault (Wikilink note graph)", "obsidian"),
                ("Complete JSON State Backup", "json"),
            ],
            value="notion",
            id="export-format",
            allow_blank=False,
        )

        yield Label("Destination Path / Directory:", classes="field-label")
        yield Input(value=self.default_output, id="export-path")

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Cancel", "btn-cancel", "default"),
            ModalButton("Export Now", "btn-export", "success"),
        ]

    def key_hints(self):
        return [("ESC", "Cancel")]

    def on_select_changed(self, event: Select.Changed) -> None:
        """Swaps the suggested destination path when the format changes."""
        suggested = self.SUGGESTED_PATHS.get(str(event.value))
        path_input = self.query_one("#export-path", Input)
        if suggested and path_input.value in self.SUGGESTED_PATHS.values():
            path_input.value = suggested

    def on_modal_button(self, button_id: str) -> None:
        if button_id != "btn-export":
            return
        fmt = self.query_one("#export-format", Select).value
        path_val = self.query_one("#export-path", Input).value.strip()
        if not path_val:
            return

        self.dismiss({
            "format": fmt,
            "output_path": path_val,
        })
