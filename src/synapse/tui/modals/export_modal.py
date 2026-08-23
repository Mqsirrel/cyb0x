"""Modal for exporting reports and Obsidian vaults."""

from __future__ import annotations

from pathlib import Path
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, RadioButton, RadioSet


class ExportModal(ModalScreen[dict]):
    """Dialog for choosing export format and destination path."""

    DEFAULT_CSS = """
    ExportModal {
        align: center middle;
    }
    #dialog {
        padding: 1 2;
        width: 65;
        height: auto;
        border: thick $primary;
        background: $surface;
    }
    .field-label {
        margin-top: 1;
        font-weight: bold;
    }
    #buttons {
        margin-top: 2;
        align: right middle;
    }
    Button {
        margin-left: 2;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[bold cyan]Export Assessment Report[/bold cyan]")
            yield Label("Export Format:", classes="field-label")
            with RadioSet(id="export-format"):
                yield RadioButton("Single Markdown Report (OSCP / eJPT format)", value=True, id="fmt-md")
                yield RadioButton("Obsidian Vault Folder (Linked .md notes)", id="fmt-obsidian")
                yield RadioButton("Full Workspace Backup (JSON)", id="fmt-json")

            yield Label("Output File / Directory Path:", classes="field-label")
            yield Input(value="./assessment_report.md", id="export-path")

            with Horizontal(id="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Export", variant="primary", id="btn-export")

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        path_input = self.query_one("#export-path", Input)
        if event.pressed.id == "fmt-md":
            path_input.value = "./assessment_report.md"
        elif event.pressed.id == "fmt-obsidian":
            path_input.value = "./obsidian_vault"
        elif event.pressed.id == "fmt-json":
            path_input.value = "./workspace_backup.json"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-export":
            path_val = self.query_one("#export-path", Input).value.strip()
            if not path_val:
                return

            radio_set = self.query_one("#export-format", RadioSet)
            selected_button = radio_set.pressed_button
            fmt = "markdown"
            if selected_button and selected_button.id == "fmt-obsidian":
                fmt = "obsidian"
            elif selected_button and selected_button.id == "fmt-json":
                fmt = "json"

            self.dismiss({
                "format": fmt,
                "path": path_val,
            })
        else:
            self.dismiss(None)
