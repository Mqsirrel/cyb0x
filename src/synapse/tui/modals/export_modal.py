"""Modal to configure and trigger report exports."""

from __future__ import annotations

from pathlib import Path
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select


class ExportModal(ModalScreen[dict]):
    """Dialog for exporting engagement reports."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    DEFAULT_CSS = """
    ExportModal {
        align: center middle;
    }
    #dialog {
        padding: 1 2;
        width: 68;
        height: auto;
        border: thick $primary;
        background: $surface;
    }
    .field-label {
        margin-top: 1;
        text-style: bold;
    }
    #buttons {
        margin-top: 2;
        align: right middle;
    }
    Button {
        margin-left: 2;
    }
    """

    def __init__(self, default_output: str = "./notion_workspace", **kwargs):
        super().__init__(**kwargs)
        self.default_output = default_output

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[bold cyan]Export Assessment Report & Workspace[/bold cyan]")
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
            )

            yield Label("Destination Path / Directory:", classes="field-label")
            yield Input(value=self.default_output, id="export-path")

            with Horizontal(id="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Export Now", variant="success", id="btn-export")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-export":
            fmt = self.query_one("#export-format", Select).value
            path_val = self.query_one("#export-path", Input).value.strip()
            if not path_val:
                return

            self.dismiss({
                "format": fmt,
                "output_path": path_val,
            })
        else:
            self.dismiss(None)
