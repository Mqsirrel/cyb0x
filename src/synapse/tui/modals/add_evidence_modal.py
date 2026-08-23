"""Modal to capture proof flags and evidence."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, TextArea


class AddEvidenceModal(ModalScreen[dict]):
    """Dialog for creating an evidence or flag proof record."""

    DEFAULT_CSS = """
    AddEvidenceModal {
        align: center middle;
    }
    #dialog {
        padding: 1 2;
        width: 70;
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
    TextArea {
        height: 5;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[bold cyan]Capture Proof Flag / Evidence[/bold cyan]")
            yield Label("Proof Type:", classes="field-label")
            yield Select(
                [
                    ("User Proof Flag (user.txt)", "user_flag"),
                    ("Root Proof Flag (proof.txt)", "root_flag"),
                    ("Command Output / Log", "command_output"),
                    ("Config / Credential Leak", "config_leak"),
                ],
                value="user_flag",
                id="ev-type",
            )

            yield Label("Title / Context:", classes="field-label")
            yield Input(placeholder="e.g. Initial foothold user flag on 10.10.11.10", id="ev-title")

            yield Label("Flag Hash / Value (32-hex or string):", classes="field-label")
            yield Input(placeholder="e.g. 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d", id="ev-hash")

            yield Label("Command Executed:", classes="field-label")
            yield Input(placeholder="e.g. whoami && id && ip a && cat user.txt", id="ev-cmd")

            yield Label("Raw Terminal Output Snippet:", classes="field-label")
            yield TextArea(id="ev-output")

            with Horizontal(id="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save Proof Record", variant="primary", id="btn-save")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            title_val = self.query_one("#ev-title", Input).value.strip()
            if not title_val:
                return

            self.dismiss({
                "proof_type": self.query_one("#ev-type", Select).value,
                "title": title_val,
                "flag_hash": self.query_one("#ev-hash", Input).value.strip(),
                "command": self.query_one("#ev-cmd", Input).value.strip(),
                "output": self.query_one("#ev-output", TextArea).text.strip(),
            })
        else:
            self.dismiss(None)
