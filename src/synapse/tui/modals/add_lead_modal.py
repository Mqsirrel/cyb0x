"""Modal to add a hypothesis or lead."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select


class AddLeadModal(ModalScreen[dict]):
    """Dialog for creating a new attack lead."""

    DEFAULT_CSS = """
    AddLeadModal {
        align: center middle;
    }
    #dialog {
        padding: 1 2;
        width: 60;
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
            yield Label("[bold cyan]Add Attack Lead / Hypothesis[/bold cyan]")
            yield Label("Lead Title:", classes="field-label")
            yield Input(placeholder="e.g. Found backup.zip -> crack password & spray SSH", id="lead-title")

            yield Label("Priority:", classes="field-label")
            yield Select(
                [
                    ("Critical", "critical"),
                    ("High", "high"),
                    ("Medium", "medium"),
                    ("Low", "low"),
                ],
                value="high",
                id="lead-priority",
            )

            yield Label("Detailed Rationale / Context:", classes="field-label")
            yield Input(placeholder="e.g. Discovered in /var/www/html/backup", id="lead-desc")

            with Horizontal(id="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save Lead", variant="primary", id="btn-save")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            title_val = self.query_one("#lead-title", Input).value.strip()
            if not title_val:
                return

            self.dismiss({
                "title": title_val,
                "priority": self.query_one("#lead-priority", Select).value,
                "description": self.query_one("#lead-desc", Input).value.strip(),
            })
        else:
            self.dismiss(None)
