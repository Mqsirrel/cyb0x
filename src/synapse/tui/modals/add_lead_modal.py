"""Modal to add an attack hypothesis or lead."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, TextArea


class AddLeadModal(ModalScreen[dict]):
    """Dialog for creating an attack hypothesis / lead."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    DEFAULT_CSS = """
    AddLeadModal {
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

    def __init__(self, target_id: int | None = None, target_ip: str | None = None, **kwargs):
        super().__init__(**kwargs)
        self.default_target_id = target_id
        self.default_target_ip = target_ip

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[bold cyan]Record Attack Hypothesis / Lead[/bold cyan]")
            yield Label("Lead Title / Vector:", classes="field-label")
            yield Input(placeholder="e.g. Test SQLi on login form, AS-REP Roasting", id="lead-title")

            yield Label("Priority:", classes="field-label")
            yield Select(
                [
                    ("Critical", "critical"),
                    ("High", "high"),
                    ("Medium", "medium"),
                    ("Low", "low"),
                ],
                value="medium",
                id="lead-priority",
            )

            yield Label("Target IP (optional):", classes="field-label")
            yield Input(value=self.default_target_ip or "", placeholder="e.g. 10.10.11.15", id="lead-target-ip")

            yield Label("Description / Action Plan:", classes="field-label")
            yield TextArea(placeholder="Detailed notes on what to check...", id="lead-desc")

            with Horizontal(id="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save Lead", variant="primary", id="btn-save")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            title_val = self.query_one("#lead-title", Input).value.strip()
            if not title_val:
                return

            self.dismiss({
                "title": title_val,
                "priority": self.query_one("#lead-priority", Select).value,
                "target_ip": self.query_one("#lead-target-ip", Input).value.strip(),
                "description": self.query_one("#lead-desc", TextArea).text.strip(),
            })
        else:
            self.dismiss(None)
