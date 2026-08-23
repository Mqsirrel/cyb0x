"""Modal to record proof flag or command evidence."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, TextArea


class AddEvidenceModal(ModalScreen[dict]):
    """Dialog for recording a proof flag or command log evidence."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

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
        height: 6;
    }
    """

    def __init__(self, target_ip: str | None = None, **kwargs):
        super().__init__(**kwargs)
        self.default_target_ip = target_ip

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[bold cyan]Record Proof Flag / Evidence[/bold cyan]")
            yield Label("Target IP:", classes="field-label")
            yield Input(value=self.default_target_ip or "", placeholder="e.g. 10.10.11.10", id="ev-target")

            yield Label("Evidence / Proof Type:", classes="field-label")
            yield Select(
                [
                    ("Root Flag (proof.txt)", "root_flag"),
                    ("User Flag (user.txt)", "user_flag"),
                    ("Command Output Proof", "command_output"),
                    ("Screenshot Reference", "screenshot"),
                    ("Credential Dump", "credential_dump"),
                ],
                value="user_flag",
                id="ev-type",
            )

            yield Label("Title / Context:", classes="field-label")
            yield Input(placeholder="e.g. proof.txt retrieved via root shell", id="ev-title")

            yield Label("Flag Hash (optional, 32-char MD5 or CTF{...}):", classes="field-label")
            yield Input(placeholder="e.g. 7c4a8d09ca3762af61e59520943dc26494f8941b", id="ev-flag")

            yield Label("Command Executed (e.g. whoami && ip a && type proof.txt):", classes="field-label")
            yield Input(placeholder="e.g. whoami && ip a && cat /root/proof.txt", id="ev-cmd")

            yield Label("Terminal Output / Proof Content:", classes="field-label")
            yield TextArea(placeholder="Paste raw terminal proof output here...", id="ev-output")

            with Horizontal(id="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save Evidence", variant="primary", id="btn-save")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            target_val = self.query_one("#ev-target", Input).value.strip()
            title_val = self.query_one("#ev-title", Input).value.strip()
            if not target_val or not title_val:
                return

            self.dismiss({
                "target_ip": target_val,
                "proof_type": self.query_one("#ev-type", Select).value,
                "title": title_val,
                "flag_hash": self.query_one("#ev-flag", Input).value.strip(),
                "command": self.query_one("#ev-cmd", Input).value.strip(),
                "output": self.query_one("#ev-output", TextArea).text.strip(),
            })
        else:
            self.dismiss(None)
