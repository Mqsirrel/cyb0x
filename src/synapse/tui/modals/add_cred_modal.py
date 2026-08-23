"""Modal to add a credential to the vault."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select


class AddCredModal(ModalScreen[dict]):
    """Dialog for creating a new credential entry."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    DEFAULT_CSS = """
    AddCredModal {
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

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[bold cyan]Add Discovered Credential[/bold cyan]")
            yield Label("Username / Account:", classes="field-label")
            yield Input(placeholder="e.g. administrator, jsmith, root", id="cred-user")

            yield Label("Password / Hash / Secret:", classes="field-label")
            yield Input(placeholder="e.g. Welcome2023! or aad3b435...", id="cred-secret")

            yield Label("Credential Type:", classes="field-label")
            yield Select(
                [
                    ("Password", "password"),
                    ("NTLM Hash", "ntlm_hash"),
                    ("Kerberos Ticket", "kerberos_ticket"),
                    ("SSH Key", "ssh_key"),
                    ("API Token", "api_token"),
                ],
                value="password",
                id="cred-type",
            )

            yield Label("Domain / Workgroup (optional):", classes="field-label")
            yield Input(placeholder="e.g. CORP.LOCAL", id="cred-domain")

            yield Label("Service Scope (e.g. smb, ssh, http):", classes="field-label")
            yield Input(placeholder="e.g. smb", id="cred-scope")

            with Horizontal(id="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Save Credential", variant="primary", id="btn-save")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            user_val = self.query_one("#cred-user", Input).value.strip()
            secret_val = self.query_one("#cred-secret", Input).value.strip()
            if not user_val or not secret_val:
                return

            self.dismiss({
                "username": user_val,
                "secret": secret_val,
                "cred_type": self.query_one("#cred-type", Select).value,
                "domain": self.query_one("#cred-domain", Input).value.strip(),
                "service_scope": self.query_one("#cred-scope", Input).value.strip(),
            })
        else:
            self.dismiss(None)
