"""Modal to add a credential to the vault."""

from __future__ import annotations

from typing import List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import Input, Label, Select

from synapse.tui.modals.base import ModalButton, SynapseModal


class AddCredModal(SynapseModal[dict]):
    """Dialog for creating a new credential entry."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    GLYPH = "▸"
    TITLE = "VAULT — Add Discovered Credential"

    DEFAULT_CSS = """
    AddCredModal #dialog {
        width: 62;
        height: auto;
    }
    """

    def compose_body(self) -> ComposeResult:
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

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Cancel", "btn-cancel", "default"),
            ModalButton("Save Credential", "btn-save", "success"),
        ]

    def key_hints(self):
        return [("ESC", "Cancel")]

    def on_modal_button(self, button_id: str) -> None:
        if button_id != "btn-save":
            return
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
