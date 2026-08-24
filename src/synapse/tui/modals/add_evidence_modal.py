"""Modal to record proof flag or command evidence."""

from __future__ import annotations

from typing import List

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import Input, Label, Select, TextArea

from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import TERRACOTTA


class AddEvidenceModal(SynapseModal[dict]):
    """Dialog for recording a proof flag or command log evidence."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    GLYPH = "▸"
    TITLE = "EVIDENCE — Capture Proof Flag / Evidence"

    DEFAULT_CSS = """
    AddEvidenceModal #dialog {
        width: 74;
        height: auto;
        max-height: 92%;
    }
    #ev-output {
        height: 6;
        margin-top: 1;
    }
    """

    def __init__(self, target_ip: str | None = None, **kwargs):
        context = (
            f"Target [bold {TERRACOTTA}]{escape(target_ip)}[/]"
            if target_ip
            else None
        )
        super().__init__(context=context, **kwargs)
        self.default_target_ip = target_ip

    def compose_body(self) -> ComposeResult:
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

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Cancel", "btn-cancel", "default"),
            ModalButton("Save Evidence", "btn-save", "success"),
        ]

    def key_hints(self):
        return [("ESC", "Cancel")]

    def on_modal_button(self, button_id: str) -> None:
        if button_id != "btn-save":
            return
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
