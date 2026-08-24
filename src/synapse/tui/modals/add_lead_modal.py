"""Modal to add an attack hypothesis or lead."""

from __future__ import annotations

from typing import List

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import Input, Label, Select, TextArea

from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import TERRACOTTA


class AddLeadModal(SynapseModal[dict]):
    """Dialog for creating an attack hypothesis / lead."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    GLYPH = "▸"
    TITLE = "LEADS — Record Attack Hypothesis"

    DEFAULT_CSS = """
    AddLeadModal #dialog {
        width: 68;
        height: auto;
    }
    #lead-desc {
        height: 5;
        margin-top: 1;
    }
    """

    def __init__(self, target_id: int | None = None, target_ip: str | None = None, **kwargs):
        context = (
            f"Linked target: [bold {TERRACOTTA}]{escape(target_ip)}[/]"
            if target_ip
            else None
        )
        super().__init__(context=context, **kwargs)
        self.default_target_id = target_id
        self.default_target_ip = target_ip

    def compose_body(self) -> ComposeResult:
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

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Cancel", "btn-cancel", "default"),
            ModalButton("Save Lead", "btn-save", "success"),
        ]

    def key_hints(self):
        return [("ESC", "Cancel")]

    def on_modal_button(self, button_id: str) -> None:
        if button_id != "btn-save":
            return
        title_val = self.query_one("#lead-title", Input).value.strip()
        if not title_val:
            return

        self.dismiss({
            "title": title_val,
            "priority": self.query_one("#lead-priority", Select).value,
            "target_ip": self.query_one("#lead-target-ip", Input).value.strip(),
            "description": self.query_one("#lead-desc", TextArea).text.strip(),
        })
