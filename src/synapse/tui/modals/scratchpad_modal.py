"""Workspace Scratchpad Modal (.).

Provides a persistent, low-friction markdown scratchpad for raw thoughts,
unverified hypotheses, lab notes, and exam observations.
"""

from __future__ import annotations

from typing import List, Tuple
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import Label, TextArea

from synapse.db.repository import DatabaseRepository
from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import TERRACOTTA


class ScratchpadModal(SynapseModal[bool]):
    """Modal dialog for editing freeform workspace notes."""

    GLYPH = "✎"
    TITLE = "WORKSPACE SCRATCHPAD & NOTES"

    BINDINGS = [
        Binding("escape", "cancel", "Save & Close"),
        Binding("ctrl+s", "save_notes", "Save Notes", priority=True),
    ]

    DEFAULT_CSS = """
    ScratchpadModal #dialog {
        width: 85%;
        height: 80%;
    }
    #scratchpad-area {
        height: 1fr;
        min-height: 10;
        border: round $panel;
        margin-top: 1;
    }
    """

    def __init__(self, repo: DatabaseRepository, workspace_name: str = "default", **kwargs):
        super().__init__(context=f"Workspace: [bold {TERRACOTTA}]{workspace_name}[/] · Freeform Markdown Notes", **kwargs)
        self.repo = repo
        self.workspace_name = workspace_name

    def compose_body(self) -> ComposeResult:
        yield Label("Freeform Assessment Notes / Hypotheses / Checklists:", classes="field-label")
        yield TextArea(id="scratchpad-area")

    def on_mount(self) -> None:
        initial_content = self.repo.get_scratchpad()
        area = self.query_one("#scratchpad-area", TextArea)
        if initial_content:
            area.load_text(initial_content)
        area.focus()

    def action_save_notes(self) -> None:
        area = self.query_one("#scratchpad-area", TextArea)
        content = area.text
        self.repo.set_scratchpad(content)
        self.notify("Scratchpad notes saved to workspace!", title="Saved")

    def action_cancel(self) -> None:
        self.action_save_notes()
        self.dismiss(True)

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Save & Close", "btn-save", "primary"),
            ModalButton("Cancel", "btn-cancel", "default"),
        ]

    def key_hints(self) -> List[Tuple[str, str]]:
        return [("ESC", "Save & Close"), ("^S", "Save")]

    def on_modal_button(self, button_id: str) -> None:
        if button_id == "btn-save":
            self.action_save_notes()
            self.dismiss(True)
