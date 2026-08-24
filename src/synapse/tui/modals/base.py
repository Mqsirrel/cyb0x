"""Shared modal anatomy for all Synapse dialogs.

Standard structure (the "docked action bar" pattern):

    ╭─ ▸ GLYPH TITLE ─────────────────────────────╮
    │ context / subtitle line (optional)          │
    │                                             │
    │ body (subclass-supplied widgets)            │
    │                                             │
    ├─────────────────────────────────────────────┤
    │ key hints ....................... [buttons] │
    ╰─────────────────────────────────────────────╯

Subclasses implement ``compose_body`` and may override ``modal_buttons``,
``key_hints``, and ``on_modal_button``. Sizing stays per-modal via
DEFAULT_CSS rules on ``#dialog``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, List, Optional, Tuple, TypeVar

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from synapse.tui.theme import MODAL_CSS, key_hint_bar

T = TypeVar("T")


@dataclass(frozen=True)
class ModalButton:
    label: str
    id: str
    variant: str = "default"


class SynapseModal(ModalScreen[T], Generic[T]):
    """Base class for every Synapse modal dialog."""

    DEFAULT_CSS = MODAL_CSS

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    GLYPH: str = "▸"
    TITLE: str = "DIALOG"

    def __init__(
        self,
        title: Optional[str] = None,
        context: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.modal_title = title or self.TITLE
        self.modal_context = context

    def border_header(self) -> Text:
        return Text(f"{self.GLYPH} {self.modal_title}")

    def compose_body(self) -> ComposeResult:
        return
        yield

    def modal_buttons(self) -> List[ModalButton]:
        return [ModalButton("Close", "btn-cancel", "default")]

    def key_hints(self) -> List[Tuple[str, str]]:
        return [("ESC", "Back")]

    def on_modal_button(self, button_id: str) -> None:
        """Handles a pressed button that is not the standard cancel."""

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog") as dialog:
            dialog.border_title = self.border_header()
            if self.modal_context:
                yield Static(Text.from_markup(self.modal_context), id="modal-context")
            with Vertical(id="modal-body"):
                yield from self.compose_body()
            with Horizontal(id="action-bar"):
                yield Static(
                    Text.from_markup(key_hint_bar(self.key_hints())), id="key-hints"
                )
                with Horizontal(id="action-buttons"):
                    for button in self.modal_buttons():
                        yield Button(button.label, variant=button.variant, id=button.id)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id in ("btn-cancel", "btn-close"):
            self.action_cancel()
        else:
            self.on_modal_button(str(event.button.id))
