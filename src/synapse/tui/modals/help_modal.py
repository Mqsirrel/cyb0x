"""Help & keyboard shortcut reference modal."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static


class HelpModal(ModalScreen[None]):
    """Dialog displaying interactive keyboard shortcuts and operational guide."""

    BINDINGS = [
        Binding("escape", "cancel", "Close"),
        Binding("q", "cancel", "Close"),
    ]

    DEFAULT_CSS = """
    HelpModal {
        align: center middle;
    }
    #dialog {
        padding: 1 2;
        width: 75;
        height: auto;
        border: thick $primary;
        background: $surface;
    }
    #help-content {
        margin-top: 1;
        margin-bottom: 1;
    }
    Button {
        align: center middle;
        margin-top: 1;
    }
    """

    @staticmethod
    def _build_help_text() -> Text:
        """Builds the shortcut guide as a rich Text object.

        A Text instance is used instead of markup-with-padding because Textual
        collapses runs of whitespace in markup strings, which destroys the
        key/description column alignment.
        """
        help_text = Text()
        help_text.append("Navigation & Tab Switching:\n", style="bold yellow")

        nav_rows = [
            ("1 - 5", "Switch tabs (Workbench, Creds, Leads, Evidence, Pivots)"),
            ("Tab / S-Tab", "Switch focus between Target Tree and Action Table"),
            ("Up / Down", "Navigate rows / tree items"),
        ]
        for key, desc in nav_rows:
            help_text.append("  ")
            help_text.append(f"{key:<14}", style="bold cyan")
            help_text.append(f"{desc}\n")

        help_text.append("\nEngagement Actions:\n", style="bold yellow")
        action_rows = [
            ("Space", "Cycle status of selected checklist item or lead"),
            ("r", "Open Command Runner modal for selected recipe"),
            ("a", "Add target host / ports manually"),
            ("c", "Save discovered credential to vault"),
            ("l", "Record new attack lead / hypothesis"),
            ("e", "Capture proof flag / evidence with OffSec validation"),
            ("x", "Export report (Notion, Markdown, Obsidian, JSON)"),
            ("? / F1", "Open this help screen"),
            ("q", "Quit Synapse"),
        ]
        for key, desc in action_rows:
            help_text.append("  ")
            help_text.append(f"{key:<14}", style="bold cyan")
            help_text.append(f"{desc}\n")

        return help_text

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[bold cyan]SYNAPSE // Keyboard Shortcuts & Operator Guide[/bold cyan]")
            yield Static(self._build_help_text(), id="help-content")
            yield Button("Close (Esc)", variant="primary", id="btn-close")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)
