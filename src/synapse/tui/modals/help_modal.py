"""Help & keyboard shortcut reference modal."""

from __future__ import annotations

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

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[bold cyan]SYNAPSE // Keyboard Shortcuts & Operator Guide[/bold cyan]")
            yield Static(
                """[bold yellow]Navigation & Tab Switching:[/bold yellow]
  [bold cyan]1[/bold cyan] - [bold cyan]5[/bold cyan]       Switch tabs (Workbench, Cred Vault, Leads, Evidence, Pivots)
  [bold cyan]Tab[/bold cyan] / [bold cyan]S-Tab[/bold cyan] Switch focus between Target Tree and Action Table
  [bold cyan]↑ / ↓[/bold cyan]       Navigate rows / tree items

[bold yellow]Engagement Actions:[/bold yellow]
  [bold cyan]Space[/bold cyan]       Cycle status of selected checklist item or lead
  [bold cyan]r[/bold cyan]           Open Command Runner modal for selected recipe
  [bold cyan]a[/bold cyan]           Add target host / ports manually
  [bold cyan]c[/bold cyan]           Save discovered credential to vault
  [bold cyan]l[/bold cyan]           Record new attack lead / hypothesis
  [bold cyan]e[/bold cyan]           Capture proof flag / evidence with OffSec validation
  [bold cyan]x[/bold cyan]           Export assessment report (Markdown, Obsidian, JSON)
  [bold cyan]?[/bold cyan] / [bold cyan]F1[/bold cyan]      Open this help screen
  [bold cyan]q[/bold cyan]           Quit Synapse
""",
                id="help-content",
            )
            yield Button("Close (Esc)", variant="primary", id="btn-close")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)
