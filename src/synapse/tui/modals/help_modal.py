"""Help & keyboard shortcut reference modal."""

from __future__ import annotations

from typing import List

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widgets import Static

from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import KRAFT, MUTED, TERRACOTTA


class HelpModal(SynapseModal[None]):
    """Dialog displaying interactive keyboard shortcuts and operational guide."""

    BINDINGS = [
        Binding("escape", "cancel", "Close"),
        Binding("q", "cancel", "Close"),
    ]

    GLYPH = "▸"
    TITLE = "HELP — Keyboard Shortcuts & Operator Guide"

    DEFAULT_CSS = """
    HelpModal #dialog {
        width: 84;
        height: auto;
        max-height: 88%;
    }
    #help-scroll {
        height: auto;
        max-height: 100%;
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
        help_text.append("Navigation & Tab Switching:\n", style=f"bold {KRAFT}")

        nav_rows = [
            ("1 - 5", "Switch tabs (Workbench, Creds, Leads, Evidence, Pivots)"),
            ("Tab / S-Tab", "Switch focus between Target Tree and Action Table"),
            ("Up / Down", "Navigate rows / tree items"),
        ]
        for key, desc in nav_rows:
            help_text.append("  ")
            help_text.append(f"{key:<14}", style=TERRACOTTA)
            help_text.append(f"{desc}\n")

        help_text.append("\nAssessment Workflow:\n", style=f"bold {KRAFT}")
        workflow_rows = [
            ("p", "Switch active methodology profile"),
            ("g", "Open Guided Workflow / Methodology phase breakdown"),
            ("n", "Open state-aware Triage: known vs unknown, and the highest-value next move"),
            ("s", "I'm Stuck: rabbit-hole analysis (dead ends vs untested surface vs un-sprayed creds)"),
            ("o", "Toggle in/out of scope for the selected target"),
            ("t", "On Creds tab: cycle credential test state for the selected target (untested→valid→invalid)"),
        ]
        for key, desc in workflow_rows:
            help_text.append("  ")
            help_text.append(f"{key:<14}", style=TERRACOTTA)
            help_text.append(f"{desc}\n")

        help_text.append("\nEngagement Actions:\n", style=f"bold {KRAFT}")
        action_rows = [
            ("Space", "Cycle status of selected checklist item or lead"),
            ("r", "Run selected recipe — auto-routes to Initial Recon when no service is selected"),
            ("^R / ^S", "Inside Runner modal: execute recipe / save output to evidence"),
            ("i", "Launch Initial Reconnaissance for the selected target (phase 0)"),
            ("a", "Add target host / ports manually"),
            ("c", "Save discovered credential to vault"),
            ("l", "Record new attack lead / hypothesis"),
            ("e", "Capture proof flag / evidence with OffSec validation"),
            ("x", "Export report (Notion, Markdown, Obsidian, JSON)"),
            ("T", "Open Theme Switcher modal (Claudish, Tokyo Night, Nord, etc.)"),
            ("? / F1", "Open this help screen"),
            ("q", "Quit Synapse"),
        ]
        for key, desc in action_rows:
            help_text.append("  ")
            help_text.append(f"{key:<14}", style=TERRACOTTA)
            help_text.append(f"{desc}\n")

        return help_text

    def compose_body(self) -> ComposeResult:
        with VerticalScroll(id="help-scroll"):
            yield Static(self._build_help_text(), id="help-content")
            yield Static(
                f"[{MUTED}]Runner modal supports ^R to run and ^S to save output as evidence.[/]",
                id="help-footnote",
            )

    def modal_buttons(self) -> List[ModalButton]:
        return [ModalButton("Close", "btn-close", "primary")]

    def key_hints(self):
        return [("ESC", "Back"), ("Q", "Close")]
