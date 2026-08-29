"""Command Palette modal (Ctrl+K).

Provides a searchable command palette exposing every action, view, modal,
and hotkey in Synapse to eliminate the need to memorize dozens of keybindings.
"""

from __future__ import annotations

from typing import List, Tuple
from textual.app import ComposeResult
from textual.widgets import Input, OptionList
from textual.widgets.option_list import Option

from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import KRAFT, MUTED, SAGE, TERRACOTTA


class CommandPaletteModal(SynapseModal[str]):
    """Filterable Command Palette for discoverability of all actions."""

    GLYPH = "⌘"
    TITLE = "COMMAND PALETTE"

    DEFAULT_CSS = """
    CommandPaletteModal #dialog {
        width: 88%;
        max-width: 96;
        height: auto;
        max-height: 85%;
    }
    CommandPaletteModal #modal-body {
        height: 1fr;
    }
    #palette-input {
        margin-bottom: 1;
    }
    #palette-list {
        height: 1fr;
        min-height: 6;
        max-height: 12;
        border: round $panel;
    }
    """

    ACTIONS: List[Tuple[str, str, str, str]] = [
        ("triage", "Triage Assessment State & Next Moves", "n", "Assessment"),
        ("stuck", "I'm Stuck (Rabbit-Hole & Escape Analysis)", "s", "Assessment"),
        ("guided", "Guided Methodology Phase Workflow", "g", "Assessment"),
        ("workspace", "Switch / Create / Clone Lab Workspace", "^L", "Workspace"),
        ("scratchpad", "Open Workspace Scratchpad / Notes", ".", "Workspace"),
        ("jump", "Jump to Target / Service / Cred / Lead", "^P", "Navigation"),
        ("run_recipe", "Run Selected Recipe in Subprocess", "r", "Execution"),
        ("initial_recon", "Launch Phase-0 Reconnaissance on Target", "i", "Execution"),
        ("add_target", "Add Target Host / CIDR Subnet", "a", "Scope"),
        ("toggle_scope", "Toggle Target In/Out of Scope", "o", "Scope"),
        ("add_cred", "Add Credential / Hash to Vault", "c", "Credentials"),
        ("mark_cred", "Cycle Credential Lifecycle on Host", "t", "Credentials"),
        ("add_lead", "Add Attack Lead / Hypothesis", "l", "Hypotheses"),
        ("add_evidence", "Capture Evidence or OffSec Flag", "e", "Evidence"),
        ("export", "Export Workspace (Notion / Markdown / Obsidian / JSON)", "x", "Export"),
        ("profile", "Select Methodology Profile (eJPTv2 / Network / Web)", "p", "Methodology"),
        ("theme", "Switch Color Palette / Theme", "T", "Appearance"),
        ("tab_workbench", "Switch to Tab 1: Workbench", "1", "Navigation"),
        ("tab_creds", "Switch to Tab 2: Credential Vault", "2", "Navigation"),
        ("tab_leads", "Switch to Tab 3: Leads Board", "3", "Navigation"),
        ("tab_evidence", "Switch to Tab 4: Evidence & Flags", "4", "Navigation"),
        ("tab_pivots", "Switch to Tab 5: Pivoting & Routes", "5", "Navigation"),
        ("help", "Show Keyboard Shortcut Help", "?", "Help"),
    ]

    def __init__(self, **kwargs):
        super().__init__(context="Type to filter actions across all categories...", **kwargs)
        self.filtered_actions = list(self.ACTIONS)

    def compose_body(self) -> ComposeResult:
        yield Input(placeholder="Search actions (e.g. cred, recon, export, tab)...", id="palette-input")
        yield OptionList(id="palette-list")

    def on_mount(self) -> None:
        self.query_one("#palette-input", Input).focus()
        self._populate_list()

    def _populate_list(self) -> None:
        opt_list = self.query_one("#palette-list", OptionList)
        opt_list.clear_options()
        for action_id, title, key, cat in self.filtered_actions:
            prompt = (
                f"[bold {TERRACOTTA}]{key:>3}[/] │ "
                f"[bold]{title}[/bold] "
                f"[dim]({cat})[/dim]"
            )
            opt_list.add_option(Option(prompt, id=action_id))
        if self.filtered_actions:
            opt_list.highlighted = 0

    def on_input_changed(self, event: Input.Changed) -> None:
        query = event.value.strip().lower()
        if not query:
            self.filtered_actions = list(self.ACTIONS)
        else:
            self.filtered_actions = [
                a for a in self.ACTIONS
                if query in a[0].lower() or query in a[1].lower() or query in a[2].lower() or query in a[3].lower()
            ]
        self._populate_list()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        opt_list = self.query_one("#palette-list", OptionList)
        if opt_list.highlighted is not None and opt_list.highlighted < len(self.filtered_actions):
            selected_action = self.filtered_actions[opt_list.highlighted][0]
            self.dismiss(selected_action)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_id:
            self.dismiss(str(event.option_id))

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Execute Action", "btn-select", "primary"),
            ModalButton("Cancel", "btn-cancel", "default"),
        ]

    def key_hints(self):
        return [("ENTER", "Execute"), ("ESC", "Cancel")]

    def on_modal_button(self, button_id: str) -> None:
        if button_id == "btn-select":
            opt_list = self.query_one("#palette-list", OptionList)
            if opt_list.highlighted is not None and opt_list.highlighted < len(self.filtered_actions):
                self.dismiss(self.filtered_actions[opt_list.highlighted][0])
