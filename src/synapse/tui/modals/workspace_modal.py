"""Workspace Manager and Lab Switcher modal (Ctrl+L).

Enables switching between active lab workspaces, creating new workspaces,
and cloning workspaces for repeat lab attempts without leaving the TUI.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from synapse.db.repository import DatabaseRepository
from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import BACKGROUND, ERROR_RED, KRAFT, MUTED, SAGE, TERRACOTTA


class WorkspaceModal(SynapseModal[dict]):
    """Modal to switch, create, or clone lab workspaces."""

    GLYPH = "◫"
    TITLE = "WORKSPACE / LAB MANAGER"

    DEFAULT_CSS = """
    WorkspaceModal #dialog {
        width: 88%;
        max-width: 96;
        height: auto;
        max-height: 85%;
    }
    WorkspaceModal #modal-body {
        height: 1fr;
    }
    #workspace-list {
        height: 5;
        min-height: 4;
        border: round $panel;
        margin-bottom: 1;
    }
    #workspace-info {
        height: 4;
        min-height: 3;
        border: round $panel;
        padding: 0 1;
        background: $surface;
        margin-bottom: 1;
    }
    #ws-name-input {
        margin-top: 1;
    }
    #action-buttons Button {
        min-width: 11;
        margin-left: 1;
    }
    """

    def __init__(self, current_workspace: str = "default", **kwargs):
        super().__init__(context=f"Active Workspace: [bold {TERRACOTTA}]{current_workspace}[/]", **kwargs)
        self.current_workspace = current_workspace
        self.workspaces: List[Dict[str, str]] = []
        self._load_workspaces()

    def _load_workspaces(self) -> None:
        base = Path.home() / ".synapse" / "workspaces"
        base.mkdir(parents=True, exist_ok=True)
        self.workspaces = []
        for db_file in sorted(base.glob("*.db")):
            name = db_file.stem
            size_kb = db_file.stat().st_size / 1024
            mtime = datetime.fromtimestamp(db_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            self.workspaces.append({
                "name": name,
                "path": str(db_file),
                "size": f"{size_kb:.1f} KB",
                "mtime": mtime,
            })

    def compose_body(self) -> ComposeResult:
        options = []
        for w in self.workspaces:
            is_active = w["name"] == self.current_workspace
            prefix = f"[{TERRACOTTA}]▶[/] " if is_active else "  "
            tag = f" [bold {SAGE}](Active)[/]" if is_active else ""
            options.append(Option(f"{prefix}[bold]{w['name']}[/bold]{tag} [dim]({w['size']})[/dim]", id=w["name"]))

        yield Label("Available Workspaces / Labs:", classes="field-label")
        yield OptionList(*options, id="workspace-list")
        yield Static("", id="workspace-info")

        yield Label("Or Create / Clone New Workspace:", classes="field-label")
        yield Input(placeholder="New workspace name (e.g. ejpt-lab08)...", id="ws-name-input")

    def on_mount(self) -> None:
        self.query_one("#workspace-list", OptionList).focus()
        self._update_info(self.current_workspace)
        opt_list = self.query_one("#workspace-list", OptionList)
        for i, w in enumerate(self.workspaces):
            if w["name"] == self.current_workspace:
                opt_list.highlighted = i
                break

    def _update_info(self, ws_name: str) -> None:
        info = self.query_one("#workspace-info", Static)
        ws = next((w for w in self.workspaces if w["name"] == ws_name), None)
        if not ws:
            info.update(f"[dim]No details for {ws_name}[/dim]")
            return

        try:
            r = DatabaseRepository(ws["path"])
            stats = r.get_stats()
            r.close()
            info.update(
                f"[bold {TERRACOTTA}]{ws['name']}[/] · Last modified: [dim]{ws['mtime']}[/dim]\n"
                f"• Targets: [bold]{stats['total_targets']}[/bold] (Pwned: [{SAGE}]{stats['pwned_targets']}[/{SAGE}], Footholds: [{KRAFT}]{stats['foothold_targets']}[/{KRAFT}])\n"
                f"• Findings: [bold {ERROR_RED}]{stats['total_findings']}[/] · Flags: [bold {TERRACOTTA}]⚑ {stats['captured_flags']}[/]\n"
                f"• Services: {stats['total_services']} · Checks: {stats['completed_checks']}/{stats['total_checks']}"
            )
        except Exception as e:
            info.update(f"[bold]{ws['name']}[/] (Size: {ws['size']})\n[dim]Could not read stats: {e}[/dim]")

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_id:
            self._update_info(str(event.option_id))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_id:
            self.dismiss({
                "action": "switch",
                "workspace": str(event.option_id),
                "db_path": str(Path.home() / ".synapse" / "workspaces" / f"{event.option_id}.db"),
            })

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Switch Lab", "btn-switch", "primary"),
            ModalButton("Create New", "btn-create", "success"),
            ModalButton("Clone for Attempt 2", "btn-clone", "default"),
            ModalButton("Cancel", "btn-cancel", "default"),
        ]

    def key_hints(self):
        return [("ENTER", "Switch"), ("ESC", "Cancel")]

    def on_modal_button(self, button_id: str) -> None:
        name_input = self.query_one("#ws-name-input", Input).value.strip()
        opt_list = self.query_one("#workspace-list", OptionList)
        selected_opt = opt_list.options[opt_list.highlighted] if opt_list.highlighted is not None else None
        selected_name = str(selected_opt.id) if selected_opt and hasattr(selected_opt, "id") and selected_opt.id else self.current_workspace

        if button_id == "btn-switch":
            self.dismiss({
                "action": "switch",
                "workspace": selected_name,
                "db_path": str(Path.home() / ".synapse" / "workspaces" / f"{selected_name}.db"),
            })
        elif button_id == "btn-create":
            if not name_input:
                self.notify("Please enter a name for the new workspace.", severity="warning")
                return
            clean_name = name_input.replace(" ", "_").lower()
            self.dismiss({
                "action": "create",
                "workspace": clean_name,
                "db_path": str(Path.home() / ".synapse" / "workspaces" / f"{clean_name}.db"),
            })
        elif button_id == "btn-clone":
            clone_name = name_input or f"{selected_name}_attempt2"
            clean_name = clone_name.replace(" ", "_").lower()
            self.dismiss({
                "action": "clone",
                "source_workspace": selected_name,
                "target_workspace": clean_name,
                "db_path": str(Path.home() / ".synapse" / "workspaces" / f"{clean_name}.db"),
            })
