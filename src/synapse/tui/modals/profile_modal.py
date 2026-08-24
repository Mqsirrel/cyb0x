"""Profile selection modal."""

from __future__ import annotations

from typing import List, Optional
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option
from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import TERRACOTTA, MUTED

PROFILES = [
    {
        "id": "ejptv2",
        "name": "eJPTv2",
        "description": "Black-box network penetration testing methodology.",
        "phases": "Host Discovery, Enumeration, Vuln Assessment, Exploitation, Post-Exploitation",
    },
    {
        "id": "network",
        "name": "Network Pentest",
        "description": "Standard internal/external infrastructure pentest.",
        "phases": "Recon, Enum, Vuln Assessment, Exploit, PrivEsc, Pivoting",
    },
    {
        "id": "web",
        "name": "Web Pentest",
        "description": "OWASP Top 10 web application testing.",
        "phases": "Recon, Mapping, Discovery, Exploitation",
    },
    {
        "id": "htb",
        "name": "HTB/Lab",
        "description": "Capture The Flag methodology (Boot2Root).",
        "phases": "Recon, Enum, Foothold, PrivEsc, Post-Exploitation",
    },
    {
        "id": "custom",
        "name": "Custom",
        "description": "User-defined custom methodology.",
        "phases": "Custom Phases",
    },
]


class ProfileModal(SynapseModal[str]):
    """Modal to switch methodology profiles."""

    TITLE = "METHODOLOGY PROFILE SELECTION"

    DEFAULT_CSS = """
    ProfileModal #dialog {
        width: 70;
        height: auto;
    }
    #profile-list {
        height: 8;
        border: solid $panel;
        margin-bottom: 1;
    }
    #profile-info {
        height: 5;
        border: solid $panel;
        padding: 0 1;
        background: #2a2520;
    }
    """

    def __init__(self, active_profile: str = "network"):
        super().__init__()
        self.active_profile = active_profile

    def compose_body(self) -> ComposeResult:
        options = []
        for p in PROFILES:
            prompt = f"[{TERRACOTTA}]▶[/{TERRACOTTA}] {p['name']} (Active)" if p["id"] == self.active_profile else f"  {p['name']}"
            options.append(Option(prompt, id=p["id"]))

        yield OptionList(*options, id="profile-list")
        yield Static("", id="profile-info")

    def on_mount(self) -> None:
        self.query_one("#profile-list", OptionList).focus()
        self._update_info(self.active_profile)
        # Select active
        opt_list = self.query_one("#profile-list", OptionList)
        for i, p in enumerate(PROFILES):
            if p["id"] == self.active_profile:
                opt_list.highlighted = i
                break

    def _update_info(self, profile_id: str) -> None:
        info = self.query_one("#profile-info", Static)
        profile = next((p for p in PROFILES if p["id"] == profile_id), None)
        if profile:
            info.update(f"[bold]{profile['name']}[/bold]\n[{MUTED}]{profile['description']}[/{MUTED}]\n\n[bold]Phases:[/] {profile['phases']}")

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_id:
            self._update_info(event.option_id)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_id:
            self.dismiss(event.option_id)

    def action_btn_select(self) -> None:
        opt_list = self.query_one("#profile-list", OptionList)
        opt = opt_list.options[opt_list.highlighted] if opt_list.highlighted is not None else None
        if hasattr(opt, "id") and opt.id: # type: ignore
            self.dismiss(opt.id) # type: ignore

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Select Profile", "btn_select", "primary"),
            ModalButton("Cancel", "btn_cancel", "default"),
        ]

    def key_hints(self):
        return [("ENTER", "Select"), ("ESC", "Cancel")]
