"""Modal to quickly add a target and optional ports."""

from __future__ import annotations

from typing import List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import Input, Label, Select

from synapse.tui.modals.base import ModalButton, SynapseModal


class AddTargetModal(SynapseModal[dict]):
    """Dialog for creating a new target host."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    GLYPH = "▸"
    TITLE = "TARGETS — Add Target Host"

    DEFAULT_CSS = """
    AddTargetModal #dialog {
        width: 62;
        height: auto;
    }
    """

    def compose_body(self) -> ComposeResult:
        yield Label("IP Address / Subnet:", classes="field-label")
        yield Input(placeholder="e.g. 10.10.11.10", id="target-ip")

        yield Label("Hostname (optional):", classes="field-label")
        yield Input(placeholder="e.g. dc01.corp.local", id="target-host")

        yield Label("Operating System:", classes="field-label")
        yield Select(
            [("Linux", "Linux"), ("Windows", "Windows"), ("FreeBSD", "FreeBSD"), ("Unknown", "Unknown")],
            value="Linux",
            id="target-os",
        )

        yield Label("Initial Ports (comma-separated, e.g. 22,80,445):", classes="field-label")
        yield Input(placeholder="e.g. 22, 80, 445", id="target-ports")

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Cancel", "btn-cancel", "default"),
            ModalButton("Add Target", "btn-save", "success"),
        ]

    def key_hints(self):
        return [("ESC", "Cancel")]

    def on_modal_button(self, button_id: str) -> None:
        if button_id != "btn-save":
            return
        ip_val = self.query_one("#target-ip", Input).value.strip()
        if not ip_val:
            return
        host_val = self.query_one("#target-host", Input).value.strip()
        os_val = self.query_one("#target-os", Select).value
        ports_raw = self.query_one("#target-ports", Input).value.strip()

        ports = []
        if ports_raw:
            for p in ports_raw.split(","):
                p = p.strip()
                if p.isdigit():
                    port_num = int(p)
                    if 1 <= port_num <= 65535:
                        ports.append(port_num)

        self.dismiss({
            "ip": ip_val,
            "hostname": host_val,
            "os": os_val,
            "ports": ports,
        })
