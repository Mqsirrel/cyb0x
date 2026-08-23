"""Modal to quickly add a target and optional ports."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select


class AddTargetModal(ModalScreen[dict]):
    """Dialog for creating a new target host."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    DEFAULT_CSS = """
    AddTargetModal {
        align: center middle;
    }
    #dialog {
        padding: 1 2;
        width: 60;
        height: auto;
        border: thick $primary;
        background: $surface;
    }
    .field-label {
        margin-top: 1;
        text-style: bold;
    }
    #buttons {
        margin-top: 2;
        align: right middle;
    }
    Button {
        margin-left: 2;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[bold cyan]Add Target Host[/bold cyan]")
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

            with Horizontal(id="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Add Target", variant="primary", id="btn-save")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
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
        else:
            self.dismiss(None)
