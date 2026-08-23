"""Modal to preview, edit, execute a command recipe, and capture output."""

from __future__ import annotations

import asyncio
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, LoadingIndicator, Static, TextArea

from synapse.runner.executor import CommandExecutor


class RunnerModal(ModalScreen[dict]):
    """Dialog for confirming, running, and capturing a command."""

    DEFAULT_CSS = """
    RunnerModal {
        align: center middle;
    }
    #dialog {
        padding: 1 2;
        width: 85;
        height: auto;
        border: thick $primary;
        background: $surface;
    }
    .field-label {
        margin-top: 1;
        font-weight: bold;
    }
    #buttons {
        margin-top: 1;
        align: right middle;
    }
    Button {
        margin-left: 2;
    }
    TextArea {
        height: 8;
    }
    #status-msg {
        margin-top: 1;
    }
    """

    def __init__(self, command: str, title: str = "Execute Command Recipe", **kwargs):
        super().__init__(**kwargs)
        self.initial_command = command
        self.recipe_title = title

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(f"[bold cyan]{self.recipe_title}[/bold cyan]")
            yield Label("Command to execute (editable):", classes="field-label")
            yield Input(value=self.initial_command, id="cmd-input")

            yield Label("Command Output & Flag Extraction:", classes="field-label")
            yield TextArea(id="cmd-output", read_only=False)

            yield Static("", id="status-msg")

            with Horizontal(id="buttons"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Run Command", variant="warning", id="btn-run")
                yield Button("Save to Evidence", variant="success", id="btn-save")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
            return

        cmd = self.query_one("#cmd-input", Input).value.strip()
        status_lbl = self.query_one("#status-msg", Static)
        output_area = self.query_one("#cmd-output", TextArea)

        if event.button.id == "btn-run":
            if not cmd:
                return

            status_lbl.update("[yellow]Executing command asynchronously...[/yellow]")
            res = await CommandExecutor.run_command_async(cmd, timeout=30.0)

            full_out = res.stdout
            if res.stderr:
                full_out += f"\n[STDERR]\n{res.stderr}"

            output_area.text = full_out

            flags_info = f" | [bold green]Flags found: {', '.join(res.extracted_flags)}[/bold green]" if res.extracted_flags else ""
            status_lbl.update(f"[green]Finished in {res.duration_seconds:.2f}s (Exit code: {res.return_code}){flags_info}[/green]")

        elif event.button.id == "btn-save":
            self.dismiss({
                "command": cmd,
                "output": output_area.text.strip(),
                "action": "save_evidence",
            })
