"""Modal to preview, edit, execute a command recipe, and capture output.

Centerpiece dialog of the TUI: header breadcrumb + target context, an
output area that expands to fill the dialog, live syntax-colored tool
output (ANSI passthrough or synapse-palette grammar highlighting), run
feedback chips, a flag-hit strip, and a fully keyboard-driven flow
(^R run / ^S save / ESC cancel).
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from rich.markup import escape
from rich.style import Style
from textual._text_area_theme import TextAreaTheme
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widgets import Button, Input, Label, LoadingIndicator, Static, TextArea

from synapse.runner.executor import CommandExecutor
from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.output_syntax import (
    SYNTAX_STYLES,
    HighlightResult,
    compute_output_highlight,
)
from synapse.tui.theme import BACKGROUND, CREAM, MUTED, SAGE, result_chips


class OutputArea(TextArea):
    """A TextArea that syntax-highlights command output.

    Textual 8.x styles TextArea content exclusively through tree-sitter
    highlight maps, so this subclass overrides ``_build_highlight_map`` to
    inject spans produced by ``compute_output_highlight`` instead. Span
    offsets are converted to UTF-8 byte offsets because that is what the
    render pipeline expects.
    """

    def __init__(self, **kwargs):
        self._synthetic: HighlightResult = HighlightResult(text="")
        super().__init__(**kwargs)
        self.register_theme(
            TextAreaTheme(
                name="synapse-output",
                base_style=Style(color="#EDE6DA", bgcolor="#26221E"),
                gutter_style=Style(color="#6B6259"),
                cursor_style=Style(color="#211E1B", bgcolor="#D97757"),
                cursor_line_style=Style(bgcolor="#2F2A25"),
                selection_style=Style(bgcolor="#7A4A38"),
                bracket_matching_style=Style(color="#D97757", bold=True),
                syntax_styles=dict(SYNTAX_STYLES),
            )
        )
        self.theme = "synapse-output"

    def set_output(self, raw_text: str) -> None:
        self._synthetic = compute_output_highlight(raw_text)
        for name, style in self._synthetic.style_map.items():
            self._theme.syntax_styles[name] = style
        self.load_text(self._synthetic.text)

    def _build_highlight_map(self) -> None:
        self._line_cache.clear()
        highlights = self._highlights
        highlights.clear()
        lines = self.text.splitlines()
        span_rows = len(self._synthetic.line_spans)
        if not span_rows:
            return
        for row, line in enumerate(lines[:span_rows]):
            byte_prefixes = [0]
            total = 0
            for ch in line:
                total += len(ch.encode("utf-8"))
                byte_prefixes.append(total)
            for start_cp, end_cp, name in self._synthetic.line_spans[row]:
                start_byte = byte_prefixes[min(start_cp, len(line))]
                end_byte = (
                    byte_prefixes[min(end_cp, len(line))] if end_cp is not None else None
                )
                highlights[row].append((start_byte, end_byte, name))


class RunnerModal(SynapseModal[dict]):
    """Dialog for confirming, running, and capturing a command."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+r", "run", "Run", priority=True),
        Binding("ctrl+s", "save", "Save Evidence", priority=True),
    ]

    GLYPH = "▸"
    TITLE = "EXECUTE"

    DEFAULT_CSS = """
    RunnerModal #dialog {
        width: 85%;
        height: 80%;
    }
    RunnerModal #modal-body {
        height: 1fr;
    }
    OutputArea {
        height: 1fr;
        min-height: 8;
        border: round $surface-raised;
    }
    #cmd-input {
        margin-top: 1;
    }
    #result-chips {
        height: auto;
    }
    #flag-strip {
        height: auto;
        max-height: 4;
    }
    #run-spinner {
        height: 1;
    }
    """

    def __init__(
        self,
        command: str,
        title: str = "Execute Command Recipe",
        context: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(title=f"EXECUTE — {title}", context=context, **kwargs)
        self.initial_command = command
        self.recipe_title = title
        self._run_in_flight = False

    def compose_body(self) -> ComposeResult:
        yield Label("Command to execute (editable):", classes="field-label")
        yield Input(value=self.initial_command, id="cmd-input")
        yield Label("Command Output & Flag Extraction:", classes="field-label")
        yield OutputArea(id="cmd-output", read_only=False)
        yield LoadingIndicator(id="run-spinner", classes="hidden")
        with VerticalScroll(id="flag-strip", classes="hidden"):
            yield Static("", id="flag-strip-text")
        yield Static("", id="result-chips")

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Cancel", "btn-cancel", "default"),
            ModalButton("Run Command", "btn-run", "primary"),
            ModalButton("Save to Evidence", "btn-save", "success"),
        ]

    def key_hints(self) -> List[Tuple[str, str]]:
        return [("ESC", "Cancel"), ("^R", "Run"), ("^S", "Save")]

    def on_mount(self) -> None:
        self.query_one("#btn-save", Button).disabled = True

    def action_cancel(self) -> None:
        self.dismiss(None)

    async def _do_run(self) -> None:
        cmd = self.query_one("#cmd-input", Input).value.strip()
        if not cmd or self._run_in_flight:
            return

        self._run_in_flight = True
        chips = self.query_one("#result-chips", Static)
        spinner = self.query_one("#run-spinner", LoadingIndicator)

        self.query_one("#btn-run", Button).disabled = True
        self.query_one("#btn-save", Button).disabled = True
        spinner.remove_class("hidden")
        chips.update(f"[italic {MUTED}]Executing command asynchronously…[/]")

        try:
            res = await CommandExecutor.run_command_async(cmd, timeout=45.0)

            full_out = res.stdout
            if res.stderr:
                full_out += f"\n[STDERR]\n{res.stderr}"

            output_area = self.query_one("#cmd-output", OutputArea)
            output_area.set_output(full_out)

            flag_strip = self.query_one("#flag-strip", VerticalScroll)
            strip_text = self.query_one("#flag-strip-text", Static)
            if res.extracted_flags:
                shown = ", ".join(escape(flag) for flag in res.extracted_flags[:8])
                more = (
                    ""
                    if len(res.extracted_flags) <= 8
                    else f" (+{len(res.extracted_flags) - 8} more)"
                )
                strip_text.update(
                    f"[bold {BACKGROUND} on {SAGE}] ⚑ FLAG HIT [/] "
                    f"[bold {CREAM}]{shown}[/][dim]{more}[/]"
                )
                flag_strip.remove_class("hidden")
            else:
                flag_strip.add_class("hidden")

            chips.update(
                result_chips(res.return_code, res.duration_seconds, len(res.extracted_flags))
            )
            self.query_one("#btn-save", Button).disabled = False
        finally:
            spinner.add_class("hidden")
            self.query_one("#btn-run", Button).disabled = False
            self._run_in_flight = False

    def action_run(self) -> None:
        self.run_worker(self._do_run(), exclusive=True, group="runner", exit_on_error=False)

    async def action_save(self) -> None:
        cmd = self.query_one("#cmd-input", Input).value.strip()
        output_area = self.query_one("#cmd-output", OutputArea)
        if not output_area.text.strip():
            return
        self.dismiss({
            "command": cmd,
            "output": output_area.text.strip(),
            "action": "save_evidence",
        })

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "btn-cancel":
            self.action_cancel()
        elif event.button.id == "btn-run":
            self.action_run()
        elif event.button.id == "btn-save":
            self.run_worker(self.action_save(), exclusive=True, group="runner")
