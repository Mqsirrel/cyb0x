"""Interactive theme selector modal."""

from __future__ import annotations

from typing import List, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import Button, Label, OptionList
from textual.widgets.option_list import Option

from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import TERRACOTTA, MUTED


THEME_CATALOG = [
    ("claudish", "Claudish (Warm Obsidian & Terracotta)", "✦ Default offensive pentest palette"),
    ("tokyo-night", "Tokyo Night (Deep Indigo & Cyber Neon)", "Vibrant neon cyberpunk aesthetic"),
    ("nord", "Nord (Arctic Ice Blue & Slate)", "Clean cool minimalist frost tones"),
    ("gruvbox", "Gruvbox (Warm Retro Dark)", "High-contrast earthy retro palette"),
    ("catppuccin-mocha", "Catppuccin Mocha (Pastel Dark)", "Soft soothing pastel dark theme"),
    ("monokai", "Monokai (Pro High-Contrast)", "Classic developer high-contrast punch"),
    ("solarized-dark", "Solarized Dark (Cyan & Navy)", "Low-strain precision laboratory tones"),
    ("rose-pine", "Rosé Pine (All Natural Dark)", "Warm pine, rose, and gold tones"),
    ("atom-one-dark", "Atom One Dark (Clean Slate)", "Modern neutral software engineer look"),
]


class ThemeModal(SynapseModal[Optional[str]]):
    """Theme switcher modal to easily preview and select TUI color schemes."""

    GLYPH = "🎨"
    TITLE = "THEME SELECTOR"

    DEFAULT_CSS = """
    ThemeModal #dialog {
        width: 76;
        height: auto;
        max-height: 85%;
    }
    #theme-list {
        height: 14;
        margin-top: 1;
        border: round $panel;
        background: $surface;
    }
    #theme-hint {
        color: $text-muted;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("enter", "select_theme", "Apply Theme"),
    ]

    def __init__(self, current_theme: str = "claudish", **kwargs):
        super().__init__(
            context=f"Active theme: [bold {TERRACOTTA}]{current_theme}[/] · Select with [bold]↑/↓[/] and press [bold]Enter[/]",
            **kwargs,
        )
        self.current_theme = current_theme

    def compose_body(self) -> ComposeResult:
        options = []
        initial_index = 0
        for idx, (t_id, t_title, t_desc) in enumerate(THEME_CATALOG):
            active_marker = " [bold green]✔ ACTIVE[/]" if t_id == self.current_theme else ""
            txt = Text.from_markup(f"[bold]{t_title}[/]{active_marker}\n  [dim]{t_desc}[/]")
            options.append(Option(txt, id=t_id))
            if t_id == self.current_theme:
                initial_index = idx

        yield Label("Select Color Scheme / Theme:", classes="field-label")
        opt_list = OptionList(*options, id="theme-list")
        opt_list.highlighted = initial_index
        yield opt_list
        yield Label("Tip: You can also search themes anytime with Ctrl+P -> type 'theme'", id="theme-hint")

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Cancel", "btn-cancel", "default"),
            ModalButton("Apply Theme", "btn-apply", "primary"),
        ]

    def key_hints(self) -> list[tuple[str, str]]:
        return [("ESC", "Cancel"), ("ENTER", "Apply Theme"), ("↑/↓", "Navigate")]

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        if event.option_id:
            self.dismiss(str(event.option_id))

    def action_select_theme(self) -> None:
        opt_list = self.query_one("#theme-list", OptionList)
        if opt_list.highlighted is not None:
            opt = opt_list.get_option_at_index(opt_list.highlighted)
            if opt and opt.id:
                self.dismiss(str(opt.id))
                return
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "btn-cancel":
            self.dismiss(None)
        elif event.button.id == "btn-apply":
            self.action_select_theme()
