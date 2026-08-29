"""Fuzzy Jump-To-Anything modal (Ctrl+P).

Allows rapid fuzzy navigation across targets, services, credentials, leads,
and findings in the current workspace.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from textual.app import ComposeResult
from textual.widgets import Input, OptionList
from textual.widgets.option_list import Option

from synapse.db.repository import DatabaseRepository
from synapse.tui.modals.base import ModalButton, SynapseModal
from synapse.tui.theme import ERROR_RED, KRAFT, MUTED, SAGE, TERRACOTTA


class JumpModal(SynapseModal[dict]):
    """Fuzzy entity search across the active engagement workspace."""

    GLYPH = "🔍"
    TITLE = "JUMP TO ANYTHING"

    DEFAULT_CSS = """
    JumpModal #dialog {
        width: 88%;
        max-width: 96;
        height: auto;
        max-height: 85%;
    }
    JumpModal #modal-body {
        height: 1fr;
    }
    #jump-input {
        margin-bottom: 1;
    }
    #jump-list {
        height: 1fr;
        min-height: 6;
        max-height: 12;
        border: round $panel;
    }
    """

    def __init__(self, repo: DatabaseRepository, **kwargs):
        super().__init__(context="Search across targets, services, credentials, leads, and findings...", **kwargs)
        self.repo = repo
        self.items: List[Dict[str, Any]] = []
        self.filtered_items: List[Dict[str, Any]] = []
        self._load_entities()

    def _load_entities(self) -> None:
        self.items = []
        targets = self.repo.list_targets()
        credentials = self.repo.list_credentials()
        leads = self.repo.list_leads()
        evidence = self.repo.list_evidence()

        for t in targets:
            self.items.append({
                "type": "target",
                "id": t.id,
                "ip": t.ip,
                "label": f"[{TERRACOTTA}]TARGET[/]  [bold]{t.ip}[/bold]" + (f" ({t.hostname})" if t.hostname else "") + f" [dim]— {t.os} [{t.status.value.upper()}][/dim]",
                "search": f"target {t.ip} {t.hostname} {t.os} {t.status.value}".lower(),
                "payload": {"type": "target", "target": t},
            })
            for s in t.services:
                self.items.append({
                    "type": "service",
                    "id": s.id,
                    "target_id": t.id,
                    "label": f"[{SAGE}]SERVICE[/] [bold]{t.ip}:{s.port}/{s.protocol}[/bold] [dim]({s.name} {s.product} {s.version})[/dim]",
                    "search": f"service port {s.port} {s.name} {s.product} {s.version} {t.ip}".lower(),
                    "payload": {"type": "service", "target": t, "service": s},
                })
                for c in s.checklists:
                    if c.status.value in ("finding", "checked"):
                        tag_color = ERROR_RED if c.status.value == "finding" else SAGE
                        self.items.append({
                            "type": "checklist",
                            "id": c.id,
                            "label": f"[{tag_color}]CHECK[/]   [bold]{c.title}[/bold] [dim]on {t.ip}:{s.port} ({c.status.value.upper()})[/dim]",
                            "search": f"check {c.title} {c.category} {t.ip} {s.port} {c.status.value}".lower(),
                            "payload": {"type": "service", "target": t, "service": s},
                        })

        for cred in credentials:
            self.items.append({
                "type": "credential",
                "id": cred.id,
                "label": f"[{KRAFT}]CRED[/]    [bold]{cred.username}[/bold] [dim]({cred.cred_type.value}) {cred.domain}[/dim]",
                "search": f"cred credential {cred.username} {cred.domain} {cred.cred_type.value}".lower(),
                "payload": {"type": "tab", "tab_id": "tab-creds"},
            })

        for lead in leads:
            self.items.append({
                "type": "lead",
                "id": lead.id,
                "label": f"[{TERRACOTTA}]LEAD[/]    [bold]{lead.title}[/bold] [dim]({lead.priority.value.upper()})[/dim]",
                "search": f"lead {lead.title} {lead.priority.value} {lead.status.value}".lower(),
                "payload": {"type": "tab", "tab_id": "tab-leads"},
            })

        self.filtered_items = list(self.items)

    def compose_body(self) -> ComposeResult:
        yield Input(placeholder="Search by IP, port, service name, username, finding...", id="jump-input")
        yield OptionList(id="jump-list")

    def on_mount(self) -> None:
        self.query_one("#jump-input", Input).focus()
        self._populate_list()

    def _populate_list(self) -> None:
        opt_list = self.query_one("#jump-list", OptionList)
        opt_list.clear_options()
        for idx, item in enumerate(self.filtered_items[:100]):
            opt_list.add_option(Option(item["label"], id=str(idx)))
        if self.filtered_items:
            opt_list.highlighted = 0

    def on_input_changed(self, event: Input.Changed) -> None:
        query = event.value.strip().lower()
        if not query:
            self.filtered_items = list(self.items)
        else:
            tokens = query.split()
            self.filtered_items = [
                item for item in self.items
                if all(t in item["search"] for t in tokens)
            ]
        self._populate_list()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        opt_list = self.query_one("#jump-list", OptionList)
        if opt_list.highlighted is not None and opt_list.highlighted < len(self.filtered_items):
            self.dismiss(self.filtered_items[opt_list.highlighted]["payload"])

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_id is not None:
            idx = int(str(event.option_id))
            if idx < len(self.filtered_items):
                self.dismiss(self.filtered_items[idx]["payload"])

    def modal_buttons(self) -> List[ModalButton]:
        return [
            ModalButton("Jump to Entity", "btn-jump", "primary"),
            ModalButton("Cancel", "btn-cancel", "default"),
        ]

    def key_hints(self):
        return [("ENTER", "Jump"), ("ESC", "Cancel")]

    def on_modal_button(self, button_id: str) -> None:
        if button_id == "btn-jump":
            opt_list = self.query_one("#jump-list", OptionList)
            if opt_list.highlighted is not None and opt_list.highlighted < len(self.filtered_items):
                self.dismiss(self.filtered_items[opt_list.highlighted]["payload"])
