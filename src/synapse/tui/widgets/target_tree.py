"""Target tree sidebar widget for Synapse TUI."""

from __future__ import annotations

from typing import List, Optional
from rich.markup import escape
from textual.widgets import Tree

from synapse.models import Target, TargetStatus
from synapse.tui.theme import (
    MUTED,
    TERRACOTTA,
    service_status_glyph,
    target_status_glyph,
)


class TargetTreeWidget(Tree):
    """Sidebar Tree displaying targets and their listening services."""

    def __init__(self, **kwargs):
        super().__init__("Targets & Attack Surface", **kwargs)
        self.show_root = False

    def populate(self, targets: List[Target], selected_target_id: Optional[int] = None) -> None:
        self.clear()
        root = self.root

        for target in targets:
            icon = target_status_glyph(target.status)
            safe_ip = escape(target.ip)
            safe_host = f" ({escape(target.hostname)})" if target.hostname else ""
            label = f"{icon} [bold]{safe_ip}[/bold]{safe_host} [{MUTED}]({len(target.services)} ports)[/]"
            if not target.in_scope:
                label = f"[dim strike]{label} ⃠ OUT-OF-SCOPE[/dim strike]"

            target_node = root.add(label, data={"type": "target", "id": target.id, "target": target})

            for svc in target.services:
                svc_icon = service_status_glyph(svc.status.value)
                safe_name = escape(svc.name)
                svc_label = f"  {svc_icon} [{TERRACOTTA}]{svc.port}/{svc.protocol}[/] [bold]{safe_name}[/bold]"
                if svc.product:
                    safe_prod = escape(svc.product[:20])
                    svc_label += f" [{MUTED}]{safe_prod}[/]"
                if not target.in_scope:
                    svc_label = f"[dim strike]{svc_label}[/dim strike]"
                target_node.add_leaf(svc_label, data={"type": "service", "id": svc.id, "target_id": target.id, "service": svc})

            target_node.expand()
