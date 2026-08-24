"""Target tree sidebar widget for Synapse TUI."""

from __future__ import annotations

from typing import List, Optional
from rich.markup import escape
from textual.widgets import Tree

from synapse.models import Target, TargetStatus


class TargetTreeWidget(Tree):
    """Sidebar Tree displaying targets and their listening services."""

    def __init__(self, **kwargs):
        super().__init__("Targets & Attack Surface", **kwargs)
        self.show_root = False

    def populate(self, targets: List[Target], selected_target_id: Optional[int] = None) -> None:
        self.clear()
        root = self.root

        for target in targets:
            # Status icon
            status_map = {
                TargetStatus.DISCOVERED: "[yellow]○[/yellow]",
                TargetStatus.SCANNING: "[cyan]◐[/cyan]",
                TargetStatus.ENUMERATED: "[blue]●[/blue]",
                TargetStatus.FOOTHOLD: "[magenta]★[/magenta]",
                TargetStatus.PWNED: "[bold green]✔ PWNED[/bold green]",
                TargetStatus.IGNORED: "[dim]✖[/dim]",
            }
            icon = status_map.get(target.status, "○")
            safe_ip = escape(target.ip)
            safe_host = f" ({escape(target.hostname)})" if target.hostname else ""
            label = f"{icon} [bold]{safe_ip}[/bold]{safe_host} [dim]({len(target.services)} ports)[/dim]"
            if not target.in_scope:
                # Out-of-scope hosts stay visible (context matters) but are dimmed and flagged.
                label = f"[dim strike]{label} ⃠ OUT-OF-SCOPE[/dim strike]"

            target_node = root.add(label, data={"type": "target", "id": target.id, "target": target})

            for svc in target.services:
                svc_icon = "[green]●[/green]" if svc.status.value == "enumerated" else "[white]○[/white]"
                if svc.status.value == "vulnerable":
                    svc_icon = "[bold red]⚡[/bold red]"
                elif svc.status.value == "dead_end":
                    svc_icon = "[dim]✖[/dim]"
                elif svc.status.value == "in_progress":
                    svc_icon = "[yellow]⟳[/yellow]"
                elif svc.status.value == "untested":
                    svc_icon = "[bold yellow]?[/bold yellow]"
                safe_name = escape(svc.name)
                svc_label = f"  {svc_icon} [cyan]{svc.port}/{svc.protocol}[/cyan] [bold]{safe_name}[/bold]"
                if svc.product:
                    safe_prod = escape(svc.product[:20])
                    svc_label += f" [dim]{safe_prod}[/dim]"
                if not target.in_scope:
                    svc_label = f"[dim strike]{svc_label}[/dim strike]"
                target_node.add_leaf(svc_label, data={"type": "service", "id": svc.id, "target_id": target.id, "service": svc})

            target_node.expand()
