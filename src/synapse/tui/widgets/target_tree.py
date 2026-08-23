"""Target tree sidebar widget for Synapse TUI."""

from __future__ import annotations

from typing import List, Optional
from textual.widgets import Tree
from textual.widgets.tree import TreeNode

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
            hostname_str = f" ({target.hostname})" if target.hostname else ""
            label = f"{icon} [bold]{target.ip}[/bold]{hostname_str} [dim]({len(target.services)} ports)[/dim]"

            target_node = root.add(label, data={"type": "target", "id": target.id, "target": target})

            for svc in target.services:
                svc_icon = "[green]●[/green]" if svc.status.value == "enumerated" else "[white]○[/white]"
                if svc.status.value == "vulnerable":
                    svc_icon = "[bold red]⚡[/bold red]"
                svc_label = f"  {svc_icon} [cyan]{svc.port}/{svc.protocol}[/cyan] [bold]{svc.name}[/bold]"
                if svc.product:
                    svc_label += f" [dim]{svc.product[:15]}[/dim]"
                target_node.add_leaf(svc_label, data={"type": "service", "id": svc.id, "target_id": target.id, "service": svc})

            target_node.expand()
