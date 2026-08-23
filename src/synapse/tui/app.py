"""Main Textual application for Synapse."""

from __future__ import annotations

from pathlib import Path
from typing import Optional
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)

from synapse.db.repository import DatabaseRepository
from synapse.export.json_exporter import export_workspace_json
from synapse.export.markdown_exporter import export_markdown_report, export_obsidian_vault
from synapse.methodology.engine import MethodologyEngine
from synapse.models import (
    ChecklistItem,
    ChecklistStatus,
    Credential,
    CredentialType,
    Evidence,
    Lead,
    LeadPriority,
    LeadStatus,
    ProofType,
    Service,
    ServiceStatus,
    Target,
    TargetStatus,
)
from synapse.tui.modals.add_cred_modal import AddCredModal
from synapse.tui.modals.add_evidence_modal import AddEvidenceModal
from synapse.tui.modals.add_lead_modal import AddLeadModal
from synapse.tui.modals.add_target_modal import AddTargetModal
from synapse.tui.modals.export_modal import ExportModal
from synapse.tui.modals.runner_modal import RunnerModal
from synapse.tui.widgets.cred_matrix import CredentialMatrixWidget
from synapse.tui.widgets.evidence_view import EvidenceViewWidget
from synapse.tui.widgets.lead_board import LeadBoardWidget
from synapse.tui.widgets.pivot_view import PivotViewWidget
from synapse.tui.widgets.service_detail import ServiceDetailWidget
from synapse.tui.widgets.target_tree import TargetTreeWidget


class SynapseTUI(App):
    """The terminal penetration testing assessment state machine and methodology copilot."""

    TITLE = "SYNAPSE // Offensive Assessment State Machine & Methodology Copilot"
    SUB_TITLE = "eJPTv2 • OSCP • CTFs • Authorized Labs"
    CSS = """
    Screen {
        background: $surface;
    }
    #main-container {
        height: 1fr;
    }
    #sidebar-pane {
        width: 32%;
        border-right: heavy $primary;
        height: 100%;
    }
    #content-pane {
        width: 68%;
        height: 100%;
        padding: 0 1;
    }
    #stats-banner {
        dock: top;
        height: 1;
        background: $primary-darken-3;
        color: $text;
        padding: 0 1;
        text-style: bold;
    }
    TargetTreeWidget {
        background: transparent;
    }
    DataTable {
        height: 1fr;
        border: round $primary;
    }
    #service-info {
        height: auto;
        padding: 1;
        background: $panel;
        margin-bottom: 1;
        border: solid $secondary;
    }
    #checklist-title {
        margin-top: 1;
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        Binding("a", "add_target", "Add Target", priority=False),
        Binding("c", "add_cred", "Add Cred", priority=False),
        Binding("l", "add_lead", "Add Lead", priority=False),
        Binding("e", "add_evidence", "Add Flag/Evidence", priority=False),
        Binding("r", "run_recipe", "Run Recipe", priority=False),
        Binding("space", "toggle_status", "Toggle Status", priority=False),
        Binding("x", "export_report", "Export Report", priority=False),
        Binding("1", "switch_tab('tab-workbench')", "Workbench", show=False),
        Binding("2", "switch_tab('tab-creds')", "Creds", show=False),
        Binding("3", "switch_tab('tab-leads')", "Leads", show=False),
        Binding("4", "switch_tab('tab-evidence')", "Evidence", show=False),
        Binding("5", "switch_tab('tab-pivots')", "Pivots", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, db_path: str | Path = ":memory:", **kwargs):
        super().__init__(**kwargs)
        self.repo = DatabaseRepository(db_path)
        self.methodology = MethodologyEngine()
        self.selected_target: Optional[Target] = None
        self.selected_service: Optional[Service] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="stats-banner")
        with TabbedContent(initial="tab-workbench", id="tabs"):
            with TabPane("1. Target & Methodology Workbench", id="tab-workbench"):
                with Horizontal(id="main-container"):
                    with Vertical(id="sidebar-pane"):
                        yield TargetTreeWidget(id="target-tree")
                    with Vertical(id="content-pane"):
                        yield ServiceDetailWidget(id="service-detail")

            with TabPane("2. Credential Vault Matrix", id="tab-creds"):
                yield CredentialMatrixWidget(id="cred-matrix")

            with TabPane("3. Hypotheses & Leads Board", id="tab-leads"):
                yield LeadBoardWidget(id="lead-board")

            with TabPane("4. Evidence & Proof Ledger", id="tab-evidence"):
                yield EvidenceViewWidget(id="evidence-view")

            with TabPane("5. Pivoting & Route Sentinel", id="tab-pivots"):
                yield PivotViewWidget(id="pivot-view")

        yield Footer()

    def on_mount(self) -> None:
        self.refresh_all_views()

    def update_stats_banner(self) -> None:
        stats = self.repo.get_stats()
        banner = self.query_one("#stats-banner", Static)
        pwn_str = f"[bold green]{stats['pwned_targets']}[/bold green]" if stats["pwned_targets"] > 0 else "0"
        flag_str = f"[bold yellow]{stats['captured_flags']}[/bold yellow]" if stats["captured_flags"] > 0 else "0"
        banner.update(
            f"🎯 Targets: [bold]{stats['total_targets']}[/bold] (Pwned: {pwn_str} | Foothold: {stats['foothold_targets']}) │ "
            f"⚡ Services: [bold]{stats['total_services']}[/bold] │ "
            f"✔ Checks: [bold green]{stats['completed_checks']}[/bold green] (Findings: [bold red]{stats['total_findings']}[/bold red]) │ "
            f"🔑 Creds: [bold cyan]{stats['total_credentials']}[/bold cyan] │ "
            f"🚩 Proof Flags: {flag_str} │ "
            f"💡 Active Leads: [bold]{stats['active_leads']}[/bold]"
        )

    def refresh_all_views(self) -> None:
        targets = self.repo.list_targets()
        self.query_one("#target-tree", TargetTreeWidget).populate(targets)

        # Refresh Creds
        creds = self.repo.list_credentials()
        self.query_one("#cred-matrix", CredentialMatrixWidget).populate(creds)

        # Refresh Leads
        leads = self.repo.list_leads()
        self.query_one("#lead-board", LeadBoardWidget).populate(leads)

        # Refresh Evidence
        evidence = self.repo.list_evidence()
        self.query_one("#evidence-view", EvidenceViewWidget).populate(evidence)

        # Refresh Pivots
        pivots = self.repo.list_pivot_routes()
        self.query_one("#pivot-view", PivotViewWidget).populate(pivots)

        self.update_stats_banner()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        node_data = event.node.data
        if not node_data:
            return

        detail = self.query_one("#service-detail", ServiceDetailWidget)

        if node_data["type"] == "service":
            svc: Service = node_data["service"]
            t_id: int = node_data["target_id"]
            target = self.repo.get_target_by_id(t_id)
            if target:
                self.selected_target = target
                self.selected_service = svc
                detail.display_service(target, svc)

        elif node_data["type"] == "target":
            target: Target = node_data["target"]
            self.selected_target = target
            self.selected_service = None
            if target.services:
                first_svc = target.services[0]
                self.selected_service = first_svc
                detail.display_service(target, first_svc)
            else:
                detail.display_empty(f"Target {target.ip} selected. No open ports recorded yet. Press 'a' to add services.")

    # -------------------------------------------------------------------------
    # Action Handlers
    # -------------------------------------------------------------------------
    def action_switch_tab(self, tab_id: str) -> None:
        self.query_one("#tabs", TabbedContent).active = tab_id

    def action_add_target(self) -> None:
        def on_result(res: Optional[dict]) -> None:
            if not res:
                return
            t = self.repo.add_or_get_target(
                ip=res["ip"],
                hostname=res.get("hostname", ""),
                os=res.get("os", "Linux"),
                status=TargetStatus.DISCOVERED,
            )
            for port in res.get("ports", []):
                svc = self.repo.add_or_update_service(
                    target_id=t.id,  # type: ignore
                    port=port,
                    protocol="tcp",
                    name="unknown",
                )
                # Populate default methodology checklists
                raw_checks = self.methodology.get_checklists_for_service(svc)
                for rc in raw_checks:
                    rendered_cmd = self.methodology.render_command(
                        rc.get("command_template", ""), t, svc
                    )
                    self.repo.add_checklist_item(
                        service_id=svc.id,  # type: ignore
                        category=rc.get("category", "enum"),
                        title=rc.get("title", ""),
                        description=rc.get("description", ""),
                        command_template=rendered_cmd,
                        status=ChecklistStatus.TODO,
                    )

            self.refresh_all_views()
            self.notify(f"Added target {t.ip} with {len(res.get('ports', []))} ports", title="Target Added")

        self.push_screen(AddTargetModal(), on_result)

    def action_add_cred(self) -> None:
        def on_result(res: Optional[dict]) -> None:
            if not res:
                return
            t_id = self.selected_target.id if self.selected_target else None
            self.repo.add_credential(
                username=res["username"],
                secret=res["secret"],
                cred_type=CredentialType(res["cred_type"]),
                domain=res.get("domain", ""),
                service_scope=res.get("service_scope", ""),
                target_id=t_id,
            )
            self.refresh_all_views()
            self.notify(f"Credential '{res['username']}' saved to vault", title="Credential Added")

        self.push_screen(AddCredModal(), on_result)

    def action_add_lead(self) -> None:
        def on_result(res: Optional[dict]) -> None:
            if not res:
                return
            t_id = self.selected_target.id if self.selected_target else None
            self.repo.add_lead(
                title=res["title"],
                priority=LeadPriority(res["priority"]),
                description=res.get("description", ""),
                status=LeadStatus.BACKLOG,
                target_id=t_id,
            )
            self.refresh_all_views()
            self.notify(f"Lead '{res['title']}' added", title="Lead Recorded")

        self.push_screen(AddLeadModal(), on_result)

    def action_add_evidence(self) -> None:
        if not self.selected_target:
            self.notify("Please select a target first to attach evidence/flags.", severity="warning")
            return

        def on_result(res: Optional[dict]) -> None:
            if not res:
                return
            self.repo.add_evidence(
                target_id=self.selected_target.id,  # type: ignore
                service_id=self.selected_service.id if self.selected_service else None,
                proof_type=ProofType(res["proof_type"]),
                title=res["title"],
                flag_hash=res.get("flag_hash", ""),
                command=res.get("command", ""),
                output=res.get("output", ""),
            )
            # If user or root flag, update target status
            if res["proof_type"] == "root_flag":
                self.repo.update_target_status(self.selected_target.id, TargetStatus.PWNED)  # type: ignore
            elif res["proof_type"] == "user_flag" and self.selected_target.status != TargetStatus.PWNED:
                self.repo.update_target_status(self.selected_target.id, TargetStatus.FOOTHOLD)  # type: ignore

            self.refresh_all_views()
            self.notify("Proof flag / evidence captured!", title="Evidence Saved")

        self.push_screen(AddEvidenceModal(), on_result)

    def action_run_recipe(self) -> None:
        tabs = self.query_one("#tabs", TabbedContent)
        if tabs.active != "tab-workbench" or not self.selected_service:
            self.notify("Select a service in the Workbench to run a recipe.", severity="warning")
            return

        table = self.query_one("#checklist-table", DataTable)
        if table.cursor_row is None:
            self.notify("Select a checklist row in the table first.", severity="warning")
            return

        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        try:
            item_id = int(row_key)
            item = self.repo.get_checklist_by_id(item_id)
            if not item or not item.command_template:
                self.notify("No command recipe defined for this check.", severity="warning")
                return

            def on_result(res: Optional[dict]) -> None:
                if not res:
                    return
                if res.get("action") == "save_evidence":
                    self.repo.add_evidence(
                        target_id=self.selected_target.id,  # type: ignore
                        service_id=self.selected_service.id,  # type: ignore
                        proof_type=ProofType.COMMAND_OUTPUT,
                        title=f"Output for: {item.title}",
                        command=res["command"],
                        output=res["output"],
                    )
                    self.repo.update_checklist_status(item.id, ChecklistStatus.CHECKED, output_snippet=res["output"][:200])  # type: ignore
                    self.refresh_all_views()
                    self.query_one("#service-detail", ServiceDetailWidget).display_service(self.selected_target, self.selected_service)  # type: ignore
                    self.notify("Command output attached to evidence and check marked complete!", title="Evidence Captured")

            self.push_screen(RunnerModal(command=item.command_template, title=f"Run: {item.title}"), on_result)

        except Exception as e:
            self.notify(f"Error launching recipe: {e}", severity="error")

    def action_toggle_status(self) -> None:
        tabs = self.query_one("#tabs", TabbedContent)

        if tabs.active == "tab-workbench":
            table = self.query_one("#checklist-table", DataTable)
            if table.cursor_row is None:
                return
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
            try:
                item_id = int(row_key)
                item = self.repo.get_checklist_by_id(item_id)
                if not item:
                    return

                # Cycle: TODO -> RUNNING -> CHECKED -> FINDING -> DEAD_END -> TODO
                cycle_map = {
                    ChecklistStatus.TODO: ChecklistStatus.RUNNING,
                    ChecklistStatus.RUNNING: ChecklistStatus.CHECKED,
                    ChecklistStatus.CHECKED: ChecklistStatus.FINDING,
                    ChecklistStatus.FINDING: ChecklistStatus.DEAD_END,
                    ChecklistStatus.DEAD_END: ChecklistStatus.TODO,
                }
                new_status = cycle_map.get(item.status, ChecklistStatus.CHECKED)
                self.repo.update_checklist_status(item.id, new_status)  # type: ignore

                # If finding, auto-spawn a high priority lead
                if new_status == ChecklistStatus.FINDING and self.selected_target:
                    self.repo.add_lead(
                        title=f"Vulnerability Finding: {item.title} on {self.selected_target.ip}:{self.selected_service.port if self.selected_service else ''}",
                        priority=LeadPriority.HIGH,
                        description=f"Identified during {item.category} check. Recipe: {item.command_template}",
                        status=LeadStatus.IN_PROGRESS,
                        target_id=self.selected_target.id,
                    )

                self.refresh_all_views()
                if self.selected_target and self.selected_service:
                    self.query_one("#service-detail", ServiceDetailWidget).display_service(self.selected_target, self.selected_service)

            except Exception:
                pass

        elif tabs.active == "tab-leads":
            table = self.query_one("#lead-table", DataTable)
            if table.cursor_row is None:
                return
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
            try:
                lead_id = int(row_key)
                lead = self.repo.get_lead_by_id(lead_id)
                if not lead:
                    return
                # Cycle: BACKLOG -> IN_PROGRESS -> CONFIRMED -> REJECTED -> BACKLOG
                lead_cycle = {
                    LeadStatus.BACKLOG: LeadStatus.IN_PROGRESS,
                    LeadStatus.IN_PROGRESS: LeadStatus.CONFIRMED,
                    LeadStatus.CONFIRMED: LeadStatus.REJECTED,
                    LeadStatus.REJECTED: LeadStatus.BACKLOG,
                }
                self.repo.update_lead_status(lead.id, lead_cycle.get(lead.status, LeadStatus.IN_PROGRESS))  # type: ignore
                self.refresh_all_views()
            except Exception:
                pass

    def action_export_report(self) -> None:
        def on_result(res: Optional[dict]) -> None:
            if not res:
                return
            fmt = res["format"]
            out_path = Path(res["path"]).expanduser().resolve()

            if fmt == "markdown":
                report_md = export_markdown_report(self.repo)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(report_md, encoding="utf-8")
                self.notify(f"Markdown report exported to {out_path}", title="Export Success")

            elif fmt == "obsidian":
                export_obsidian_vault(self.repo, out_path)
                self.notify(f"Obsidian vault notes exported to {out_path}", title="Export Success")

            elif fmt == "json":
                json_data = export_workspace_json(self.repo)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json_data, encoding="utf-8")
                self.notify(f"Workspace JSON backup saved to {out_path}", title="Export Success")

        self.push_screen(ExportModal(), on_result)
