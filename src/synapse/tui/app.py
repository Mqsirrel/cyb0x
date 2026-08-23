"""Main Textual application for Synapse."""

from __future__ import annotations

from pathlib import Path
from typing import Optional
from rich.markup import escape
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)

from synapse.assessment import (
    build_snapshots,
    detect_rabbit_holes,
    get_next_actions,
    get_top_action,
)
from synapse.db.repository import DatabaseRepository
from synapse.export.json_exporter import export_workspace_json
from synapse.export.markdown_exporter import export_markdown_report, export_obsidian_vault
from synapse.export.notion_exporter import export_notion_workspace
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
from synapse.parsers.nmap_parser import parse_nmap_text
from synapse.tui.modals.add_cred_modal import AddCredModal
from synapse.tui.modals.add_evidence_modal import AddEvidenceModal
from synapse.tui.modals.add_lead_modal import AddLeadModal
from synapse.tui.modals.add_target_modal import AddTargetModal
from synapse.tui.modals.export_modal import ExportModal
from synapse.tui.modals.help_modal import HelpModal
from synapse.tui.modals.initial_recon_modal import InitialReconModal
from synapse.tui.modals.runner_modal import RunnerModal
from synapse.tui.modals.stuck_modal import StuckModal
from synapse.tui.modals.triage_modal import TriageModal
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
        background: $surface-darken-1;
        color: $text;
        padding: 0 1;
        text-style: bold;
        border-bottom: solid $primary-darken-2;
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
        Binding("i", "initial_recon", "Initial Recon", priority=False),
        Binding("r", "run_recipe", "Run Recipe", priority=False),
        Binding("n", "triage", "Triage (Next?)", priority=False),
        Binding("s", "stuck_check", "I'm Stuck", priority=False),
        Binding("o", "toggle_scope", "Scope Toggle", priority=False),
        Binding("c", "add_cred", "Add Cred", priority=False),
        Binding("t", "mark_cred_tested", "Mark Cred Tested", priority=False),
        Binding("l", "add_lead", "Add Lead", priority=False),
        Binding("e", "add_evidence", "Add Flag/Evidence", priority=False),
        Binding("space", "toggle_status", "Toggle Status", priority=False),
        Binding("x", "export_report", "Export Report", priority=False),
        Binding("question_mark", "show_help", "Help (?)", priority=False),
        Binding("f1", "show_help", "Help (F1)", priority=False, show=False),
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
        self.auto_select_first_service()

    def auto_select_first_service(self) -> None:
        """Populates the methodology checklist with the first discovered service on launch."""
        detail_widget = self.query_one("#service-detail", ServiceDetailWidget)
        targets = self.repo.list_targets()

        if not targets:
            detail_widget.display_empty()
            return

        first = targets[0]
        self.selected_target = first
        if first.services:
            self.selected_service = first.services[0]
            detail_widget.display_service(first, first.services[0])
        else:
            self.selected_service = None
            detail_widget.display_empty(f"Target {first.ip} has no open services recorded.")

        tree = self.query_one("#target-tree", TargetTreeWidget)
        if tree.root.children:
            tree.root.children[0].expand()

    def _assessment_inputs(self):
        """Batched repo data shared by the banner, triage, and stuck workflows."""
        targets = self.repo.list_targets()
        credentials = self.repo.list_credentials()
        leads = self.repo.list_leads()
        return targets, credentials, leads

    def update_stats_banner(self) -> None:
        stats = self.repo.get_stats()
        banner = self.query_one("#stats-banner", Static)
        pwn_str = f"[bold green]{stats['pwned_targets']}[/bold green]"
        foothold_str = f"[magenta]{stats['foothold_targets']}[/magenta]"
        flag_str = f"[bold yellow]{stats['captured_flags']}[/bold yellow]"
        finding_str = f"[bold red]{stats['total_findings']}[/bold red]"
        checks_str = f"[cyan]{stats['completed_checks']}/{stats['total_checks']}[/cyan]"

        targets, credentials, leads = self._assessment_inputs()
        oos = sum(1 for t in targets if not t.in_scope)
        scope_str = f" ({len(targets) - oos} in-scope)" if oos else ""

        top = get_top_action(targets, credentials, leads)
        next_str = (
            f" │ [bold white on #14507d] NEXT: {escape(top.title[:60])} [/]" if top else ""
        )

        banner_text = (
            f" [bold white]🎯 Targets:[/bold white] {stats['total_targets']}{scope_str} (Pwned: {pwn_str} │ Foothold: {foothold_str}) │ "
            f"[bold white]⚡ Services:[/bold white] {stats['total_services']} │ "
            f"[bold white]✔ Checks:[/bold white] {checks_str} │ "
            f"[bold white]★ Findings:[/bold white] {finding_str} │ "
            f"[bold white]🔑 Creds:[/bold white] {stats['total_credentials']} │ "
            f"[bold white]🚩 Flags:[/bold white] {flag_str}"
            f"{next_str}"
        )
        banner.update(banner_text)

    def refresh_all_views(self) -> None:
        targets, credentials, leads = self._assessment_inputs()
        self.query_one("#target-tree", TargetTreeWidget).populate(targets)

        self.query_one("#cred-matrix", CredentialMatrixWidget).populate(credentials, targets)

        self.query_one("#lead-board", LeadBoardWidget).populate(leads)

        evidence = self.repo.list_evidence()
        services_map = {s.id: s for t in targets for s in t.services}
        checks_map = {c.id: c for s in services_map.values() for c in s.checklists}
        self.query_one("#evidence-view", EvidenceViewWidget).populate(evidence, services_map, checks_map)

        evidence_by_service: dict = {}
        for ev in evidence:
            if ev.service_id is not None:
                evidence_by_service[ev.service_id] = evidence_by_service.get(ev.service_id, 0) + 1
        detail_widget = self.query_one("#service-detail", ServiceDetailWidget)
        detail_widget.evidence_counts = evidence_by_service

        pivots = self.repo.list_pivot_routes()
        self.query_one("#pivot-view", PivotViewWidget).populate(pivots)

        self.update_stats_banner()

        # If nothing is currently selected and targets exist, select the first target and service
        if not self.selected_target and targets:
            self.selected_target = targets[0]
            detail_widget = self.query_one("#service-detail", ServiceDetailWidget)
            if targets[0].services:
                self.selected_service = targets[0].services[0]
                detail_widget.display_service(targets[0], targets[0].services[0])
            else:
                detail_widget.display_empty(f"Target {targets[0].ip} has no open services recorded.")

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        node_data = event.node.data
        if not node_data:
            return

        detail_widget = self.query_one("#service-detail", ServiceDetailWidget)

        if node_data["type"] == "service":
            svc: Service = node_data["service"]
            target: Target = self.repo.get_target_by_id(node_data["target_id"])  # type: ignore
            self.selected_target = target
            self.selected_service = svc
            detail_widget.display_service(target, svc)

        elif node_data["type"] == "target":
            target: Target = node_data["target"]
            self.selected_target = target
            self.selected_service = None
            if target.services:
                self.selected_service = target.services[0]
                detail_widget.display_service(target, target.services[0])
            else:
                detail_widget.display_empty(f"Target {target.ip} has no open services recorded.")

    def action_switch_tab(self, tab_id: str) -> None:
        self.query_one("#tabs", TabbedContent).active = tab_id

    def action_show_help(self) -> None:
        if isinstance(self.screen, ModalScreen):
            return
        self.push_screen(HelpModal())

    def action_add_target(self) -> None:
        if isinstance(self.screen, ModalScreen):
            return

        def on_result(res: Optional[dict]) -> None:
            if not res:
                return
            t = self.repo.add_or_get_target(
                ip=res["ip"],
                hostname=res.get("hostname", ""),
                os=res.get("os", "Unknown"),
            )
            for p in res.get("ports", []):
                svc = self.repo.add_or_update_service(target_id=t.id, port=p)
                for rc in self.methodology.get_checklists_for_service(svc):
                    cmd = self.methodology.render_command(rc.get("command_template", ""), t, svc)
                    self.repo.add_checklist_item(
                        service_id=svc.id,
                        category=rc.get("category", "enum"),
                        title=rc.get("title", ""),
                        description=rc.get("description", ""),
                        command_template=cmd,
                    )
            self.refresh_all_views()
            self.notify(f"Target {t.ip} added successfully", title="Target Added")

        self.push_screen(AddTargetModal(), on_result)

    def _ingest_recon_output(self, target: Target, output: str) -> int:
        """Parses Nmap text output captured by the recon runner and attaches discovered
        services to the target through the standard methodology pipeline.

        Returns the number of services processed (0 when the output is not parseable).
        """
        if not output:
            return 0

        try:
            parsed_targets = parse_nmap_text(output)
        except Exception:
            return 0

        ingested = 0
        for pt in parsed_targets:
            if pt.get("ip") != target.ip:
                continue
            for svc_data in pt.get("services", []):
                try:
                    svc = self.repo.add_or_update_service(
                        target_id=target.id,  # type: ignore
                        port=svc_data["port"],
                        protocol=svc_data.get("protocol", "tcp"),
                        name=svc_data.get("name", "unknown"),
                        product=svc_data.get("product", ""),
                        version=svc_data.get("version", ""),
                        banner=svc_data.get("banner", ""),
                    )
                except Exception:
                    continue
                for rc in self.methodology.get_checklists_for_service(svc):
                    cmd = self.methodology.render_command(rc.get("command_template", ""), target, svc)
                    self.repo.add_checklist_item(
                        service_id=svc.id,  # type: ignore
                        category=rc.get("category", "enum"),
                        title=rc.get("title", ""),
                        description=rc.get("description", ""),
                        command_template=cmd,
                    )
                ingested += 1
        return ingested

    def action_initial_recon(self) -> None:
        """Launches host-level phase-0 reconnaissance recipes for the selected target."""
        if isinstance(self.screen, ModalScreen):
            return

        if not self.selected_target:
            self.notify("Select or add a target first ('a') to launch initial recon.", severity="warning")
            return

        self._launch_initial_recon(self.repo.get_target_by_id(self.selected_target.id))  # type: ignore

    def _launch_initial_recon(self, recon_target: Optional[Target]) -> None:
        """Shared phase-0 launcher; also the auto-route destination for 'r' on bare targets."""
        if not recon_target:
            return

        recipes = self.methodology.get_initial_recon_commands(recon_target)
        if not recipes:
            self.notify("No initial recon recipes defined in the methodology knowledge base.", severity="warning")
            return

        def on_recipe_chosen(chosen: Optional[dict]) -> None:
            if not chosen:
                return

            def on_result(res: Optional[dict]) -> None:
                if not res:
                    return
                if res.get("action") != "save_evidence":
                    return

                fresh = self.repo.get_target_by_ip(recon_target.ip)
                if not fresh:
                    return

                self.repo.add_evidence(
                    target_id=fresh.id,  # type: ignore
                    proof_type=ProofType.COMMAND_OUTPUT,
                    title=f"Initial Recon: {chosen['title']}",
                    command=res.get("command", ""),
                    output=res.get("output", ""),
                )

                ingested = self._ingest_recon_output(fresh, res.get("output", ""))
                if fresh.status == TargetStatus.DISCOVERED:
                    self.repo.update_target_status(fresh.id, TargetStatus.SCANNING)

                self.refresh_all_views()
                self.query_one("#tabs", TabbedContent).active = "tab-workbench"

                if ingested:
                    self.notify(
                        f"Recon complete — {ingested} service(s) discovered and attached with methodology checklists.",
                        title="Initial Recon",
                    )
                else:
                    self.notify("Recon evidence saved. No parseable service data in output.", title="Initial Recon")

            self.push_screen(RunnerModal(command=chosen["command"], title=f"Recon: {chosen['title']}"), on_result)

        self.push_screen(InitialReconModal(target_ip=recon_target.ip, recipes=recipes), on_recipe_chosen)

    # -------------------------------------------------------------------------
    # State-Aware Triage & Rabbit-Hole Detection
    # -------------------------------------------------------------------------
    def _evidence_counts_by_target(self) -> tuple[dict, dict]:
        evidence = self.repo.list_evidence()
        by_target: dict = {}
        flags: dict = {}
        for ev in evidence:
            by_target[ev.target_id] = by_target.get(ev.target_id, 0) + 1
            if ev.flag_hash:
                flags[ev.target_id] = flags.get(ev.target_id, 0) + 1
        return by_target, flags

    def action_triage(self) -> None:
        """Opens the state-aware triage board (known / unknown / next move)."""
        if isinstance(self.screen, ModalScreen):
            return

        targets, credentials, leads = self._assessment_inputs()
        if not targets:
            self.notify("Nothing to triage yet — add a target first ('a').", severity="warning")
            return

        recon_counts, flag_counts = self._evidence_counts_by_target()
        valid_by_ip: dict = {}
        for c in credentials:
            for ip_key, data in c.tested_targets.items():
                if isinstance(data, dict) and data.get("valid"):
                    host = str(ip_key).split(":")[0]
                    valid_by_ip[host] = valid_by_ip.get(host, 0) + 1

        snapshots = build_snapshots(targets, recon_counts, flag_counts, valid_by_ip)
        actions = get_next_actions(targets, credentials, leads)
        focus_ip = self.selected_target.ip if self.selected_target else None
        self.push_screen(TriageModal(list(snapshots.values()), actions, focus_ip=focus_ip))

    def action_stuck_check(self) -> None:
        """'I'm stuck' workflow: rabbit-hole analysis with concrete escape routes."""
        if isinstance(self.screen, ModalScreen):
            return

        targets, credentials, leads = self._assessment_inputs()
        if not targets:
            self.notify("Nothing to analyze yet — add a target first ('a').", severity="warning")
            return

        report = detect_rabbit_holes(targets, credentials, leads)
        self.push_screen(StuckModal(report))

    def action_toggle_scope(self) -> None:
        """Toggles in-scope state of the selected target and refreshes filtered views."""
        if isinstance(self.screen, ModalScreen):
            return
        if not self.selected_target or self.selected_target.id is None:
            self.notify("Select a target in the Workbench tree to toggle its scope.", severity="warning")
            return

        new_scope = not self.selected_target.in_scope
        self.repo.set_target_scope(self.selected_target.id, new_scope)
        self.selected_target.in_scope = new_scope
        state = "in scope" if new_scope else "OUT OF SCOPE"
        self.notify(f"{self.selected_target.ip} marked {state}.", title="Scope Updated")
        self.refresh_all_views()

    def action_mark_cred_tested(self) -> None:
        """Credential lifecycle: cycle the selected credential's test state against the selected target.

        Cycle per host: untested → valid → invalid → untested. Press on the Creds tab.
        """
        tabs = self.query_one("#tabs", TabbedContent)
        if tabs.active != "tab-creds":
            return
        if not self.selected_target or self.selected_target.id is None:
            self.notify("Select a target in the Workbench first — credentials are tested per-host.", severity="warning")
            return

        table = self.query_one("#cred-table", DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        try:
            cred = self.repo.get_credential_by_id(int(row_key))
        except (ValueError, TypeError):
            return
        if not cred:
            return

        host_ip = self.selected_target.ip
        entry = cred.tested_targets.get(host_ip) or cred.tested_targets.get(f"{host_ip}:{cred.service_scope}")
        current_valid = bool(entry.get("valid")) if isinstance(entry, dict) else False
        was_tested = entry is not None

        if not was_tested:
            valid, label = True, f"VALID on {host_ip}"
        elif current_valid:
            valid, label = False, f"INVALID on {host_ip}"
        else:
            # Reset to untested: wipe both host and compound keys for this host
            remaining = {k: v for k, v in cred.tested_targets.items() if str(k).split(":")[0] != host_ip}
            self.repo.update_credential_tested_targets(cred.id, remaining)  # type: ignore
            self.refresh_all_views()
            self.notify(f"'{cred.username}' reset to untested on {host_ip}.", title="Cred Lifecycle")
            return

        service_hint = cred.service_scope
        self.repo.record_credential_test(cred.id, host_ip, service_hint, valid=valid, admin=False)  # type: ignore
        self.refresh_all_views()
        self.notify(f"'{cred.username}' marked {label}.", title="Cred Lifecycle")


    def _refresh_service_state(self, service: Optional[Service]) -> Service:
        """Derives service status from its checklist state machine.

        finding -> VULNERABLE, running -> IN_PROGRESS, all dead-end -> DEAD_END,
        fully resolved -> ENUMERATED. Re-reads the checklist from the repository
        so callers can pass stale references safely. Returns the fresh model.
        """
        if not service or not service.id:
            return service  # type: ignore
        fresh = self.repo.get_service_by_id(service.id)
        if not fresh or not fresh.checklists:
            return fresh or service
        statuses = {c.status for c in fresh.checklists}
        if ChecklistStatus.FINDING in statuses:
            new_status = ServiceStatus.VULNERABLE
        elif ChecklistStatus.RUNNING in statuses:
            new_status = ServiceStatus.IN_PROGRESS
        elif statuses <= {ChecklistStatus.DEAD_END}:
            new_status = ServiceStatus.DEAD_END
        elif statuses <= {ChecklistStatus.CHECKED, ChecklistStatus.FINDING, ChecklistStatus.DEAD_END}:
            new_status = ServiceStatus.ENUMERATED
        else:
            return fresh
        self.repo.update_service_status(fresh.id, new_status)  # type: ignore
        fresh.status = new_status
        return fresh

    def action_add_cred(self) -> None:
        if isinstance(self.screen, ModalScreen):
            return

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
        if isinstance(self.screen, ModalScreen):
            return

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
        if isinstance(self.screen, ModalScreen):
            return

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
        if isinstance(self.screen, ModalScreen):
            return

        tabs = self.query_one("#tabs", TabbedContent)
        if tabs.active != "tab-workbench" or not self.selected_service:
            # Seamless fallback: a fresh target with no service context belongs in phase-0 recon.
            if self.selected_target and not self.selected_service:
                self.notify(
                    f"No service selected — routing to Initial Recon for {self.selected_target.ip}.",
                    title="Auto-route",
                    severity="information",
                )
                self._launch_initial_recon(self.repo.get_target_by_id(self.selected_target.id))  # type: ignore
            else:
                self.notify("Select a service in the Workbench to run a recipe.", severity="warning")
            return

        table = self.query_one("#checklist-table", DataTable)
        if table.row_count == 0 or table.cursor_row is None:
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
                        checklist_id=item.id,
                        proof_type=ProofType.COMMAND_OUTPUT,
                        title=f"Output for: {item.title}",
                        command=res["command"],
                        output=res["output"],
                    )
                    self.repo.update_checklist_status(item.id, ChecklistStatus.CHECKED, output_snippet=res["output"][:200])  # type: ignore
                    self.selected_service = self._refresh_service_state(self.selected_service)
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
            if table.row_count == 0 or table.cursor_row is None:
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

                self.selected_service = self._refresh_service_state(self.selected_service)
                self.refresh_all_views()
                if self.selected_target and self.selected_service:
                    self.query_one("#service-detail", ServiceDetailWidget).display_service(self.selected_target, self.selected_service)

            except Exception:
                pass

        elif tabs.active == "tab-leads":
            table = self.query_one("#lead-table", DataTable)
            if table.row_count == 0 or table.cursor_row is None:
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
        if isinstance(self.screen, ModalScreen):
            return

        def on_result(res: Optional[dict]) -> None:
            if not res:
                return
            fmt = res["format"]
            out_path = Path(res["output_path"]).expanduser().resolve()

            if fmt == "notion":
                export_notion_workspace(self.repo, out_path)
                self.notify(f"Notion workspace exported to {out_path}", title="Export Success")

            elif fmt == "markdown":
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
