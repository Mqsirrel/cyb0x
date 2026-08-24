"""Main Textual application for Synapse."""

from __future__ import annotations

from pathlib import Path
from typing import Optional
from rich.markup import escape
from textual import work
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
    ChecklistStatus,
    CredentialType,
    LeadPriority,
    LeadStatus,
    ProofType,
    Service,
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
from synapse.tui.modals.theme_modal import ThemeModal
from synapse.tui.modals.triage_modal import TriageModal
from synapse.tui.theme import (
    BACKGROUND,
    CLAUDISH_LIGHT_THEME,
    CLAUDISH_THEME,
    ERROR_RED,
    KRAFT,
    MUTED,
    SAGE,
    SYNAPSE_THEME,
    TERRACOTTA,
)
from synapse.tui.widgets.cred_matrix import CredentialMatrixWidget
from synapse.tui.widgets.evidence_view import EvidenceViewWidget
from synapse.tui.widgets.lead_board import LeadBoardWidget
from synapse.tui.widgets.pivot_view import PivotViewWidget
from synapse.tui.widgets.service_detail import ServiceDetailWidget
from synapse.tui.widgets.target_tree import TargetTreeWidget


from textual.theme import BUILTIN_THEMES

# Eradicate dracula and light themes globally from Textual's built-in theme registry
for _unwanted in ("dracula", "textual-light", "ansi-light", "solarized-light", "atom-one-light", "catppuccin-latte", "rose-pine-dawn"):
    BUILTIN_THEMES.pop(_unwanted, None)


class SynapseTUI(App):
    """The terminal penetration testing assessment state machine and methodology copilot."""

    TITLE = "SYNAPSE // Offensive Assessment State Machine & Methodology Copilot"
    SUB_TITLE = "eJPTv2 • OSCP • CTFs • Authorized Labs"
    CSS = """
    Screen {
        background: $background;
    }
    Header {
        background: #191715;
        color: $foreground;
    }
    Footer {
        background: #191715;
        color: $text-muted;
    }
    #stats-banner {
        height: 1;
        background: #191715;
        color: $foreground;
        padding: 0 1;
        border-bottom: solid $panel;
    }
    #main-container {
        height: 1fr;
    }
    #sidebar-pane {
        width: 32%;
        border-right: solid $panel;
        height: 100%;
    }
    #content-pane {
        width: 68%;
        height: 100%;
        padding: 0 1;
    }
    TargetTreeWidget {
        background: transparent;
    }
    Tree {
        background: transparent;
        padding: 0 1;
    }
    Tree:focus .tree--cursor {
        background: #383028;
        color: $foreground;
        text-style: bold;
    }
    .tree--cursor {
        background: #2a2520;
        color: $foreground;
    }
    
    /* Tabs & TabbedContent styling */
    TabbedContent {
        height: 1fr;
    }
    Tabs {
        background: #191715;
        border-bottom: solid $panel;
        height: 3;
    }
    Tab {
        padding: 0 2;
        background: transparent;
        color: $text-muted;
        text-style: none;
    }
    Tab:hover {
        color: $foreground;
        background: #26221e;
    }
    Tab.-active {
        color: $foreground;
        text-style: bold;
        background: #2c2722;
        border-bottom: tall $primary;
    }
    Tabs:focus Tab.-active {
        background: #352e27;
    }
    Underline {
        display: none;
    }
    
    /* DataTable styling */
    DataTable {
        height: 1fr;
        background: transparent;
        border: round $panel;
    }
    DataTable > .datatable--header {
        background: #191715;
        color: #8c8273;
        text-style: bold;
        border-bottom: solid $panel;
    }
    DataTable > .datatable--cursor {
        background: #332b24;
        color: $foreground;
        text-style: bold;
    }
    DataTable:focus > .datatable--cursor {
        background: #4a3b30;
        color: $foreground;
        text-style: bold;
    }
    DataTable > .datatable--hover {
        background: #24201c;
    }
    
    /* Service Info panel */
    #service-info {
        height: auto;
        padding: 1;
        background: #26221e;
        margin-bottom: 1;
        border: round $panel;
    }
    #checklist-title {
        margin-top: 1;
        margin-bottom: 1;
    }
    
    /* Sleek Scrollbar */
    ScrollBar {
        background: transparent;
        color: #38312a;
    }
    ScrollBar > .scrollbar--thumb {
        background: #473f36;
        color: #473f36;
    }
    ScrollBar > .scrollbar--thumb:hover {
        background: $primary;
        color: $primary;
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
        Binding("p", "select_profile", "Profile (P)", priority=False),
        Binding("g", "guided_workflow", "Guide (G)", priority=False),
        Binding("T", "select_theme", "Themes (T)", priority=False),
        Binding("ctrl+t", "select_theme", "Themes", show=False),
        Binding("question_mark", "show_help", "Help (?)", priority=False),
        Binding("f1", "show_help", "Help (F1)", priority=False, show=False),
        Binding("1", "switch_tab('tab-workbench')", "Workbench", show=False),
        Binding("2", "switch_tab('tab-creds')", "Creds", show=False),
        Binding("3", "switch_tab('tab-leads')", "Leads", show=False),
        Binding("4", "switch_tab('tab-evidence')", "Evidence", show=False),
        Binding("5", "switch_tab('tab-pivots')", "Pivots", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, db_path: str | Path = ":memory:", repo: Optional[DatabaseRepository] = None, **kwargs):
        super().__init__(**kwargs)
        # Unregister unwanted default themes (like dracula, light themes)
        for unwanted in ("dracula", "textual-light", "ansi-light", "solarized-light", "atom-one-light", "catppuccin-latte", "rose-pine-dawn"):
            try:
                self.unregister_theme(unwanted)
            except Exception:
                pass

        # Register Claudish & Synapse themes
        self.register_theme(CLAUDISH_THEME)
        self.register_theme(CLAUDISH_LIGHT_THEME)
        self.register_theme(SYNAPSE_THEME)
        self.theme = "claudish"
        self.active_profile = "ejptv2"
        self.repo = repo if repo is not None else DatabaseRepository(db_path)
        self.methodology = MethodologyEngine()
        self.active_profile = self.repo.get_metadata("active_profile_id", "") or "ejptv2"
        if not self.methodology.set_active_profile(self.active_profile):
            # Persisted profile no longer exists (renamed/removed YAML): fall
            # back to the first bundled profile instead of running profileless.
            fallback = next(iter(self.methodology.get_available_profiles()), None)
            self.active_profile = fallback.id if fallback else ""
            if fallback:
                self.methodology.set_active_profile(self.active_profile)
        self.selected_target: Optional[Target] = None
        self.selected_service: Optional[Service] = None
        # Cached workspace snapshot (single source for all widgets) + per-tab
        # dirty tracking so mutations only rebuild the visible tab immediately.
        self._snapshot: Optional[dict] = None
        self._dirty_tabs: set = set()

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
        """Fresh batched repo data (targets, credentials, leads) for cold paths."""
        targets = self.repo.list_targets()
        credentials = self.repo.list_credentials()
        leads = self.repo.list_leads()
        return targets, credentials, leads

    def _load_snapshot(self) -> dict:
        """Loads every dataset the UI needs in one pass and caches the result.

        This replaces the old pattern of re-querying targets/creds/leads twice
        per refresh (once for widgets, once again inside the stats banner).
        """
        targets = self.repo.list_targets()
        credentials = self.repo.list_credentials()
        leads = self.repo.list_leads()
        evidence = self.repo.list_evidence()
        pivots = self.repo.list_pivot_routes()

        services_map = {s.id: s for t in targets for s in t.services}
        checks_map = {c.id: c for s in services_map.values() for c in s.checklists}
        evidence_by_service: dict = {}
        for ev in evidence:
            if ev.service_id is not None:
                evidence_by_service[ev.service_id] = evidence_by_service.get(ev.service_id, 0) + 1

        snap = {
            "targets": targets,
            "credentials": credentials,
            "leads": leads,
            "evidence": evidence,
            "pivots": pivots,
            "services_map": services_map,
            "checks_map": checks_map,
            "evidence_by_service": evidence_by_service,
        }
        self._snapshot = snap
        return snap

    _ALL_TABS = ("tab-workbench", "tab-creds", "tab-leads", "tab-evidence", "tab-pivots")

    def _populate_tab(self, tab_id: str, snap: dict) -> None:
        """Rebuilds a single tab's widgets from an already-loaded snapshot."""
        if tab_id == "tab-workbench":
            self.query_one("#target-tree", TargetTreeWidget).populate(snap["targets"])
            detail_widget = self.query_one("#service-detail", ServiceDetailWidget)
            detail_widget.evidence_counts = snap["evidence_by_service"]
        elif tab_id == "tab-creds":
            self.query_one("#cred-matrix", CredentialMatrixWidget).populate(snap["credentials"], snap["targets"])
        elif tab_id == "tab-leads":
            self.query_one("#lead-board", LeadBoardWidget).populate(snap["leads"])
        elif tab_id == "tab-evidence":
            self.query_one("#evidence-view", EvidenceViewWidget).populate(
                snap["evidence"], snap["services_map"], snap["checks_map"]
            )
        elif tab_id == "tab-pivots":
            self.query_one("#pivot-view", PivotViewWidget).populate(snap["pivots"])

    def update_stats_banner(self, snap: Optional[dict] = None) -> None:
        stats = self.repo.get_stats()
        banner = self.query_one("#stats-banner", Static)

        if snap is not None:
            targets, credentials, leads = snap["targets"], snap["credentials"], snap["leads"]
        else:
            targets, credentials, leads = self._assessment_inputs()
        oos = sum(1 for t in targets if not t.in_scope)
        scope_str = f" ({len(targets) - oos} in-scope)" if oos else ""

        top = get_top_action(targets, credentials, leads)
        next_str = (
            f" │ [bold {BACKGROUND} on {TERRACOTTA}] NEXT: {escape(top.title[:60])} [/]" if top else ""
        )

        profile = self.methodology.profile_loader.get_profile(self.active_profile)
        profile_name = profile.name if profile else "No Profile"
        phase_badge = "[Enum]" # Just hardcode Enum for now as active phase, or calculate it? Let's just put [Active Phase: Recon]
        # Or let's just make it simple
        banner_text = (
            f" [bold {TERRACOTTA}]{profile_name}[/] │ "
            f" ▸ [bold]Targets:[/] {stats['total_targets']}{scope_str} │ "
            f"[{SAGE}]Pwned: [bold]{stats['pwned_targets']}[/bold][/{SAGE}] │ "
            f"[{KRAFT}]Foothold: {stats['foothold_targets']}[/] │ "
            f"[bold]Services:[/] {stats['total_services']} │ "
            f"[bold]Checks:[/] [{MUTED}]{stats['completed_checks']}/{stats['total_checks']}[/] │ "
            f"[bold]Findings:[/] [bold {ERROR_RED}]{stats['total_findings']}[/] │ "
            f"[bold]Creds:[/] {len(credentials)} │ "
            f"[bold]Flags:[/] [bold {TERRACOTTA}]⚑ {stats['captured_flags']}[/]"
            f"{next_str}"
        )
        banner.update(banner_text)

    def refresh_all_views(self) -> None:
        """Full synchronous refresh of every view from one freshly loaded snapshot."""
        snap = self._load_snapshot()

        self.query_one("#target-tree", TargetTreeWidget).populate(snap["targets"])
        detail_widget = self.query_one("#service-detail", ServiceDetailWidget)
        detail_widget.evidence_counts = snap["evidence_by_service"]

        self.query_one("#cred-matrix", CredentialMatrixWidget).populate(snap["credentials"], snap["targets"])
        self.query_one("#lead-board", LeadBoardWidget).populate(snap["leads"])
        self.query_one("#evidence-view", EvidenceViewWidget).populate(
            snap["evidence"], snap["services_map"], snap["checks_map"]
        )
        self.query_one("#pivot-view", PivotViewWidget).populate(snap["pivots"])

        self.update_stats_banner(snap)
        self._dirty_tabs.clear()

        # If nothing is currently selected and targets exist, select the first target and service
        if not self.selected_target and snap["targets"]:
            first = snap["targets"][0]
            self.selected_target = first
            if first.services:
                self.selected_service = first.services[0]
                detail_widget.display_service(first, first.services[0])
            else:
                self.selected_service = None
                detail_widget.display_empty(f"Target {first.ip} has no open services recorded.")

    def refresh_active_view(self) -> None:
        """Fast-path refresh after mutations.

        Loads the workspace snapshot once, rebuilds only the visible tab now,
        and marks hidden tabs dirty so they repopulate lazily when opened —
        instead of rebuilding all five tabs on every keystroke.
        """
        snap = self._load_snapshot()
        active = self.query_one("#tabs", TabbedContent).active
        if active is None:
            for tab_id in self._ALL_TABS:
                self._populate_tab(tab_id, snap)
            self._dirty_tabs.clear()
        else:
            self._populate_tab(active, snap)
            self._dirty_tabs = {t for t in self._ALL_TABS if t != active}
        self.update_stats_banner(snap)

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        """Lazily repopulates tabs that went stale while they were hidden."""
        pane_id = event.pane.id if event.pane is not None else None
        if pane_id and pane_id in self._dirty_tabs and self._snapshot is not None:
            self._populate_tab(pane_id, self._snapshot)
            self._dirty_tabs.discard(pane_id)

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
            self.refresh_active_view()
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
        # Batch the whole ingestion into one commit (transaction() is nested-safe).
        with self.repo.transaction():
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

                self.refresh_active_view()
                self.query_one("#tabs", TabbedContent).active = "tab-workbench"

                if ingested:
                    self.notify(
                        f"Recon complete — {ingested} service(s) discovered and attached with methodology checklists.",
                        title="Initial Recon",
                    )
                else:
                    self.notify("Recon evidence saved. No parseable service data in output.", title="Initial Recon")

            self.push_screen(
                RunnerModal(
                    command=chosen["command"],
                    title=f"Recon: {chosen['title']}",
                    context=f"Target [bold {TERRACOTTA}]{recon_target.ip}[/] · phase-0 discovery",
                ),
                on_result,
            )

        self.push_screen(InitialReconModal(target_ip=recon_target.ip, recipes=recipes), on_recipe_chosen)

    # -------------------------------------------------------------------------
    # State-Aware Triage & Rabbit-Hole Detection
    # -------------------------------------------------------------------------
    def _evidence_counts_by_target(self, evidence: Optional[list] = None) -> tuple[dict, dict]:
        if evidence is None:
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

        snap = self._load_snapshot()
        targets, credentials, leads = snap["targets"], snap["credentials"], snap["leads"]
        if not targets:
            self.notify("Nothing to triage yet — add a target first ('a').", severity="warning")
            return

        recon_counts, flag_counts = self._evidence_counts_by_target(snap["evidence"])
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

        snap = self._load_snapshot()
        targets, credentials, leads = snap["targets"], snap["credentials"], snap["leads"]
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
        self.refresh_active_view()

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
            self.refresh_active_view()
            self.notify(f"'{cred.username}' reset to untested on {host_ip}.", title="Cred Lifecycle")
            return

        service_hint = cred.service_scope
        self.repo.record_credential_test(cred.id, host_ip, service_hint, valid=valid, admin=False)  # type: ignore
        self.refresh_active_view()
        self.notify(f"'{cred.username}' marked {label}.", title="Cred Lifecycle")


    def _refresh_service_state(self, service: Optional[Service]) -> Service:
        """Derives service status from its checklist state machine.

        Delegates to the repository, which owns the transition rules so every
        surface (TUI, CLI, future callers) shares one state machine. Re-reads
        the checklist from the repository so stale references are safe.
        """
        if not service or not service.id:
            return service  # type: ignore
        fresh = self.repo.refresh_service_state(service.id)
        return fresh or service

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
            self.refresh_active_view()
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
            self.refresh_active_view()
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

            self.refresh_active_view()
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
                    self.refresh_active_view()
                    self.query_one("#service-detail", ServiceDetailWidget).display_service(self.selected_target, self.selected_service)  # type: ignore
                    self.notify("Command output attached to evidence and check marked complete!", title="Evidence Captured")

            svc_ctx = (
                f"{self.selected_target.ip} ▸ {self.selected_service.port}/{self.selected_service.protocol}"
                f" {self.selected_service.name}"
                if self.selected_service
                else None
            )
            self.push_screen(
                RunnerModal(
                    command=item.command_template,
                    title=f"Run: {item.title}",
                    context=svc_ctx,
                ),
                on_result,
            )

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
                self.refresh_active_view()
                if self.selected_target and self.selected_service:
                    self.query_one("#service-detail", ServiceDetailWidget).display_service(self.selected_target, self.selected_service)

            except Exception as e:
                self.notify(f"Could not toggle check status: {e}", severity="error")

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
                self.refresh_active_view()
            except Exception as e:
                self.notify(f"Could not update lead status: {e}", severity="error")

    @work(thread=True, exclusive=True, group="export")
    def _run_export_worker(self, fmt: str, out_path: Path) -> None:
        """Runs report generation off the UI thread; notifies when finished."""
        try:
            if fmt == "notion":
                export_notion_workspace(self.repo, out_path)
                message = f"Notion workspace exported to {out_path}"
            elif fmt == "markdown":
                report_md = export_markdown_report(self.repo)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(report_md, encoding="utf-8")
                message = f"Markdown report exported to {out_path}"
            elif fmt == "obsidian":
                export_obsidian_vault(self.repo, out_path)
                message = f"Obsidian vault notes exported to {out_path}"
            elif fmt == "json":
                json_data = export_workspace_json(self.repo)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json_data, encoding="utf-8")
                message = f"Workspace JSON backup saved to {out_path}"
            else:
                message = f"Unknown export format: {fmt}"
        except Exception as e:
            self.call_from_thread(self.notify, f"Export failed: {e}", title="Export Error", severity="error")
            return
        self.call_from_thread(self.notify, message, title="Export Success")

        self.push_screen(ExportModal(), on_result)

    def action_select_theme(self) -> None:
        """Open the interactive theme switcher modal."""
        if isinstance(self.screen, ModalScreen):
            return

        def _apply_theme(chosen: Optional[str]) -> None:
            if chosen and chosen in self.available_themes:
                self.theme = chosen
                self.notify(f"Color scheme active: {chosen.title()}", title="Theme Changed", timeout=3.0)
                self.update_stats_banner()
                self.refresh_active_view()

        self.push_screen(ThemeModal(current_theme=self.theme), _apply_theme)

    def watch_theme(self, old_theme: str, new_theme: str) -> None:
        """Called automatically by Textual whenever app.theme changes."""
        try:
            self.update_stats_banner()
            self.refresh_active_view()
        except Exception:
            pass


    def action_select_profile(self) -> None:
        """Open the profile selection modal."""
        if isinstance(self.screen, ModalScreen):
            return

        from synapse.tui.modals.profile_modal import ProfileModal
        def _apply_profile(chosen: Optional[str]) -> None:
            if chosen and self.methodology.set_active_profile(chosen):
                self.active_profile = chosen
                self.repo.set_metadata("active_profile_id", chosen)
                self.notify(f"Methodology profile switched", title="Profile Changed")
                self.update_stats_banner()

        self.push_screen(
            ProfileModal(
                profiles=self.methodology.get_available_profiles(),
                active_profile=self.active_profile,
            ),
            _apply_profile,
        )

    def action_guided_workflow(self) -> None:
        """Open the guided methodology breakdown modal for the selected target."""
        if isinstance(self.screen, ModalScreen):
            return
        from synapse.assessment.engine import evaluate_phase_progress
        from synapse.tui.modals.guided_phase_modal import GuidedPhaseModal

        profile = self.methodology.active_profile
        target = self.selected_target
        if target is None or profile is None:
            targets = self._assessment_inputs()[0]
            target = next((t for t in targets if t.in_scope), None)

        context = f"Target: {target.ip}" + (f" ({target.hostname})" if target.hostname else "") if target else ""
        progress = (
            evaluate_phase_progress(target, profile, self.repo.list_evidence(target.id))
            if target and profile
            else {}
        )
        self.push_screen(GuidedPhaseModal(profile=profile, progress=progress, context=context))
