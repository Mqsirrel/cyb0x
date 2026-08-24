"""Deterministic, offline assessment engine for Synapse engagements.

Consumes plain repository models (targets with embedded services/checklists,
credentials, leads) and derives:

- ``TargetSnapshot``: what is known / unknown / tested / dead-ended per host.
- ``NextAction``: prioritized, rationale-backed investigations (triage view).
- ``StuckReport``: rabbit-hole detection separating proven dead ends from
  untested surface and un-sprayed credentials.

No SQL, no network, no LLM: pure functions over Pydantic models so results are
instant and reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PhaseStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"

@dataclass
class PhaseProgress:
    phase_id: str
    completed_checks: list[str] = field(default_factory=list)
    pending_checks: list[str] = field(default_factory=list)
    running_checks: list[str] = field(default_factory=list)
    dead_ends: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommended_actions: list[NextAction] = field(default_factory=list)
    phase_status: PhaseStatus = PhaseStatus.NOT_STARTED

from dataclasses import dataclass, field
from datetime import datetime, timezone

from synapse.models import (
    ChecklistStatus,
    Credential,
    Lead,
    LeadStatus,
    Service,
    ServiceStatus,
    Target,
    TargetStatus,
)

# Priority tiers surfaced in the TUI (lower number == do it first).
PRIORITY_RECON = 0
PRIORITY_EXPLOIT = 1
PRIORITY_ENUM = 2
PRIORITY_SPRAY = 3
PRIORITY_RESUME = 4
PRIORITY_CLEANUP = 5

_PRIORITY_LABELS = {
    PRIORITY_RECON: "RECON",
    PRIORITY_EXPLOIT: "EXPLOIT",
    PRIORITY_ENUM: "ENUM",
    PRIORITY_SPRAY: "SPRAY",
    PRIORITY_RESUME: "RESUME",
    PRIORITY_CLEANUP: "CLEANUP",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _unique_by_ip(targets: list[Target]) -> list[Target]:
    """Collapses duplicate target rows for the same IP (first occurrence wins).

    Hand-built model lists can carry the same host twice; without this, a bare
    duplicate masks the known services of its twin and recon is re-recommended
    for an already-scanned host.
    """
    seen: set = set()
    unique: list[Target] = []
    for t in targets:
        if t.ip in seen:
            continue
        seen.add(t.ip)
        unique.append(t)
    return unique


def _disproven_service(svc: Service) -> bool:
    """True when every methodology check on the service came back DEAD_END.

    Checklist state outranks ``Service.status`` (a derived cache callers may
    not have refreshed): a service whose checks all dead-ended must never be
    treated as untouched attack surface, whatever its cached status says.
    """
    return bool(svc.checklists) and all(
        c.status == ChecklistStatus.DEAD_END for c in svc.checklists
    )


def _cred_valid_somewhere(cred: Credential) -> bool:
    """True if any recorded test of this credential succeeded."""
    return any(
        isinstance(data, dict) and data.get("valid")
        for data in cred.tested_targets.values()
    )


@dataclass
class TargetSnapshot:
    """Aggregated per-host state: what is known vs unknown vs tested."""

    ip: str
    hostname: str = ""
    status: TargetStatus = TargetStatus.DISCOVERED
    in_scope: bool = True

    recon_runs: int = 0
    services_total: int = 0
    services_untested: int = 0
    services_in_progress: int = 0
    services_enumerated: int = 0
    services_vulnerable: int = 0
    services_dead_end: int = 0

    checks_total: int = 0
    checks_todo: int = 0
    checks_running: int = 0
    checks_done: int = 0
    checks_finding: int = 0
    checks_dead_end: int = 0

    evidence_count: int = 0
    flag_count: int = 0
    valid_creds: int = 0

    @property
    def coverage(self) -> float:
        """Fraction of checklist items resolved (done/finding/dead-end) or 1.0 when nothing planned."""
        if self.checks_total == 0:
            return 1.0
        resolved = self.checks_done + self.checks_finding + self.checks_dead_end
        return resolved / self.checks_total

    @property
    def is_bare(self) -> bool:
        return self.services_total == 0

    @property
    def label(self) -> str:
        host = f" ({self.hostname})" if self.hostname else ""
        return f"{self.ip}{host}"

    def summary_line(self) -> str:
        parts = [f"{self.services_total} svc"]
        if self.services_untested:
            parts.append(f"{self.services_untested} untested")
        if self.services_dead_end:
            parts.append(f"{self.services_dead_end} dead-end")
        parts.append(
            f"checks {self.checks_done + self.checks_finding}/{self.checks_total}"
            if self.checks_total
            else "no checks"
        )
        if self.flag_count:
            parts.append(f"{self.flag_count} flags")
        return ", ".join(parts)


@dataclass
class NextAction:
    """A single recommended investigation with its reasoning."""

    priority: int
    kind: str  # recon | exploit | enum | spray | resume | cleanup
    title: str
    rationale: str
    target_ip: str | None = None
    port: int | None = None

    @property
    def priority_label(self) -> str:
        return _PRIORITY_LABELS.get(self.priority, "INFO")


@dataclass
class StuckReport:
    """Rabbit-hole triage: separates proven dead ends from untouched surface."""

    dead_end_services: list[str] = field(default_factory=list)
    dead_end_checks: list[str] = field(default_factory=list)
    running_checks: list[str] = field(default_factory=list)
    untested_ports: list[str] = field(default_factory=list)
    unsprayed_credentials: list[str] = field(default_factory=list)
    stale_leads: list[str] = field(default_factory=list)
    suggestions: list[NextAction] = field(default_factory=list)

    @property
    def is_stuck(self) -> bool:
        """Stuck means: activity exists but nothing actionable is left open.

        Housekeeping hints (kind == "cleanup", e.g. the out-of-scope reminder)
        are not attack surface and must not mask a genuine stuck verdict.
        """
        has_activity = bool(self.dead_end_services or self.dead_end_checks)
        open_surface = (
            self.untested_ports
            or self.unsprayed_credentials
            or self.running_checks
            or [a for a in self.suggestions if a.kind != "cleanup"]
        )
        return has_activity and not open_surface


def build_snapshots(targets: list[Target], evidence_by_target: dict[int, int] | None = None,
                    flags_by_target: dict[int, int] | None = None,
                    valid_creds_by_ip: dict[str, int] | None = None) -> dict[str, TargetSnapshot]:
    """Builds per-target state snapshots from batched repository data."""
    evidence_by_target = evidence_by_target or {}
    flags_by_target = flags_by_target or {}
    valid_creds_by_ip = valid_creds_by_ip or {}

    snaps: dict[str, TargetSnapshot] = {}
    for t in targets:
        snap = TargetSnapshot(
            ip=t.ip,
            hostname=t.hostname or "",
            status=t.status,
            in_scope=t.in_scope,
            recon_runs=evidence_by_target.get(t.id, 0),  # type: ignore
            flag_count=flags_by_target.get(t.id, 0),  # type: ignore
            valid_creds=valid_creds_by_ip.get(t.ip, 0),
        )
        for svc in t.services:
            snap.services_total += 1
            if svc.status == ServiceStatus.UNTESTED:
                snap.services_untested += 1
            elif svc.status == ServiceStatus.IN_PROGRESS:
                snap.services_in_progress += 1
            elif svc.status == ServiceStatus.ENUMERATED:
                snap.services_enumerated += 1
            elif svc.status == ServiceStatus.VULNERABLE:
                snap.services_vulnerable += 1
            elif svc.status == ServiceStatus.DEAD_END:
                snap.services_dead_end += 1

            for chk in svc.checklists:
                snap.checks_total += 1
                if chk.status == ChecklistStatus.TODO:
                    snap.checks_todo += 1
                elif chk.status == ChecklistStatus.RUNNING:
                    snap.checks_running += 1
                elif chk.status == ChecklistStatus.CHECKED:
                    snap.checks_done += 1
                elif chk.status == ChecklistStatus.FINDING:
                    snap.checks_finding += 1
                elif chk.status == ChecklistStatus.DEAD_END:
                    snap.checks_dead_end += 1

        snaps[t.ip] = snap
    return snaps


def unsprayed_hosts_for_credential(cred: Credential, targets: list[Target]) -> list[str]:
    """In-scope hosts where this credential has never been attempted."""
    tested_hosts = {str(ip).split(":")[0] for ip in cred.tested_targets.keys()}
    return [
        t.ip
        for t in targets
        if t.in_scope and t.status != TargetStatus.IGNORED and t.ip not in tested_hosts
    ]


def get_next_actions(
    targets: list[Target],
    credentials: list[Credential] | None = None,
    leads: list[Lead] | None = None,
    limit: int = 10,
) -> list[NextAction]:
    """Derives the highest-value next investigations, deterministically ordered.

    Ordering: phase-0 gaps first, then confirmed-access opportunities (valid
    admin creds), then untested enumeration surface, then sprays, resumptions,
    and housekeeping. Out-of-scope and ignored targets are excluded.
    """
    credentials = credentials or []
    leads = leads or []
    actions: list[NextAction] = []

    live_targets = _unique_by_ip(
        [t for t in targets if t.in_scope and t.status != TargetStatus.IGNORED]
    )
    snapshots = build_snapshots(live_targets)

    # 1. Bare targets: phase-0 recon is always the first move.
    for t in live_targets:
        snap = snapshots[t.ip]
        if snap.is_bare:
            actions.append(
                NextAction(
                    priority=PRIORITY_RECON,
                    kind="recon",
                    title=f"Run initial reconnaissance on {snap.label}",
                    rationale="No services discovered yet — the attack surface is unknown.",
                    target_ip=t.ip,
                )
            )

    # 2. Valid admin credentials on hosts that are not yet footholds.
    for cred in credentials:
        admin_hosts = {
            str(ip).split(":")[0]
            for ip, data in cred.tested_targets.items()
            if isinstance(data, dict) and data.get("admin") and data.get("valid")
        }
        for ip in sorted(admin_hosts):
            t = next((x for x in live_targets if x.ip == ip), None)
            if t and t.status not in (TargetStatus.FOOTHOLD, TargetStatus.PWNED):
                actions.append(
                    NextAction(
                        priority=PRIORITY_EXPLOIT,
                        kind="exploit",
                        title=f"Leverage '{cred.username}' (admin-valid on {ip}) to gain a shell",
                        rationale="Administrative access confirmed but host is not marked foothold/pwned yet.",
                        target_ip=ip,
                    )
                )

    # 2.5 Confirmed findings awaiting exploitation. Checklist state is the
    # source of truth here (service status is a derived cache that callers
    # may not have refreshed).
    for t in live_targets:
        if t.status in (TargetStatus.FOOTHOLD, TargetStatus.PWNED):
            continue
        for s in t.services:
            findings = [c.title for c in s.checklists if c.status == ChecklistStatus.FINDING]
            if not findings:
                continue
            label = findings[0] + (f" (+{len(findings) - 1} more)" if len(findings) > 1 else "")
            actions.append(
                NextAction(
                    priority=PRIORITY_EXPLOIT,
                    kind="exploit",
                    title=f"Exploit confirmed finding '{label}' on {t.ip}:{s.port}",
                    rationale=f"{len(findings)} methodology check(s) flagged as findings — capitalize before moving on.",
                    target_ip=t.ip,
                    port=s.port,
                )
            )

    # 3. Untested services with pending methodology checks.
    for t in live_targets:
        snap = snapshots[t.ip]
        if snap.is_bare:
            continue
        pending = sorted(
            s.port
            for s in t.services
            if s.status == ServiceStatus.UNTESTED and not _disproven_service(s)
        )
        todo_checks = sum(1 for s in t.services for c in s.checklists if c.status == ChecklistStatus.TODO)
        if pending:
            port_str = ",".join(str(p) for p in pending[:6]) + ("…" if len(pending) > 6 else "")
            actions.append(
                NextAction(
                    priority=PRIORITY_ENUM,
                    kind="enum",
                    title=f"Enumerate untested service(s) on {t.ip}: port {port_str}",
                    rationale=f"{len(pending)} open service(s) never touched; {todo_checks} recipe check(s) pending.",
                    target_ip=t.ip,
                )
            )
        elif snap.checks_todo and not snap.checks_running:
            actions.append(
                NextAction(
                    priority=PRIORITY_RESUME,
                    kind="resume",
                    title=f"Work through {snap.checks_todo} remaining check(s) on {t.ip}",
                    rationale="All services touched but methodology coverage is incomplete.",
                    target_ip=t.ip,
                )
            )

    # 4. Credential spraying gaps: valid creds never attempted elsewhere.
    for cred in credentials:
        if not _cred_valid_somewhere(cred):
            continue
        untested = unsprayed_hosts_for_credential(cred, live_targets)
        if untested:
            preview = ", ".join(untested[:4]) + ("…" if len(untested) > 4 else "")
            actions.append(
                NextAction(
                    priority=PRIORITY_SPRAY,
                    kind="spray",
                    title=f"Credential spray: try '{cred.username}' against {preview}",
                    rationale=f"Valid credential never attempted on {len(untested)} in-scope host(s).",
                )
            )

    # 5. Resume interrupted work.
    for t in live_targets:
        running = [(s, c) for s in t.services for c in s.checklists if c.status == ChecklistStatus.RUNNING]
        if running:
            s0, c0 = running[0]
            actions.append(
                NextAction(
                    priority=PRIORITY_RESUME,
                    kind="resume",
                    title=f"Resume '{c0.title}' on {t.ip}:{s0.port}",
                    rationale=f"{len(running)} check(s) left in RUNNING state — finish or mark them.",
                    target_ip=t.ip,
                    port=s0.port,
                )
            )

    # 6. Housekeeping: stale hypotheses.
    now = _now()
    for lead in leads:
        if lead.status != LeadStatus.BACKLOG:
            continue
        age_days = (now - lead.created_at.replace(tzinfo=timezone.utc)).days
        if age_days >= 3:
            actions.append(
                NextAction(
                    priority=PRIORITY_CLEANUP,
                    kind="cleanup",
                    title=f"Triage stale lead #{lead.id}: {lead.title[:60]}",
                    rationale=f"Backlogged for {age_days} days without progress — confirm or reject it.",
                )
            )

    # Deterministic dedup: identical (kind, subject) recommendations collapse
    # to the highest-priority occurrence (e.g. several admin-valid creds on
    # the same unowned host are one move, not N).
    seen: set = set()
    deduped: list[NextAction] = []
    for act in sorted(actions, key=lambda a: (a.priority, a.title)):
        key = (act.kind, act.target_ip, act.port)
        if act.kind in ("exploit", "enum", "resume") and key in seen:
            continue
        seen.add(key)
        deduped.append(act)

    deduped.sort(key=lambda a: (a.priority, a.target_ip or "", a.port or 0))
    return deduped[:limit]


def get_top_action(
    targets: list[Target],
    credentials: list[Credential] | None = None,
    leads: list[Lead] | None = None,
) -> NextAction | None:
    """Single highest-value action, for compact surfaces like the stats banner."""
    actions = get_next_actions(targets, credentials, leads, limit=1)
    return actions[0] if actions else None


def detect_rabbit_holes(
    targets: list[Target],
    credentials: list[Credential] | None = None,
    leads: list[Lead] | None = None,
) -> StuckReport:
    """Analyzes the workspace for rabbit-hole symptoms and escape routes.

    A rabbit hole = accumulated dead ends while untouched surface or untried
    credentials remain. The report names concrete, state-derived exits instead
    of dumping generic commands.
    """
    credentials = credentials or []
    leads = leads or []
    report = StuckReport()

    live_targets = _unique_by_ip(
        [t for t in targets if t.in_scope and t.status != TargetStatus.IGNORED]
    )
    oos_count = len(targets) - len(live_targets)

    for t in live_targets:
        for svc in t.services:
            svc_tag = f"{t.ip}:{svc.port}/{svc.protocol} ({svc.name})"
            if svc.status == ServiceStatus.DEAD_END:
                report.dead_end_services.append(svc_tag)
            elif svc.status == ServiceStatus.UNTESTED and not _disproven_service(svc):
                report.untested_ports.append(svc_tag)

            for chk in svc.checklists:
                tag = f"{svc_tag} — {chk.title}"
                if chk.status == ChecklistStatus.DEAD_END:
                    report.dead_end_checks.append(tag)
                elif chk.status == ChecklistStatus.RUNNING:
                    report.running_checks.append(tag)
                elif chk.status == ChecklistStatus.TODO:
                    report.untested_ports.append(tag)

    for lead in leads:
        if lead.status == LeadStatus.BACKLOG:
            report.stale_leads.append(f"#{lead.id} {lead.title[:60]}")

    for cred in credentials:
        # A credential disproven everywhere it was tried is not an escape
        # route — mirror the spray gating in get_next_actions.
        if cred.tested_targets and not _cred_valid_somewhere(cred):
            continue
        untested = unsprayed_hosts_for_credential(cred, live_targets)
        if untested:
            preview = ", ".join(untested[:4]) + ("…" if len(untested) > 4 else "")
            report.unsprayed_credentials.append(f"{cred.username} → not tried on: {preview}")

    # Escape routes mirror the triage engine but only surface the categories
    # that counteract the stuck feeling. Resume counts: finishing interrupted
    # work is exactly how you climb out of a rabbit hole.
    escapes = get_next_actions(targets, credentials, leads, limit=8)
    report.suggestions = [a for a in escapes if a.kind in ("recon", "enum", "spray", "exploit", "resume")]

    if oos_count:
        report.suggestions.append(
            NextAction(
                priority=PRIORITY_CLEANUP,
                kind="cleanup",
                title=f"{oos_count} out-of-scope target(s) hidden from suggestions",
                rationale="Re-check scope ('o') if any of these were excluded by mistake.",
            )
        )

    return report



def evaluate_phase_progress(target, profile, repo) -> dict[str, PhaseProgress]:
    progress = {}
    phases = profile.get("phases", [])
    
    # Pre-populate phases
    for p in phases:
        progress[p["id"]] = PhaseProgress(phase_id=p["id"])
    
    # Gather evidence
    evidence_rows = repo._conn.execute("SELECT title, proof_type FROM evidence WHERE target_id = ?", (target.id,)).fetchall()
    proof_types = set()
    for row in evidence_rows:
        proof_types.add(row["proof_type"])
        # Map evidence to phase (simplistic: user/root flag to privesc, others to enum/exploit)
        if row["proof_type"] in ("user_flag", "root_flag") and "privesc" in progress:
            progress["privesc"].evidence.append(row["title"])
        elif "exploit" in progress:
            progress["exploit"].evidence.append(row["title"])
            
    # Gather checklists
    for svc in target.services:
        for chk in svc.checklists:
            cat = chk.category
            if cat not in progress:
                progress[cat] = PhaseProgress(phase_id=cat)
            
            p = progress[cat]
            if chk.status == ChecklistStatus.CHECKED:
                p.completed_checks.append(chk.title)
            elif chk.status == ChecklistStatus.TODO:
                p.pending_checks.append(chk.title)
                p.recommended_actions.append(NextAction(
                    priority=2, kind=cat, title=f"Run {chk.title}", rationale="Pending check", target_ip=target.ip
                ))
            elif chk.status == ChecklistStatus.RUNNING:
                p.running_checks.append(chk.title)
            elif chk.status == ChecklistStatus.DEAD_END:
                p.dead_ends.append(chk.title)
            elif chk.status == ChecklistStatus.FINDING:
                p.findings.append(chk.title)
                
    # Evaluate Status
    # Non-linear transitions (Privesc jump)
    has_foothold = target.status in (TargetStatus.FOOTHOLD, TargetStatus.PWNED) or "user_flag" in proof_types or "root_flag" in proof_types
    
    for p in phases:
        pid = p["id"]
        phase_prog = progress[pid]
        
        # Check dependencies
        deps = p.get("depends_on", [])
        blocked = False
        for d in deps:
            if d in progress:
                # If dependency is not completed and has work to do, it blocks us
                if progress[d].phase_status != PhaseStatus.COMPLETED and (progress[d].pending_checks or progress[d].running_checks or progress[d].phase_status == PhaseStatus.IN_PROGRESS):
                    blocked = True
        
        if pid == "privesc" and has_foothold:
            blocked = False
            if not phase_prog.pending_checks and not phase_prog.running_checks and not phase_prog.completed_checks and not phase_prog.findings and not phase_prog.evidence:
                phase_prog.phase_status = PhaseStatus.NOT_STARTED
            else:
                phase_prog.phase_status = PhaseStatus.IN_PROGRESS
            continue

        if blocked:
            phase_prog.phase_status = PhaseStatus.BLOCKED
            continue
            
        if phase_prog.pending_checks or phase_prog.running_checks:
            if phase_prog.completed_checks or phase_prog.running_checks or phase_prog.findings or phase_prog.dead_ends:
                phase_prog.phase_status = PhaseStatus.IN_PROGRESS
            else:
                phase_prog.phase_status = PhaseStatus.NOT_STARTED
        elif phase_prog.completed_checks or phase_prog.findings or phase_prog.dead_ends:
            phase_prog.phase_status = PhaseStatus.COMPLETED
        else:
            phase_prog.phase_status = PhaseStatus.NOT_STARTED
            
    return progress
