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
from datetime import datetime, timezone
from typing import Dict, List, Optional

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
    target_ip: Optional[str] = None
    port: Optional[int] = None

    @property
    def priority_label(self) -> str:
        return _PRIORITY_LABELS.get(self.priority, "INFO")


@dataclass
class StuckReport:
    """Rabbit-hole triage: separates proven dead ends from untouched surface."""

    dead_end_services: List[str] = field(default_factory=list)
    dead_end_checks: List[str] = field(default_factory=list)
    untested_ports: List[str] = field(default_factory=list)
    unsprayed_credentials: List[str] = field(default_factory=list)
    stale_leads: List[str] = field(default_factory=list)
    suggestions: List[NextAction] = field(default_factory=list)

    @property
    def is_stuck(self) -> bool:
        """Stuck means: activity exists but nothing actionable is left open."""
        has_activity = bool(self.dead_end_services or self.dead_end_checks)
        no_open_surface = not (self.untested_ports or self.unsprayed_credentials or self.suggestions)
        return has_activity and no_open_surface


def build_snapshots(targets: List[Target], evidence_by_target: Optional[Dict[int, int]] = None,
                    flags_by_target: Optional[Dict[int, int]] = None,
                    valid_creds_by_ip: Optional[Dict[str, int]] = None) -> Dict[str, TargetSnapshot]:
    """Builds per-target state snapshots from batched repository data."""
    evidence_by_target = evidence_by_target or {}
    flags_by_target = flags_by_target or {}
    valid_creds_by_ip = valid_creds_by_ip or {}

    snaps: Dict[str, TargetSnapshot] = {}
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


def unsprayed_hosts_for_credential(cred: Credential, targets: List[Target]) -> List[str]:
    """In-scope hosts where this credential has never been attempted."""
    tested_hosts = {str(ip).split(":")[0] for ip in cred.tested_targets.keys()}
    return [
        t.ip
        for t in targets
        if t.in_scope and t.status != TargetStatus.IGNORED and t.ip not in tested_hosts
    ]


def get_next_actions(
    targets: List[Target],
    credentials: Optional[List[Credential]] = None,
    leads: Optional[List[Lead]] = None,
    limit: int = 10,
) -> List[NextAction]:
    """Derives the highest-value next investigations, deterministically ordered.

    Ordering: phase-0 gaps first, then confirmed-access opportunities (valid
    admin creds), then untested enumeration surface, then sprays, resumptions,
    and housekeeping. Out-of-scope and ignored targets are excluded.
    """
    credentials = credentials or []
    leads = leads or []
    actions: List[NextAction] = []

    live_targets = [t for t in targets if t.in_scope and t.status != TargetStatus.IGNORED]
    snapshots = build_snapshots(targets)

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

    # 3. Untested services with pending methodology checks.
    for t in live_targets:
        snap = snapshots[t.ip]
        if snap.is_bare:
            continue
        pending = sorted(s.port for s in t.services if s.status == ServiceStatus.UNTESTED)
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
        already_valid = any(
            isinstance(d, dict) and d.get("valid") for d in cred.tested_targets.values()
        )
        if not already_valid:
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
    deduped: List[NextAction] = []
    for act in sorted(actions, key=lambda a: (a.priority, a.title)):
        key = (act.kind, act.target_ip, act.port)
        if act.kind in ("exploit", "enum", "resume") and key in seen:
            continue
        seen.add(key)
        deduped.append(act)

    deduped.sort(key=lambda a: (a.priority, a.target_ip or "", a.port or 0))
    return deduped[:limit]


def get_top_action(
    targets: List[Target],
    credentials: Optional[List[Credential]] = None,
    leads: Optional[List[Lead]] = None,
) -> Optional[NextAction]:
    """Single highest-value action, for compact surfaces like the stats banner."""
    actions = get_next_actions(targets, credentials, leads, limit=1)
    return actions[0] if actions else None


def detect_rabbit_holes(
    targets: List[Target],
    credentials: Optional[List[Credential]] = None,
    leads: Optional[List[Lead]] = None,
) -> StuckReport:
    """Analyzes the workspace for rabbit-hole symptoms and escape routes.

    A rabbit hole = accumulated dead ends while untouched surface or untried
    credentials remain. The report names concrete, state-derived exits instead
    of dumping generic commands.
    """
    credentials = credentials or []
    leads = leads or []
    report = StuckReport()

    live_targets = [t for t in targets if t.in_scope and t.status != TargetStatus.IGNORED]
    oos_count = len(targets) - len(live_targets)

    for t in live_targets:
        for svc in t.services:
            svc_tag = f"{t.ip}:{svc.port}/{svc.protocol} ({svc.name})"
            if svc.status == ServiceStatus.DEAD_END:
                report.dead_end_services.append(svc_tag)
            elif svc.status == ServiceStatus.UNTESTED:
                report.untested_ports.append(svc_tag)

            for chk in svc.checklists:
                tag = f"{svc_tag} — {chk.title}"
                if chk.status == ChecklistStatus.DEAD_END:
                    report.dead_end_checks.append(tag)
                elif chk.status == ChecklistStatus.TODO:
                    report.untested_ports.append(tag)

    for lead in leads:
        if lead.status == LeadStatus.BACKLOG:
            report.stale_leads.append(f"#{lead.id} {lead.title[:60]}")

    for cred in credentials:
        untested = unsprayed_hosts_for_credential(cred, live_targets)
        if untested:
            preview = ", ".join(untested[:4]) + ("…" if len(untested) > 4 else "")
            report.unsprayed_credentials.append(f"{cred.username} → not tried on: {preview}")

    # Escape routes mirror the triage engine but only surface the categories
    # that counteract the stuck feeling.
    escapes = get_next_actions(targets, credentials, leads, limit=8)
    report.suggestions = [a for a in escapes if a.kind in ("recon", "enum", "spray", "exploit")]

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
