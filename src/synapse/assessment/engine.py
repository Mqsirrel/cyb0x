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

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

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


class PhaseStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


@dataclass
class PhaseProgress:
    """Guided-workflow view of one methodology phase for a single target."""

    phase_id: str
    completed_checks: list[str] = field(default_factory=list)
    pending_checks: list[str] = field(default_factory=list)
    running_checks: list[str] = field(default_factory=list)
    dead_ends: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommended_actions: list[NextAction] = field(default_factory=list)
    phase_status: PhaseStatus = PhaseStatus.NOT_STARTED
    blocked_reason: str | None = None

    @property
    def total_checks(self) -> int:
        return (
            len(self.completed_checks)
            + len(self.pending_checks)
            + len(self.running_checks)
            + len(self.dead_ends)
            + len(self.findings)
        )

    @property
    def resolved_checks(self) -> int:
        return len(self.completed_checks) + len(self.findings) + len(self.dead_ends)

    @property
    def completion_ratio(self) -> float:
        if self.total_checks == 0:
            return 1.0 if self.evidence else 0.0
        return self.resolved_checks / self.total_checks


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
    assessment_complete: bool = False

    @property
    def is_stuck(self) -> bool:
        """Stuck means: activity exists but nothing actionable is left open.

        Housekeeping hints (kind == "cleanup", e.g. the out-of-scope reminder)
        are not attack surface and must not mask a genuine stuck verdict, and a
        fully-owned scope is completion — silence there is success, not a trap.
        """
        if self.assessment_complete:
            return False
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
    admin creds, confirmed findings, owned-but-not-rooted privesc work), then
    untested enumeration surface, then sprays, resumptions, and housekeeping.
    Out-of-scope and ignored targets are excluded.
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

    # 2.7 Owned-but-not-rooted hosts with no open work: the main line is now
    # local privilege escalation. Without this nudge the triage board goes
    # silent at the exact moment the tester most needs direction (post-exploit).
    # Findings are deliberately NOT counted as open here: section 2.5 already
    # retires finding-nags once a host is owned, so counting them would keep
    # the host silent forever.
    for t in live_targets:
        if t.status != TargetStatus.FOOTHOLD:
            continue
        snap = snapshots[t.ip]
        if snap.checks_todo or snap.checks_running:
            continue  # pending surface / interrupted work already drive actions below
        actions.append(
            NextAction(
                priority=PRIORITY_EXPLOIT,
                kind="privesc",
                title=f"Enumerate privilege-escalation vectors on {snap.label}",
                rationale="Host at foothold but root not confirmed — hunt sudo rules, SUID binaries, and harvested credential reuse.",
                target_ip=t.ip,
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
        if act.kind in ("exploit", "enum", "resume", "privesc") and key in seen:
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
    report.assessment_complete = bool(live_targets) and all(
        t.status == TargetStatus.PWNED for t in live_targets
    )

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
    report.suggestions = [
        a for a in escapes if a.kind in ("recon", "enum", "spray", "exploit", "privesc", "resume")
    ]

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


# --- Guided methodology workflow (data-driven phase evaluation) -------------

# Rank order for target_status prerequisites: a phase unlocked at "foothold"
# stays unlocked once the target reaches "pwned".
_STATUS_RANK = {
    TargetStatus.DISCOVERED: 0,
    TargetStatus.SCANNING: 1,
    TargetStatus.ENUMERATED: 2,
    TargetStatus.FOOTHOLD: 3,
    TargetStatus.PWNED: 4,
}


def _prerequisite_met(cond, target: Target, evidence_by_type: dict[str, list[str]]) -> bool:
    if cond.condition_type == "target_status":
        try:
            required = _STATUS_RANK[TargetStatus(str(cond.value))]
        except (KeyError, ValueError):
            return False
        return _STATUS_RANK.get(target.status, 0) >= required
    if cond.condition_type == "evidence_type":
        return bool(evidence_by_type.get(str(cond.value)))
    return False


def evaluate_phase_progress(
    target: Target,
    profile,
    evidence: Iterable = (),
) -> dict[str, PhaseProgress]:
    """Evaluates guided-workflow phase state for one target against a profile.

    Pure function over repository models: ``profile`` is a
    ``MethodologyProfile`` and ``evidence`` an iterable of ``Evidence``
    (pass ``repo.list_evidence(target.id)``). No SQL, no LLM.

    Semantics (all data-driven from the profile):
    - Checks route to phases via ``checklist_categories`` (first phase by
      order wins when categories overlap).
    - A phase is BLOCKED until every ``depends_on`` phase is COMPLETED,
      unless any ``prerequisites`` condition is met (non-linear branch jump).
    - A phase is COMPLETED when no pending/running checks remain AND every
      ``evidence_required`` proof type has been captured.
    """
    phases = profile.ordered_phases()
    progress: dict[str, PhaseProgress] = {p.id: PhaseProgress(phase_id=p.id) for p in phases}

    category_owner: dict[str, str] = {}
    for p in phases:
        for cat in p.checklist_categories or []:
            category_owner.setdefault(cat, p.id)

    # Route checklist items into their phases.
    for svc in target.services:
        for chk in svc.checklists:
            pid = category_owner.get(chk.category)
            if pid is None:
                continue  # category not claimed by this profile's phases
            prog = progress[pid]
            if chk.status == ChecklistStatus.TODO:
                prog.pending_checks.append(chk.title)
                prog.recommended_actions.append(
                    NextAction(
                        priority=PRIORITY_ENUM,
                        kind=chk.category or "enum",
                        title=f"Run '{chk.title}' ({svc.name} on {svc.port}/tcp)",
                        rationale="Pending methodology check routed to this phase.",
                        target_ip=target.ip,
                        port=svc.port,
                    )
                )
            elif chk.status == ChecklistStatus.RUNNING:
                prog.running_checks.append(chk.title)
                prog.recommended_actions.append(
                    NextAction(
                        priority=PRIORITY_RESUME,
                        kind="resume",
                        title=f"Resume '{chk.title}' ({svc.name} on {svc.port}/tcp)",
                        rationale="Check left in RUNNING state — finish or mark the outcome.",
                        target_ip=target.ip,
                        port=svc.port,
                    )
                )
            elif chk.status == ChecklistStatus.CHECKED:
                prog.completed_checks.append(chk.title)
            elif chk.status == ChecklistStatus.FINDING:
                prog.findings.append(chk.title)
                prog.recommended_actions.append(
                    NextAction(
                        priority=PRIORITY_EXPLOIT,
                        kind="exploit",
                        title=f"Exploit finding '{chk.title}' ({svc.port}/tcp)",
                        rationale="Confirmed finding — capitalize on it before further enumeration.",
                        target_ip=target.ip,
                        port=svc.port,
                    )
                )
            elif chk.status == ChecklistStatus.DEAD_END:
                prog.dead_ends.append(chk.title)

    # Index captured evidence by proof type.
    evidence_by_type: dict[str, list[str]] = defaultdict(list)
    for ev in evidence:
        evidence_by_type[ev.proof_type.value].append(ev.title)

    # Attach required evidence to the phases that demand it.
    for p in phases:
        for ptype in p.evidence_required or []:
            progress[p.id].evidence.extend(evidence_by_type.get(ptype, []))

    phases_by_id = {p.id: p for p in phases}

    def _open_work(pid: str) -> tuple[bool, bool]:
        """(has_open_checks, missing_required_evidence) for a phase."""
        prog = progress[pid]
        open_checks = bool(prog.pending_checks or prog.running_checks)
        missing_ev = any(
            not evidence_by_type.get(t) for t in (phases_by_id[pid].evidence_required or [])
        )
        return open_checks, missing_ev

    _sat_cache: dict[str, bool] = {}

    def deps_satisfied(p, visiting: frozenset = frozenset()) -> bool:
        """True when every declared dependency is settled: completed outright,
        or carrying zero work whose own upstream is likewise settled (so
        sparse engagements aren't gated by permanently empty stages, while a
        genuinely unfinished upstream keeps the tail of the chain blocked).
        Cycles degrade to False."""
        for d in (p.depends_on or []):
            if d in visiting or d not in phases_by_id:
                return False
            if d in _sat_cache:
                ok = _sat_cache[d]
            else:
                prog = progress[d]
                open_checks, missing_ev = _open_work(d)
                resolved = bool(prog.completed_checks or prog.findings or prog.dead_ends or prog.evidence)
                if resolved:
                    ok = not open_checks and not missing_ev
                else:
                    # No work routed here yet: pass-through only if the whole
                    # upstream spine is equally clear.
                    ok = (
                        not open_checks
                        and not missing_ev
                        and deps_satisfied(phases_by_id[d], visiting | {d})
                    )
                _sat_cache[d] = ok
            if not ok:
                return False
        return True

    # A pristine engagement (no methodology surface routed anywhere yet) must
    # not present evidence-gated phases as active work: "capture user.txt"
    # before recon has even run inverts the workflow. The gate only becomes
    # live once some checklist surface exists.
    any_routed_surface = any(prog.total_checks for prog in progress.values())

    for p in phases:
        prog = progress[p.id]

        deps_met = deps_satisfied(p)
        prereq_hit = next(
            (
                c for c in (p.prerequisites or [])
                if _prerequisite_met(c, target, evidence_by_type)
            ),
            None,
        )

        if not deps_met and prereq_hit is None:
            waiting_on = ", ".join(d for d in (p.depends_on or []))
            prog.phase_status = PhaseStatus.BLOCKED
            prog.blocked_reason = f"Waiting on phase(s): {waiting_on}" if waiting_on else "Prerequisites not met."
            continue

        if prog.pending_checks or prog.running_checks:
            had_activity = bool(prog.completed_checks or prog.running_checks or prog.findings or prog.dead_ends)
            prog.phase_status = PhaseStatus.IN_PROGRESS if had_activity else PhaseStatus.NOT_STARTED
            continue

        missing_evidence = [
            t for t in (p.evidence_required or []) if not evidence_by_type.get(t)
        ]
        if missing_evidence:
            if not any_routed_surface:
                prog.phase_status = PhaseStatus.NOT_STARTED
                prog.blocked_reason = None
                continue
            prog.phase_status = PhaseStatus.IN_PROGRESS
            prog.blocked_reason = None
            prog.recommended_actions.append(
                NextAction(
                    priority=PRIORITY_EXPLOIT,
                    kind="exploit",
                    title=f"Capture required proof ({', '.join(missing_evidence)}) to close '{p.name}'",
                    rationale="All checks resolved but completion requires captured evidence.",
                    target_ip=target.ip,
                )
            )
            continue

        prog.phase_status = (
            PhaseStatus.COMPLETED
            if (prog.completed_checks or prog.findings or prog.dead_ends or prog.evidence)
            else PhaseStatus.NOT_STARTED
        )

    return progress
