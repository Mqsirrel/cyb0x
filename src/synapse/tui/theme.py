"""SYNAPSE TUI theme: single source of truth for the "synapse" look.

Warm dark-charcoal surfaces, terracotta accent, cream text, sage/kraft
secondary tones. All widgets, modals, and chips must consume the constants
exported here instead of hardcoding hex values.
"""

from __future__ import annotations

from synapse.models import (
    ChecklistStatus,
    LeadPriority,
    LeadStatus,
    ServiceStatus,
    TargetStatus,
)

BACKGROUND = "#211E1B"
SURFACE = "#2A2622"
SURFACE_RAISED = "#332E29"
TERRACOTTA = "#D97757"
CREAM = "#EDE6DA"
MUTED = "#A8A099"
KRAFT = "#D4A27F"
SAGE = "#8FA876"
ERROR_RED = "#C4553B"

from textual.theme import Theme

SYNAPSE_THEME = Theme(
    name="synapse",
    primary=TERRACOTTA,
    secondary=KRAFT,
    accent=SAGE,
    foreground=CREAM,
    background=BACKGROUND,
    surface=SURFACE,
    panel=SURFACE_RAISED,
    warning=KRAFT,
    error=ERROR_RED,
    success=SAGE,
    dark=True,
    variables={
        "text-muted": MUTED,
        "surface-raised": SURFACE_RAISED,
        "block-cursor-background": TERRACOTTA,
    },
)

CHECKLIST_CHIP: dict[ChecklistStatus, str] = {
    ChecklistStatus.TODO: f"[dim {MUTED} on {SURFACE_RAISED}]   [ ] TODO   [/]",
    ChecklistStatus.RUNNING: f"[bold {BACKGROUND} on {KRAFT}] ⟳ RUNNING  [/]",
    ChecklistStatus.CHECKED: f"[bold {BACKGROUND} on {SAGE}] ✔ CHECKED  [/]",
    ChecklistStatus.FINDING: f"[bold {CREAM} on {ERROR_RED}] ★ FINDING  [/]",
    ChecklistStatus.DEAD_END: f"[dim {MUTED} on {SURFACE_RAISED}] ✖ DEAD-END [/]",
}

LEAD_PRIORITY_CHIP: dict[LeadPriority, str] = {
    LeadPriority.CRITICAL: f"[bold {CREAM} on {ERROR_RED}] CRITICAL [/]",
    LeadPriority.HIGH: f"[bold {BACKGROUND} on {TERRACOTTA}]   HIGH   [/]",
    LeadPriority.MEDIUM: f"[bold {BACKGROUND} on {KRAFT}]  MEDIUM  [/]",
    LeadPriority.LOW: f"[dim {MUTED} on {SURFACE_RAISED}]   LOW    [/]",
}

LEAD_STATUS_CHIP: dict[LeadStatus, str] = {
    LeadStatus.BACKLOG: f"[dim {MUTED} on {SURFACE_RAISED}]  BACKLOG   [/]",
    LeadStatus.IN_PROGRESS: f"[bold {BACKGROUND} on {KRAFT}] ⟳ PROGRESS [/]",
    LeadStatus.CONFIRMED: f"[bold {BACKGROUND} on {SAGE}] ✔ CONFIRMED[/]",
    LeadStatus.REJECTED: f"[strike dim {MUTED} on {SURFACE_RAISED}] ✖ REJECTED [/]",
}

SERVICE_STATUS_CHIP: dict[str, str] = {
    "untested": f"[bold {KRAFT}]UNTESTED[/bold {KRAFT}]",
    "in_progress": f"[{KRAFT}]IN PROGRESS[/]",
    "enumerated": f"[bold {SAGE}]ENUMERATED[/bold {SAGE}]",
    "vulnerable": f"[bold {ERROR_RED}]VULNERABLE[/bold {ERROR_RED}]",
    "dead_end": f"[dim {MUTED}]DEAD END[/dim {MUTED}]",
}

SERVICE_STATUS_GLYPH: dict[str, str] = {
    "untested": f"[bold {KRAFT}]?[/]",
    "in_progress": f"[{KRAFT}]⟳[/]",
    "enumerated": f"[{SAGE}]●[/]",
    "vulnerable": f"[bold {ERROR_RED}]⚡[/]",
    "dead_end": f"[dim]{MUTED}✖[/dim]",
}

TARGET_STATUS_GLYPH: dict[TargetStatus, str] = {
    TargetStatus.DISCOVERED: f"[{MUTED}]○[/]",
    TargetStatus.SCANNING: f"[{TERRACOTTA}]◐[/]",
    TargetStatus.ENUMERATED: f"[{SAGE}]●[/]",
    TargetStatus.FOOTHOLD: f"[{KRAFT}]★[/]",
    TargetStatus.PWNED: f"[bold {SAGE}]✔ PWNED[/]",
    TargetStatus.IGNORED: f"[dim]{MUTED}✖[/dim]",
}

TRIAGE_CHIP: dict[str, str] = {
    "RECON": f"[bold {BACKGROUND} on {KRAFT}]  RECON  [/]",
    "EXPLOIT": f"[bold {CREAM} on {ERROR_RED}] EXPLOIT [/]",
    "ENUM": f"[bold {BACKGROUND} on {SAGE}]   ENUM   [/]",
    "SPRAY": f"[bold {BACKGROUND} on {KRAFT}]   SPRAY  [/]",
    "RESUME": f"[bold {TERRACOTTA} on {SURFACE_RAISED}]  RESUME  [/]",
    "CLEANUP": f"[dim {MUTED} on {SURFACE_RAISED}] CLEANUP [/]",
}


def checklist_chip(status: ChecklistStatus) -> str:
    return CHECKLIST_CHIP.get(status, CHECKLIST_CHIP[ChecklistStatus.TODO])


def lead_priority_chip(priority: LeadPriority) -> str:
    return LEAD_PRIORITY_CHIP.get(priority, LEAD_PRIORITY_CHIP[LeadPriority.MEDIUM])


def lead_status_chip(status: LeadStatus) -> str:
    return LEAD_STATUS_CHIP.get(status, LEAD_STATUS_CHIP[LeadStatus.BACKLOG])


def service_status_chip(status_value: str) -> str:
    return SERVICE_STATUS_CHIP.get(
        status_value, f"[{MUTED}]{status_value.upper()}[/]"
    )


def service_status_glyph(status_value: str) -> str:
    return SERVICE_STATUS_GLYPH.get(status_value, SERVICE_STATUS_GLYPH["untested"])


def target_status_glyph(status: TargetStatus) -> str:
    return TARGET_STATUS_GLYPH.get(status, TARGET_STATUS_GLYPH[TargetStatus.DISCOVERED])


def triage_chip(priority_label: str) -> str:
    return TRIAGE_CHIP.get(priority_label, f"[dim {MUTED}]{'':^9}[/]")


def cred_test_chip(host_ip: str, valid: bool, admin: bool) -> str:
    host = host_ip
    if admin:
        return f"[bold {CREAM} on {SAGE}] {host}:✔(Admin) [/]"
    if valid:
        return f"[bold {SAGE}] {host}:✔ [/]"
    return f"[dim {ERROR_RED}] {host}:✖ [/]"


def result_chips(return_code: int, seconds: float, flags: int) -> str:
    if return_code == 0:
        exit_chip = f"[bold {BACKGROUND} on {SAGE}] ✔ EXIT {return_code} [/]"
    else:
        exit_chip = f"[bold {CREAM} on {ERROR_RED}] ✖ EXIT {return_code} [/]"
    time_chip = f"[{MUTED}]· {seconds:.1f}s ·[/]"
    flag_chip = (
        f"[bold {TERRACOTTA}] ⚑ {flags} FLAG{'S' if flags != 1 else ''} [/]"
        if flags
        else f"[dim {MUTED}] ⚑ 0 FLAGS [/]"
    )
    return f"{exit_chip} {time_chip} {flag_chip}"


def key_hint(key: str, action: str) -> str:
    return f"[reverse] {key} [/] [dim {MUTED}]{action}[/]"


def key_hint_bar(hints: list[tuple[str, str]]) -> str:
    return "   ".join(key_hint(key, action) for key, action in hints)


MODAL_CSS = """
SynapseModal {
    align: center middle;
}
#dialog {
    width: auto;
    height: auto;
    max-height: 92%;
    padding: 0 1 1 1;
    background: $surface;
    border: round $panel;
    border-title-color: $primary;
    border-title-style: bold;
}
#modal-context {
    color: $text-muted;
    margin-top: 1;
}
#modal-body {
    height: auto;
}
#action-bar {
    dock: bottom;
    height: auto;
    margin-top: 1;
}
#key-hints {
    width: 1fr;
    height: auto;
    padding-top: 1;
    color: $text-muted;
}
#action-buttons {
    width: auto;
    height: auto;
    align-horizontal: right;
}
#action-buttons Button {
    margin-left: 2;
    min-width: 14;
}
.field-label {
    margin-top: 1;
    text-style: bold;
}
.hidden {
    display: none;
}
"""
