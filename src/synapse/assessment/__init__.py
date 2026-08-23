"""Deterministic engagement assessment: state snapshots, next actions, rabbit-hole detection."""

from synapse.assessment.engine import (
    NextAction,
    StuckReport,
    TargetSnapshot,
    build_snapshots,
    detect_rabbit_holes,
    get_next_actions,
    get_top_action,
    unsprayed_hosts_for_credential,
)

__all__ = [
    "NextAction",
    "StuckReport",
    "TargetSnapshot",
    "build_snapshots",
    "detect_rabbit_holes",
    "get_next_actions",
    "get_top_action",
    "unsprayed_hosts_for_credential",
]
