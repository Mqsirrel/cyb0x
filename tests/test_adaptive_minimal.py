"""Tests for minimal adaptive enumeration improvements (DEFERRED status, check-level triage, phase ordering)."""

import pytest
from synapse.db.repository import DatabaseRepository
from synapse.models import ChecklistStatus, ServiceStatus, TargetStatus
from synapse.assessment.engine import (
    build_snapshots,
    detect_rabbit_holes,
    get_next_actions,
)
from synapse.tui.theme import checklist_chip


def test_deferred_status_lifecycle_and_coverage():
    """DEFERRED checklist items count toward resolved coverage without marking service DEAD_END."""
    repo = DatabaseRepository(":memory:")
    t = repo.add_or_get_target("10.10.10.10")
    svc = repo.add_or_update_service(t.id, 80, "tcp", "http")

    # Add 3 checks: 1 checked, 1 deferred (e.g. non-applicable IIS check), 1 todo
    c1 = repo.add_checklist_item(svc.id, title="HTTP Header Grab", status=ChecklistStatus.CHECKED)
    c2 = repo.add_checklist_item(svc.id, title="IIS WebDAV Check", status=ChecklistStatus.DEFERRED)
    c3 = repo.add_checklist_item(svc.id, title="Gobuster Fuzz", status=ChecklistStatus.TODO)

    snap = build_snapshots(repo.list_targets())["10.10.10.10"]
    assert snap.checks_total == 3
    assert snap.checks_done == 1
    assert snap.checks_deferred == 1
    assert snap.checks_todo == 1
    # Coverage should be 2/3 resolved (done + deferred)
    assert abs(snap.coverage - (2.0 / 3.0)) < 1e-6

    # Once all remaining checks are resolved (either checked or deferred), service becomes ENUMERATED
    repo.update_checklist_status(c3.id, ChecklistStatus.CHECKED)
    refreshed_svc = repo.refresh_service_state(svc.id)
    assert refreshed_svc.status == ServiceStatus.ENUMERATED


def test_deferred_checks_do_not_trigger_false_stuck_alarms():
    """Deferred checks must not count as dead-ends or open attack surface in rabbit-hole analysis."""
    repo = DatabaseRepository(":memory:")
    t = repo.add_or_get_target("10.10.10.10")
    svc = repo.add_or_update_service(t.id, 80, "tcp", "http")

    # Mark 1 check checked and 2 non-applicable checks as DEFERRED
    repo.add_checklist_item(svc.id, title="Basic HTTP Recon", status=ChecklistStatus.CHECKED)
    repo.add_checklist_item(svc.id, title="CGI Scan (Not Applicable)", status=ChecklistStatus.DEFERRED)
    repo.add_checklist_item(svc.id, title="WebDAV (Disabled)", status=ChecklistStatus.DEFERRED)

    report = detect_rabbit_holes(repo.list_targets())
    # Neither dead ends nor untested ports should contain the deferred items
    assert not report.dead_end_checks
    assert not report.untested_ports
    assert not report.is_stuck


def test_triage_next_action_recommends_specific_check_hint():
    """Triage 'n' recommends the specific priority check on an untested service, preferring recon."""
    repo = DatabaseRepository(":memory:")
    t = repo.add_or_get_target("10.10.10.20")
    svc = repo.add_or_update_service(t.id, 80, "tcp", "http")

    # Add checks with different categories
    repo.add_checklist_item(svc.id, category="exploit", title="Brute Force Login", status=ChecklistStatus.TODO)
    repo.add_checklist_item(svc.id, category="recon", title="Fingerprint Server Banner", status=ChecklistStatus.TODO)
    repo.add_checklist_item(svc.id, category="enum", title="Directory Enumeration", status=ChecklistStatus.TODO)

    actions = get_next_actions(repo.list_targets())
    enum_actions = [a for a in actions if a.kind == "enum"]
    assert len(enum_actions) == 1
    action = enum_actions[0]

    # Port should be present, and title should hint the recon check
    assert "80" in action.title
    assert "Fingerprint Server Banner" in action.title
    assert "Start with 'Fingerprint Server Banner'" in action.rationale


def test_checklist_theme_chip_deferred():
    """Verify DEFERRED chip renders cleanly in theme dictionary."""
    chip = checklist_chip(ChecklistStatus.DEFERRED)
    assert "DEFERRED" in chip
    assert "↷" in chip
