"""Unit tests for the deterministic assessment engine."""

from datetime import datetime, timedelta, timezone

from synapse.assessment import (
    build_snapshots,
    detect_rabbit_holes,
    get_next_actions,
    get_top_action,
    unsprayed_hosts_for_credential,
)
from synapse.db.repository import DatabaseRepository
from synapse.models import (
    ChecklistStatus,
    Credential,
    CredentialType,
    Lead,
    LeadPriority,
    ServiceStatus,
    TargetStatus,
)


def _seed_repo() -> DatabaseRepository:
    return DatabaseRepository(":memory:")


def test_bare_target_routes_to_recon_first():
    repo = _seed_repo()
    repo.add_or_get_target("10.10.10.5", hostname="dc01.corp.local")

    actions = get_next_actions(repo.list_targets())
    assert actions, "A bare target must always yield an action"
    assert actions[0].kind == "recon"
    assert actions[0].priority == 0
    assert "initial reconnaissance" in actions[0].title.lower()
    assert "attack surface is unknown" in actions[0].rationale


def test_untested_services_generate_enum_actions_with_ports():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5")
    svc = repo.add_or_update_service(t.id, 445, "tcp", "microsoft-ds")
    repo.add_or_update_service(t.id, 22, "tcp", "ssh")

    actions = get_next_actions(repo.list_targets())
    enum_actions = [a for a in actions if a.kind == "enum"]
    assert len(enum_actions) == 1
    assert "445" in enum_actions[0].title and "22" in enum_actions[0].title
    assert svc.port == 445


def test_valid_admin_cred_on_unowned_host_suggests_exploit():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5")
    cred = repo.add_credential("administrator", "Secret123!", target_id=t.id)
    repo.record_credential_test(cred.id, "10.10.10.5", service="smb", valid=True, admin=True)

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    exploit_actions = [a for a in actions if a.kind == "exploit"]
    assert exploit_actions, "Admin-valid cred on non-foothold host must surface an exploit action"
    assert "administrator" in exploit_actions[0].title


def test_no_exploit_suggestion_once_host_is_pwned():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5", status=TargetStatus.PWNED)
    cred = repo.add_credential("administrator", "Secret123!", target_id=t.id)
    repo.record_credential_test(cred.id, "10.10.10.5", valid=True, admin=True)

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert not [a for a in actions if a.kind == "exploit"]


def test_credential_spray_gap_detected():
    repo = _seed_repo()
    t1 = repo.add_or_get_target("10.10.10.5")
    repo.add_or_get_target("10.10.10.6")
    repo.add_or_get_target("10.10.10.7")
    cred = repo.add_credential("svc-backup", "Passw0rd", target_id=t1.id)
    # Valid only on .5
    repo.record_credential_test(cred.id, "10.10.10.5", valid=True)

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    sprays = [a for a in actions if a.kind == "spray"]
    assert sprays, "Valid cred with untested hosts must suggest spraying"
    assert "svc-backup" in sprays[0].title
    assert "2 in-scope host(s)" in sprays[0].rationale


def test_out_of_scope_targets_excluded_from_all_suggestions():
    repo = _seed_repo()
    live = repo.add_or_get_target("10.10.10.5")
    oos = repo.add_or_get_target("10.10.10.9")
    repo.set_target_scope(oos.id, False)

    cred = repo.add_credential("admin", "pw", target_id=live.id)
    repo.record_credential_test(cred.id, "10.10.10.5", valid=True)
    # Cred never tried on the out-of-scope host -> no spray suggestion may mention it
    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    for a in actions:
        if a.kind == "spray":
            assert "10.10.10.9" not in a.title and "10.10.10.9" not in a.rationale

    report = detect_rabbit_holes(repo.list_targets(), repo.list_credentials())
    for line in report.unsprayed_credentials:
        assert "10.10.10.9" not in line
    # But the report should hint that hidden targets exist
    assert any("out-of-scope" in s.title.lower() for s in report.suggestions)


def test_ignored_status_excluded_like_out_of_scope():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5", status=TargetStatus.IGNORED)
    actions = get_next_actions(repo.list_targets())
    assert not [a for a in actions if a.target_ip == t.ip]


def test_snapshot_coverage_and_counts():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5")
    svc = repo.add_or_update_service(t.id, 80, "tcp", "http")
    c1 = repo.add_checklist_item(svc.id, title="dirb scan")
    c2 = repo.add_checklist_item(svc.id, title="nikto scan")
    c3 = repo.add_checklist_item(svc.id, title="dead end check")
    repo.update_checklist_status(c1.id, ChecklistStatus.CHECKED)
    repo.update_checklist_status(c3.id, ChecklistStatus.DEAD_END)
    assert c2.status == ChecklistStatus.TODO  # untouched

    snaps = build_snapshots(repo.list_targets())
    snap = snaps["10.10.10.5"]
    assert snap.services_total == 1
    assert snap.services_untested == 1
    assert snap.checks_total == 3
    assert snap.checks_done == 1
    assert snap.checks_dead_end == 1
    assert abs(snap.coverage - (2 / 3)) < 1e-9


def test_running_checks_generate_resume_action():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5")
    svc = repo.add_or_update_service(t.id, 21, "tcp", "ftp")
    chk = repo.add_checklist_item(svc.id, title="anon FTP probe")
    repo.update_checklist_status(chk.id, ChecklistStatus.RUNNING)

    actions = get_next_actions(repo.list_targets())
    resumes = [a for a in actions if a.kind == "resume"]
    assert resumes and "anon FTP probe" in resumes[0].title
    assert resumes[0].port == 21


def test_stale_lead_generates_cleanup_action():
    old_lead = Lead(
        id=1,
        title="Old hypothesis",
        priority=LeadPriority.MEDIUM,
        created_at=datetime.now(timezone.utc) - timedelta(days=5),
        updated_at=datetime.now(timezone.utc),
    )
    repo = _seed_repo()
    repo.add_or_get_target("10.10.10.5")
    actions = get_next_actions(repo.list_targets(), [], [old_lead])
    cleanups = [a for a in actions if a.kind == "cleanup"]
    assert cleanups and "Old hypothesis" in cleanups[0].title


def test_fresh_lead_not_flagged_stale():
    fresh_lead = Lead(
        id=1,
        title="Fresh hypothesis",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    repo = _seed_repo()
    repo.add_or_get_target("10.10.10.5")
    actions = get_next_actions(repo.list_targets(), [], [fresh_lead])
    assert not [a for a in actions if a.kind == "cleanup"]


def test_rabbit_hole_signature_requires_dead_ends_without_surface():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5")
    svc = repo.add_or_update_service(t.id, 3306, "tcp", "mysql")
    chk = repo.add_checklist_item(svc.id, title="default creds mysql")
    repo.update_checklist_status(chk.id, ChecklistStatus.DEAD_END)
    repo.update_service_status(svc.id, ServiceStatus.DEAD_END)

    report = detect_rabbit_holes(repo.list_targets(), [], [])
    assert report.dead_end_services
    assert report.is_stuck, "All checks dead-ended with zero open surface -> stuck"

    # Adding one untested port breaks the stuck signature
    repo.add_or_update_service(t.id, 8443, "tcp", "http-alt")
    report2 = detect_rabbit_holes(repo.list_targets(), [], [])
    assert not report2.is_stuck
    assert any(a.kind == "enum" for a in report2.suggestions)


def test_unsprayed_hosts_respects_compound_keys_and_scope():
    repo = _seed_repo()
    repo.add_or_get_target("10.10.10.5")
    repo.add_or_get_target("10.10.10.6")
    oos = repo.add_or_get_target("10.10.10.99")
    repo.set_target_scope(oos.id, False)

    cred = Credential(
        id=1,
        username="bob",
        secret="x",
        cred_type=CredentialType.PASSWORD,
        tested_targets={"10.10.10.5:smb": {"target_ip": "10.10.10.5", "valid": True}},
    )
    untested = unsprayed_hosts_for_credential(cred, repo.list_targets())
    assert untested == ["10.10.10.6"]


def test_get_top_action_prefers_recon():
    repo = _seed_repo()
    repo.add_or_get_target("10.10.10.5")
    top = get_top_action(repo.list_targets())
    assert top is not None and top.kind == "recon"


def test_engine_is_deterministic():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5")
    repo.add_or_update_service(t.id, 22, "tcp", "ssh")
    repo.add_or_update_service(t.id, 80, "tcp", "http")
    cred = repo.add_credential("a", "b", target_id=t.id)
    repo.record_credential_test(cred.id, "10.10.10.5", valid=True)

    inputs = (repo.list_targets(), repo.list_credentials(), [])
    first = get_next_actions(*inputs)
    second = get_next_actions(*inputs)
    assert [(a.title, a.priority, a.target_ip, a.port) for a in first] == [
        (a.title, a.priority, a.target_ip, a.port) for a in second
    ]
