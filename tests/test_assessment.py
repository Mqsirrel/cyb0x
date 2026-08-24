"""Unit tests for the deterministic assessment engine."""

from datetime import datetime, timedelta, timezone

from synapse.assessment import (
    build_snapshots,
    detect_rabbit_holes,
    get_next_actions,
    get_top_action,
    unsprayed_hosts_for_credential,
)
from synapse.assessment.engine import PRIORITY_EXPLOIT
from synapse.db.repository import DatabaseRepository
from synapse.models import (
    ChecklistItem,
    ChecklistStatus,
    Credential,
    CredentialType,
    Lead,
    LeadPriority,
    LeadStatus,
    Service,
    ServiceStatus,
    Target,
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


def test_multiple_admin_credentials_same_host_collapse_to_one_exploit():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5")
    c1 = repo.add_credential("administrator", "pw1", target_id=t.id)
    c2 = repo.add_credential("svc-admin", "pw2", target_id=t.id)
    repo.record_credential_test(c1.id, "10.10.10.5", valid=True, admin=True)
    repo.record_credential_test(c2.id, "10.10.10.5", valid=True, admin=True)

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    exploits = [a for a in actions if a.kind == "exploit" and a.target_ip == "10.10.10.5"]
    assert len(exploits) == 1, "several admin-valid creds on one host are one move"


def test_foothold_status_suppresses_exploit_suggestion():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5", status=TargetStatus.FOOTHOLD)
    cred = repo.add_credential("administrator", "pw", target_id=t.id)
    repo.record_credential_test(cred.id, "10.10.10.5", valid=True, admin=True)

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert not [a for a in actions if a.kind == "exploit"]


def test_valid_non_admin_cred_does_not_suggest_exploit():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5")
    svc = repo.add_or_update_service(t.id, 22, "tcp", "ssh")
    repo.add_checklist_item(svc.id, title="banner check")
    cred = repo.add_credential("lowpriv", "pw", target_id=t.id)
    repo.record_credential_test(cred.id, "10.10.10.5", valid=True, admin=False)

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert not [a for a in actions if a.kind == "exploit"]


def test_spray_suppressed_once_every_live_host_tested():
    repo = _seed_repo()
    t1 = repo.add_or_get_target("10.10.10.5")
    t2 = repo.add_or_get_target("10.10.10.6")
    svc2 = repo.add_or_update_service(t2.id, 22, "tcp", "ssh")  # keep .6 non-bare
    repo.add_checklist_item(svc2.id, title="check")
    cred = repo.add_credential("svc", "pw", target_id=t1.id)
    repo.record_credential_test(cred.id, "10.10.10.5", valid=True)
    repo.record_credential_test(cred.id, "10.10.10.6", valid=True)

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert not [a for a in actions if a.kind == "spray"]


def test_todo_checks_surface_resume_when_no_untested_services_left():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5")
    svc = repo.add_or_update_service(t.id, 80, "tcp", "http", status=ServiceStatus.ENUMERATED)
    done = repo.add_checklist_item(svc.id, title="headers")
    todo = repo.add_checklist_item(svc.id, title="dirb sweep")
    repo.update_checklist_status(done.id, ChecklistStatus.CHECKED)

    actions = get_next_actions(repo.list_targets())
    resumes = [a for a in actions if a.kind == "resume"]
    assert resumes and "remaining check(s)" in resumes[0].title
    assert not [a for a in actions if a.kind == "enum"]


def test_running_check_defers_todo_resume_to_interrupted_work():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5")
    svc = repo.add_or_update_service(t.id, 80, "tcp", "http")
    running = repo.add_checklist_item(svc.id, title="nikto long scan")
    todo = repo.add_checklist_item(svc.id, title="dirb sweep")
    repo.update_checklist_status(running.id, ChecklistStatus.RUNNING)

    actions = get_next_actions(repo.list_targets())
    resume_titles = [a.title for a in actions if a.kind == "resume"]
    assert any("Resume" in t_ for t_ in resume_titles)
    assert not any("Work through" in t_ for t_ in resume_titles), (
        "TODO backlog must not compete with an interrupted RUNNING check"
    )


def test_dead_end_services_excluded_from_enum_pending():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.10.5")
    dead = repo.add_or_update_service(t.id, 3306, "tcp", "mysql", status=ServiceStatus.DEAD_END)
    repo.add_checklist_item(dead.id, title="default creds", status=ChecklistStatus.DEAD_END)

    actions = get_next_actions(repo.list_targets())
    assert not [a for a in actions if a.kind == "enum"], "dead-ended port must not resurface as pending"


def test_action_limit_truncates_output():
    repo = _seed_repo()
    for i in range(6):
        repo.add_or_get_target(f"10.10.10.{i + 1}")
    actions = get_next_actions(repo.list_targets(), limit=2)
    assert len(actions) == 2


# ---------------------------------------------------------------------------
# End-to-end scenario traces (one per engagement state)
# ---------------------------------------------------------------------------

def test_scenario1_fresh_target_knows_nothing_but_recon():
    """Unknown ≠ tested-clean: a bare host has no coverage and one move."""
    repo = _seed_repo()
    repo.add_or_get_target("10.0.0.1", hostname="fresh.corp.local")

    snap = build_snapshots(repo.list_targets())["10.0.0.1"]
    assert snap.is_bare
    assert snap.services_total == 0
    assert snap.coverage == 1.0  # vacuously complete: nothing planned yet

    actions = get_next_actions(repo.list_targets())
    assert [a.kind for a in actions] == ["recon"], "bare host must produce exactly recon"
    assert "attack surface is unknown" in actions[0].rationale


def test_scenario2_http_enum_then_silence_once_complete():
    """Completing the enum action must remove it — no repeat recommendations."""
    repo = _seed_repo()
    t = repo.add_or_get_target("10.0.0.2")
    svc = repo.add_or_update_service(t.id, 80, "tcp", "http", product="nginx")
    chk = repo.add_checklist_item(svc.id, title="dirb sweep")

    actions = get_next_actions(repo.list_targets())
    assert [a.kind for a in actions] == ["enum"]
    assert "80" in actions[0].title

    # Simulate the operator finishing the work.
    repo.update_checklist_status(chk.id, ChecklistStatus.CHECKED)
    repo.refresh_service_state(svc.id)
    assert get_next_actions(repo.list_targets()) == [], "finished host must go quiet"


def test_scenario3_smb_dead_end_moves_to_rabbit_hole_not_pending():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.0.0.3")
    svc = repo.add_or_update_service(t.id, 445, "tcp", "microsoft-ds")
    chk = repo.add_checklist_item(svc.id, title="enum4linux")
    assert get_next_actions(repo.list_targets())[0].kind == "enum"

    repo.update_checklist_status(chk.id, ChecklistStatus.DEAD_END)
    repo.refresh_service_state(svc.id)

    actions = get_next_actions(repo.list_targets())
    assert not [a for a in actions if a.target_ip == "10.0.0.3"], "dead-end port must not resurface"

    report = detect_rabbit_holes(repo.list_targets(), [], [])
    assert any("445" in s for s in report.dead_end_services)
    assert report.is_stuck


def test_scenario4_credential_lifecycle_updates_recommendations():
    """Admin cred → exploit + spray; owning the box and recording tests retires both."""
    repo = _seed_repo()
    t1 = repo.add_or_get_target("10.0.0.4")
    svc = repo.add_or_update_service(t1.id, 22, "tcp", "ssh")
    repo.add_checklist_item(svc.id, title="banner grab")
    t2 = repo.add_or_get_target("10.0.0.8")
    repo.add_or_update_service(t2.id, 22, "tcp", "ssh")

    cred = repo.add_credential("root", "toor", target_id=t1.id)
    repo.record_credential_test(cred.id, "10.0.0.4", valid=True, admin=True)

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    exploits = [a for a in actions if a.kind == "exploit" and a.port is None]
    sprays = [a for a in actions if a.kind == "spray"]
    assert exploits and sprays, "admin-valid cred must drive exploit; other hosts drive spray"
    assert "10.0.0.8" in sprays[0].title
    assert exploits[0].priority < sprays[0].priority, "confirmed access outranks spraying"

    # Completing those actions retires them.
    repo.record_credential_test(cred.id, "10.0.0.8", valid=False)
    repo.update_target_status(t1.id, TargetStatus.PWNED)
    actions2 = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert not [a for a in actions2 if a.kind == "exploit"]
    assert not [a for a in actions2 if a.kind == "spray"]


def test_scenario5_partial_progress_lists_only_untouched_surface():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.0.0.5")
    done_svc = repo.add_or_update_service(t.id, 21, "tcp", "ftp", status=ServiceStatus.ENUMERATED)
    repo.add_checklist_item(done_svc.id, title="anon ftp", status=ChecklistStatus.CHECKED)
    todo_svc = repo.add_or_update_service(t.id, 139, "tcp", "netbios-ssn")
    repo.add_checklist_item(todo_svc.id, title="nbtstat scan")

    snap = build_snapshots(repo.list_targets())["10.0.0.5"]
    assert snap.services_enumerated == 1 and snap.services_untested == 1
    assert abs(snap.coverage - 0.5) < 1e-9, "one of two checks resolved"

    actions = get_next_actions(repo.list_targets())
    enums = [a for a in actions if a.kind == "enum"]
    resumes = [a for a in actions if a.kind == "resume"]
    assert len(enums) == 1, "one consolidated enum action per host"
    assert "139" in enums[0].title and "(21)" not in enums[0].title
    assert not resumes, "TODO backlog must not compete with untouched ports"


def test_scenario6_confirmed_finding_becomes_top_exploit_action():
    """Regression: a VULNERABLE host used to produce ZERO recommendations."""
    repo = _seed_repo()
    t = repo.add_or_get_target("10.0.0.6")
    svc = repo.add_or_update_service(t.id, 80, "tcp", "http")
    repo.add_checklist_item(svc.id, title="shellshock cgi", status=ChecklistStatus.FINDING)
    repo.add_checklist_item(svc.id, title="dirb sweep")  # sibling TODO surface

    snap = build_snapshots(repo.list_targets())["10.0.0.6"]
    assert snap.checks_finding == 1

    actions = get_next_actions(repo.list_targets())
    exploits = [a for a in actions if a.kind == "exploit" and a.port == 80]
    assert exploits, "confirmed finding must drive the next move"
    assert exploits[0].priority == PRIORITY_EXPLOIT
    assert "shellshock cgi" in exploits[0].title
    assert "findings" in exploits[0].rationale
    assert any(a.kind == "enum" for a in actions), "untouched sibling surface still listed"

    # Gaining foothold retires the exploit nag, like admin-cred suggestions.
    repo.update_target_status(t.id, TargetStatus.FOOTHOLD)
    assert not [a for a in get_next_actions(repo.list_targets()) if a.kind == "exploit"]


def test_scenario6b_multiple_findings_on_one_service_collapse():
    repo = _seed_repo()
    t = repo.add_or_get_target("10.0.0.6")
    svc = repo.add_or_update_service(t.id, 443, "tcp", "https")
    repo.add_checklist_item(svc.id, title="heartbleed", status=ChecklistStatus.FINDING)
    repo.add_checklist_item(svc.id, title="weak cipher", status=ChecklistStatus.FINDING)

    actions = get_next_actions(repo.list_targets())
    exploits = [a for a in actions if a.kind == "exploit" and a.port == 443]
    assert len(exploits) == 1, "several findings on one service are one move"
    assert "heartbleed" in exploits[0].title and "(+1 more)" in exploits[0].title


def test_scenario7_running_check_blocks_false_stuck_verdict():
    """Regression: interrupted work was invisible to rabbit-hole detection."""
    repo = _seed_repo()
    t = repo.add_or_get_target("10.0.0.7")
    dead_svc = repo.add_or_update_service(t.id, 3306, "tcp", "mysql")
    repo.add_checklist_item(dead_svc.id, title="default creds", status=ChecklistStatus.DEAD_END)
    busy_svc = repo.add_or_update_service(t.id, 25, "tcp", "smtp")
    run_chk = repo.add_checklist_item(busy_svc.id, title="smtp user enum")
    repo.update_checklist_status(run_chk.id, ChecklistStatus.RUNNING)
    repo.refresh_service_state(dead_svc.id)
    repo.refresh_service_state(busy_svc.id)

    report = detect_rabbit_holes(repo.list_targets(), [], [])
    assert report.running_checks and "smtp user enum" in report.running_checks[0]
    assert not report.is_stuck, "an interrupted check is open work, not a dead end"
    assert any(a.kind == "resume" for a in report.suggestions), "resume is an escape route"

    # Finishing the interrupted check leaves pure dead-end -> genuinely stuck.
    repo.update_checklist_status(run_chk.id, ChecklistStatus.DEAD_END)
    repo.refresh_service_state(busy_svc.id)
    report2 = detect_rabbit_holes(repo.list_targets(), [], [])
    assert not report2.running_checks
    assert report2.is_stuck


def test_scenario8_multi_target_ordering_is_phase_ordered_and_deterministic():
    repo = _seed_repo()
    repo.add_or_get_target("10.0.0.9")                                   # recon tier
    http = repo.add_or_get_target("10.0.0.10")                           # enum tier
    repo.add_or_update_service(http.id, 8080, "tcp", "http")
    own = repo.add_or_get_target("10.0.0.11")                            # exploit tier
    osvc = repo.add_or_update_service(own.id, 445, "tcp", "microsoft-ds")
    repo.add_checklist_item(osvc.id, title="null session")
    cred = repo.add_credential("admin", "admin", target_id=own.id)
    repo.record_credential_test(cred.id, "10.0.0.11", valid=True, admin=True)

    inputs = (repo.list_targets(), repo.list_credentials(), [])
    actions = get_next_actions(*inputs, limit=10)

    priorities = [a.priority for a in actions]
    assert priorities == sorted(priorities), "actions must be phase-ordered"
    kinds = [a.kind for a in actions]
    assert kinds[0] == "recon"
    assert kinds.index("exploit") < kinds.index("enum"), "confirmed access beats exploration"

    rerun = get_next_actions(*inputs, limit=10)
    assert [(a.kind, a.target_ip, a.port) for a in actions] == [
        (a.kind, a.target_ip, a.port) for a in rerun
    ], "identical state must yield identical ordering"


def test_scenario8b_out_of_scope_host_never_leaks_into_any_action_kind():
    """Scope enforcement must survive every path, including findings and sprays."""
    repo = _seed_repo()
    live = repo.add_or_get_target("10.0.0.12")
    lsvc = repo.add_or_update_service(live.id, 80, "tcp", "http")
    repo.add_checklist_item(lsvc.id, title="rce probe", status=ChecklistStatus.FINDING)
    cred = repo.add_credential("sa", "sa", target_id=live.id)
    repo.record_credential_test(cred.id, "10.0.0.12", valid=True, admin=True)

    oos = repo.add_or_get_target("10.9.9.9")
    repo.set_target_scope(oos.id, False)
    osvc = repo.add_or_update_service(oos.id, 80, "tcp", "http")
    repo.add_checklist_item(osvc.id, title="oos finding", status=ChecklistStatus.FINDING)

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    for a in actions:
        assert a.target_ip != "10.9.9.9", f"{a.kind} leaked an out-of-scope host"

    report = detect_rabbit_holes(repo.list_targets(), repo.list_credentials())
    leaked = (
        report.dead_end_services
        + report.dead_end_checks
        + report.running_checks
        + report.untested_ports
        + report.unsprayed_credentials
        + [f"{s.title} {s.rationale}" for s in report.suggestions]
    )
    for line in leaked:
        assert "10.9.9.9" not in line


# ---------------------------------------------------------------------------
# Adversarial states (loophole regressions: engine must be hard to fool)
# ---------------------------------------------------------------------------

def _seed_disproven_service(repo, ip, port=3306, name="mysql"):
    """Service whose cached status is UNTESTED but whose only methodology
    check already came back DEAD_END (caller skipped refresh_service_state)."""
    t = repo.add_or_get_target(ip)
    svc = repo.add_or_update_service(t.id, port, "tcp", name)  # stale UNTESTED cache
    chk = repo.add_checklist_item(svc.id, title="default creds")
    repo.update_checklist_status(chk.id, ChecklistStatus.DEAD_END)
    return t


def test_adversary1_stale_cache_must_not_resurrect_disproven_port():
    """A disproven surface behind a stale UNTESTED status is not enum work."""
    repo = _seed_repo()
    _seed_disproven_service(repo, "10.10.20.1")

    actions = get_next_actions(repo.list_targets())
    assert not [a for a in actions if a.kind == "enum"], (
        "checklist DEAD_END outranks the cached service status — no re-enum"
    )


def test_adversary1b_fully_disproven_host_is_a_rabbit_hole():
    """The same stale cache must not fake 'open surface' in the stuck report."""
    repo = _seed_repo()
    _seed_disproven_service(repo, "10.10.20.2")

    report = detect_rabbit_holes(repo.list_targets())
    assert report.dead_end_checks, "the disproven check is the dead-end evidence"
    assert not report.untested_ports, "disproven port must not count as untouched"
    assert report.is_stuck, "everything tried and disproven -> genuinely stuck"


def test_adversary2_disproven_credential_is_not_an_escape_route():
    """A cred rejected on every host it was tried on must not block or pollute
    the stuck verdict, matching the spray gating in get_next_actions."""
    repo = _seed_repo()
    t1 = repo.add_or_get_target("10.10.21.1")
    svc = repo.add_or_update_service(t1.id, 445, "tcp", "microsoft-ds")
    chk = repo.add_checklist_item(svc.id, title="null session")
    repo.update_checklist_status(chk.id, ChecklistStatus.DEAD_END)
    repo.refresh_service_state(svc.id)

    bad_cred = repo.add_credential("bob", "wrongpw", target_id=t1.id)
    repo.record_credential_test(bad_cred.id, "10.10.21.1", valid=False)

    # While another host still has open surface the report stays honest...
    t2 = repo.add_or_get_target("10.10.21.2")
    svc2 = repo.add_or_update_service(t2.id, 22, "tcp", "ssh")
    banner = repo.add_checklist_item(svc2.id, title="banner grab")
    report = detect_rabbit_holes(repo.list_targets(), repo.list_credentials())
    assert not report.unsprayed_credentials, "rejected cred is not an untried asset"

    # ...and once that surface closes, the invalid cred cannot mask 'stuck'.
    repo.update_checklist_status(banner.id, ChecklistStatus.CHECKED)
    repo.refresh_service_state(svc2.id)
    report2 = detect_rabbit_holes(repo.list_targets(), repo.list_credentials())
    assert report2.is_stuck


def test_adversary3_oos_hint_does_not_mask_genuine_stuck_verdict():
    """Housekeeping suggestions are not attack surface: all-dead-end work plus
    an out-of-scope target is still a rabbit hole."""
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.22.1")
    svc = repo.add_or_update_service(t.id, 21, "tcp", "ftp")
    chk = repo.add_checklist_item(svc.id, title="anon ftp")
    repo.update_checklist_status(chk.id, ChecklistStatus.DEAD_END)
    repo.refresh_service_state(svc.id)

    oos = repo.add_or_get_target("10.10.22.99")
    repo.set_target_scope(oos.id, False)

    report = detect_rabbit_holes(repo.list_targets())
    assert any(s.kind == "cleanup" for s in report.suggestions), "scope hint still offered"
    assert report.is_stuck, "cleanup hint must not impersonate open attack surface"


def test_adversary4_duplicate_target_rows_cannot_resurrect_recon():
    """Hand-built model lists may carry one IP twice; known services win and
    recon is neither phantom-recommended nor duplicated."""
    served = Target(
        id=1,
        ip="10.10.23.1",
        services=[
            Service(
                id=1,
                target_id=1,
                port=80,
                name="http",
                checklists=[ChecklistItem(id=1, service_id=1, title="dirb sweep")],
            )
        ],
    )
    bare_twin = Target(id=2, ip="10.10.23.1")

    actions = get_next_actions([served, bare_twin])
    assert not [a for a in actions if a.kind == "recon"], (
        "recon already completed: services are known, duplicates must not undo it"
    )
    assert [a.kind for a in actions] == ["enum"]


def test_adversary5_all_five_check_statuses_on_one_host_yield_clean_plan():
    """TODO/RUNNING/CHECKED/FINDING/DEAD_END mixed: exactly exploit + enum +
    resume, with the finding ranked first and no todo-backlog competition."""
    repo = _seed_repo()
    t = repo.add_or_get_target("10.10.24.1")
    vuln = repo.add_or_update_service(t.id, 80, "tcp", "http")
    repo.add_checklist_item(vuln.id, title="header audit", status=ChecklistStatus.CHECKED)
    repo.add_checklist_item(vuln.id, title="shellshock cgi", status=ChecklistStatus.FINDING)
    repo.add_checklist_item(vuln.id, title="old cgi probe", status=ChecklistStatus.DEAD_END)
    running = repo.add_checklist_item(vuln.id, title="nikto long scan")
    repo.update_checklist_status(running.id, ChecklistStatus.RUNNING)
    fresh = repo.add_or_update_service(t.id, 443, "tcp", "https")
    repo.add_checklist_item(fresh.id, title="cipher sweep")  # TODO

    actions = get_next_actions(repo.list_targets())
    kinds = [a.kind for a in actions]
    assert sorted(kinds) == ["enum", "exploit", "resume"]
    assert kinds.index("exploit") < kinds.index("enum"), "confirmed finding first"
    exploit = next(a for a in actions if a.kind == "exploit")
    assert exploit.port == 80 and "shellshock cgi" in exploit.title
    resume = next(a for a in actions if a.kind == "resume")
    assert "nikto long scan" in resume.title, "interrupted check wins over todo backlog"
    assert not any("Work through" in a.title for a in actions)


def test_adversary6_invalid_creds_invisible_valid_cred_still_drives_spray():
    repo = _seed_repo()
    w = repo.add_or_get_target("10.10.25.1")
    wsvc = repo.add_or_update_service(w.id, 22, "tcp", "ssh")
    repo.add_checklist_item(wsvc.id, title="banner")
    v = repo.add_or_get_target("10.10.25.2")
    vsvc = repo.add_or_update_service(v.id, 22, "tcp", "ssh")
    repo.add_checklist_item(vsvc.id, title="banner")

    bad = repo.add_credential("guest", "guest", target_id=w.id)
    repo.record_credential_test(bad.id, "10.10.25.1", valid=False, admin=False)
    good = repo.add_credential("root", "toor", target_id=v.id)
    repo.record_credential_test(good.id, "10.10.25.2", valid=True, admin=True)

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    blob = " ".join(a.title + a.rationale for a in actions)
    assert "guest" not in blob, "invalid credential must be invisible to planning"
    sprays = [a for a in actions if a.kind == "spray"]
    assert sprays and "10.10.25.1" in sprays[0].title, "valid cred still sprays"
    exploits = [a for a in actions if a.kind == "exploit" and a.port is None]
    assert exploits and "root" in exploits[0].title


def test_adversary7_scope_sweep_running_and_recon_bait_hosts():
    """Out-of-scope AND ignored hosts stay silent even when carrying RUNNING
    checks, FINDINGS, admin-valid creds, or zero services (recon bait)."""
    repo = _seed_repo()
    live = repo.add_or_get_target("10.10.26.1")
    lsvc = repo.add_or_update_service(live.id, 80, "tcp", "http")
    repo.add_checklist_item(lsvc.id, title="rce probe", status=ChecklistStatus.FINDING)

    hidden_ips = ["10.10.26.50", "10.10.26.60"]
    for ip in hidden_ips:
        status = TargetStatus.IGNORED if ip.endswith("60") else TargetStatus.DISCOVERED
        hidden = repo.add_or_get_target(ip, status=status)
        hsvc = repo.add_or_update_service(hidden.id, 22, "tcp", "ssh")
        run = repo.add_checklist_item(hsvc.id, title="leak-run")
        repo.update_checklist_status(run.id, ChecklistStatus.RUNNING)
        fnd = repo.add_checklist_item(hsvc.id, title="leak-finding")
        repo.update_checklist_status(fnd.id, ChecklistStatus.FINDING)
        hc = repo.add_credential("leak", "leak", target_id=hidden.id)
        repo.record_credential_test(hc.id, ip, valid=True, admin=True)
        if ip.endswith("50"):
            repo.set_target_scope(hidden.id, False)

    targets, creds = repo.list_targets(), repo.list_credentials()
    actions = get_next_actions(targets, creds)
    for a in actions:
        assert a.target_ip not in hidden_ips, f"{a.kind} leaked {a.target_ip}"
    # A cred harvested on a hidden host stays a valid asset, but sprays may
    # only ever name live hosts.
    for a in (a for a in actions if a.kind == "spray"):
        for ip in hidden_ips:
            assert ip not in a.title and ip not in a.rationale

    report = detect_rabbit_holes(targets, creds)
    leaked = (
        report.dead_end_services
        + report.dead_end_checks
        + report.running_checks
        + report.untested_ports
        + report.unsprayed_credentials
        + [f"{s.title} {s.rationale}" for s in report.suggestions]
    )
    for line in leaked:
        for ip in hidden_ips:
            assert ip not in line, f"rabbit-hole report leaked {ip}: {line}"


def test_adversary8_lead_lifecycle_gates_staleness_nag():
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=9)
    leads = [
        Lead(id=1, title="stale backlog lead", created_at=old, updated_at=now),
        Lead(id=2, title="confirmed old", status=LeadStatus.CONFIRMED, created_at=old, updated_at=now),
        Lead(id=3, title="rejected old", status=LeadStatus.REJECTED, created_at=old, updated_at=now),
        Lead(id=4, title="in-progress old", status=LeadStatus.IN_PROGRESS, created_at=old, updated_at=now),
        Lead(id=5, title="future backlog", created_at=now + timedelta(days=9), updated_at=now),
    ]
    repo = _seed_repo()
    repo.add_or_get_target("10.10.27.1")

    actions = get_next_actions(repo.list_targets(), [], leads)
    cleanups = [a.title for a in actions if a.kind == "cleanup"]
    assert len(cleanups) == 1 and "#1" in cleanups[0], cleanups


def test_adversary9_partial_exploitation_retires_owned_host_only():
    """FOOTHOLD retires its own finding nag; sibling findings and interrupted
    post-exploit work survive."""
    repo = _seed_repo()
    owned = repo.add_or_get_target("10.10.28.1", status=TargetStatus.FOOTHOLD)
    osvc = repo.add_or_update_service(owned.id, 80, "tcp", "http")
    orun = repo.add_checklist_item(osvc.id, title="post-exploit enum")
    repo.update_checklist_status(orun.id, ChecklistStatus.RUNNING)
    ofind = repo.add_checklist_item(osvc.id, title="owned rce")
    repo.update_checklist_status(ofind.id, ChecklistStatus.FINDING)

    sibling = repo.add_or_get_target("10.10.28.2")
    ssvc = repo.add_or_update_service(sibling.id, 445, "tcp", "microsoft-ds")
    repo.add_checklist_item(ssvc.id, title="eternal blue", status=ChecklistStatus.FINDING)

    actions = get_next_actions(repo.list_targets())
    exploits = [(a.target_ip, a.port) for a in actions if a.kind == "exploit"]
    assert exploits == [("10.10.28.2", 445)], "owned host retired, sibling surfaced"
    assert any(
        a.kind == "resume" and a.target_ip == "10.10.28.1" for a in actions
    ), "interrupted post-exploit work still resumable"
