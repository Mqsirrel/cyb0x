"""Independent validation scenario and regression tests for cyb0x.

Tests methodology generalization across an independent lab scenario (Mercury:
Web CMS + ProFTPD mod_copy -> www-data foothold -> SUID find privesc -> root)
and multi-target lateral pivot, as well as regressions for all validation issues.
"""

import pytest

from synapse.assessment.engine import (
    PhaseStatus,
    PRIORITY_ENUM,
    PRIORITY_EXPLOIT,
    PRIORITY_RECON,
    PRIORITY_RESUME,
    PRIORITY_SPRAY,
    detect_rabbit_holes,
    evaluate_phase_progress,
    get_next_actions,
    get_top_action,
    unsprayed_hosts_for_credential,
)
from synapse.db.repository import DatabaseRepository
from synapse.methodology.engine import MethodologyEngine
from synapse.models import (
    ChecklistStatus,
    CredentialType,
    ProofType,
    ServiceStatus,
    SeverityLevel,
    TargetStatus,
)


@pytest.fixture
def repo():
    return DatabaseRepository(":memory:")


@pytest.fixture
def engine():
    return MethodologyEngine()


@pytest.fixture
def htb_profile(engine):
    profile = engine.profile_loader.get_profile("htb_lab")
    assert profile is not None
    return profile


@pytest.fixture
def ejpt_profile(engine):
    profile = engine.profile_loader.get_profile("ejptv2")
    assert profile is not None
    return profile


# =============================================================================
# 1. Independent Generalization Scenario: "Mercury" (Web + SUID Privesc)
# =============================================================================

def test_independent_mercury_scenario_generalization(repo, engine, htb_profile):
    """Tests an independent target not designed around Lavoisier."""
    target_ip = "10.10.11.85"
    user_flag = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    root_flag = "fedcba98765432100123456789abcdef"

    # --- Stage 0: Scope / Bare Target ---
    t = repo.add_or_get_target(target_ip, hostname="mercury.htb")
    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert len(actions) == 1
    assert actions[0].kind == "recon"
    assert actions[0].priority == PRIORITY_RECON

    phases = evaluate_phase_progress(t, htb_profile, repo.list_evidence(t.id))
    # On a pristine target with no routed surface, all phases start as NOT_STARTED
    assert phases["port_scan"].phase_status == PhaseStatus.NOT_STARTED
    assert phases["service_enum"].phase_status == PhaseStatus.NOT_STARTED
    assert not phases["service_enum"].recommended_actions

    # --- Stage 1: Port Scan Discovery (FTP:21, HTTP:80, MySQL:3306, HTTP-DEV:8000) ---
    s_ftp = repo.add_or_update_service(t.id, 21, "tcp", "ftp", "ProFTPD", "1.3.5")
    s_http = repo.add_or_update_service(t.id, 80, "tcp", "http", "Apache httpd", "2.4.41")
    s_mysql = repo.add_or_update_service(t.id, 3306, "tcp", "mysql", "MySQL", "8.0")
    s_dev = repo.add_or_update_service(t.id, 8000, "tcp", "http", "Python http.server", "3.8")

    for s in (s_ftp, s_http, s_mysql, s_dev):
        for chk in engine.get_checklists_for_service(s):
            repo.add_checklist_item(
                s.id,
                category=chk.get("category", "enum"),
                title=chk.get("title", ""),
                description=chk.get("description", ""),
                command_template=chk.get("command_template", ""),
            )

    # Port scan completed, enum unblocked
    t = repo.get_target_by_id(t.id)
    phases = evaluate_phase_progress(t, htb_profile, repo.list_evidence(t.id))
    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert any(a.kind == "enum" for a in actions)
    assert not any(a.kind == "recon" for a in actions)

    # --- Stage 2: Enumeration & Decoys ---
    # MySQL: Access denied -> dead end
    for c in repo.get_checklists_by_service(s_mysql.id):
        repo.update_checklist_status(c.id, ChecklistStatus.DEAD_END)
    repo.refresh_service_state(s_mysql.id)
    assert repo.get_service_by_id(s_mysql.id).status == ServiceStatus.DEAD_END

    # HTTP-DEV: Default basic auth fails -> dead end
    for c in repo.get_checklists_by_service(s_dev.id):
        repo.update_checklist_status(c.id, ChecklistStatus.DEAD_END)
    repo.refresh_service_state(s_dev.id)

    # FTP: Anon login & enum fails (dead end)
    ftp_checks = repo.get_checklists_by_service(s_ftp.id)
    for c in ftp_checks:
        if c.category in ("recon", "enum", "exploit"):
            repo.update_checklist_status(c.id, ChecklistStatus.DEAD_END)

    # HTTP 80: Web enum discovers login & upload
    http_checks = repo.get_checklists_by_service(s_http.id)
    for c in http_checks:
        if c.category in ("recon", "enum"):
            repo.update_checklist_status(c.id, ChecklistStatus.CHECKED)
        elif c.category in ("vuln_check", "exploit"):
            repo.update_checklist_status(c.id, ChecklistStatus.DEAD_END)

    report = detect_rabbit_holes(repo.list_targets(), repo.list_credentials())
    assert any("3306" in line for line in report.dead_end_services)
    assert not report.is_stuck, "Open ports remain on 21 and 80"

    # --- Stage 3: Vulnerability Assessment & Finding ---
    # ProFTPD 1.3.5 mod_copy vulnerability confirmed
    vuln_chk = next(c for c in ftp_checks if "Known Exploits" in c.title or c.category == "vuln_check")
    repo.update_checklist_status(
        vuln_chk.id,
        ChecklistStatus.FINDING,
        output_snippet="CVE-2015-3306 ProFTPD 1.3.5 mod_copy arbitrary file copy",
    )
    repo.refresh_service_state(s_ftp.id)
    repo.refresh_service_state(s_http.id)

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert actions[0].kind == "exploit"
    assert actions[0].priority == PRIORITY_EXPLOIT
    assert "21" in actions[0].title or "ProFTPD" in actions[0].title or "Exploit confirmed finding" in actions[0].title

    # --- Stage 4: Exploitation -> Foothold ---
    # Exploit mod_copy to drop PHP webshell -> www-data reverse shell
    repo.update_checklist_status(vuln_chk.id, ChecklistStatus.CHECKED)
    repo.add_evidence(
        target_id=t.id,
        service_id=s_http.id,
        proof_type=ProofType.USER_FLAG,
        title="user.txt",
        command="cat /home/mercury/user.txt",
        output=user_flag,
        flag_hash=user_flag,
    )
    repo.update_target_status(t.id, TargetStatus.FOOTHOLD)

    # Foothold achieved: privesc phase unblocks; privesc nudge is top action
    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert actions[0].kind == "privesc"
    assert actions[0].priority == PRIORITY_EXPLOIT
    assert "privilege-escalation" in actions[0].title.lower()

    # Close remaining exploit check on FTP (unneeded since mod_copy webshell succeeded)
    for c in ftp_checks:
        if c.category == "exploit":
            repo.update_checklist_status(c.id, ChecklistStatus.DEAD_END)

    t = repo.get_target_by_id(t.id)
    phases = evaluate_phase_progress(t, htb_profile, repo.list_evidence(t.id))
    assert phases["foothold_user_flag"].phase_status == PhaseStatus.COMPLETED
    assert phases["privilege_escalation"].phase_status == PhaseStatus.NOT_STARTED

    # --- Stage 5: Privilege Escalation (SUID find binary) ---
    suid_find = repo.add_checklist_item(
        s_http.id,
        category="privesc",
        title="SUID binary /usr/bin/find allows root shell",
        description="find . -exec /bin/sh -p \\; -quit",
        command_template="/usr/bin/find . -exec /bin/sh -p \\; -quit",
        status=ChecklistStatus.FINDING,
        severity=SeverityLevel.CRITICAL,
    )

    # Engine must recommend exploiting the confirmed privesc finding
    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert actions[0].kind == "exploit"
    assert "find" in actions[0].title or "privilege-escalation" in actions[0].title.lower()

    # Exploit vector executed -> root shell -> proof captured
    repo.update_checklist_status(suid_find.id, ChecklistStatus.CHECKED, output_snippet="uid=0(root) gid=0(root)")
    repo.add_evidence(
        target_id=t.id,
        service_id=s_http.id,
        checklist_id=suid_find.id,
        proof_type=ProofType.ROOT_FLAG,
        title="root.txt",
        command="cat /root/root.txt",
        output=root_flag,
        flag_hash=root_flag,
    )
    repo.update_target_status(t.id, TargetStatus.PWNED)

    # --- Stage 6: Completion ---
    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert actions == [], "Completed target must yield zero next actions"

    report = detect_rabbit_holes(repo.list_targets(), repo.list_credentials())
    assert report.assessment_complete is True
    assert report.is_stuck is False

    t = repo.get_target_by_id(t.id)
    phases = evaluate_phase_progress(t, htb_profile, repo.list_evidence(t.id))
    assert all(p.phase_status == PhaseStatus.COMPLETED for p in phases.values())
    for p in phases.values():
        assert not p.recommended_actions, "Completed phases on rooted box must have no recommended actions"


# =============================================================================
# 2. Multi-Target Lateral Movement & Pivot Scenario
# =============================================================================

def test_multi_target_lateral_movement_and_spray(repo, engine):
    """Validates multi-host spray and pivoting dynamics across compromised hosts."""
    t1 = repo.add_or_get_target("10.10.10.10", hostname="web.corp.local")
    t2 = repo.add_or_get_target("10.10.10.20", hostname="db.corp.local")

    s1 = repo.add_or_update_service(t1.id, 80, "tcp", "http")
    s2 = repo.add_or_update_service(t2.id, 445, "tcp", "microsoft-ds")

    # Host 1 compromised to root
    repo.update_target_status(t1.id, TargetStatus.PWNED)
    cred = repo.add_credential("corp_admin", "Summer2024!", CredentialType.PASSWORD, target_id=t1.id)
    repo.record_credential_test(cred.id, t1.ip, service="http", valid=True, admin=True)

    # Engine must NOT suggest spraying on Host 1 (PWNED), but MUST suggest spraying on Host 2
    unsprayed = unsprayed_hosts_for_credential(cred, repo.list_targets())
    assert unsprayed == ["10.10.10.20"]

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    sprays = [a for a in actions if a.kind == "spray"]
    assert len(sprays) == 1
    assert "10.10.10.20" in sprays[0].title
    assert "10.10.10.10" not in sprays[0].title

    # Spray succeeds on Host 2 with admin rights
    repo.record_credential_test(cred.id, t2.ip, service="smb", valid=True, admin=True)
    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    exploits = [a for a in actions if a.kind == "exploit"]
    assert any("corp_admin" in a.title and "10.10.10.20" in a.title for a in exploits)


# =============================================================================
# 3. Regression Tests for Discovered Issues
# =============================================================================

def test_regression_foothold_privesc_finding_not_masked_by_pre_foothold_findings(repo):
    """When a foothold target has pre-foothold web findings AND a new privesc finding,

    the engine must recommend exploiting the privesc finding (not generic enumeration).
    """
    t = repo.add_or_get_target("10.10.10.5", status=TargetStatus.FOOTHOLD)
    s_web = repo.add_or_update_service(t.id, 80, "tcp", "http")
    s_ssh = repo.add_or_update_service(t.id, 22, "tcp", "ssh")

    # Pre-foothold web finding (category: vuln_check)
    repo.add_checklist_item(
        s_web.id,
        category="vuln_check",
        title="Backup file exposed on port 80",
        status=ChecklistStatus.FINDING,
    )

    # Post-foothold privesc finding (category: privesc)
    repo.add_checklist_item(
        s_ssh.id,
        category="privesc",
        title="sudo -l NOPASSWD /bin/bash",
        status=ChecklistStatus.FINDING,
    )

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert actions, "Must have an action for confirmed privesc finding"
    top = actions[0]
    assert top.kind == "exploit"
    assert "privilege-escalation" in top.title.lower() or "sudo -l" in top.title
    assert "Enumerate privilege-escalation" not in top.title


def test_regression_foothold_nudge_fires_when_pre_foothold_findings_exist(repo):
    """When a foothold target has pre-foothold web findings but NO privesc findings yet,

    the generic privesc enumeration nudge must fire (not go completely silent).
    """
    t = repo.add_or_get_target("10.10.10.5", status=TargetStatus.FOOTHOLD)
    s_web = repo.add_or_update_service(t.id, 80, "tcp", "http")

    # Pre-foothold web finding remains FINDING in database
    repo.add_checklist_item(
        s_web.id,
        category="vuln_check",
        title="Backup file exposed on port 80",
        status=ChecklistStatus.FINDING,
    )

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    privesc_actions = [a for a in actions if a.kind == "privesc"]
    assert len(privesc_actions) == 1
    assert "Enumerate privilege-escalation" in privesc_actions[0].title


def test_regression_pwned_target_services_not_in_untested_surface(repo):
    """Leftover TODO checks on a PWNED target must NOT appear in untested surface."""
    t1 = repo.add_or_get_target("10.10.10.5", status=TargetStatus.PWNED)
    s1 = repo.add_or_update_service(t1.id, 21, "tcp", "ftp")
    repo.add_checklist_item(s1.id, category="enum", title="FTP anonymous check", status=ChecklistStatus.TODO)

    # Target 2 is still being worked on
    t2 = repo.add_or_get_target("10.10.10.6", status=TargetStatus.DISCOVERED)
    s2 = repo.add_or_update_service(t2.id, 80, "tcp", "http")
    repo.add_checklist_item(s2.id, category="enum", title="HTTP dirb", status=ChecklistStatus.TODO)

    report = detect_rabbit_holes(repo.list_targets(), repo.list_credentials())
    assert not any("10.10.10.5" in line for line in report.untested_ports), (
        "PWNED target's leftover checks must not be suggested as untested surface"
    )
    assert any("10.10.10.6" in line for line in report.untested_ports)

    actions = get_next_actions(repo.list_targets(), repo.list_credentials())
    assert not any(a.target_ip == "10.10.10.5" for a in actions), "PWNED host must not yield actions"


def test_regression_unsprayed_credentials_excludes_pwned_targets(repo):
    """Credentials must not be recommended to spray against PWNED targets."""
    t1 = repo.add_or_get_target("10.10.10.5", status=TargetStatus.PWNED)
    cred = repo.add_credential("admin", "pass123", target_id=t1.id)
    repo.record_credential_test(cred.id, "10.10.10.5", valid=True)

    untested = unsprayed_hosts_for_credential(cred, repo.list_targets())
    assert untested == [], "No hosts left to spray when only target is PWNED"


def test_regression_blocked_phase_has_no_recommended_actions(repo, htb_profile):
    """A phase that is BLOCKED must clear its recommended actions."""
    t = repo.add_or_get_target("10.10.10.5")
    s = repo.add_or_update_service(t.id, 80, "tcp", "http")
    repo.add_checklist_item(s.id, category="recon", title="Port scan", status=ChecklistStatus.TODO)
    repo.add_checklist_item(s.id, category="enum", title="Content discovery", status=ChecklistStatus.TODO)

    t = repo.get_target_by_id(t.id)
    phases = evaluate_phase_progress(t, htb_profile, repo.list_evidence(t.id))
    assert phases["port_scan"].phase_status == PhaseStatus.NOT_STARTED
    assert len(phases["port_scan"].recommended_actions) > 0

    assert phases["service_enum"].phase_status == PhaseStatus.BLOCKED
    assert len(phases["service_enum"].recommended_actions) == 0, (
        "Blocked phase must not recommend actions before unblocking"
    )


def test_regression_untested_surface_deduplication(repo):
    """detect_rabbit_holes must not duplicate service tags when checklists exist."""
    t = repo.add_or_get_target("10.10.10.5")
    s = repo.add_or_update_service(t.id, 80, "tcp", "http", status=ServiceStatus.UNTESTED)
    repo.add_checklist_item(s.id, category="enum", title="Dir brute", status=ChecklistStatus.TODO)

    report = detect_rabbit_holes(repo.list_targets(), repo.list_credentials())
    # Should only contain the checklist item tag, not an extra duplicate line for the service
    assert len(report.untested_ports) == 1
    assert "Dir brute" in report.untested_ports[0]
