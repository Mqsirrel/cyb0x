"""Integration: cyb0x across the Lavoisier synthetic pentest lab.

Drives the real pipeline (CLI ingest -> repository -> methodology engine ->
assessment engine -> guided workflow) through the exact seven stages
documented in ``lab/README.md`` §3 and asserts the documented assessment
state after every stage:

    Scope → Recon → Enumeration → Vulnerability Assessment → Exploitation
          → Foothold → Privilege Escalation → Completion

The lab itself (lab/) runs under Docker Compose; this test is its
deterministic twin: identical topology, findings, dead ends, branches,
credentials, and flags, so it validates the decision engine on any machine,
Docker or not. The live counterpart is tests/test_live_lab.py.
"""

from pathlib import Path

import pytest
from click.testing import CliRunner

from synapse.assessment.engine import (
    PhaseStatus,
    PRIORITY_EXPLOIT,
    detect_rabbit_holes,
    evaluate_phase_progress,
    get_next_actions,
)
from synapse.cli import main
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
from synapse.parsers.nmap_parser import parse_nmap_xml
from synapse.runner.executor import extract_proof_flags

REPO_ROOT = Path(__file__).resolve().parent.parent
LAB = REPO_ROOT / "lab"
SCAN = LAB / "scans" / "nmap_initial.xml"

TARGET_IP = "172.29.0.10"
USER_FLAG = "5f1ec9bb31ae4c7db02a7fa4e91d33c8"
ROOT_FLAG = "9c2d44af71e05b83ac6d94f20b1e77aa"


@pytest.fixture
def env(tmp_path):
    """Fresh workspace + engines for one lab walkthrough."""
    db_file = tmp_path / "lavoisier.db"
    repo = DatabaseRepository(db_file)
    engine = MethodologyEngine()
    profile = engine.profile_loader.get_profile("ejptv2")
    assert profile is not None, "bundled ejptv2 profile must load"
    return repo, engine, profile


def _target(repo):
    return repo.get_target_by_ip(TARGET_IP)


def _actions(repo):
    return get_next_actions(repo.list_targets(), repo.list_credentials())


def _phases(repo, profile):
    t = _target(repo)
    return evaluate_phase_progress(t, profile, repo.list_evidence(t.id))


def _svc(repo, port):
    return next(s for s in repo.get_services_by_target(_target(repo).id) if s.port == port)


def _check(repo, service_id, title_part):
    return next(c for c in repo.get_checklists_by_service(service_id) if title_part in c.title)


def test_lab_scan_ingest_contract():
    """The committed recon artifact parses and auto-attaches full checklists."""
    parsed = parse_nmap_xml(SCAN)
    assert len(parsed) == 1
    host = parsed[0]
    assert host["ip"] == TARGET_IP and host["hostname"] == "lavoisier.local"

    engine = MethodologyEngine()
    by_port = {s["port"]: s for s in host["services"]}
    assert set(by_port) == {2121, 2222, 8080, 31337}
    expected_rules = {2121: ("ftp", 4), 2222: ("ssh", 3), 8080: ("http", 7), 31337: ("generic_unknown", 2)}
    for port, (rule, n_checks) in expected_rules.items():
        sdata = by_port[port]
        svc_probe = type("Probe", (), {
            "port": port, "name": sdata.get("name", ""), "product": sdata.get("product", ""),
            "banner": "", "version": "",
        })()
        assert engine.match_service(svc_probe) == rule, port
        assert len(engine.get_checklists_for_service(svc_probe)) == n_checks, port


def test_lab_flag_constants_are_valid_proof_format():
    """Lab flags must be ingestible as OffSec-style evidence."""
    assert extract_proof_flags(f"user.txt\n{USER_FLAG}") == [USER_FLAG]
    assert extract_proof_flags(f"proof.txt\n{ROOT_FLAG}") == [ROOT_FLAG]


def test_full_lavoisier_walkthrough(env, tmp_path):
    repo, engine, profile = env

    # ------------------------------------------------------------------
    # Stage 0 — Scope: bare target, recon owns the plan, no proof nag
    # ------------------------------------------------------------------
    repo.add_or_get_target(TARGET_IP, hostname="lavoisier.local")
    actions = _actions(repo)
    assert [(a.kind, a.priority_label) for a in actions] == [("recon", "RECON")]

    progress = _phases(repo, profile)
    # Pristine spine: no routed surface anywhere, so every phase reads
    # not_started (empty stages pass through by profile design).
    assert progress["host_discovery"].phase_status == PhaseStatus.NOT_STARTED
    assert progress["service_enumeration"].phase_status == PhaseStatus.NOT_STARTED
    # Regression (pristine-target fix): an empty engagement must not present
    # evidence-gated phases as active work before any surface exists.
    assert progress["exploitation_foothold"].phase_status == PhaseStatus.NOT_STARTED
    assert not progress["exploitation_foothold"].recommended_actions

    # ------------------------------------------------------------------
    # Stage 1 — Recon: ingest through the REAL CLI pipeline
    # ------------------------------------------------------------------
    repo.close()  # hand the workspace to the CLI process
    runner = CliRunner()
    res = runner.invoke(main, ["--db", str(tmp_path / "lavoisier.db"), "ingest", str(SCAN)])
    assert res.exit_code == 0, res.output
    assert "Ingestion Complete" in res.output
    repo = DatabaseRepository(tmp_path / "lavoisier.db")

    services = repo.get_services_by_target(_target(repo).id)
    assert sorted(s.port for s in services) == [2121, 2222, 8080, 31337]
    assert all(s.status == ServiceStatus.UNTESTED for s in services)

    snap_checks = sum(len(s.checklists) for s in services)
    assert snap_checks == 16, "methodology recipes must auto-attach per service"
    http_cmd = _check(repo, _svc(repo, 8080).id, "Directory Brute").command_template
    assert TARGET_IP in http_cmd and "8080" in http_cmd, "recipes rendered with lab variables"

    actions = _actions(repo)
    assert not [a for a in actions if a.kind == "recon"], "recon retires itself after ingestion"
    top = get_next_actions(repo.list_targets(), repo.list_credentials())[0]
    assert top.kind == "enum"
    for p in (2121, 2222, 31337):
        assert str(p) in top.title
    progress = _phases(repo, profile)
    assert progress["host_discovery"].phase_status == PhaseStatus.NOT_STARTED
    assert len(progress["host_discovery"].pending_checks) > 0, "recon recipes routed as pending work"
    assert progress["vulnerability_assessment"].phase_status == PhaseStatus.BLOCKED

    # ------------------------------------------------------------------
    # Stage 2 — Enumeration: two decoys dead-end, breadcrumbs branch
    # ------------------------------------------------------------------
    ftp, vault, http, ssh = (_svc(repo, p) for p in (2121, 31337, 8080, 2222))

    # FTP anonymous login works but the share is retired -> all checks die.
    for c in repo.get_checklists_by_service(ftp.id):
        repo.update_checklist_status(c.id, ChecklistStatus.DEAD_END)
    repo.refresh_service_state(ftp.id)
    assert repo.get_service_by_id(ftp.id).status == ServiceStatus.DEAD_END

    # VAULT-SYNC banner grab confirms token-only auth; password probes die.
    vault_checks = repo.get_checklists_by_service(vault.id)
    repo.update_checklist_status(vault_checks[0].id, ChecklistStatus.CHECKED)
    for c in vault_checks[1:]:
        repo.update_checklist_status(c.id, ChecklistStatus.DEAD_END)
    repo.refresh_service_state(vault.id)

    # HTTP breadcrumbs: stack + robots.txt + dirb reveal /admin/ and /backups/.
    repo.update_checklist_status(_check(repo, http.id, "Technology Stack").id, ChecklistStatus.CHECKED)
    repo.update_checklist_status(_check(repo, http.id, "Standard Files").id, ChecklistStatus.CHECKED)
    repo.update_checklist_status(_check(repo, http.id, "Directory Brute").id, ChecklistStatus.CHECKED)
    repo.update_checklist_status(_check(repo, http.id, "Virtual Host").id, ChecklistStatus.DEAD_END)
    # SSH banner + auth methods enumerated (spray preparation).
    ssh_checks = repo.get_checklists_by_service(ssh.id)
    for c in ssh_checks:
        if c.category != "exploit":
            repo.update_checklist_status(c.id, ChecklistStatus.CHECKED)

    report = detect_rabbit_holes(repo.list_targets(), repo.list_credentials())
    assert any("2121" in s for s in report.dead_end_services), "FTP decoy fully disproven"
    assert any("31337" in line for line in report.dead_end_checks), (
        "vault-sync auth probes recorded as dead ends"
    )
    assert not report.is_stuck, "HTTP/SSH vuln work remains open — not a rabbit hole"

    actions = _actions(repo)
    enum_titles = " ".join(a.title for a in actions if a.kind == "enum")
    assert "2121" not in enum_titles and "31337" not in enum_titles, (
        "dead-ended ports must never resurface as pending surface"
    )
    assert "2222" in enum_titles and "8080" in enum_titles

    # ------------------------------------------------------------------
    # Stage 3 — Vulnerability Assessment: backup leak becomes a FINDING
    # ------------------------------------------------------------------
    finding = repo.add_checklist_item(
        http.id,
        category="vuln_check",
        title="Exposed backup archive leaks plaintext credentials (/backups/)",
        description="site-backup.tar.gz world-readable; contains config/db_credentials.txt",
        command_template=f"curl -s http://{TARGET_IP}:8080/backups/site-backup.tar.gz | tar -tz",
        status=ChecklistStatus.FINDING,
        severity=SeverityLevel.HIGH,
        remediation="Disable autoindex; purge archives from the webroot.",
    )
    assert finding.status == ChecklistStatus.FINDING
    for part in ("Nikto", "Authentication Forms", "LFI"):
        repo.update_checklist_status(_check(repo, http.id, part).id, ChecklistStatus.DEAD_END)
    repo.refresh_service_state(http.id)
    assert repo.get_service_by_id(http.id).status == ServiceStatus.VULNERABLE

    cred = repo.add_credential(
        "developer", "s3cr3t_dev", CredentialType.PASSWORD,
        target_id=_target(repo).id,
        notes="harvested from site-backup.tar.gz config/db_credentials.txt",
    )

    actions = _actions(repo)
    kinds_in_order = [a.kind for a in actions]
    assert "exploit" in kinds_in_order and "enum" in kinds_in_order
    exploit = next(a for a in actions if a.kind == "exploit")
    assert exploit.priority == PRIORITY_EXPLOIT
    assert ":8080" in exploit.title and "backup archive" in exploit.title
    assert kinds_in_order.index("exploit") < kinds_in_order.index("enum"), (
        "branch point: confirmed finding outranks remaining SSH enumeration"
    )

    progress = _phases(repo, profile)
    assert progress["host_discovery"].phase_status == PhaseStatus.COMPLETED
    assert progress["service_enumeration"].phase_status == PhaseStatus.COMPLETED
    assert progress["vulnerability_assessment"].phase_status == PhaseStatus.COMPLETED
    assert progress["exploitation_foothold"].phase_status == PhaseStatus.IN_PROGRESS

    # ------------------------------------------------------------------
    # Stage 4 — Exploitation → Foothold (evidence changes machine state)
    # ------------------------------------------------------------------
    ssh_login = next(
        c for c in repo.get_checklists_by_service(ssh.id) if c.category == "exploit"
    )
    repo.update_checklist_status(ssh_login.id, ChecklistStatus.RUNNING)
    actions = _actions(repo)
    resumes = [a for a in actions if a.kind == "resume"]
    assert resumes and ("2222" in resumes[0].title or "Resume" in resumes[0].title)

    # Credential spray succeeds: developer:s3cr3t_dev -> SSH session.
    repo.update_checklist_status(ssh_login.id, ChecklistStatus.FINDING, output_snippet="Welcome to Lavoisier!")
    repo.record_credential_test(cred.id, TARGET_IP, service="ssh", valid=True, admin=False)
    repo.refresh_service_state(ssh.id)
    repo.add_evidence(
        target_id=_target(repo).id,
        service_id=ssh.id,
        checklist_id=ssh_login.id,
        proof_type=ProofType.USER_FLAG,
        title="user.txt",
        command="cat /home/developer/user.txt",
        output=USER_FLAG,
        flag_hash=USER_FLAG,
    )
    repo.update_target_status(_target(repo).id, TargetStatus.FOOTHOLD)

    progress = _phases(repo, profile)
    assert progress["exploitation_foothold"].phase_status == PhaseStatus.COMPLETED
    # Non-linear branch (prerequisite jump): privesc unlocks at foothold even
    # though zero privesc-category checks exist yet.
    assert progress["local_privesc"].phase_status == PhaseStatus.NOT_STARTED

    # Closing the capitalized finding leaves the owned host with zero open
    # work — the engine must nudge toward privilege escalation (regression:
    # foothold hosts used to go completely silent here).
    repo.update_checklist_status(ssh_login.id, ChecklistStatus.CHECKED)
    repo.refresh_service_state(ssh.id)
    actions = _actions(repo)
    privesc = [a for a in actions if a.kind == "privesc"]
    assert len(privesc) == 1 and privesc[0].target_ip == TARGET_IP, actions
    assert privesc[0].priority == PRIORITY_EXPLOIT
    assert [a.kind for a in actions] == ["privesc"], "owned quiet host yields exactly the privesc nudge"

    # ------------------------------------------------------------------
    # Stage 5 — Privilege Escalation: sudo + group-writable script
    # ------------------------------------------------------------------
    sudo_l = repo.add_checklist_item(
        ssh.id, category="privesc", title="sudo -l enumeration",
        command_template="sudo -l",
    )
    repo.update_checklist_status(sudo_l.id, ChecklistStatus.RUNNING)
    actions = _actions(repo)
    assert not [a for a in actions if a.kind == "privesc"], (
        "open post-exploit work replaces the generic nudge"
    )
    assert any(a.kind == "resume" and "sudo -l" in a.title for a in actions)

    repo.update_checklist_status(sudo_l.id, ChecklistStatus.CHECKED, output_snippet="(root) NOPASSWD: /usr/local/bin/vault-report.sh")
    writable = repo.add_checklist_item(
        ssh.id, category="privesc", severity=SeverityLevel.HIGH,
        title="vault-report.sh root-owned but group-writable by devops",
        description="developer is a devops member; sudo NOPASSWD executes attacker-controlled script as root",
        command_template='echo "/bin/sh" > /usr/local/bin/vault-report.sh && sudo /usr/local/bin/vault-report.sh',
    )
    repo.update_checklist_status(writable.id, ChecklistStatus.FINDING)

    # Global triage stays quiet for owned hosts (pinned semantics); the guided
    # workflow carries post-exploit momentum via phase-local actions instead.
    progress = _phases(repo, profile)
    local = progress["local_privesc"]
    assert local.findings == ["vault-report.sh root-owned but group-writable by devops"]
    assert any(a.kind == "exploit" and "vault-report" in a.title for a in local.recommended_actions)

    # Vector exploited -> root shell -> proof captured, host pwned.
    repo.update_checklist_status(writable.id, ChecklistStatus.CHECKED, output_snippet="# whoami\nroot")
    repo.add_evidence(
        target_id=_target(repo).id,
        service_id=ssh.id,
        checklist_id=writable.id,
        proof_type=ProofType.ROOT_FLAG,
        title="proof.txt",
        command="cat /root/proof.txt",
        output=ROOT_FLAG,
        flag_hash=ROOT_FLAG,
    )
    repo.update_target_status(_target(repo).id, TargetStatus.PWNED)

    # ------------------------------------------------------------------
    # Stage 6 — Completion: silence that reads as success, not stuck
    # ------------------------------------------------------------------
    actions = _actions(repo)
    assert actions == [], f"completed scope must be silent, got: {[a.kind for a in actions]}"

    progress = _phases(repo, profile)
    statuses = {pid: p.phase_status for pid, p in progress.items()}
    assert statuses == {pid: PhaseStatus.COMPLETED for pid in progress}, statuses
    assert progress["proof_flag"].evidence == ["proof.txt"]

    report = detect_rabbit_holes(repo.list_targets(), repo.list_credentials())
    assert report.assessment_complete is True
    assert any("2121" in s for s in report.dead_end_services), "FTP decoy remains documented"
    assert any("31337" in line for line in report.dead_end_checks), "vault decoy remains documented"
    assert report.is_stuck is False, "completion is not a rabbit hole (regression fix)"

    # The public CLI stays healthy on the finished workspace.
    res_final = runner.invoke(main, ["--db", str(tmp_path / "lavoisier.db"), "status"])
    assert res_final.exit_code == 0
