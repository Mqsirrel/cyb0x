"""Unit tests for methodology knowledge base and rule engine."""

import pytest
from synapse.methodology.engine import MethodologyEngine
from synapse.models import Service, Target


def test_methodology_service_matching():
    engine = MethodologyEngine()

    # FTP Service
    ftp_svc = Service(target_id=1, port=21, name="ftp", product="vsftpd", version="3.0.3")
    assert engine.match_service(ftp_svc) == "ftp"
    ftp_checks = engine.get_checklists_for_service(ftp_svc)
    assert len(ftp_checks) >= 3
    assert any("Anonymous" in c["title"] for c in ftp_checks)

    # SMB Service
    smb_svc = Service(target_id=1, port=445, name="microsoft-ds", product="Samba")
    assert engine.match_service(smb_svc) == "smb"
    smb_checks = engine.get_checklists_for_service(smb_svc)
    assert len(smb_checks) >= 4
    assert any("Null" in c["title"] or "RID" in c["title"] for c in smb_checks)

    # HTTP Service
    http_svc = Service(target_id=1, port=8080, name="http", product="Apache Tomcat")
    assert engine.match_service(http_svc) == "http"
    http_checks = engine.get_checklists_for_service(http_svc)
    assert len(http_checks) >= 5

    # Unknown Port fallback
    unknown_svc = Service(target_id=1, port=31337, name="unknown")
    assert engine.match_service(unknown_svc) == "generic_unknown"


def test_methodology_command_rendering():
    engine = MethodologyEngine()
    target = Target(ip="10.10.11.120", hostname="web01.corp.local")
    svc = Service(target_id=1, port=80, name="http")

    template = "ffuf -u http://{IP}:{PORT}/FUZZ -w {WORDLIST} -H 'Host: {HOST}'"
    rendered = engine.render_command(
        template, target, svc, wordlist="/usr/share/wordlists/dirb/common.txt"
    )

    assert "http://10.10.11.120:80/FUZZ" in rendered
    assert "/usr/share/wordlists/dirb/common.txt" in rendered
    assert "Host: web01.corp.local" in rendered
