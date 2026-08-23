"""Unit tests for methodology knowledge base and rule engine."""

from pathlib import Path

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


def test_initial_recon_rules_loaded_and_rendered():
    engine = MethodologyEngine()
    target = Target(ip="10.10.11.50", hostname="")

    recipes = engine.get_initial_recon_commands(target)
    assert len(recipes) >= 3
    for rc in recipes:
        assert rc["title"]
        assert rc["command_template"]
        # Host-level recipes must be fully rendered with no service context
        assert "{IP}" not in rc["command_template"]
        assert "10.10.11.50" in rc["command_template"]

    # Hostname substitution ({HOST}) when available
    named_target = Target(ip="10.10.11.50", hostname="dc01.corp.local")
    ping_cmd = engine.render_command("ping -c 4 {HOST}", named_target)
    assert "ping -c 4 dc01.corp.local" == ping_cmd


def test_render_command_without_service_leaves_port_token():
    engine = MethodologyEngine()
    target = Target(ip="10.10.11.50")
    rendered = engine.render_command("nmap -p {PORT} {IP}", target)
    assert "nmap -p {PORT} 10.10.11.50" == rendered


def test_initial_recon_custom_override(tmp_path: Path):
    custom = tmp_path / "custom_methodology.yaml"
    custom.write_text(
        """
services:
  my_service:
    ports: [9090]
    name_patterns: ["custom-api"]
    checklists:
      - category: "enum"
        title: "Check Swagger"
        command_template: "curl -s http://{IP}:{PORT}/docs"
initial_recon:
  - category: "recon"
    title: "Custom Sweep"
    description: "User-defined phase-0 recipe"
    command_template: "rustscan -a {IP}"
""",
        encoding="utf-8",
    )
    engine = MethodologyEngine(custom_rules_path=custom)
    target = Target(ip="192.168.1.10")

    recipes = engine.get_initial_recon_commands(target)
    assert len(recipes) == 1
    assert recipes[0]["title"] == "Custom Sweep"
    assert recipes[0]["command_template"] == "rustscan -a 192.168.1.10"

    # Custom service rules still merge alongside the recon override
    svc = Service(target_id=1, port=9090, name="custom-api")
    assert engine.match_service(svc) == "my_service"
