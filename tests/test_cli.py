"""Unit tests for Synapse CLI commands."""

from pathlib import Path
import pytest
from click.testing import CliRunner
from synapse.cli import main

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p 22,80 10.10.11.200" start="1600000000">
<host>
<status state="up"/>
<address addr="10.10.11.200" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>
  <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports>
</host>
</nmaprun>"""


def test_cli_add_target_and_list(tmp_path: Path):
    runner = CliRunner()
    db_file = str(tmp_path / "cli_test.db")

    # Add target
    res = runner.invoke(main, ["--db", db_file, "add-target", "10.10.11.199", "-p", "22,80", "--os", "Linux"])
    assert res.exit_code == 0
    assert "Added target 10.10.11.199" in res.output

    # List targets
    res_list = runner.invoke(main, ["--db", db_file, "list-targets"])
    assert res_list.exit_code == 0
    assert "10.10.11.199" in res_list.output

    # Status
    res_status = runner.invoke(main, ["--db", db_file, "status"])
    assert res_status.exit_code == 0
    assert "Total Targets in Scope" in res_status.output


def test_cli_ingest_and_export(tmp_path: Path):
    runner = CliRunner()
    db_file = str(tmp_path / "ingest_test.db")
    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(SAMPLE_XML, encoding="utf-8")

    # Ingest
    res = runner.invoke(main, ["--db", db_file, "ingest", str(xml_file)])
    assert res.exit_code == 0
    assert "Ingestion Complete" in res.output

    # Export markdown
    out_md = tmp_path / "report.md"
    res_exp = runner.invoke(main, ["--db", db_file, "export", "-f", "markdown", "-o", str(out_md)])
    assert res_exp.exit_code == 0
    assert out_md.exists()
    assert "10.10.11.200" in out_md.read_text(encoding="utf-8")
