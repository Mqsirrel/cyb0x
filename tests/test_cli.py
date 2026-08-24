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
    assert "Added 1 target(s)" in res.output

    # List targets
    res_list = runner.invoke(main, ["--db", db_file, "list-targets"])
    assert res_list.exit_code == 0
    assert "10.10.11.199" in res_list.output

    # Status
    res_status = runner.invoke(main, ["--db", db_file, "status"])
    assert res_status.exit_code == 0
    assert "Total Targets in Scope" in res_status.output

    # Add cred
    res_cred = runner.invoke(main, ["--db", db_file, "add-cred", "admin", "SecretPass123", "-t", "10.10.11.199"])
    assert res_cred.exit_code == 0
    assert "Saved credential" in res_cred.output

    # List creds (masked by default)
    res_creds_list = runner.invoke(main, ["--db", db_file, "list-creds"])
    assert res_creds_list.exit_code == 0
    assert "admin" in res_creds_list.output

    # Next steps / copilot
    res_next = runner.invoke(main, ["--db", db_file, "next", "10.10.11.199"])
    assert res_next.exit_code == 0
    assert "Methodology Copilot" in res_next.output


def test_cli_ingest_and_export(tmp_path: Path):
    runner = CliRunner()
    db_file = str(tmp_path / "ingest_test.db")
    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(SAMPLE_XML, encoding="utf-8")

    # Ingest
    res = runner.invoke(main, ["--db", db_file, "ingest", str(xml_file)])
    assert res.exit_code == 0
    assert "Ingestion Complete" in res.output

    # Export Notion workspace (default)
    notion_out = tmp_path / "notion_workspace"
    res_notion = runner.invoke(main, ["--db", db_file, "export", "-f", "notion", "-o", str(notion_out)])
    assert res_notion.exit_code == 0
    assert (notion_out / "SYNAPSE Assessment Workspace.md").exists()
    assert (notion_out / "Targets" / "10.10.11.200.md").exists()

    # Export markdown
    out_md = tmp_path / "report.md"
    res_exp = runner.invoke(main, ["--db", db_file, "export", "-f", "markdown", "-o", str(out_md)])
    assert res_exp.exit_code == 0
    assert out_md.exists()
    assert "10.10.11.200" in out_md.read_text(encoding="utf-8")

    # Export JSON backup
    out_json = tmp_path / "backup.json"
    res_json = runner.invoke(main, ["--db", db_file, "export", "-f", "json", "-o", str(out_json)])
    assert res_json.exit_code == 0
    assert out_json.exists()

    # Import JSON backup into new workspace
    new_db = str(tmp_path / "restored.db")
    res_imp = runner.invoke(main, ["--db", new_db, "import-backup", str(out_json)])
    assert res_imp.exit_code == 0
    assert "Workspace Restored Successfully" in res_imp.output


def test_cli_next_uses_deterministic_engine_and_respects_scope(tmp_path: Path):
    runner = CliRunner()
    db_file = str(tmp_path / "next_test.db")

    res = runner.invoke(main, ["--db", db_file, "add-target", "10.10.11.150"])
    assert res.exit_code == 0

    # Bare target -> deterministic recon recommendation surfaces
    res_next = runner.invoke(main, ["--db", db_file, "next", "10.10.11.150"])
    assert res_next.exit_code == 0
    assert "Methodology Copilot" in res_next.output
    assert "initial reconnaissance" in res_next.output

    # Out-of-scope host must get zero recommendations (scope bypass guard)
    from synapse.db.repository import DatabaseRepository
    repo = DatabaseRepository(db_file)
    t = repo.get_target_by_ip("10.10.11.150")
    repo.set_target_scope(t.id, False)
    repo.close()

    res_oos = runner.invoke(main, ["--db", db_file, "next", "10.10.11.150"])
    assert res_oos.exit_code == 0
    assert "OUT-OF-SCOPE" in res_oos.output
    assert "initial reconnaissance" not in res_oos.output
    assert "Nothing open for this host" in res_oos.output
