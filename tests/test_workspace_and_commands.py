"""Tests for persistent command history, workspace management, doctor diagnostics, and TUI modals."""

import pytest
from pathlib import Path
from click.testing import CliRunner

from synapse.cli import main
from synapse.db.migrations import run_migrations, CURRENT_SCHEMA_VERSION
from synapse.db.repository import DatabaseRepository
from synapse.models import Target, TargetStatus, Service, ServiceStatus, ChecklistItem, ChecklistStatus
from synapse.tui.modals.workspace_modal import WorkspaceModal
from synapse.tui.modals.command_palette_modal import CommandPaletteModal
from synapse.tui.modals.jump_modal import JumpModal
from synapse.tui.modals.scratchpad_modal import ScratchpadModal
from synapse.tui.modals.runner_modal import RunnerModal
from synapse.tui.widgets.service_detail import ServiceDetailWidget


def test_command_logging_and_retrieval(tmp_path: Path):
    db_path = tmp_path / "test_cmd.db"
    repo = DatabaseRepository(db_path)

    # Add target and service
    target = repo.add_or_get_target("10.10.11.50", hostname="monolith.htb", os="Linux")
    svc = repo.add_or_update_service(target.id, 80, "tcp", "http", "Apache httpd", "2.4.49")
    checklist = repo.add_checklist_item(svc.id, "HTTP Directory Bruteforce", "discovery", "ffuf -u http://10.10.11.50/FUZZ -w wordlist.txt")

    # Log command
    cmd_record = repo.log_command(
        command="ffuf -u http://10.10.11.50/FUZZ -w wordlist.txt",
        return_code=0,
        stdout="Found /admin (200)\nFound /api (301)",
        stderr="",
        duration_seconds=1.45,
        extracted_flags=["HTB{s0m3_fl4g}"],
        target_id=target.id,
        service_id=svc.id,
        checklist_id=checklist.id,
    )

    assert cmd_record.id is not None
    assert cmd_record.target_id == target.id
    assert cmd_record.target_ip == "10.10.11.50"
    assert cmd_record.service_id == svc.id
    assert cmd_record.checklist_id == checklist.id
    assert cmd_record.duration_seconds == 1.45
    assert cmd_record.extracted_flags == ["HTB{s0m3_fl4g}"]

    # Retrieve by ID
    fetched = repo.get_command_by_id(cmd_record.id)
    assert fetched is not None
    assert fetched.command == cmd_record.command
    assert fetched.extracted_flags == ["HTB{s0m3_fl4g}"]

    # List commands
    all_cmds = repo.list_commands()
    assert len(all_cmds) == 1
    assert all_cmds[0].id == cmd_record.id

    # List filtered by target
    filtered_tgt = repo.list_commands(target_id=target.id)
    assert len(filtered_tgt) == 1

    filtered_other = repo.list_commands(target_id=999)
    assert len(filtered_other) == 0

    repo.close()


def test_scratchpad_metadata(tmp_path: Path):
    db_path = tmp_path / "test_scratch.db"
    repo = DatabaseRepository(db_path)

    assert repo.get_scratchpad() == ""

    test_notes = "# Exam Lab Notes\n- Found SQLi on port 8080\n- Root password hint in /etc/motd"
    repo.set_scratchpad(test_notes)

    assert repo.get_scratchpad() == test_notes
    repo.close()


def test_cli_doctor_and_commands(tmp_path: Path):
    runner = CliRunner()
    db_path = str(tmp_path / "cli_doctor_test.db")

    # Run doctor
    res_doc = runner.invoke(main, ["doctor"])
    assert res_doc.exit_code == 0
    assert "SYNAPSE Doctor" in res_doc.output
    assert "Python Interpreter" in res_doc.output
    assert "SQLite Engine" in res_doc.output

    # Add a target and run list-commands
    repo = DatabaseRepository(db_path)
    t = repo.add_or_get_target("192.168.1.100")
    repo.log_command("nmap -sV 192.168.1.100", return_code=0, duration_seconds=3.21, target_id=t.id)
    repo.close()

    res_cmds = runner.invoke(main, ["--db", db_path, "list-commands"])
    assert res_cmds.exit_code == 0
    assert "Command Execution History" in res_cmds.output
    assert "nmap -sV" in res_cmds.output
    assert "192.168.1.100" in res_cmds.output

    # List workspaces
    res_ws = runner.invoke(main, ["list-workspaces"])
    assert res_ws.exit_code == 0


def test_command_palette_modal_structure():
    modal = CommandPaletteModal()
    assert len(modal.ACTIONS) >= 20
    # Check that key actions exist
    action_ids = [a[0] for a in modal.ACTIONS]
    assert "triage" in action_ids
    assert "stuck" in action_ids
    assert "workspace" in action_ids
    assert "scratchpad" in action_ids
    assert "jump" in action_ids


def test_jump_modal_entities(tmp_path: Path):
    db_path = tmp_path / "test_jump.db"
    repo = DatabaseRepository(db_path)

    t = repo.add_or_get_target("10.10.10.1", hostname="box.htb", os="Linux")
    s = repo.add_or_update_service(t.id, 22, "tcp", "ssh", "OpenSSH", "8.2")
    c = repo.add_checklist_item(s.id, "SSH Banner Check", "recon", "nc -vn 10.10.10.1 22")
    repo.update_checklist_status(c.id, ChecklistStatus.FINDING)
    cred = repo.add_credential("root", "toor", target_id=t.id)
    lead = repo.add_lead(title="Check for sudoers misconfig", target_id=t.id)

    modal = JumpModal(repo)
    assert len(modal.items) >= 4

    types = {item["type"] for item in modal.items}
    assert "target" in types
    assert "service" in types
    assert "credential" in types
    assert "lead" in types
    assert "checklist" in types

    repo.close()


@pytest.mark.asyncio
async def test_service_detail_target_360():
    from synapse.tui.app import SynapseTUI

    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        target = app.repo.add_or_get_target("10.10.11.100", hostname="target.htb", os="Windows")
        app.repo.add_or_update_service(target.id, 445, "tcp", "microsoft-ds", "Windows SMB", "")
        app.refresh_all_views()

        detail = app.query_one("#service-detail", ServiceDetailWidget)
        snap = app._load_snapshot()
        t = app.repo.get_target_by_id(target.id)
        assert t is not None
        detail.display_target_360(t, snap["credentials"], snap["evidence"])

        header_text = detail.query_one("#service-header").render().plain
        assert "TARGET 360° OVERVIEW" in header_text
        assert "10.10.11.100" in header_text


@pytest.mark.asyncio
async def test_runner_modal_autolog(tmp_path: Path):
    db_path = tmp_path / "test_runner_log.db"
    repo = DatabaseRepository(db_path)
    t = repo.add_or_get_target("127.0.0.1")

    modal = RunnerModal(
        command="echo 'TEST_COMMAND_OUTPUT'",
        title="Test Command",
        repo=repo,
        target_id=t.id,
    )

    assert modal.repo == repo
    assert modal.target_id == t.id
    repo.close()

