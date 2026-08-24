"""Opt-in live validation of the Lavoisier Docker Compose lab.

These tests boot the real stack and black-box probe every weakness, so they
only run when explicitly requested AND Docker is available:

    SYNAPSE_LIVE_LAB=1 uv run pytest tests/test_live_lab.py -v

Everywhere else they self-skip, keeping the default suite fast, deterministic,
and green on machines without Docker (the deterministic twin of this lab
lives in tests/test_lab_scenario.py).
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
LAB = REPO_ROOT / "lab"

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("SYNAPSE_LIVE_LAB") != "1",
        reason="set SYNAPSE_LIVE_LAB=1 to run the live Docker lab",
    ),
    pytest.mark.skipif(
        shutil.which("docker") is None,
        reason="docker CLI not available",
    ),
]


def _compose(*args: str) -> None:
    subprocess.run(
        ["docker", "compose", *args],
        cwd=LAB,
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="module")
def live_lab():
    """Boots a pristine stack, yields, then fully resets it."""
    _compose("down", "-v")
    _compose("up", "-d", "--build")
    try:
        yield LAB
    finally:
        _compose("down", "-v")


def test_lab_integrity_end_to_end(live_lab):
    """Every weakness, credential, flag, and privesc vector must be armed."""
    proc = subprocess.run(
        [str(live_lab / "verify_lab.sh")],
        cwd=live_lab,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, f"verify_lab.sh failed:\n{proc.stdout}\n{proc.stderr}"
    assert "FAIL" not in proc.stdout


def test_lab_reset_restores_pristine_flags(live_lab):
    """Reset determinism: flags are constants, not generated per-boot."""
    user_flag = subprocess.run(
        ["docker", "compose", "exec", "-T", "target", "cat", "/home/developer/user.txt"],
        cwd=live_lab, check=True, capture_output=True, text=True,
    ).stdout.strip()
    proof_flag = subprocess.run(
        ["docker", "compose", "exec", "-T", "target", "head", "-1", "/root/proof.txt"],
        cwd=live_lab, check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert user_flag == "5f1ec9bb31ae4c7db02a7fa4e91d33c8"
    assert proof_flag == "9c2d44af71e05b83ac6d94f20b1e77aa"

    # A down -v / up cycle must reproduce byte-identical state.
    _compose("down", "-v")
    _compose("up", "-d")
    user_flag_again = subprocess.run(
        ["docker", "compose", "exec", "-T", "target", "cat", "/home/developer/user.txt"],
        cwd=live_lab, check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert user_flag_again == user_flag
