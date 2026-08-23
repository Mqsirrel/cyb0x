"""Unit tests for command executor and proof flag extraction."""

import pytest
from synapse.runner.executor import CommandExecutor, extract_proof_flags


def test_extract_proof_flags():
    sample_text = """
    uid=0(root) gid=0(root) groups=0(root)
    Linux victim 5.4.0 #1 SMP Debian
    7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
    Some other text
    flag{congratulations_you_pwned_it}
    HTB{super_secret_user_flag_123}
    """
    flags = extract_proof_flags(sample_text)
    assert "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d" in flags
    assert "flag{congratulations_you_pwned_it}" in flags
    assert "HTB{super_secret_user_flag_123}" in flags


@pytest.mark.asyncio
async def test_command_execution_async():
    res = await CommandExecutor.run_command_async("echo '7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d'")
    assert res.return_code == 0
    assert "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d" in res.stdout
    assert "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d" in res.extracted_flags
    assert res.duration_seconds >= 0.0
