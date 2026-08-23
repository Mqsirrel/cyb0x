"""Command execution engine and proof flag extraction."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class ExecutionResult:
    command: str
    return_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    started_at: datetime
    finished_at: datetime
    extracted_flags: List[str]


def extract_proof_flags(text: str) -> List[str]:
    """Finds 32-character hex MD5 hashes (OffSec style) or CTF-style flags in terminal text."""
    flags = []

    # 1. CTF style flags: e.g. CTF{...}, flag{...}, HTB{...}, THM{...}
    ctf_matches = re.findall(r"(?:flag|CTF|HTB|THM|EJPT)\{[^\{\}\s]+\}", text, re.IGNORECASE)
    flags.extend(ctf_matches)

    # 2. 32-character hex hashes (standard OffSec user.txt / proof.txt MD5 hashes)
    hex_matches = re.findall(r"\b[0-9a-fA-F]{32}\b", text)
    for h in hex_matches:
        if h not in flags:
            flags.append(h)

    return list(dict.fromkeys(flags))


class CommandExecutor:
    """Executes commands asynchronously and captures output."""

    @staticmethod
    async def run_command_async(
        command: str, timeout: Optional[float] = 60.0
    ) -> ExecutionResult:
        started_at = datetime.now(timezone.utc)
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            return_code = process.returncode or 0

        except asyncio.TimeoutError:
            try:
                process.kill()
            except Exception:
                pass
            stdout = ""
            stderr = f"Command timed out after {timeout} seconds."
            return_code = -1

        except Exception as e:
            stdout = ""
            stderr = f"Execution failed: {str(e)}"
            return_code = -1

        finished_at = datetime.now(timezone.utc)
        duration = (finished_at - started_at).total_seconds()
        flags = extract_proof_flags(stdout)

        return ExecutionResult(
            command=command,
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            started_at=started_at,
            finished_at=finished_at,
            extracted_flags=flags,
        )
