"""Command execution engine, process tree termination, and proof flag extraction."""

from __future__ import annotations

import asyncio
import os
import re
import signal
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

MAX_OUTPUT_BYTES = 512 * 1024  # 512 KB output cap


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
    """Finds proof flags (CTF style or standalone 32-character hex hashes) in text."""
    flags: List[str] = []

    # 1. CTF style flags: e.g. CTF{...}, flag{...}, HTB{...}, THM{...}, EJPT{...}, OffSec{...}
    ctf_matches = re.findall(
        r"(?:flag|CTF|HTB|THM|EJPT|OffSec)\{[^\{\}\s\r\n]+\}", text, re.IGNORECASE
    )
    flags.extend(ctf_matches)

    # 2. Standalone 32-character hex hashes (standard OffSec user.txt / proof.txt MD5)
    for line in text.splitlines():
        line = line.strip()
        # Standalone hash or labeled proof line
        if re.fullmatch(r"[0-9a-fA-F]{32}", line):
            flags.append(line)
        else:
            labeled = re.findall(
                r"(?:flag|proof|user\.txt|root\.txt|hash)[:=]\s*([0-9a-fA-F]{32})\b",
                line,
                re.IGNORECASE,
            )
            flags.extend(labeled)

    return list(dict.fromkeys(flags))


class CommandExecutor:
    """Executes commands asynchronously with process tree termination and output capping."""

    @staticmethod
    async def run_command_async(
        command: str, timeout: Optional[float] = 60.0
    ) -> ExecutionResult:
        started_at = datetime.now(timezone.utc)
        stdout = ""
        stderr = ""
        return_code = 0

        kwargs = {
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.PIPE,
        }
        # Process group support on POSIX
        if sys.platform != "win32":
            kwargs["preexec_fn"] = os.setsid  # type: ignore

        try:
            process = await asyncio.create_subprocess_shell(command, **kwargs)

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
                if len(stdout_bytes) > MAX_OUTPUT_BYTES:
                    stdout_bytes = (
                        stdout_bytes[:MAX_OUTPUT_BYTES]
                        + b"\n\n[... Truncated by Synapse: Output exceeded 512KB ...]"
                    )
                if len(stderr_bytes) > MAX_OUTPUT_BYTES:
                    stderr_bytes = (
                        stderr_bytes[:MAX_OUTPUT_BYTES]
                        + b"\n\n[... Truncated by Synapse: Stderr exceeded 512KB ...]"
                    )

                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")
                return_code = process.returncode if process.returncode is not None else 0

            except asyncio.TimeoutError:
                # Terminate entire process tree
                if sys.platform != "win32" and process.pid:
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
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
