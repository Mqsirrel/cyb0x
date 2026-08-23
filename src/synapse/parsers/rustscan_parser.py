"""Rustscan output parser (JSON and raw text output)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Union


def parse_rustscan_json(json_content_or_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Parses Rustscan JSON or command output."""
    if isinstance(json_content_or_path, Path) or (
        isinstance(json_content_or_path, str)
        and not json_content_or_path.strip().startswith("[")
        and not json_content_or_path.strip().startswith("{")
        and Path(json_content_or_path).exists()
    ):
        with open(json_content_or_path, "r", encoding="utf-8") as f:
            raw = f.read()
    else:
        raw = str(json_content_or_path)

    results = []

    # Attempt structured JSON parsing
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            for item in data:
                ip = item.get("ip")
                ports = item.get("ports", [])
                if ip and ports:
                    services = [
                        {
                            "port": int(p),
                            "protocol": "tcp",
                            "name": "unknown",
                            "product": "",
                            "version": "",
                            "banner": "",
                        }
                        for p in ports
                    ]
                    results.append(
                        {
                            "ip": ip,
                            "hostname": "",
                            "os": "Unknown",
                            "services": services,
                        }
                    )
            if results:
                return results
    except Exception:
        pass

    # Regex fallback: Open 10.10.11.10:22 / Open 10.10.11.10:80
    targets_map: Dict[str, List[int]] = {}
    for line in raw.splitlines():
        match = re.search(r"Open\s+([0-9a-fA-F.:]+):(\d+)", line)
        if match:
            ip = match.group(1)
            port = int(match.group(2))
            targets_map.setdefault(ip, []).append(port)

    for ip, ports in targets_map.items():
        results.append(
            {
                "ip": ip,
                "hostname": "",
                "os": "Unknown",
                "services": [
                    {
                        "port": p,
                        "protocol": "tcp",
                        "name": "unknown",
                        "product": "",
                        "version": "",
                        "banner": "",
                    }
                    for p in sorted(set(ports))
                ],
            }
        )

    return results
