"""Masscan output parser (JSON and list format)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Union


def parse_masscan_json(content_or_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Parses Masscan JSON or list output with truncation resilience."""
    if isinstance(content_or_path, Path) or (
        isinstance(content_or_path, str)
        and not content_or_path.strip().startswith("[")
        and not content_or_path.strip().startswith("{")
        and Path(content_or_path).exists()
    ):
        with open(content_or_path, "r", encoding="utf-8") as f:
            raw = f.read()
    else:
        raw = str(content_or_path)

    targets_map: Dict[str, List[Dict[str, Any]]] = {}

    # 1. Try standard JSON format or repaired truncated JSON
    data = None
    try:
        data = json.loads(raw)
    except Exception:
        clean = raw.strip()
        if clean.startswith("["):
            clean_fixed = re.sub(r",\s*$", "", clean) + "]"
            try:
                data = json.loads(clean_fixed)
            except Exception:
                pass

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            ip = item.get("ip")
            if not ip:
                continue
            ports = item.get("ports", [])
            for p in ports:
                if not isinstance(p, dict):
                    continue
                port_num = p.get("port")
                proto = p.get("proto", "tcp")
                if port_num is not None:
                    targets_map.setdefault(ip, []).append(
                        {
                            "port": int(port_num),
                            "protocol": proto,
                            "name": "unknown",
                            "product": "",
                            "version": "",
                            "banner": "",
                        }
                    )
        if targets_map:
            return [
                {
                    "ip": ip,
                    "hostname": "",
                    "os": "Unknown",
                    "services": svcs,
                }
                for ip, svcs in targets_map.items()
            ]

    # 2. Try line / list format: Discovered open port 80/tcp on 10.10.11.10
    for line in raw.splitlines():
        match = re.search(
            r"Discovered open port (\d+)/(tcp|udp) on ([0-9a-fA-F.:]+)", line
        )
        if match:
            port = int(match.group(1))
            proto = match.group(2).lower()
            ip = match.group(3)
            targets_map.setdefault(ip, []).append(
                {
                    "port": port,
                    "protocol": proto,
                    "name": "unknown",
                    "product": "",
                    "version": "",
                    "banner": "",
                }
            )

    return [
        {
            "ip": ip,
            "hostname": "",
            "os": "Unknown",
            "services": svcs,
        }
        for ip, svcs in targets_map.items()
    ]
