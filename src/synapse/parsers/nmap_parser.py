"""Nmap scan output parser supporting XML (-oX), Grepable (-oG), and normal text (-oN)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


def parse_nmap_xml(xml_content_or_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Parses Nmap XML output string or file path into structured target data."""
    if isinstance(xml_content_or_path, Path) or (
        isinstance(xml_content_or_path, str)
        and not xml_content_or_path.strip().startswith("<")
        and Path(xml_content_or_path).exists()
    ):
        tree = ET.parse(xml_content_or_path)
        root = tree.getroot()
    else:
        root = ET.fromstring(xml_content_or_path)

    results = []

    for host in root.findall("host"):
        # Status check
        status_elem = host.find("status")
        if status_elem is not None and status_elem.get("state") != "up":
            continue

        # Extract IP address
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if not ip:
            continue

        # Extract Hostname
        hostname = ""
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                name = hn.get("name")
                if name:
                    hostname = name
                    break

        # Extract OS match
        os_name = "Unknown"
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "Unknown")

        # Extract Ports and Services
        services = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port_id = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")

                service_elem = port_elem.find("service")
                svc_name = "unknown"
                product = ""
                version = ""
                extrainfo = ""

                if service_elem is not None:
                    svc_name = service_elem.get("name", "unknown")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    extrainfo = service_elem.get("extrainfo", "")

                # Collect script outputs as banner / extra context
                script_outputs = []
                for script_elem in port_elem.findall("script"):
                    s_id = script_elem.get("id", "")
                    s_out = script_elem.get("output", "").strip()
                    if s_out:
                        script_outputs.append(f"[{s_id}]\n{s_out}")

                banner = extrainfo
                if script_outputs:
                    banner = f"{banner}\n" + "\n".join(script_outputs) if banner else "\n".join(script_outputs)

                services.append(
                    {
                        "port": port_id,
                        "protocol": protocol,
                        "name": svc_name,
                        "product": product,
                        "version": version,
                        "banner": banner.strip(),
                    }
                )

        results.append(
            {
                "ip": ip,
                "hostname": hostname,
                "os": os_name,
                "services": services,
            }
        )

    return results


def parse_nmap_gnmap(content: str) -> List[Dict[str, Any]]:
    """Parses Nmap Grepable (-oG) output."""
    targets_map: Dict[str, Dict[str, Any]] = {}

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Host: 10.10.11.10 (box.local) Ports: 22/open/tcp//ssh//OpenSSH 8.2p1/, 80/open/tcp//http//Apache...
        host_match = re.search(r"Host:\s+([0-9a-fA-F.:]+)(?:\s+\((.*?)\))?", line)
        if not host_match:
            continue

        ip = host_match.group(1)
        hostname = host_match.group(2) or ""

        if ip not in targets_map:
            targets_map[ip] = {
                "ip": ip,
                "hostname": hostname,
                "os": "Unknown",
                "services": [],
            }

        ports_match = re.search(r"Ports:\s+(.*)", line)
        if ports_match:
            ports_str = ports_match.group(1)
            # e.g., 22/open/tcp//ssh//OpenSSH 8.2p1 Ubuntu 4ubuntu0.5/, 80/open/tcp//http//Apache httpd 2.4.41/
            port_items = ports_str.split(", ")
            for item in port_items:
                parts = item.split("/")
                if len(parts) >= 5 and parts[1] == "open":
                    try:
                        port_num = int(parts[0])
                        protocol = parts[2]
                        svc_name = parts[4] or "unknown"
                        product = parts[6] if len(parts) > 6 else ""
                        version = parts[7] if len(parts) > 7 else ""
                        targets_map[ip]["services"].append(
                            {
                                "port": port_num,
                                "protocol": protocol,
                                "name": svc_name,
                                "product": product,
                                "version": version,
                                "banner": "",
                            }
                        )
                    except ValueError:
                        continue

    return list(targets_map.values())


def parse_nmap_text(content: str) -> List[Dict[str, Any]]:
    """Parses standard Nmap text output (-oN or terminal copy)."""
    targets: List[Dict[str, Any]] = []
    current_target: Optional[Dict[str, Any]] = None

    for line in content.splitlines():
        line = line.strip()

        # Nmap scan report for 10.10.11.10 or box.local (10.10.11.10)
        report_match = re.search(
            r"Nmap scan report for\s+(?:([^\s\(\)]+)\s+\(([0-9a-fA-F.:]+)\)|([0-9a-fA-F.:]+))",
            line,
        )
        if report_match:
            if current_target:
                targets.append(current_target)
            if report_match.group(2):
                hostname = report_match.group(1)
                ip = report_match.group(2)
            else:
                hostname = ""
                ip = report_match.group(3)

            current_target = {
                "ip": ip,
                "hostname": hostname,
                "os": "Unknown",
                "services": [],
            }
            continue

        if not current_target:
            continue

        # OS Details: Linux 4.15 - 5.6
        os_match = re.search(r"OS details?:\s+(.*)", line, re.IGNORECASE)
        if os_match:
            current_target["os"] = os_match.group(1).strip()
            continue

        # 22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
        port_match = re.match(
            r"^(\d+)/(tcp|udp)\s+open\s+([^\s]+)(?:\s+(.*))?", line, re.IGNORECASE
        )
        if port_match:
            port_num = int(port_match.group(1))
            protocol = port_match.group(2).lower()
            svc_name = port_match.group(3)
            extra = port_match.group(4) or ""

            current_target["services"].append(
                {
                    "port": port_num,
                    "protocol": protocol,
                    "name": svc_name,
                    "product": extra,
                    "version": "",
                    "banner": "",
                }
            )

    if current_target:
        targets.append(current_target)

    return targets
