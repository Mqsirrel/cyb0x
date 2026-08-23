"""NetExec (nxc) and CrackMapExec (cme) output parser."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Union


def parse_netexec_output(content_or_path: Union[str, Path]) -> Dict[str, Any]:
    """Parses NetExec / CrackMapExec logs, extracting targets, services, and credentials."""
    if isinstance(content_or_path, Path) or (
        isinstance(content_or_path, str)
        and not content_or_path.strip().startswith("SMB")
        and not content_or_path.strip().startswith("WINRM")
        and not content_or_path.strip().startswith("SSH")
        and not content_or_path.strip().startswith("MSSQL")
        and not content_or_path.strip().startswith("LDAP")
        and not content_or_path.strip().startswith("FTP")
        and not content_or_path.strip().startswith("RDP")
        and Path(content_or_path).exists()
    ):
        with open(content_or_path, "r", encoding="utf-8") as f:
            raw = f.read()
    else:
        raw = str(content_or_path)

    targets_map: Dict[str, Dict[str, Any]] = {}
    credentials: List[Dict[str, Any]] = []

    # Matches: PROTO IP PORT [HOSTNAME] [*|+|-|!] REST
    header_pattern = re.compile(
        r"^(SMB|WINRM|SSH|MSSQL|LDAP|FTP|RDP|WMI|VNC)\s+([0-9a-fA-F.:]+)\s+(\d+)\s+(?:([A-Za-z0-9._\-]+)\s+)?(?=\[|\*|\+|\-|\!)(.+)$",
        re.IGNORECASE,
    )

    # Strictly matches credentials directly following [+] STATUS
    cred_pattern = re.compile(
        r"\[\+\]\s+(?:([a-zA-Z0-9._\-]+)\\)?([a-zA-Z0-9._\-]+):(.*)$",
        re.IGNORECASE,
    )

    for line in raw.splitlines():
        line = line.strip()
        match = header_pattern.match(line)
        if not match:
            continue

        proto_name = match.group(1).lower()
        ip = match.group(2)
        port = int(match.group(3))
        hostname = match.group(4) or ""
        rest = match.group(5)

        # Check hostname in rest if not in column: (name:DC01)
        name_match = re.search(r"\(name:([^\)]+)\)", rest, re.IGNORECASE)
        extracted_hostname = hostname
        if not extracted_hostname and name_match:
            extracted_hostname = name_match.group(1)

        # Check domain info in rest: (domain:CORP.LOCAL)
        domain_match = re.search(r"\(domain:([^\)]+)\)", rest, re.IGNORECASE)
        domain_name = domain_match.group(1) if domain_match else ""

        if ip not in targets_map:
            targets_map[ip] = {
                "ip": ip,
                "hostname": extracted_hostname if extracted_hostname != ip else "",
                "os": "Windows" if proto_name in ("smb", "winrm", "wmi") else "Unknown",
                "domain": domain_name,
                "services": [],
            }
        elif extracted_hostname and not targets_map[ip]["hostname"]:
            targets_map[ip]["hostname"] = extracted_hostname

        # Propagate domain info to the target record if newly discovered
        if domain_name and not targets_map[ip].get("domain"):
            targets_map[ip]["domain"] = domain_name

        # Check OS info in rest: [*] Windows 10...
        os_match = re.search(r"\[\*\]\s+(Windows[^\(]+)", rest, re.IGNORECASE)
        if os_match:
            targets_map[ip]["os"] = os_match.group(1).strip()

        # Add service
        existing_ports = [s["port"] for s in targets_map[ip]["services"]]
        if port not in existing_ports:
            targets_map[ip]["services"].append(
                {
                    "port": port,
                    "protocol": "tcp",
                    "name": proto_name,
                    "product": f"NetExec {proto_name.upper()}",
                    "version": "",
                    "banner": rest,
                }
            )

        # Check for successful authentication / credential leak
        cred_match = cred_pattern.search(rest)
        if cred_match:
            cred_domain = cred_match.group(1) or domain_name
            username = cred_match.group(2)
            secret_and_flags = cred_match.group(3).strip()

            is_pwn3d = "(pwn3d!)" in secret_and_flags.lower()
            # Remove (Pwn3d!) tag from secret
            clean_secret = re.sub(r"\s*\(Pwn3d\!\)\s*", "", secret_and_flags, flags=re.IGNORECASE).strip()
            if not clean_secret:
                clean_secret = "<blank>"

            # Determine cred type: NTLM hash (32 hex or LM:NTLM 32:32 hex) or password
            is_ntlm = bool(
                re.fullmatch(r"[0-9a-fA-F]{32}", clean_secret)
                or re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}", clean_secret)
            )
            cred_type = "ntlm_hash" if is_ntlm else "password"

            credentials.append(
                {
                    "target_ip": ip,
                    "domain": cred_domain,
                    "username": username,
                    "secret": clean_secret,
                    "cred_type": cred_type,
                    "service_scope": proto_name,
                    "is_admin": is_pwn3d,
                    "notes": f"Captured from NetExec {proto_name} check on {ip}:{port}",
                }
            )

    return {
        "targets": list(targets_map.values()),
        "credentials": credentials,
    }
