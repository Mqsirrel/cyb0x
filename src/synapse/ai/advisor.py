"""Pluggable AI advisor for pentest triage and reasoning."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
import httpx

from synapse.models import Target, Service, Lead, LeadPriority


class AIAdvisor:
    """Provides automated security reasoning and triage with offline deterministic fallbacks."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        provider: str = "auto",
        api_base: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.api_key = (
            api_key
            or os.environ.get("SYNAPSE_AI_API_KEY")
            or os.environ.get("OPENCODE_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
        )
        self.provider = provider
        self.api_base = api_base or os.environ.get("SYNAPSE_AI_BASE") or "https://api.openai.com/v1"
        self.model = model or os.environ.get("SYNAPSE_AI_MODEL") or "gpt-4o-mini"

    @property
    def is_ai_available(self) -> bool:
        return bool(self.api_key)

    def analyze_target_attack_surface(self, target: Target) -> List[Dict[str, Any]]:
        """Analyzes a target's open services and returns prioritized attack hypotheses."""
        if not target.services:
            return [
                {
                    "title": "No Open Ports Discovered",
                    "priority": LeadPriority.LOW,
                    "rationale": "Run a full TCP/UDP port scan to discover listening services.",
                    "suggested_command": f"nmap -sV -sC -p- -T4 {target.ip}",
                }
            ]

        # Deterministic rule-based analysis (always fast, reliable, offline)
        suggestions: List[Dict[str, Any]] = []
        ports = {s.port: s for s in target.services}
        svc_names = {s.name.lower(): s for s in target.services}

        # Check SMB / Active Directory signals
        if 445 in ports or "smb" in svc_names or "microsoft-ds" in svc_names:
            suggestions.append(
                {
                    "title": f"SMB Enumeration & Null Session on {target.ip}:445",
                    "priority": LeadPriority.CRITICAL,
                    "rationale": "SMB often exposes anonymous shares, readable configs, user RID cycling, or legacy exploits (MS17-010).",
                    "suggested_command": f"netexec smb {target.ip} -u '' -p '' --shares --rid-brute",
                }
            )

        # Check Kerberos (DC Indicator)
        if 88 in ports or "kerberos" in svc_names:
            suggestions.append(
                {
                    "title": f"Active Directory Domain Controller Detected on {target.ip}",
                    "priority": LeadPriority.CRITICAL,
                    "rationale": "Port 88 (Kerberos) indicates a Domain Controller. Perform user enumeration, AS-REP Roasting, and Kerberoasting.",
                    "suggested_command": f"kerbrute userenum --dc {target.ip} -d CORP.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
                }
            )

        # Check HTTP/HTTPS services
        http_ports = [p for p in ports if p in (80, 443, 8080, 8443, 8000, 5000, 3000) or "http" in ports[p].name.lower()]
        for hp in http_ports:
            svc = ports[hp]
            suggestions.append(
                {
                    "title": f"Web Application Fuzzing on {target.ip}:{hp}",
                    "priority": LeadPriority.HIGH,
                    "rationale": f"Port {hp} ({svc.product or 'HTTP'}) may host admin portals, API documentation, or vulnerable scripts.",
                    "suggested_command": f"ffuf -u http://{target.ip}:{hp}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,401,403 -c",
                }
            )

        # Check NFS / RPC
        if 2049 in ports or 111 in ports or "nfs" in svc_names:
            suggestions.append(
                {
                    "title": f"NFS Export & Mount Enumeration on {target.ip}",
                    "priority": LeadPriority.HIGH,
                    "rationale": "NFS shares may allow unauthenticated mounting and root_squash misconfigurations.",
                    "suggested_command": f"showmount -e {target.ip}",
                }
            )

        # Check MSSQL
        if 1433 in ports or "mssql" in svc_names or "ms-sql-s" in svc_names:
            suggestions.append(
                {
                    "title": f"MSSQL Default Authentication Test on {target.ip}:1433",
                    "priority": LeadPriority.HIGH,
                    "rationale": "Test default sa account or spray discovered credentials to attempt xp_cmdshell command execution.",
                    "suggested_command": f"netexec mssql {target.ip} -u 'sa' -p '' --local-auth",
                }
            )

        # Check Redis
        if 6379 in ports or "redis" in svc_names:
            suggestions.append(
                {
                    "title": f"Unauthenticated Redis Exploitation on {target.ip}:6379",
                    "priority": LeadPriority.CRITICAL,
                    "rationale": "Redis servers without auth allow writing SSH keys to /root/.ssh/authorized_keys or webshell injection.",
                    "suggested_command": f"redis-cli -h {target.ip} -p 6379 INFO",
                }
            )

        # Check Docker API
        if 2375 in ports or 2376 in ports or "docker" in svc_names:
            suggestions.append(
                {
                    "title": f"Unauthenticated Docker Daemon Escape on {target.ip}:2375",
                    "priority": LeadPriority.CRITICAL,
                    "rationale": "Unauthenticated Docker API allows mounting the host root filesystem into a container.",
                    "suggested_command": f"docker -H tcp://{target.ip}:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh",
                }
            )

        # Check SSH
        if 22 in ports or "ssh" in svc_names:
            suggestions.append(
                {
                    "title": f"SSH Credential Spray & Banner Audit on {target.ip}:22",
                    "priority": LeadPriority.MEDIUM,
                    "rationale": "Test any discovered passwords or cracked hashes against SSH.",
                    "suggested_command": f"hydra -L users.txt -P passwords.txt -s 22 ssh://{target.ip} -t 4",
                }
            )

        return suggestions

    async def query_llm_analysis(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """Queries the configured LLM endpoint asynchronously if available."""
        if not self.is_ai_available:
            return None

        sys_msg = system_prompt or (
            "You are Synapse, an expert offensive security reasoning engine assisting with authorized penetration tests, "
            "eJPTv2 labs, and CTFs. Provide concise, high-signal, prioritized attack hypotheses and exact commands."
        )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": sys_msg},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self.api_base.rstrip('/')}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data["choices"][0]["message"]["content"]
        except Exception:
            pass

        return None
