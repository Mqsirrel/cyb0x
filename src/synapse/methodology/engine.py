"""Methodology engine for matching services to checklists and command recipes."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from synapse.models import ChecklistItem, ChecklistStatus, Service, Target


class MethodologyEngine:
    """Matches network services against curated methodology rules and renders commands."""

    def __init__(self, custom_rules_path: Optional[Path] = None):
        self.rules: Dict[str, Any] = {}
        self._load_default_rules()
        if custom_rules_path and custom_rules_path.exists():
            self._load_custom_rules(custom_rules_path)

    def _load_default_rules(self) -> None:
        bundled_path = Path(__file__).parent / "data" / "services.yaml"
        if bundled_path.exists():
            try:
                with open(bundled_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "services" in data:
                        self.rules = data["services"]
            except Exception:
                self.rules = {}

    def _load_custom_rules(self, path: Path) -> None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "services" in data:
                    self.rules.update(data["services"])
        except Exception:
            pass

    def match_service(self, service: Service) -> str:
        """Determines the best rule key for a given service based on pattern & port scoring."""
        svc_name = (service.name or "").lower()
        svc_product = (service.product or "").lower()
        svc_banner = (service.banner or "").lower()
        combined_text = f"{svc_name} {svc_product} {svc_banner}".strip()

        best_key = "generic_unknown"
        highest_score = 0

        for key, defn in self.rules.items():
            if key == "generic_unknown":
                continue
            ports = defn.get("ports", [])
            patterns = defn.get("name_patterns", [])

            score = 0
            # Name/banner pattern match is prioritized
            for pat in patterns:
                if re.search(pat, combined_text, re.IGNORECASE):
                    score += 10
                    break

            # Exact port match
            if service.port in ports:
                score += 5

            if score > highest_score:
                highest_score = score
                best_key = key

        return best_key

    def get_checklists_for_service(self, service: Service) -> List[Dict[str, Any]]:
        """Returns the list of raw checklist definitions for a service."""
        rule_key = self.match_service(service)
        rule_defn = self.rules.get(rule_key, self.rules.get("generic_unknown", {}))
        return rule_defn.get("checklists", [])

    def render_command(
        self,
        template: str,
        target: Target,
        service: Service,
        user: str = "admin",
        password: str = "password",
        ntlm_hash: str = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        domain: str = "WORKGROUP",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    ) -> str:
        """Substitutes variables into a command template safely with URL and protocol awareness."""
        if not template:
            return ""

        # Determine HTTP vs HTTPS protocol
        is_ssl = (
            service.port in [443, 8443, 9443]
            or "ssl" in (service.name or "").lower()
            or "https" in (service.name or "").lower()
        )
        proto_scheme = "https" if is_ssl else "http"

        # Auto-extract domain if default WORKGROUP was passed
        resolved_domain = domain
        if resolved_domain == "WORKGROUP":
            if service.banner:
                d_match = re.search(r"\(domain:([^\)]+)\)", service.banner, re.IGNORECASE)
                if d_match:
                    resolved_domain = d_match.group(1).upper()
            if resolved_domain == "WORKGROUP" and target.hostname and "." in target.hostname:
                parts = target.hostname.split(".", 1)
                if len(parts) > 1 and parts[1]:
                    resolved_domain = parts[1].upper()

        target_host = target.hostname if target.hostname else target.ip

        replacements = {
            "IP": target.ip,
            "PORT": str(service.port),
            "HOST": target_host,
            "USER": user,
            "PASS": password,
            "HASH": ntlm_hash,
            "DOMAIN": resolved_domain,
            "WORDLIST": wordlist,
            "PRODUCT": service.product or service.name,
            "VERSION": service.version or "",
            "PROTO": proto_scheme,
        }

        # Substitute {PROTO} or auto-adjust http:// to https:// when SSL is active
        rendered = template
        if is_ssl and "http://{IP}:{PORT}" in rendered:
            rendered = rendered.replace("http://{IP}:{PORT}", "https://{IP}:{PORT}")

        def replace_token(match: re.Match) -> str:
            token = match.group(1)
            return replacements.get(token, match.group(0))

        return re.sub(r"\{(\w+)\}", replace_token, rendered)
