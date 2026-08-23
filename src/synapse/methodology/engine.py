"""Methodology engine for matching services to checklists and command recipes."""

from __future__ import annotations

import re
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
        """Determines the best rule key for a given service."""
        svc_name = (service.name or "").lower()
        svc_product = (service.product or "").lower()
        svc_banner = (service.banner or "").lower()
        combined_text = f"{svc_name} {svc_product} {svc_banner}"

        # 1. Exact port & pattern matches
        for key, defn in self.rules.items():
            if key == "generic_unknown":
                continue
            ports = defn.get("ports", [])
            patterns = defn.get("name_patterns", [])

            # Check port match
            port_match = service.port in ports

            # Check regex pattern match
            pattern_match = False
            for pat in patterns:
                if re.search(pat, combined_text, re.IGNORECASE):
                    pattern_match = True
                    break

            if port_match or pattern_match:
                return key

        return "generic_unknown"

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
        domain: str = "WORKGROUP",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    ) -> str:
        """Substitutes variables into a command template."""
        if not template:
            return ""

        replacements = {
            "{IP}": target.ip,
            "{PORT}": str(service.port),
            "{HOST}": target.hostname if target.hostname else target.ip,
            "{USER}": user,
            "{PASS}": password,
            "{DOMAIN}": domain,
            "{WORDLIST}": wordlist,
            "{PRODUCT}": service.product or service.name,
            "{VERSION}": service.version or "",
        }

        rendered = template
        for k, v in replacements.items():
            rendered = rendered.replace(k, v)
        return rendered
