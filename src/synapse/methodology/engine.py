"""Methodology engine for matching services to checklists and command recipes."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from synapse.models import Service, Target


class MethodologyEngine:
    """Matches network services against curated methodology rules and renders commands."""

    def __init__(self, custom_rules_path: Optional[Path] = None):
        self.rules: Dict[str, Any] = {}
        self.initial_recon_rules: List[Dict[str, Any]] = []
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self._load_default_rules()
        if custom_rules_path and custom_rules_path.exists():
            self._load_custom_rules(custom_rules_path)

    def _rebuild_pattern_cache(self) -> None:
        """Precompiles name/banner regexes once so match_service avoids re-compilation."""
        self._compiled_patterns = {
            key: [re.compile(p, re.IGNORECASE) for p in (defn.get("name_patterns", []) or [])]
            for key, defn in self.rules.items()
        }

    def _load_default_rules(self) -> None:
        bundled_path = Path(__file__).parent / "data" / "services.yaml"
        if bundled_path.exists():
            try:
                with open(bundled_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "services" in data:
                        self.rules = data["services"]
                    if data and "initial_recon" in data:
                        self.initial_recon_rules = data["initial_recon"]
            except Exception:
                self.rules = {}
        self._rebuild_pattern_cache()

    def _load_custom_rules(self, path: Path) -> None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "services" in data:
                    self.rules.update(data["services"])
                if data and isinstance(data.get("initial_recon"), list):
                    self.initial_recon_rules = data["initial_recon"]
        except Exception:
            pass
        self._rebuild_pattern_cache()

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

            score = 0
            # Name/banner pattern match is prioritized (patterns precompiled at load)
            for pat in self._compiled_patterns.get(key, []):
                if pat.search(combined_text):
                    score += 10
                    break

            # Exact port match
            if service.port in defn.get("ports", []):
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

    def get_initial_recon_commands(self, target: Target) -> List[Dict[str, str]]:
        """Renders host-level phase-0 reconnaissance recipes for a target with no services yet."""
        rendered: List[Dict[str, str]] = []
        for rc in self.initial_recon_rules:
            if not isinstance(rc, dict):
                continue
            rendered.append(
                {
                    "category": rc.get("category", "recon"),
                    "title": rc.get("title", ""),
                    "description": rc.get("description", ""),
                    "command_template": self.render_command(rc.get("command_template", ""), target),
                }
            )
        return rendered

    def render_command(
        self,
        template: str,
        target: Target,
        service: Optional[Service] = None,
        user: str = "admin",
        password: str = "password",
        ntlm_hash: str = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        domain: str = "WORKGROUP",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    ) -> str:
        """Substitutes variables into a command template safely with URL and protocol awareness.

        When ``service`` is None (host-level initial recon recipes), service-scoped
        tokens such as {PORT} are intentionally left unsubstituted.
        """
        if not template:
            return ""

        # Determine HTTP vs HTTPS protocol
        is_ssl = bool(service) and (
            service.port in [443, 8443, 9443]
            or "ssl" in (service.name or "").lower()
            or "https" in (service.name or "").lower()
        )
        proto_scheme = "https" if is_ssl else "http"

        # Auto-extract domain if default WORKGROUP was passed
        resolved_domain = domain
        if resolved_domain == "WORKGROUP":
            if service and service.banner:
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
            "HOST": target_host,
            "USER": user,
            "PASS": password,
            "HASH": ntlm_hash,
            "DOMAIN": resolved_domain,
            "WORDLIST": wordlist,
            "PRODUCT": (service.product or service.name) if service else "",
            "VERSION": service.version if service else "",
            "PROTO": proto_scheme,
        }

        if service:
            replacements["PORT"] = str(service.port)

        # Substitute {PROTO} or auto-adjust http:// to https:// when SSL is active
        rendered = template
        if is_ssl and "http://{IP}:{PORT}" in rendered:
            rendered = rendered.replace("http://{IP}:{PORT}", "https://{IP}:{PORT}")

        # Values originate from scan data (banners, hostnames, harvested creds) —
        # an untrusted trust boundary. Quote them so shell metacharacters can
        # never break out of the command executed via create_subprocess_shell.
        def quote_value(value: str, prev_char: str) -> str:
            if not value:
                return ""
            if prev_char == "'":
                return value.replace("'", "'\\''")
            if prev_char == '"':
                return re.sub(r'(["$`\\])', r"\\\1", value)
            return shlex.quote(value)

        def replace_token(match: re.Match) -> str:
            token = match.group(1)
            if token not in replacements:
                return match.group(0)
            prev_char = rendered[match.start() - 1] if match.start() > 0 else ""
            return quote_value(str(replacements[token]), prev_char)

        return re.sub(r"\{(\w+)\}", replace_token, rendered)

