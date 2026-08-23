"""Full workspace JSON backup and restore for Synapse."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from synapse.db.repository import DatabaseRepository
from synapse.models import (
    ChecklistStatus,
    CredentialType,
    LeadPriority,
    LeadStatus,
    ProofType,
    ServiceStatus,
    TargetStatus,
)


def export_workspace_json(repo: DatabaseRepository) -> str:
    """Exports entire assessment workspace into a structured JSON string."""
    targets = repo.list_targets()
    credentials = repo.list_credentials()
    leads = repo.list_leads()
    evidence_list = repo.list_evidence()
    routes = repo.list_pivot_routes()

    data = {
        "version": "1.0",
        "targets": [t.model_dump(mode="json") for t in targets],
        "credentials": [c.model_dump(mode="json") for c in credentials],
        "leads": [l.model_dump(mode="json") for l in leads],
        "evidence": [e.model_dump(mode="json") for e in evidence_list],
        "pivot_routes": [r.model_dump(mode="json") for r in routes],
    }

    return json.dumps(data, indent=2)


def import_workspace_json(
    repo: DatabaseRepository, json_str_or_path: str | Path
) -> Dict[str, int]:
    """Imports workspace data from JSON into the repository with full fidelity."""
    if isinstance(json_str_or_path, Path) or (
        isinstance(json_str_or_path, str)
        and not json_str_or_path.strip().startswith("{")
        and Path(json_str_or_path).exists()
    ):
        with open(json_str_or_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = json.loads(str(json_str_or_path))

    counts = {
        "targets": 0,
        "services": 0,
        "checklists": 0,
        "credentials": 0,
        "leads": 0,
        "evidence": 0,
        "routes": 0,
    }

    # 1. Import targets and services
    for t_data in data.get("targets", []):
        t = repo.add_or_get_target(
            ip=t_data["ip"],
            hostname=t_data.get("hostname", ""),
            os=t_data.get("os", "Unknown"),
            status=TargetStatus(t_data.get("status", "discovered")),
            tags=t_data.get("tags", []),
            notes=t_data.get("notes", ""),
        )
        counts["targets"] += 1

        for s_data in t_data.get("services", []):
            s = repo.add_or_update_service(
                target_id=t.id,  # type: ignore
                port=s_data["port"],
                protocol=s_data.get("protocol", "tcp"),
                name=s_data.get("name", "unknown"),
                product=s_data.get("product", ""),
                version=s_data.get("version", ""),
                banner=s_data.get("banner", ""),
                status=ServiceStatus(s_data.get("status", "untested")),
                notes=s_data.get("notes", ""),
            )
            counts["services"] += 1

            for c_data in s_data.get("checklists", []):
                repo.add_checklist_item(
                    service_id=s.id,  # type: ignore
                    category=c_data.get("category", "enum"),
                    title=c_data["title"],
                    description=c_data.get("description", ""),
                    command_template=c_data.get("command_template", ""),
                    status=ChecklistStatus(c_data.get("status", "todo")),
                    output_snippet=c_data.get("output_snippet", ""),
                )
                counts["checklists"] += 1

    # 2. Import credentials
    for c_data in data.get("credentials", []):
        t_id = None
        if c_data.get("target_ip"):
            t = repo.get_target_by_ip(c_data["target_ip"])
            if t:
                t_id = t.id

        cred = repo.add_credential(
            username=c_data["username"],
            secret=c_data["secret"],
            cred_type=CredentialType(c_data.get("cred_type", "password")),
            domain=c_data.get("domain", ""),
            service_scope=c_data.get("service_scope", ""),
            target_id=t_id,
            notes=c_data.get("notes", ""),
        )
        if c_data.get("tested_targets"):
            for tip, tinfo in c_data["tested_targets"].items():
                repo.record_credential_test(
                    cred_id=cred.id,  # type: ignore
                    target_ip=tinfo.get("target_ip", tip.split(":")[0]),
                    service=tinfo.get("service", "smb"),
                    valid=tinfo.get("valid", False),
                    admin=tinfo.get("admin", False),
                )
        counts["credentials"] += 1

    # 3. Import leads
    for l_data in data.get("leads", []):
        t_id = None
        if l_data.get("target_ip"):
            t = repo.get_target_by_ip(l_data["target_ip"])
            if t:
                t_id = t.id
        repo.add_lead(
            title=l_data["title"],
            description=l_data.get("description", ""),
            priority=LeadPriority(l_data.get("priority", "medium")),
            status=LeadStatus(l_data.get("status", "backlog")),
            target_id=t_id,
        )
        counts["leads"] += 1

    # 4. Import evidence
    for e_data in data.get("evidence", []):
        t_id = None
        if e_data.get("target_ip"):
            t = repo.get_target_by_ip(e_data["target_ip"])
            if t:
                t_id = t.id
        if t_id is not None:
            repo.add_evidence(
                target_id=t_id,
                title=e_data["title"],
                proof_type=ProofType(e_data.get("proof_type", "command_output")),
                command=e_data.get("command", ""),
                output=e_data.get("output", ""),
                flag_hash=e_data.get("flag_hash", ""),
                screenshot_path=e_data.get("screenshot_path", ""),
            )
            counts["evidence"] += 1

    # 5. Import pivot routes
    for r_data in data.get("pivot_routes", []):
        repo.add_pivot_route(
            name=r_data["name"],
            jump_host_ip=r_data["jump_host_ip"],
            target_subnet=r_data["target_subnet"],
            tunnel_type=r_data.get("tunnel_type", "ligolo_ng"),
            local_bind=r_data.get("local_bind", "127.0.0.1:1080"),
            notes=r_data.get("notes", ""),
        )
        counts["routes"] += 1

    return counts
