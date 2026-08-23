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
    SeverityLevel,
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
        "version": "2.0",
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
    """Imports workspace data from JSON into the repository with full fidelity and resilience."""
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
        ip_val = t_data.get("ip")
        if not ip_val:
            continue

        t = repo.add_or_get_target(
            ip=ip_val,
            hostname=t_data.get("hostname", ""),
            os=t_data.get("os", "Unknown"),
            status=TargetStatus(t_data.get("status", "discovered")),
            in_scope=t_data.get("in_scope", True),
            tags=t_data.get("tags", []),
            notes=t_data.get("notes", ""),
        )
        counts["targets"] += 1

        for s_data in t_data.get("services", []):
            port_val = s_data.get("port")
            if port_val is None or not isinstance(port_val, int):
                continue

            s = repo.add_or_update_service(
                target_id=t.id,  # type: ignore
                port=port_val,
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
                title_val = c_data.get("title")
                if not title_val:
                    continue

                repo.add_checklist_item(
                    service_id=s.id,  # type: ignore
                    category=c_data.get("category", "enum"),
                    title=title_val,
                    description=c_data.get("description", ""),
                    command_template=c_data.get("command_template", ""),
                    status=ChecklistStatus(c_data.get("status", "todo")),
                    severity=SeverityLevel(c_data.get("severity", "info")),
                    remediation=c_data.get("remediation", ""),
                    output_snippet=c_data.get("output_snippet", ""),
                )
                counts["checklists"] += 1

    # 2. Import credentials
    for c_data in data.get("credentials", []):
        user_val = c_data.get("username")
        secret_val = c_data.get("secret")
        if not user_val or not secret_val:
            continue

        t_id = None
        if c_data.get("target_ip"):
            t = repo.get_target_by_ip(c_data["target_ip"])
            if t:
                t_id = t.id

        cred = repo.add_credential(
            username=user_val,
            secret=secret_val,
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
        title_val = l_data.get("title")
        if not title_val:
            continue

        t_id = None
        if l_data.get("target_ip"):
            t = repo.get_target_by_ip(l_data["target_ip"])
            if t:
                t_id = t.id
        repo.add_lead(
            title=title_val,
            description=l_data.get("description", ""),
            priority=LeadPriority(l_data.get("priority", "medium")),
            severity=SeverityLevel(l_data.get("severity", "info")),
            status=LeadStatus(l_data.get("status", "backlog")),
            target_id=t_id,
        )
        counts["leads"] += 1

    # 4. Import evidence
    for e_data in data.get("evidence", []):
        title_val = e_data.get("title")
        if not title_val:
            continue

        t_id = None
        if e_data.get("target_ip"):
            t = repo.get_target_by_ip(e_data["target_ip"])
            if t:
                t_id = t.id
        if t_id is not None:
            # Restore relational links (service / methodology check) so the
            # evidence ledger keeps its context across workspace round-trips.
            svc_id = None
            chk_id = None
            t_fresh = repo.get_target_by_id(t_id)
            exported_target = next(
                (x for x in data.get("targets", []) if x.get("ip") == e_data.get("target_ip")),
                None,
            )
            if t_fresh and exported_target:
                exported_svc = next(
                    (s for s in (exported_target.get("services") or []) if s.get("id") == e_data.get("service_id")),
                    None,
                )
                if exported_svc:
                    match = next(
                        (
                            s
                            for s in t_fresh.services
                            if s.port == exported_svc.get("port")
                            and s.protocol == exported_svc.get("protocol", "tcp")
                        ),
                        None,
                    )
                    if match:
                        svc_id = match.id
                        exported_chk = next(
                            (
                                c
                                for c in (exported_svc.get("checklists") or [])
                                if c.get("id") == e_data.get("checklist_id")
                            ),
                            None,
                        )
                        if exported_chk and exported_chk.get("title"):
                            chk_match = next(
                                (c for c in match.checklists if c.title == exported_chk["title"]),
                                None,
                            )
                            if chk_match:
                                chk_id = chk_match.id

            repo.add_evidence(
                target_id=t_id,
                title=title_val,
                proof_type=ProofType(e_data.get("proof_type", "command_output")),
                service_id=svc_id,
                checklist_id=chk_id,
                command=e_data.get("command", ""),
                output=e_data.get("output", ""),
                flag_hash=e_data.get("flag_hash", ""),
                screenshot_path=e_data.get("screenshot_path", ""),
            )
            counts["evidence"] += 1

    # 5. Import pivot routes
    for r_data in data.get("pivot_routes", []):
        if not r_data.get("name") or not r_data.get("jump_host_ip") or not r_data.get("target_subnet"):
            continue
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
