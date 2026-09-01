"""Markdown and Obsidian export engine for Synapse."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from synapse.db.repository import DatabaseRepository


def _escape_md_table(val: str) -> str:
    """Escapes pipes and newlines for safe Markdown table cell rendering."""
    if not val:
        return ""
    return str(val).replace("|", "\\|").replace("\n", " ").replace("\r", "")


def _safe_code_fence(code: str, lang: str = "text") -> str:
    """Safely wraps code blocks even if the content contains triple backticks."""
    if "```" in code:
        return f"````{lang}\n{code}\n````"
    return f"```{lang}\n{code}\n```"


def export_markdown_report(
    repo: DatabaseRepository,
    title: str = "Penetration Testing Assessment Report",
) -> str:
    """Generates a publication-ready Markdown report matching OffSec and industry standards."""
    stats = repo.get_stats()
    targets = repo.list_targets()
    credentials = repo.list_credentials()
    leads = repo.list_leads()
    evidence_list = repo.list_evidence()
    routes = repo.list_pivot_routes()

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    section_num = 1

    lines = [
        f"# {title}",
        f"*Generated on: {now_str} via Synapse Copilot*",
        "",
        "---",
        "",
        f"## {section_num}. Executive & Engagement Summary",
        "",
        "| Metric | Count |",
        "| :--- | :--- |",
        f"| **Total Targets in Scope** | `{stats['total_targets']}` |",
        f"| **Fully Pwned / Compromised Targets** | `{stats['pwned_targets']}` |",
        f"| **Foothold / Partial Access** | `{stats['foothold_targets']}` |",
        f"| **Total Discovered Open Services** | `{stats['total_services']}` |",
        f"| **Completed Methodology Checks** | `{stats['completed_checks']}` |",
        f"| **Identified Findings / Vectors** | `{stats['total_findings']}` |",
        f"| **Discovered Credentials / Hashes** | `{stats['total_credentials']}` |",
        f"| **Captured Proof Flags** | `{stats['captured_flags']}` |",
        "",
        "---",
        "",
    ]
    section_num += 1

    # Section: Credentials Matrix
    lines.extend([
        f"## {section_num}. Discovered Credentials & Access Matrix",
        "",
    ])
    if credentials:
        lines.extend([
            "| Domain | Username | Secret / Hash | Type | Service Scope | Tested Targets |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for cred in credentials:
            tested_summary = []
            for tip, tdata in cred.tested_targets.items():
                status_mark = (
                    "✓ (Admin)"
                    if tdata.get("admin")
                    else ("✓" if tdata.get("valid") else "✗")
                )
                tested_summary.append(f"`{_escape_md_table(tip)}`:{status_mark}")
            tested_str = (
                ", ".join(tested_summary) if tested_summary else "*None recorded*"
            )
            secret_disp = (
                cred.secret
                if len(cred.secret) <= 32
                else cred.secret[:29] + "..."
            )
            lines.append(
                f"| `{_escape_md_table(cred.domain or '-')}` | `{_escape_md_table(cred.username)}` | `{_escape_md_table(secret_disp)}` | `{cred.cred_type.value}` | `{_escape_md_table(cred.service_scope or 'general')}` | {tested_str} |"
            )
        lines.append("")
    else:
        lines.extend(["*No credentials recorded in this engagement.*", ""])
    section_num += 1

    # Section: Pivot Routes & Network Topology
    if routes:
        lines.extend([
            f"## {section_num}. Network Topology & Active Pivot Chains",
            "",
            "| Route Name | Jump Host | Target Subnet | Tunnel Type | Local Bind | Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for r in routes:
            lines.append(
                f"| {_escape_md_table(r.name)} | `{_escape_md_table(r.jump_host_ip)}` | `{_escape_md_table(r.target_subnet)}` | `{_escape_md_table(r.tunnel_type)}` | `{_escape_md_table(r.local_bind)}` | `{_escape_md_table(r.status)}` |"
            )
        lines.append("")
        section_num += 1

    # Section: Target Breakdown
    lines.extend([
        "---",
        "",
        f"## {section_num}. Target Machine Breakdown & Findings",
        "",
    ])
    section_num += 1

    if not targets:
        lines.extend(["*No target hosts currently registered in workspace.*", ""])

    for target in targets:
        hostname_str = f" ({target.hostname})" if target.hostname else ""
        lines.extend([
            f"### Target: `{target.ip}`{hostname_str}",
            "",
            f"- **Operating System:** {target.os}",
            f"- **Assessment Status:** `{target.status.value.upper()}`",
            f"- **Tags:** {', '.join([f'`{t}`' for t in target.tags]) if target.tags else 'None'}",
        ])
        if target.notes:
            lines.extend([f"- **Notes:** {target.notes}"])
        lines.append("")

        # Services Table
        lines.extend([
            "#### Open Ports & Services",
            "",
        ])
        if target.services:
            lines.extend([
                "| Port | Protocol | Service | Product / Version | Status |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ])
            for svc in target.services:
                prod_ver = f"{svc.product} {svc.version}".strip() or "-"
                lines.append(
                    f"| `{svc.port}` | `{svc.protocol}` | `{_escape_md_table(svc.name)}` | {_escape_md_table(prod_ver)} | `{svc.status.value}` |"
                )
            lines.append("")

            # Methodology Details & Findings for this Target
            for svc in target.services:
                findings = [
                    c
                    for c in svc.checklists
                    if c.status.value in ("finding", "checked")
                ]
                if findings or svc.notes:
                    lines.extend([
                        f"##### Port `{svc.port}/{svc.protocol}` ({svc.name}) Details",
                        "",
                    ])
                    if svc.notes:
                        lines.extend([f"**Analyst Notes:** {svc.notes}", ""])
                    for item in svc.checklists:
                        if item.status.value == "finding":
                            lines.extend([
                                f"- **[VULNERABILITY / FINDING] {item.title}**",
                                f"  - *Category:* `{item.category}`",
                                f"  - *Command Recipe:* `{item.command_template}`",
                            ])
                            if item.output_snippet:
                                lines.extend([
                                    "  - *Output Snippet:*",
                                    _safe_code_fence(item.output_snippet.strip(), "text"),
                                ])
                        elif item.status.value == "checked":
                            lines.append(f"- `[✓]` {item.title}")
                        elif item.status.value == "deferred":
                            lines.append(f"- `[↷]` *{item.title} (Deferred)*")
                    lines.append("")
        else:
            lines.extend(["*No open services recorded for this target.*", ""])

        # Target Evidence & Proof Flags
        target_ev = [e for e in evidence_list if e.target_id == target.id]
        if target_ev:
            lines.extend([
                "#### Evidence & Proof of Concept",
                "",
            ])
            for ev in target_ev:
                lines.extend([
                    f"##### Proof: {ev.title} ({ev.proof_type.value})",
                    f"- **Captured At:** {ev.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                ])
                if ev.flag_hash:
                    lines.append(f"- **Flag Hash:** `{ev.flag_hash}`")
                if ev.command:
                    lines.extend([
                        "- **Execution Command:**",
                        _safe_code_fence(ev.command, "bash"),
                    ])
                if ev.output:
                    lines.extend([
                        "- **Terminal Output:**",
                        _safe_code_fence(ev.output.strip(), "text"),
                    ])
                lines.append("")

        lines.extend(["---", ""])

    # Section: Leads & Hypotheses
    if leads:
        lines.extend([
            f"## {section_num}. Hypotheses & Follow-up Leads",
            "",
            "| Priority | Status | Target | Lead Title | Description |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for lead in leads:
            lines.append(
                f"| `{lead.priority.value.upper()}` | `{lead.status.value}` | `{_escape_md_table(lead.target_ip or 'Global')}` | **{_escape_md_table(lead.title)}** | {_escape_md_table(lead.description or '-')} |"
            )
        lines.append("")

    return "\n".join(lines)


def export_obsidian_vault(repo: DatabaseRepository, output_dir: Path) -> Path:
    """Exports structured individual Markdown notes formatted for an Obsidian vault."""
    output_dir.mkdir(parents=True, exist_ok=True)
    targets_dir = output_dir / "Targets"
    targets_dir.mkdir(parents=True, exist_ok=True)

    targets = repo.list_targets()
    credentials = repo.list_credentials()
    leads = repo.list_leads()

    # 1. Index Note
    index_content = [
        "# Engagement Dashboard",
        f"*Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*",
        "",
        "## Targets",
    ]
    def _clean_target_filename(raw_name: str) -> str:
        cleaned = re.sub(r"[/\\:]", "_", raw_name.strip())
        while ".." in cleaned:
            cleaned = cleaned.replace("..", "_")
        return cleaned.strip("._") or "target"

    for t in targets:
        safe_ip_name = _clean_target_filename(t.ip)
        index_content.append(f"- [[{safe_ip_name}]] - {t.os} (`{t.status.value}`)")

    index_content.extend([
        "",
        "## Quick Links",
        "- [[Credentials]]",
        "- [[Leads & Hypotheses]]",
    ])
    (output_dir / "Dashboard.md").write_text("\n".join(index_content), encoding="utf-8")

    # 2. Target Notes
    for t in targets:
        safe_ip_name = _clean_target_filename(t.ip)
        target_lines = [
            f"# Target: {t.ip}",
            f"- **Hostname:** {t.hostname or 'None'}",
            f"- **OS:** {t.os}",
            f"- **Status:** `{t.status.value}`",
            "",
            "## Services & Methodology",
        ]
        for svc in t.services:
            target_lines.append(
                f"### Port {svc.port}/{svc.protocol} - {svc.name} ({svc.product} {svc.version})"
            )
            for c in svc.checklists:
                mark = "[x]" if c.status.value in ("checked", "finding") else ("[-]" if c.status.value == "deferred" else "[ ]")
                finding_tag = " **[FINDING]**" if c.status.value == "finding" else ""
                deferred_tag = " *(Deferred)*" if c.status.value == "deferred" else ""
                target_lines.append(f"- {mark} {c.title}{finding_tag}{deferred_tag}")
                if c.command_template:
                    target_lines.append(f"  - Recipe: `{c.command_template}`")
                if c.output_snippet:
                    target_lines.extend([
                        "  - Output:",
                        _safe_code_fence(c.output_snippet.strip(), "text"),
                    ])
            target_lines.append("")

        (targets_dir / f"{safe_ip_name}.md").write_text(
            "\n".join(target_lines), encoding="utf-8"
        )

    # 3. Credentials Note
    cred_lines = [
        "# Discovered Credentials",
        "",
        "| Username | Secret | Domain | Scope | Tested |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for c in credentials:
        cred_lines.append(
            f"| `{_escape_md_table(c.username)}` | `{_escape_md_table(c.secret)}` | `{_escape_md_table(c.domain)}` | `{_escape_md_table(c.service_scope)}` | `{len(c.tested_targets)} targets` |"
        )
    (output_dir / "Credentials.md").write_text("\n".join(cred_lines), encoding="utf-8")

    # 4. Leads Note
    lead_lines = ["# Leads & Hypotheses", ""]
    for l in leads:
        lead_lines.append(
            f"- [{l.priority.value.upper()}] **{l.title}** (`{l.status.value}`) - {l.description}"
        )
    (output_dir / "Leads & Hypotheses.md").write_text("\n".join(lead_lines), encoding="utf-8")

    return output_dir
