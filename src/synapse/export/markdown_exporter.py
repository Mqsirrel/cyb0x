"""Markdown and Obsidian export engine for Synapse."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from synapse.db.repository import DatabaseRepository


def export_markdown_report(repo: DatabaseRepository, title: str = "Penetration Testing Assessment Report") -> str:
    """Generates a publication-ready Markdown report matching OffSec and industry standards."""
    stats = repo.get_stats()
    targets = repo.list_targets()
    credentials = repo.list_credentials()
    leads = repo.list_leads()
    evidence_list = repo.list_evidence()
    routes = repo.list_pivot_routes()

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"# {title}",
        f"*Generated on: {now_str} via Synapse Copilot*",
        "",
        "---",
        "",
        "## 1. Executive & Engagement Summary",
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

    # Section 2: Credentials Matrix
    lines.extend([
        "## 2. Discovered Credentials & Access Matrix",
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
                status_mark = "✓ (Admin)" if tdata.get("admin") else ("✓" if tdata.get("valid") else "✗")
                tested_summary.append(f"`{tip}`:{status_mark}")
            tested_str = ", ".join(tested_summary) if tested_summary else "*None recorded*"
            secret_disp = cred.secret if len(cred.secret) <= 32 else cred.secret[:29] + "..."
            lines.append(
                f"| `{cred.domain or '-'}` | `{cred.username}` | `{secret_disp}` | `{cred.cred_type.value}` | `{cred.service_scope or 'general'}` | {tested_str} |"
            )
        lines.append("")
    else:
        lines.extend(["*No credentials recorded in this engagement.*", ""])

    # Section 3: Pivot Routes & Network Topology
    if routes:
        lines.extend([
            "## 3. Network Topology & Active Pivot Chains",
            "",
            "| Route Name | Jump Host | Target Subnet | Tunnel Type | Local Bind | Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for r in routes:
            lines.append(
                f"| {r.name} | `{r.jump_host_ip}` | `{r.target_subnet}` | `{r.tunnel_type}` | `{r.local_bind}` | `{r.status}` |"
            )
        lines.append("")

    # Section 4: Target Breakdown
    lines.extend([
        "---",
        "",
        "## 4. Target Machine Breakdown & Findings",
        "",
    ])

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
                    f"| `{svc.port}` | `{svc.protocol}` | `{svc.name}` | {prod_ver} | `{svc.status.value}` |"
                )
            lines.append("")

            # Methodology Details & Findings for this Target
            for svc in target.services:
                findings = [c for c in svc.checklists if c.status.value in ("finding", "checked")]
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
                                    "    ```text",
                                    f"    {item.output_snippet.strip()}",
                                    "    ```",
                                ])
                        elif item.status.value == "checked":
                            lines.append(f"- `[✓]` {item.title}")
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
                        "```bash",
                        ev.command,
                        "```",
                    ])
                if ev.output:
                    lines.extend([
                        "- **Terminal Output:**",
                        "```text",
                        ev.output.strip(),
                        "```",
                    ])
                lines.append("")

        lines.extend(["---", ""])

    # Section 5: Leads & Hypotheses
    if leads:
        lines.extend([
            "## 5. Hypotheses & Follow-up Leads",
            "",
            "| Priority | Status | Target | Lead Title | Description |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for lead in leads:
            lines.append(
                f"| `{lead.priority.value.upper()}` | `{lead.status.value}` | `{lead.target_ip or 'Global'}` | **{lead.title}** | {lead.description or '-'} |"
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
    evidence_list = repo.list_evidence()

    # 1. Index Note
    index_content = [
        "# Engagement Dashboard",
        f"*Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*",
        "",
        "## Targets",
    ]
    for t in targets:
        index_content.append(f"- [[{t.ip}]] - {t.os} (`{t.status.value}`)")

    index_content.extend([
        "",
        "## Quick Links",
        "- [[Credentials]]",
        "- [[Leads & Hypotheses]]",
        "- [[Evidence & Flags]]",
    ])
    (output_dir / "Dashboard.md").write_text("\n".join(index_content), encoding="utf-8")

    # 2. Target Notes
    for t in targets:
        target_lines = [
            f"# Target: {t.ip}",
            f"- **Hostname:** {t.hostname or 'None'}",
            f"- **OS:** {t.os}",
            f"- **Status:** `{t.status.value}`",
            "",
            "## Services & Methodology",
        ]
        for svc in t.services:
            target_lines.append(f"### Port {svc.port}/{svc.protocol} - {svc.name} ({svc.product} {svc.version})")
            for c in svc.checklists:
                mark = "[x]" if c.status.value in ("checked", "finding") else "[ ]"
                finding_tag = " **[FINDING]**" if c.status.value == "finding" else ""
                target_lines.append(f"- {mark} {c.title}{finding_tag}")
                if c.command_template:
                    target_lines.append(f"  - Recipe: `{c.command_template}`")
                if c.output_snippet:
                    target_lines.extend(["  - Output:", "    ```text", f"    {c.output_snippet.strip()}", "    ```"])
            target_lines.append("")

        (targets_dir / f"{t.ip}.md").write_text("\n".join(target_lines), encoding="utf-8")

    # 3. Credentials Note
    cred_lines = ["# Discovered Credentials", "", "| Username | Secret | Domain | Scope | Tested |", "| :--- | :--- | :--- | :--- | :--- |"]
    for c in credentials:
        cred_lines.append(f"| `{c.username}` | `{c.secret}` | `{c.domain}` | `{c.service_scope}` | `{len(c.tested_targets)} targets` |")
    (output_dir / "Credentials.md").write_text("\n".join(cred_lines), encoding="utf-8")

    # 4. Leads Note
    lead_lines = ["# Leads & Hypotheses", ""]
    for l in leads:
        lead_lines.append(f"- [{l.priority.value.upper()}] **{l.title}** (`{l.status.value}`) - {l.description}")
    (output_dir / "Leads & Hypotheses.md").write_text("\n".join(lead_lines), encoding="utf-8")

    return output_dir
