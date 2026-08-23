"""Notion Workspace Exporter for Synapse.

Generates a structured, Notion-native workspace bundle (Markdown files with
relative child links, callouts, database tables, and checklist blocks)
optimized for Notion's 'Import -> Markdown' feature.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from synapse.db.repository import DatabaseRepository
from synapse.models import (
    ChecklistStatus,
    Credential,
    Evidence,
    Lead,
    PivotRoute,
    ProofType,
    Service,
    Target,
    TargetStatus,
)


def _escape_md_table(text: str) -> str:
    """Escapes pipes, newlines, and backticks for standard Markdown tables."""
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", "").replace("`", "'")


def _safe_code_fence(content: str, lang: str = "bash") -> str:
    """Safely wraps content in Markdown fenced code blocks."""
    ticks = "```"
    while ticks in content:
        ticks += "`"
    return f"{ticks}{lang}\n{content}\n{ticks}"


def _clean_filename(raw_name: str) -> str:
    """Sanitizes file names to prevent path traversal and illegal characters."""
    cleaned = re.sub(r"[/\\:]", "_", raw_name.strip())
    while ".." in cleaned:
        cleaned = cleaned.replace("..", "_")
    return cleaned.strip("._") or "target"


def export_notion_workspace(repo: DatabaseRepository, output_dir: Path) -> Path:
    """Exports a Notion-native structured assessment workspace.

    Structure:
    ├── SYNAPSE Assessment Workspace.md  (Top-level Notion dashboard with callouts)
    ├── Targets/
    │   ├── 10.10.11.150.md             (Child page per target with service tables & recipes)
    │   └── ...
    ├── Credentials.md                   (Credential Vault table)
    ├── Leads & Hypotheses.md            (Attack leads board)
    ├── Evidence & Flags.md              (Proof flags and execution logs)
    └── Pivoting & Networks.md           (Pivoting routes and subnets)
    """
    output_dir = Path(output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    targets_dir = output_dir / "Targets"
    targets_dir.mkdir(parents=True, exist_ok=True)

    targets = repo.list_targets()
    credentials = repo.list_credentials()
    leads = repo.list_leads()
    evidence_list = repo.list_evidence()
    routes = repo.list_pivot_routes()
    stats = repo.get_stats()

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # =========================================================================
    # 1. Main Notion Dashboard (Parent Page)
    # =========================================================================
    pwned_count = stats.get("pwned_targets", 0)
    foothold_count = stats.get("foothold_targets", 0)
    flags_count = stats.get("captured_flags", 0)
    findings_count = stats.get("total_findings", 0)

    dash_lines = [
        "# SYNAPSE Assessment Workspace",
        f"> 🛡️ **Engagement Status Report** • *Exported on {now_utc}*",
        ">",
        f"> 🎯 **Targets:** {stats['total_targets']} ({pwned_count} Pwned, {foothold_count} Foothold) │ ⚡ **Services:** {stats['total_services']} │ ✔ **Checks:** {stats['completed_checks']}/{stats['total_checks']} │ ★ **Findings:** {findings_count} │ 🔑 **Creds:** {stats['total_credentials']} │ 🚩 **Flags:** {flags_count}",
        "",
        "## 🧭 Workspace Navigation",
        "- [📋 Discovered Targets & Systems](Targets/)",
        "- [🔑 Credential Vault Matrix](Credentials.md)",
        "- [💡 Attack Hypotheses & Leads](Leads%20%26%20Hypotheses.md)",
        "- [🚩 Proof Flags & Evidence Ledger](Evidence%20%26%20Flags.md)",
        "- [🌐 Pivoting & Routing Sentinel](Pivoting%20%26%20Networks.md)",
        "",
        "## 🎯 Target Overview",
        "",
        "| Target IP / Host | OS | Status | Open Ports | Page Link |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    for t in targets:
        safe_name = _clean_filename(t.ip)
        ports_str = ", ".join(f"{s.port}/{s.protocol}" for s in t.services) if t.services else "None"
        status_badge = f"`{t.status.value.upper()}`"
        host_str = f" ({t.hostname})" if t.hostname else ""
        link_str = f"[{t.ip}{host_str}](Targets/{safe_name}.md)"

        dash_lines.append(
            f"| `{t.ip}` | {t.os} | {status_badge} | `{ports_str}` | {link_str} |"
        )

    dash_lines.extend([
        "",
        "---",
        "*Exported by SYNAPSE // Offensive Assessment State Machine & Methodology Copilot*",
    ])

    (output_dir / "SYNAPSE Assessment Workspace.md").write_text(
        "\n".join(dash_lines), encoding="utf-8"
    )

    # =========================================================================
    # 2. Individual Target Pages (Targets/<ip>.md)
    # =========================================================================
    for t in targets:
        safe_name = _clean_filename(t.ip)
        t_lines = [
            f"# Target: {t.ip}",
            f"> 🖥️ **Host Overview**",
            f"> - **IP Address:** `{t.ip}`",
            f"> - **Hostname:** `{t.hostname or 'None'}`",
            f"> - **Operating System:** `{t.os}`",
            f"> - **Assessment Status:** `{t.status.value.upper()}`",
            "",
            "## ⚡ Attack Surface & Services",
            "",
        ]

        if not t.services:
            t_lines.append("> ℹ️ *No open ports or services recorded for this target.*")
        else:
            t_lines.extend([
                "| Port | Proto | Service | Product / Version | Status |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ])
            for s in t.services:
                prod = f"{s.product} {s.version}".strip() or "-"
                t_lines.append(
                    f"| `{s.port}` | `{s.protocol}` | **{_escape_md_table(s.name)}** | {_escape_md_table(prod)} | `{s.status.value}` |"
                )
            t_lines.append("")

            # Methodology & Checklists per Service
            t_lines.append("## 🔍 Service Methodology & Action Items")
            t_lines.append("")

            for s in t.services:
                t_lines.append(f"### Port {s.port}/{s.protocol} - {s.name.upper()}")
                if s.banner:
                    t_lines.extend([
                        "> 📜 **Service Banner / Script Output:**",
                        _safe_code_fence(s.banner[:400], "text"),
                        "",
                    ])

                if not s.checklists:
                    t_lines.append("- *No action items recorded for this service.*")
                else:
                    for c in s.checklists:
                        chk = "x" if c.status.value in ("checked", "finding") else " "
                        tag = " 🔥 **[VULNERABILITY FINDING]**" if c.status.value == "finding" else ""
                        sev_badge = f" `[{c.severity.value.upper()}]`" if hasattr(c, "severity") and c.severity else ""
                        t_lines.append(f"- [{chk}] **{c.title}**{sev_badge}{tag}")

                        if c.description:
                            t_lines.append(f"  - *{c.description}*")
                        if c.command_template:
                            t_lines.append(f"  - **Recipe:** `{c.command_template}`")
                        if c.remediation:
                            t_lines.append(f"  - > 💡 **Remediation:** {c.remediation}")
                        if c.output_snippet:
                            t_lines.extend([
                                "  - **Evidence Output:**",
                                _safe_code_fence(c.output_snippet.strip(), "text"),
                            ])
                t_lines.append("")

        t_lines.extend([
            "---",
            "[⬅ Back to Workspace Dashboard](../SYNAPSE%20Assessment%20Workspace.md)",
        ])

        (targets_dir / f"{safe_name}.md").write_text("\n".join(t_lines), encoding="utf-8")

    # =========================================================================
    # 3. Credentials Vault Page (Credentials.md)
    # =========================================================================
    cred_lines = [
        "# Credential Vault & Lateral Movement Matrix",
        "> 🔑 **Discovered Passwords, NTLM Hashes, and Kerberos Tickets**",
        "",
        "| ID | Domain | Username | Secret / Hash | Type | Scope | Tested Targets & Admin Status |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    if not credentials:
        cred_lines.append("| - | - | *No credentials recorded* | - | - | - | - |")
    else:
        for c in credentials:
            tested_parts = []
            for tip, tdata in c.tested_targets.items():
                if ":" in tip and tdata.get("service") and tip.endswith(f":{tdata.get('service')}"):
                    continue
                if tdata.get("admin"):
                    tested_parts.append(f"`{tip}:✔(Pwn3d)`")
                elif tdata.get("valid"):
                    tested_parts.append(f"`{tip}:✔`")
                else:
                    tested_parts.append(f"`{tip}:✖`")

            tested_disp = " ".join(tested_parts) if tested_parts else "*Untested*"

            cred_lines.append(
                f"| `{c.id}` | `{_escape_md_table(c.domain or '-')}` | **{_escape_md_table(c.username)}** | `{_escape_md_table(c.secret)}` | `{c.cred_type.value}` | `{_escape_md_table(c.service_scope or 'general')}` | {tested_disp} |"
            )

    cred_lines.extend([
        "",
        "---",
        "[⬅ Back to Workspace Dashboard](SYNAPSE%20Assessment%20Workspace.md)",
    ])
    (output_dir / "Credentials.md").write_text("\n".join(cred_lines), encoding="utf-8")

    # =========================================================================
    # 4. Leads & Hypotheses Page (Leads & Hypotheses.md)
    # =========================================================================
    lead_lines = [
        "# Attack Hypotheses & Leads Board",
        "> 💡 **Prioritized attack avenues and investigation backlog to prevent rabbit holes.**",
        "",
        "| Priority | Status | Target | Hypothesis / Lead Title | Description |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    if not leads:
        lead_lines.append("| - | - | - | *No active leads recorded* | - |")
    else:
        for l in leads:
            p_badge = f"`{l.priority.value.upper()}`"
            s_badge = f"`{l.status.value}`"
            lead_lines.append(
                f"| {p_badge} | {s_badge} | `{_escape_md_table(l.target_ip or 'Global')}` | **{_escape_md_table(l.title)}** | {_escape_md_table(l.description or '-')} |"
            )

    lead_lines.extend([
        "",
        "---",
        "[⬅ Back to Workspace Dashboard](SYNAPSE%20Assessment%20Workspace.md)",
    ])
    (output_dir / "Leads & Hypotheses.md").write_text("\n".join(lead_lines), encoding="utf-8")

    # =========================================================================
    # 5. Evidence & Proof Flags Page (Evidence & Flags.md)
    # =========================================================================
    ev_lines = [
        "# Proof Flags & Evidence Ledger",
        "> 🚩 **OffSec Exam & CTF Proof Validation Record**",
        "",
    ]

    if not evidence_list:
        ev_lines.append("> ℹ️ *No proof flags or evidence logs recorded yet.*")
    else:
        for ev in evidence_list:
            proof_badge = f"`{ev.proof_type.value.upper()}`"
            target_str = f" on `{ev.target_ip}`" if ev.target_ip else ""
            ev_lines.extend([
                f"### {ev.title}{target_str} ({proof_badge})",
                f"- **Created At:** `{ev.created_at}`",
            ])
            if ev.flag_hash:
                ev_lines.append(f"- > 🚩 **Flag Hash / Secret:** `{ev.flag_hash}`")
            if ev.command:
                ev_lines.extend([
                    "- **Verification Command:**",
                    _safe_code_fence(ev.command, "bash"),
                ])
            if ev.output:
                ev_lines.extend([
                    "- **Terminal Output:**",
                    _safe_code_fence(ev.output, "text"),
                ])
            ev_lines.append("")

    ev_lines.extend([
        "---",
        "[⬅ Back to Workspace Dashboard](SYNAPSE%20Assessment%20Workspace.md)",
    ])
    (output_dir / "Evidence & Flags.md").write_text("\n".join(ev_lines), encoding="utf-8")

    # =========================================================================
    # 6. Pivoting & Networks Page (Pivoting & Networks.md)
    # =========================================================================
    pivot_lines = [
        "# Pivoting & Route Sentinel",
        "> 🌐 **Multi-hop lab tunneling routes, jump hosts, and proxychains configuration.**",
        "",
        "| Route Name | Jump Host | Target Subnet | Tunnel Type | Local SOCKS Bind | Notes |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    if not routes:
        pivot_lines.append("| - | - | *No active pivot routes* | - | - | - |")
    else:
        for r in routes:
            pivot_lines.append(
                f"| **{_escape_md_table(r.name)}** | `{r.jump_host_ip}` | `{r.target_subnet}` | `{r.tunnel_type}` | `{r.local_bind}` | {_escape_md_table(r.notes or '-')} |"
            )

    pivot_lines.extend([
        "",
        "---",
        "[⬅ Back to Workspace Dashboard](SYNAPSE%20Assessment%20Workspace.md)",
    ])
    (output_dir / "Pivoting & Networks.md").write_text("\n".join(pivot_lines), encoding="utf-8")

    return output_dir
