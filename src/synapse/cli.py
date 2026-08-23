"""Rich CLI commands and entry point for Synapse."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path
from typing import Optional
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from synapse.ai.advisor import AIAdvisor
from synapse.db.repository import DatabaseRepository
from synapse.export.json_exporter import export_workspace_json, import_workspace_json
from synapse.export.markdown_exporter import export_markdown_report, export_obsidian_vault
from synapse.export.notion_exporter import export_notion_workspace
from synapse.methodology.engine import MethodologyEngine
from synapse.models import (
    ChecklistStatus,
    CredentialType,
    LeadPriority,
    LeadStatus,
    ProofType,
    ServiceStatus,
    TargetStatus,
)
from synapse.parsers.masscan_parser import parse_masscan_json
from synapse.parsers.netexec_parser import parse_netexec_output
from synapse.parsers.nmap_parser import parse_nmap_gnmap, parse_nmap_text, parse_nmap_xml
from synapse.parsers.rustscan_parser import parse_rustscan_json

console = Console()


def get_default_db_path(workspace: str = "default") -> Path:
    """Returns path to workspace SQLite database."""
    base = Path.home() / ".synapse" / "workspaces"
    base.mkdir(parents=True, exist_ok=True)
    try:
        base.chmod(0o700)
    except Exception:
        pass
    return base / f"{workspace}.db"


@click.group(invoke_without_command=True)
@click.option("--workspace", "-w", default="default", help="Workspace name (default: 'default')")
@click.option("--db", "db_path", type=click.Path(), default=None, help="Custom SQLite DB path")
@click.pass_context
def main(ctx: click.Context, workspace: str, db_path: Optional[str]) -> None:
    """SYNAPSE: Terminal Pentest Assessment State Machine & Methodology Copilot."""
    if db_path:
        ctx.obj = {"repo": DatabaseRepository(db_path), "workspace": workspace, "db_path": db_path}
    else:
        db_p = get_default_db_path(workspace)
        ctx.obj = {"repo": DatabaseRepository(db_p), "workspace": workspace, "db_path": str(db_p)}

    if ctx.invoked_subcommand is None:
        from synapse.tui.app import SynapseTUI

        tui = SynapseTUI(db_path=ctx.obj["db_path"])
        tui.run()


@main.command()
@click.pass_context
def tui(ctx: click.Context) -> None:
    """Launch the interactive terminal user interface."""
    from synapse.tui.app import SynapseTUI

    app = SynapseTUI(db_path=ctx.obj["db_path"])
    app.run()


@main.command()
@click.argument("scan_file", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["auto", "nmap-xml", "nmap-gnmap", "nmap-text", "netexec", "rustscan", "masscan"]),
    default="auto",
    help="Scan format (default: 'auto')",
)
@click.pass_context
def ingest(ctx: click.Context, scan_file: str, fmt: str) -> None:
    """Ingest scan files (Nmap XML/gnmap, Rustscan JSON, Masscan, NetExec logs)."""
    repo: DatabaseRepository = ctx.obj["repo"]
    engine = MethodologyEngine()
    file_path = Path(scan_file)
    content = file_path.read_text(encoding="utf-8", errors="replace")

    parsed_targets = []
    parsed_creds = []

    try:
        if fmt == "nmap-xml" or (fmt == "auto" and (content.strip().startswith("<?xml") or "<nmaprun" in content)):
            console.print(f"[cyan]Detected Nmap XML scan: {file_path.name}[/cyan]")
            parsed_targets = parse_nmap_xml(file_path)

        elif fmt == "nmap-gnmap" or (fmt == "auto" and "Host:" in content and "Ports:" in content):
            console.print(f"[cyan]Detected Nmap Grepable (-oG) scan: {file_path.name}[/cyan]")
            parsed_targets = parse_nmap_gnmap(content)

        elif fmt == "netexec":
            console.print(f"[cyan]Detected NetExec log: {file_path.name}[/cyan]")
            res = parse_netexec_output(content)
            parsed_targets = res.get("targets", [])
            parsed_creds = res.get("credentials", [])

        elif fmt == "rustscan":
            console.print(f"[cyan]Parsing as Rustscan output: {file_path.name}[/cyan]")
            parsed_targets = parse_rustscan_json(content)

        elif fmt == "masscan":
            console.print(f"[cyan]Parsing as Masscan output: {file_path.name}[/cyan]")
            parsed_targets = parse_masscan_json(content)

        elif fmt == "nmap-text":
            console.print(f"[cyan]Parsing as standard Nmap text: {file_path.name}[/cyan]")
            parsed_targets = parse_nmap_text(content)

        elif fmt == "auto":
            # 1. Try NetExec log
            res = parse_netexec_output(content)
            if res.get("targets") or res.get("credentials"):
                console.print(f"[cyan]Detected NetExec log: {file_path.name}[/cyan]")
                parsed_targets = res.get("targets", [])
                parsed_creds = res.get("credentials", [])

            # 2. Try Rustscan JSON or masscan
            if not parsed_targets and (content.strip().startswith("[") or "Open " in content):
                parsed_targets = parse_rustscan_json(content)
                if not parsed_targets:
                    parsed_targets = parse_masscan_json(content)

            # 3. Fallback to standard Nmap text
            if not parsed_targets and ("Nmap scan report" in content or "PORT" in content):
                console.print(f"[cyan]Parsing as standard Nmap text: {file_path.name}[/cyan]")
                parsed_targets = parse_nmap_text(content)

    except Exception as e:
        console.print(f"[red]Error parsing scan file {file_path.name}: {e}[/red]")
        return

    if not parsed_targets and not parsed_creds:
        console.print("[yellow]No targets or credentials could be extracted from file.[/yellow]")
        return

    added_targets = 0
    added_services = 0
    added_checks = 0

    for pt in parsed_targets:
        target = repo.add_or_get_target(
            ip=pt["ip"],
            hostname=pt.get("hostname", ""),
            os=pt.get("os", "Unknown"),
        )
        added_targets += 1

        for svc_data in pt.get("services", []):
            svc = repo.add_or_update_service(
                target_id=target.id,  # type: ignore
                port=svc_data["port"],
                protocol=svc_data.get("protocol", "tcp"),
                name=svc_data.get("name", "unknown"),
                product=svc_data.get("product", ""),
                version=svc_data.get("version", ""),
                banner=svc_data.get("banner", ""),
            )
            added_services += 1

            # Auto-populate methodology checklists
            raw_checks = engine.get_checklists_for_service(svc)
            for rc in raw_checks:
                rendered_cmd = engine.render_command(
                    rc.get("command_template", ""), target, svc
                )
                repo.add_checklist_item(
                    service_id=svc.id,  # type: ignore
                    category=rc.get("category", "enum"),
                    title=rc.get("title", ""),
                    description=rc.get("description", ""),
                    command_template=rendered_cmd,
                    status=ChecklistStatus.TODO,
                )
                added_checks += 1

    # Ingest credentials if any
    added_creds = 0
    for pc in parsed_creds:
        t = repo.get_target_by_ip(pc["target_ip"])
        cred = repo.add_credential(
            username=pc["username"],
            secret=pc["secret"],
            cred_type=CredentialType(pc.get("cred_type", "password")),
            domain=pc.get("domain", ""),
            service_scope=pc.get("service_scope", ""),
            target_id=t.id if t else None,
            notes=pc.get("notes", ""),
        )
        if pc.get("is_admin") and t:
            repo.record_credential_test(
                cred.id, t.ip, pc.get("service_scope", "smb"), valid=True, admin=True  # type: ignore
            )
        added_creds += 1

    console.print(
        Panel(
            f"[bold green]Ingestion Complete![/bold green]\n"
            f"• Targets: [bold]{added_targets}[/bold]\n"
            f"• Services: [bold]{added_services}[/bold]\n"
            f"• Methodology Action Items Loaded: [bold]{added_checks}[/bold]\n"
            f"• Credentials Discovered: [bold]{added_creds}[/bold]",
            title="Synapse Ingestion Summary",
            border_style="green",
        )
    )


@main.command(name="status")
@click.pass_context
def show_status(ctx: click.Context) -> None:
    """Display overall engagement metrics and workspace health."""
    repo: DatabaseRepository = ctx.obj["repo"]
    stats = repo.get_stats()

    table = Table(
        title=f"Assessment Status [Workspace: {ctx.obj['workspace']}]",
        border_style="cyan",
    )
    table.add_column("Metric", style="bold white")
    table.add_column("Count", style="bold green")

    table.add_row("Total Targets in Scope", str(stats["total_targets"]))
    table.add_row("Fully Pwned (Root/Admin)", str(stats["pwned_targets"]))
    table.add_row("Footholds Established", str(stats["foothold_targets"]))
    table.add_row("Total Discovered Services", str(stats["total_services"]))
    table.add_row("Completed Methodology Checks", str(stats["completed_checks"]))
    table.add_row("Vulnerability Findings", str(stats["total_findings"]))
    table.add_row("Discovered Credentials", str(stats["total_credentials"]))
    table.add_row("Captured Proof Flags", str(stats["captured_flags"]))
    table.add_row("Active Leads / Hypotheses", str(stats["active_leads"]))

    console.print(table)


@main.command(name="list-targets")
@click.pass_context
def list_targets(ctx: click.Context) -> None:
    """List all registered targets and open ports."""
    repo: DatabaseRepository = ctx.obj["repo"]
    targets = repo.list_targets()

    if not targets:
        console.print(
            "[dim]No targets in workspace. Ingest a scan or run 'synapse add-target'.[/dim]"
        )
        return

    table = Table(title="Scope & Target Matrix", border_style="cyan")
    table.add_column("IP Address", style="bold cyan")
    table.add_column("Hostname", style="white")
    table.add_column("OS", style="yellow")
    table.add_column("Status", style="bold")
    table.add_column("Open Ports / Services", style="white")

    for t in targets:
        svc_summary = (
            ", ".join([f"{s.port}/{s.name}" for s in t.services])
            if t.services
            else "[dim]None[/dim]"
        )
        status_color = (
            "green"
            if t.status == TargetStatus.PWNED
            else ("magenta" if t.status == TargetStatus.FOOTHOLD else "white")
        )
        table.add_row(
            t.ip,
            t.hostname or "-",
            t.os,
            f"[{status_color}]{t.status.value.upper()}[/{status_color}]",
            svc_summary,
        )

    console.print(table)


@main.command(name="add-target")
@click.argument("ip_or_cidr")
@click.option("--hostname", "-h", default="", help="Hostname or FQDN")
@click.option("--os", default="Unknown", help="Operating System (Linux/Windows)")
@click.option("--ports", "-p", default="", help="Comma-separated ports (e.g. 22,80,445)")
@click.pass_context
def add_target(
    ctx: click.Context, ip_or_cidr: str, hostname: str, os: str, ports: str
) -> None:
    """Add target host(s) or CIDR subnet manually."""
    repo: DatabaseRepository = ctx.obj["repo"]
    engine = MethodologyEngine()

    target_ips = []
    # Expand CIDR if subnet provided
    if "/" in ip_or_cidr:
        try:
            net = ipaddress.ip_network(ip_or_cidr, strict=False)
            target_ips = [str(ip) for ip in net.hosts()]
            if not target_ips:
                target_ips = [str(net.network_address)]
        except ValueError:
            target_ips = [ip_or_cidr]
    else:
        target_ips = [ip_or_cidr]

    valid_ports = []
    if ports:
        for p in ports.split(","):
            p = p.strip()
            if p.isdigit() and 1 <= int(p) <= 65535:
                valid_ports.append(int(p))

    for ip in target_ips:
        t = repo.add_or_get_target(ip=ip, hostname=hostname, os=os)
        for port_num in valid_ports:
            svc = repo.add_or_update_service(target_id=t.id, port=port_num)  # type: ignore
            for rc in engine.get_checklists_for_service(svc):
                cmd = engine.render_command(rc.get("command_template", ""), t, svc)
                repo.add_checklist_item(
                    service_id=svc.id,  # type: ignore
                    category=rc.get("category", "enum"),
                    title=rc.get("title", ""),
                    description=rc.get("description", ""),
                    command_template=cmd,
                )

    console.print(
        f"[bold green]✔ Added {len(target_ips)} target(s) to workspace {ctx.obj['workspace']}[/bold green]"
    )


@main.command(name="add-cred")
@click.argument("username")
@click.argument("secret")
@click.option(
    "--type",
    "cred_type",
    default="password",
    help="password, ntlm_hash, ssh_key, api_token",
)
@click.option("--domain", "-d", default="", help="Active Directory domain")
@click.option("--scope", "-s", default="", help="Service scope (e.g. smb, ssh, http)")
@click.option("--target-ip", "-t", default=None, help="Associated target IP")
@click.pass_context
def add_cred(
    ctx: click.Context,
    username: str,
    secret: str,
    cred_type: str,
    domain: str,
    scope: str,
    target_ip: Optional[str],
) -> None:
    """Save a credential or password hash into the vault."""
    repo: DatabaseRepository = ctx.obj["repo"]
    t = repo.get_target_by_ip(target_ip) if target_ip else None
    repo.add_credential(
        username=username,
        secret=secret,
        cred_type=CredentialType(cred_type),
        domain=domain,
        service_scope=scope,
        target_id=t.id if t else None,
    )
    console.print(f"[bold green]✔ Saved credential '{username}' to vault[/bold green]")


@main.command(name="list-creds")
@click.option(
    "--show-secrets", is_flag=True, default=False, help="Display full secrets instead of masking"
)
@click.pass_context
def list_creds(ctx: click.Context, show_secrets: bool) -> None:
    """List all credentials stored in the vault."""
    repo: DatabaseRepository = ctx.obj["repo"]
    creds = repo.list_credentials()

    if not creds:
        console.print("[dim]No credentials recorded yet. Add via 'synapse add-cred'.[/dim]")
        return

    table = Table(title="Credential Vault & Lateral Movement Matrix", border_style="cyan")
    table.add_column("Domain", style="white")
    table.add_column("Username", style="bold cyan")
    table.add_column("Secret / Hash", style="yellow")
    table.add_column("Type", style="magenta")
    table.add_column("Scope", style="white")
    table.add_column("Tested Targets", style="green")

    for c in creds:
        tested_summary = []
        for tip, tdata in c.tested_targets.items():
            mark = "✔ (Pwn3d)" if tdata.get("admin") else ("✔" if tdata.get("valid") else "✖")
            tested_summary.append(f"{tip}:{mark}")
        tested_str = ", ".join(tested_summary) if tested_summary else "[dim]Untested[/dim]"

        if show_secrets:
            secret_disp = c.secret
        else:
            secret_disp = (
                c.secret[:4] + "****" + c.secret[-4:]
                if len(c.secret) > 8
                else "********"
            )

        table.add_row(
            c.domain or "-",
            c.username,
            secret_disp,
            c.cred_type.value,
            c.service_scope or "general",
            tested_str,
        )

    console.print(table)


@main.command(name="next")
@click.argument("ip", required=False, default=None)
@click.pass_context
def suggest_next_steps(ctx: click.Context, ip: Optional[str]) -> None:
    """Triage attack surface and suggest next attack steps."""
    repo: DatabaseRepository = ctx.obj["repo"]
    advisor = AIAdvisor()

    if ip:
        target = repo.get_target_by_ip(ip)
        if not target:
            console.print(f"[red]Target {ip} not found in workspace.[/red]")
            return
        targets = [target]
    else:
        targets = repo.list_targets()

    if not targets:
        console.print("[dim]No targets in workspace.[/dim]")
        return

    for t in targets:
        suggestions = advisor.analyze_target_attack_surface(t)
        panel_content = f"[bold white]Target:[/bold white] {t.ip} ({t.os})\n"
        panel_content += f"[bold white]Status:[/bold white] {t.status.value.upper()}\n\n"
        panel_content += "[bold cyan]Recommended High-Value Actions:[/bold cyan]\n"
        for s in suggestions:
            pri = s.get("priority", LeadPriority.MEDIUM)
            pri_val = pri.value.upper() if hasattr(pri, "value") else str(pri).upper()
            pri_color = "red" if pri_val == "CRITICAL" else ("yellow" if pri_val == "HIGH" else "green")
            panel_content += f"  • [{pri_color}][{pri_val}][/{pri_color}] [bold]{s['title']}[/bold]\n"
            panel_content += f"    Rationale: {s.get('rationale', '-')}\n"
            if s.get("suggested_command"):
                panel_content += f"    Recipe: [green]{s['suggested_command']}[/green]\n"

        console.print(
            Panel(
                panel_content,
                title=f"Methodology Copilot: {t.ip}",
                border_style="cyan",
            )
        )


@main.command(name="import-backup")
@click.argument("json_file", type=click.Path(exists=True))
@click.pass_context
def import_backup(ctx: click.Context, json_file: str) -> None:
    """Restore workspace state from a JSON backup file."""
    repo: DatabaseRepository = ctx.obj["repo"]
    file_path = Path(json_file)
    counts = import_workspace_json(repo, file_path)
    console.print(
        Panel(
            f"[bold green]Workspace Restored Successfully![/bold green]\n"
            f"• Targets: [bold]{counts['targets']}[/bold]\n"
            f"• Services: [bold]{counts['services']}[/bold]\n"
            f"• Checklists: [bold]{counts['checklists']}[/bold]\n"
            f"• Credentials: [bold]{counts['credentials']}[/bold]\n"
            f"• Leads: [bold]{counts['leads']}[/bold]\n"
            f"• Evidence: [bold]{counts['evidence']}[/bold]\n"
            f"• Routes: [bold]{counts['routes']}[/bold]",
            title="Import Summary",
            border_style="green",
        )
    )


@main.command(name="export")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["notion", "markdown", "obsidian", "json"]),
    default="notion",
    help="Export format (notion, markdown, obsidian, json)",
)
@click.option(
    "--output",
    "-o",
    default="./notion_workspace",
    help="Output file or directory path",
)
@click.pass_context
def export_report(ctx: click.Context, fmt: str, output: str) -> None:
    """Export engagement report to Notion Workspace, Markdown, Obsidian Vault, or JSON."""
    repo: DatabaseRepository = ctx.obj["repo"]
    out_path = Path(output).expanduser().resolve()

    if fmt == "notion":
        export_notion_workspace(repo, out_path)
        console.print(f"[bold green]✔ Notion assessment workspace generated at: {out_path}[/bold green]")

    elif fmt == "markdown":
        report_md = export_markdown_report(repo)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report_md, encoding="utf-8")
        console.print(f"[bold green]✔ Markdown report exported to: {out_path}[/bold green]")

    elif fmt == "obsidian":
        export_obsidian_vault(repo, out_path)
        console.print(f"[bold green]✔ Obsidian vault generated at: {out_path}[/bold green]")

    elif fmt == "json":
        json_data = export_workspace_json(repo)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json_data, encoding="utf-8")
        console.print(f"[bold green]✔ Workspace JSON backup saved to: {out_path}[/bold green]")


if __name__ == "__main__":
    main()
