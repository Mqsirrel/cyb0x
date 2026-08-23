"""Script to capture pixel-perfect SVG and PNG screenshots of the Synapse TUI."""

import asyncio
from pathlib import Path
from synapse.tui.app import SynapseTUI
from synapse.export.json_exporter import import_workspace_json
from synapse.db.repository import DatabaseRepository
from synapse.parsers.nmap_parser import parse_nmap_xml
from synapse.parsers.netexec_parser import parse_netexec_output
from synapse.methodology.engine import MethodologyEngine
from synapse.models import ChecklistStatus, CredentialType, TargetStatus, LeadPriority, LeadStatus, ProofType


async def capture():
    # 1. Setup in-memory repo with populated engagement data
    db_path = "/tmp/synapse_screenshot_demo.db"
    if Path(db_path).exists():
        Path(db_path).unlink()

    repo = DatabaseRepository(db_path)
    engine = MethodologyEngine()

    # Ingest Nmap XML
    parsed_targets = parse_nmap_xml(Path("sample_scans/oscp_ad_lab.xml"))
    for pt in parsed_targets:
        t = repo.add_or_get_target(ip=pt["ip"], hostname=pt["hostname"], os=pt["os"])
        for s in pt["services"]:
            svc = repo.add_or_update_service(
                target_id=t.id,
                port=s["port"],
                protocol=s["protocol"],
                name=s["name"],
                product=s["product"],
                version=s["version"],
                banner=s.get("banner", ""),
            )
            for rc in engine.get_checklists_for_service(svc):
                cmd = engine.render_command(rc.get("command_template", ""), t, svc)
                repo.add_checklist_item(
                    service_id=svc.id,
                    category=rc.get("category", "enum"),
                    title=rc.get("title", ""),
                    description=rc.get("description", ""),
                    command_template=cmd,
                )

    # Ingest NetExec
    nxc_res = parse_netexec_output(Path("sample_scans/netexec_ad_spray.log"))
    for pc in nxc_res["credentials"]:
        t = repo.get_target_by_ip(pc["target_ip"])
        cred = repo.add_credential(
            username=pc["username"],
            secret=pc["secret"],
            cred_type=CredentialType(pc["cred_type"]),
            domain=pc["domain"],
            service_scope=pc["service_scope"],
            target_id=t.id if t else None,
        )
        if pc.get("is_admin") and t:
            repo.record_credential_test(cred.id, t.ip, pc["service_scope"], valid=True, admin=True)

    # Set some interesting states
    target_dc = repo.get_target_by_ip("10.10.11.15")
    if target_dc:
        repo.update_target_status(target_dc.id, TargetStatus.FOOTHOLD)
        target_dc_full = repo.get_target_by_id(target_dc.id)
        for s in target_dc_full.services:
            if s.port == 445:
                for c in s.checklists:
                    if "Anonymous" in c.title:
                        repo.update_checklist_status(c.id, ChecklistStatus.CHECKED)
                    elif "RID" in c.title:
                        repo.update_checklist_status(c.id, ChecklistStatus.RUNNING)
                    elif "Vulnerabilities" in c.title or "Certipy" in c.title or "Dump SAM" in c.title:
                        repo.update_checklist_status(c.id, ChecklistStatus.FINDING, output_snippet="Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::")

    target_web = repo.get_target_by_ip("10.10.11.10")
    if target_web:
        repo.update_target_status(target_web.id, TargetStatus.PWNED)
        repo.add_evidence(
            target_id=target_web.id,
            proof_type=ProofType.ROOT_FLAG,
            title="Proof flag proof.txt on web01",
            command="whoami && hostname && ip a && cat /root/proof.txt",
            output="root\nweb01.corp.local\n10.10.11.10\ne4d909c290d0fb1ca068ffaddf22cbd0",
            flag_hash="e4d909c290d0fb1ca068ffaddf22cbd0",
        )

    # Add Leads
    repo.add_lead(
        title="Kerberoasting on DC01 (Targeting SPN accounts)",
        priority=LeadPriority.CRITICAL,
        description="Identified Kerberos on port 88. Run GetUserSPNs.py to request TGS tickets for offline cracking.",
        status=LeadStatus.IN_PROGRESS,
        target_id=target_dc.id if target_dc else None,
    )
    repo.add_lead(
        title="Web01 Tomcat Manager /manager/html credential brute-force",
        priority=LeadPriority.HIGH,
        description="Tomcat 9.0.41 exposed on 8080. Test default tomcat:s3cret creds.",
        status=LeadStatus.CONFIRMED,
        target_id=target_web.id if target_web else None,
    )

    # 2. Launch App in headless test pilot
    app = SynapseTUI(db_path=db_path)
    async with app.run_test(size=(140, 42)) as pilot:
        await pilot.pause()
        app.refresh_all_views()
        await pilot.pause()

        # Focus service 445 on DC01
        dc_full = repo.get_target_by_ip("10.10.11.15")
        if dc_full:
            smb_svc = next((s for s in dc_full.services if s.port == 445), None)
            if smb_svc:
                app.selected_target = dc_full
                app.selected_service = smb_svc
                app.query_one("#service-detail").display_service(dc_full, smb_svc)
                await pilot.pause()

        # Save Workbench screenshot
        svg_path = "/tmp/synapse_workbench.svg"
        app.save_screenshot(svg_path)
        print(f"Saved SVG screenshot to {svg_path}")

        # Switch to Tab 2 (Creds)
        app.action_switch_tab("tab-creds")
        await pilot.pause()
        svg_creds = "/tmp/synapse_creds.svg"
        app.save_screenshot(svg_creds)
        print(f"Saved SVG screenshot to {svg_creds}")

        # Switch to Tab 3 (Leads)
        app.action_switch_tab("tab-leads")
        await pilot.pause()
        svg_leads = "/tmp/synapse_leads.svg"
        app.save_screenshot(svg_leads)
        print(f"Saved SVG screenshot to {svg_leads}")


if __name__ == "__main__":
    asyncio.run(capture())
