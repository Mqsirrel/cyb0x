"""Performance benchmark harness for Synapse.

Generates a synthetic large-scan workspace, then measures:

- Ingest throughput (targets/services/checklists written through the repository)
- Full workspace load (`list_targets` — the TUI refresh hot path)
- Engagement stats aggregation
- Single-check toggle round trip (status update + full target reload)

Usage:
    uv run python scripts/bench_perf.py [--hosts 200] [--ports 15] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from synapse.db.repository import DatabaseRepository  # noqa: E402
from synapse.methodology.engine import MethodologyEngine  # noqa: E402
from synapse.models import ChecklistStatus  # noqa: E402


SERVICE_PROFILES = [
    (21, "tcp", "ftp", "vsftpd", "3.0.3"),
    (22, "tcp", "ssh", "OpenSSH", "9.6p1"),
    (25, "tcp", "smtp", "Postfix smtpd", "3.7"),
    (53, "tcp", "domain", "ISC BIND", "9.18"),
    (80, "tcp", "http", "nginx", "1.24.0"),
    (110, "tcp", "pop3", "Dovecot pop3d", "2.3"),
    (139, "tcp", "netbios-ssn", "Samba smbd", "4.17"),
    (443, "tcp", "https", "Apache httpd", "2.4.57"),
    (445, "tcp", "microsoft-ds", "Windows Server 2019", "-"),
    (1433, "tcp", "ms-sql-s", "Microsoft SQL Server", "2019"),
    (3306, "tcp", "mysql", "MySQL", "8.0.34"),
    (3389, "tcp", "ms-wbt-server", "Microsoft Terminal Services", "-"),
    (5432, "tcp", "postgresql", "PostgreSQL DB", "15.4"),
    (6379, "tcp", "redis", "Redis key-value store", "7.2"),
    (8080, "tcp", "http-proxy", "Tomcat/Coyote", "10.1"),
]


def generate_scan(hosts: int, ports: int) -> List[Dict]:
    """Synthesizes parsed-target dicts in the same shape the nmap parser returns."""
    profiles = SERVICE_PROFILES[:ports]
    parsed = []
    for i in range(hosts):
        octet = (i % 254) + 1
        subnet = 10 + (i // 254) % 250
        parsed.append(
            {
                "ip": f"10.{subnet}.0.{octet}",
                "hostname": f"host{i}.corp.local" if i % 3 == 0 else "",
                "os": "Linux" if i % 2 else "Windows",
                "services": [
                    {
                        "port": p,
                        "protocol": proto,
                        "name": name,
                        "product": product,
                        "version": version,
                        "banner": f"{product} {version}",
                    }
                    for (p, proto, name, product, version) in profiles
                ],
            }
        )
    return parsed


def run_ingest(repo: DatabaseRepository, engine: MethodologyEngine, parsed_targets: List[Dict]) -> Dict[str, int]:
    """Mirrors the CLI `ingest` command write path."""
    counts = {"targets": 0, "services": 0, "checks": 0}
    for pt in parsed_targets:
        target = repo.add_or_get_target(ip=pt["ip"], hostname=pt.get("hostname", ""), os=pt.get("os", "Unknown"))
        counts["targets"] += 1
        for svc_data in pt["services"]:
            svc = repo.add_or_update_service(
                target_id=target.id,
                port=svc_data["port"],
                protocol=svc_data.get("protocol", "tcp"),
                name=svc_data.get("name", "unknown"),
                product=svc_data.get("product", ""),
                version=svc_data.get("version", ""),
                banner=svc_data.get("banner", ""),
            )
            counts["services"] += 1
            for rc in engine.get_checklists_for_service(svc):
                cmd = engine.render_command(rc.get("command_template", ""), target, svc)
                repo.add_checklist_item(
                    service_id=svc.id,
                    category=rc.get("category", "enum"),
                    title=rc.get("title", ""),
                    description=rc.get("description", ""),
                    command_template=cmd,
                )
                counts["checks"] += 1
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description="Synapse performance benchmark")
    ap.add_argument("--hosts", type=int, default=200)
    ap.add_argument("--ports", type=int, default=15)
    ap.add_argument("--toggles", type=int, default=50, help="checklist toggle iterations")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    results: Dict[str, object] = {"hosts": args.hosts, "ports": args.ports}

    with tempfile.TemporaryDirectory(prefix="synapse_bench_") as tmp:
        db_path = Path(tmp) / "bench.db"
        repo = DatabaseRepository(db_path)
        engine = MethodologyEngine()
        scan = generate_scan(args.hosts, args.ports)

        t0 = time.perf_counter()
        counts = run_ingest(repo, engine, scan)
        ingest_s = time.perf_counter() - t0
        results["ingest_seconds"] = round(ingest_s, 3)
        results.update({f"ingested_{k}": v for k, v in counts.items()})

        t0 = time.perf_counter()
        targets = repo.list_targets()
        load_s = time.perf_counter() - t0
        total_checks = sum(len(c.checklists) for t in targets for c in t.services)
        results["full_load_ms"] = round(load_s * 1000, 1)
        results["loaded_checks"] = total_checks

        t0 = time.perf_counter()
        stats = repo.get_stats()
        stats_s = time.perf_counter() - t0
        results["stats_ms"] = round(stats_s * 1000, 2)
        results["stat_total_checks"] = stats["total_checks"]

        first_target = targets[0]
        first_item = first_target.services[0].checklists[0]
        t0 = time.perf_counter()
        for _ in range(args.toggles):
            repo.update_checklist_status(first_item.id, ChecklistStatus.CHECKED)
            repo.get_target_by_id(first_target.id)
        toggle_s = time.perf_counter() - t0
        results["toggle_roundtrip_ms"] = round(toggle_s / args.toggles * 1000, 2)

        t0 = time.perf_counter()
        creds = [repo.add_credential(f"user{i}", f"Pass{i}!", domain="CORP") for i in range(20)]
        cred_s = time.perf_counter() - t0
        for c in creds:
            repo.delete_credential(c.id)
        results["add_20_creds_ms"] = round(cred_s * 1000, 1)

    if args.json:
        print(json.dumps(results))
    else:
        print("=" * 56)
        print(" SYNAPSE PERFORMANCE BENCHMARK")
        print("=" * 56)
        print(f" Synthetic lab     : {args.hosts} hosts x {args.ports} services")
        print(f" Ingest            : {results['ingest_seconds']}s "
              f"(targets={counts['targets']}, services={counts['services']}, checks={counts['checks']})")
        print(f" Full load         : {results['full_load_ms']} ms "
              f"({results['loaded_checks']} checks hydrated)")
        print(f" Stats query       : {results['stats_ms']} ms")
        print(f" Toggle roundtrip  : {results['toggle_roundtrip_ms']} ms "
              f"(status update + full target reload)")
        print(f" Add 20 creds      : {results['add_20_creds_ms']} ms")
        print("=" * 56)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
