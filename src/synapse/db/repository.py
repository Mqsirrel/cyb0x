"""Repository for SQLite database operations in Synapse."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

from synapse.db.migrations import run_migrations
from synapse.db.schema import SCHEMA_SQL
from synapse.models import (
    ChecklistItem,
    ChecklistStatus,
    Credential,
    CredentialType,
    Evidence,
    Lead,
    LeadPriority,
    LeadStatus,
    PivotRoute,
    ProofType,
    Service,
    ServiceStatus,
    SeverityLevel,
    Target,
    TargetStatus,
)


class DatabaseRepository:
    """Handles all persistence and queries for Synapse workspaces."""

    def __init__(self, db_path: str | Path = ":memory:"):
        self._mem_conn: Optional[sqlite3.Connection] = None
        if isinstance(db_path, str) and db_path == ":memory:":
            self.db_path = ":memory:"
            # Keep a persistent connection for in-memory DBs
            self._mem_conn = sqlite3.connect(":memory:")
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys = ON;")
        else:
            p = Path(db_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(p)

        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    def _init_db(self) -> None:
        conn = self.get_connection()
        conn.executescript(SCHEMA_SQL)
        run_migrations(conn)
        conn.commit()
        if self._mem_conn is None:
            conn.close()

    # -------------------------------------------------------------------------
    # Target Operations
    # -------------------------------------------------------------------------
    def add_or_get_target(
        self,
        ip: str,
        hostname: str = "",
        os: str = "Unknown",
        status: TargetStatus = TargetStatus.DISCOVERED,
        tags: Optional[List[str]] = None,
        notes: str = "",
    ) -> Target:
        tags_json = json.dumps(tags or [])
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM targets WHERE ip = ?", (ip,))
            row = cur.fetchone()
            if row:
                new_host = hostname if hostname else row["hostname"]
                new_os = os if (os != "Unknown" and os) else row["os"]
                cur.execute(
                    "UPDATE targets SET hostname = ?, os = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (new_host, new_os, row["id"]),
                )
                conn.commit()
                target_id = row["id"]
            else:
                cur.execute(
                    """
                    INSERT INTO targets (ip, hostname, os, status, tags, notes)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (ip, hostname, os, status.value, tags_json, notes),
                )
                target_id = cur.lastrowid
                conn.commit()
        finally:
            if self._mem_conn is None:
                conn.close()

        return self.get_target_by_id(target_id)  # type: ignore

    def get_target_by_id(self, target_id: int) -> Optional[Target]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
            row = cur.fetchone()
            if not row:
                return None
            target = self._row_to_target(row)
        finally:
            if self._mem_conn is None:
                conn.close()

        target.services = self.get_services_by_target(target_id)
        return target

    def get_target_by_ip(self, ip: str) -> Optional[Target]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id FROM targets WHERE ip = ?", (ip,))
            row = cur.fetchone()
            if not row:
                return None
            target_id = row["id"]
        finally:
            if self._mem_conn is None:
                conn.close()

        return self.get_target_by_id(target_id)

    def list_targets(self) -> List[Target]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM targets ORDER BY ip ASC")
            rows = cur.fetchall()
            targets = [self._row_to_target(r) for r in rows]
        finally:
            if self._mem_conn is None:
                conn.close()

        for t in targets:
            t.services = self.get_services_by_target(t.id)  # type: ignore
        return targets

    def update_target_status(self, target_id: int, status: TargetStatus) -> bool:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE targets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status.value, target_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()

    def update_target_notes(self, target_id: int, notes: str) -> bool:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE targets SET notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (notes, target_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()

    def delete_target(self, target_id: int) -> bool:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM targets WHERE id = ?", (target_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()

    # -------------------------------------------------------------------------
    # Service Operations
    # -------------------------------------------------------------------------
    def add_or_update_service(
        self,
        target_id: int,
        port: int,
        protocol: str = "tcp",
        name: str = "unknown",
        product: str = "",
        version: str = "",
        banner: str = "",
        status: ServiceStatus = ServiceStatus.UNTESTED,
        notes: str = "",
    ) -> Service:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM services WHERE target_id = ? AND port = ? AND protocol = ?",
                (target_id, port, protocol),
            )
            row = cur.fetchone()
            if row:
                new_name = name if (name != "unknown" and name) else row["name"]
                new_prod = product if product else row["product"]
                new_ver = version if version else row["version"]
                new_banner = banner if banner else row["banner"]
                cur.execute(
                    """
                    UPDATE services
                    SET name = ?, product = ?, version = ?, banner = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (new_name, new_prod, new_ver, new_banner, row["id"]),
                )
                service_id = row["id"]
            else:
                cur.execute(
                    """
                    INSERT INTO services (target_id, port, protocol, name, product, version, banner, status, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (target_id, port, protocol, name, product, version, banner, status.value, notes),
                )
                service_id = cur.lastrowid
            conn.commit()
        finally:
            if self._mem_conn is None:
                conn.close()

        return self.get_service_by_id(service_id)  # type: ignore

    def get_service_by_id(self, service_id: int) -> Optional[Service]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM services WHERE id = ?", (service_id,))
            row = cur.fetchone()
            if not row:
                return None
            service = self._row_to_service(row)
        finally:
            if self._mem_conn is None:
                conn.close()

        service.checklists = self.get_checklists_by_service(service_id)
        return service

    def get_services_by_target(self, target_id: int) -> List[Service]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM services WHERE target_id = ? ORDER BY port ASC",
                (target_id,),
            )
            rows = cur.fetchall()
            services = [self._row_to_service(r) for r in rows]
        finally:
            if self._mem_conn is None:
                conn.close()

        for s in services:
            s.checklists = self.get_checklists_by_service(s.id)  # type: ignore
        return services

    def update_service_status(self, service_id: int, status: ServiceStatus) -> bool:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE services SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status.value, service_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()

    def update_service_notes(self, service_id: int, notes: str) -> bool:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE services SET notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (notes, service_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()

    # -------------------------------------------------------------------------
    # Checklist Operations
    # -------------------------------------------------------------------------
    def add_checklist_item(
        self,
        service_id: int,
        title: str,
        category: str = "enum",
        description: str = "",
        command_template: str = "",
        status: ChecklistStatus = ChecklistStatus.TODO,
        output_snippet: str = "",
    ) -> ChecklistItem:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT id FROM checklists WHERE service_id = ? AND title = ?",
                (service_id, title),
            )
            existing = cur.fetchone()
            if existing:
                item_id = existing["id"]
                if output_snippet:
                    cur.execute(
                        "UPDATE checklists SET output_snippet = ?, status = ? WHERE id = ?",
                        (output_snippet, status.value, item_id),
                    )
                    conn.commit()
            else:
                cur.execute(
                    """
                    INSERT INTO checklists (service_id, category, title, description, command_template, status, output_snippet)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (service_id, category, title, description, command_template, status.value, output_snippet),
                )
                item_id = cur.lastrowid
                conn.commit()
        finally:
            if self._mem_conn is None:
                conn.close()

        return self.get_checklist_by_id(item_id)  # type: ignore

    def get_checklist_by_id(self, item_id: int) -> Optional[ChecklistItem]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM checklists WHERE id = ?", (item_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_checklist(row)
        finally:
            if self._mem_conn is None:
                conn.close()

    def get_checklists_by_service(self, service_id: int) -> List[ChecklistItem]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM checklists WHERE service_id = ? ORDER BY id ASC",
                (service_id,),
            )
            rows = cur.fetchall()
            return [self._row_to_checklist(r) for r in rows]
        finally:
            if self._mem_conn is None:
                conn.close()

    def update_checklist_status(
        self, item_id: int, status: ChecklistStatus, output_snippet: Optional[str] = None
    ) -> bool:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            if output_snippet is not None:
                cur.execute(
                    """
                    UPDATE checklists
                    SET status = ?, output_snippet = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (status.value, output_snippet, item_id),
                )
            else:
                cur.execute(
                    """
                    UPDATE checklists
                    SET status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (status.value, item_id),
                )
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()

    # -------------------------------------------------------------------------
    # Lead Operations
    # -------------------------------------------------------------------------
    def add_lead(
        self,
        title: str,
        description: str = "",
        priority: LeadPriority = LeadPriority.MEDIUM,
        status: LeadStatus = LeadStatus.BACKLOG,
        target_id: Optional[int] = None,
    ) -> Lead:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO leads (target_id, title, description, priority, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (target_id, title, description, priority.value, status.value),
            )
            lead_id = cur.lastrowid
            conn.commit()
        finally:
            if self._mem_conn is None:
                conn.close()

        return self.get_lead_by_id(lead_id)  # type: ignore

    def get_lead_by_id(self, lead_id: int) -> Optional[Lead]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT l.*, t.ip as target_ip
                FROM leads l
                LEFT JOIN targets t ON l.target_id = t.id
                WHERE l.id = ?
                """,
                (lead_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_lead(row)
        finally:
            if self._mem_conn is None:
                conn.close()

    def list_leads(self, target_id: Optional[int] = None) -> List[Lead]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            if target_id is not None:
                cur.execute(
                    """
                    SELECT l.*, t.ip as target_ip
                    FROM leads l
                    LEFT JOIN targets t ON l.target_id = t.id
                    WHERE l.target_id = ?
                    ORDER BY 
                        CASE l.priority 
                            WHEN 'critical' THEN 1 
                            WHEN 'high' THEN 2 
                            WHEN 'medium' THEN 3 
                            WHEN 'low' THEN 4 
                            ELSE 5 
                        END ASC, l.id ASC
                    """,
                    (target_id,),
                )
            else:
                cur.execute(
                    """
                    SELECT l.*, t.ip as target_ip
                    FROM leads l
                    LEFT JOIN targets t ON l.target_id = t.id
                    ORDER BY 
                        CASE l.priority 
                            WHEN 'critical' THEN 1 
                            WHEN 'high' THEN 2 
                            WHEN 'medium' THEN 3 
                            WHEN 'low' THEN 4 
                            ELSE 5 
                        END ASC, l.id ASC
                    """
                )
            rows = cur.fetchall()
            return [self._row_to_lead(r) for r in rows]
        finally:
            if self._mem_conn is None:
                conn.close()

    def update_lead_status(self, lead_id: int, status: LeadStatus) -> bool:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE leads SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status.value, lead_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()

    def delete_lead(self, lead_id: int) -> bool:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM leads WHERE id = ?", (lead_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()

    # -------------------------------------------------------------------------
    # Credential Operations
    # -------------------------------------------------------------------------
    def add_credential(
        self,
        username: str,
        secret: str,
        cred_type: CredentialType = CredentialType.PASSWORD,
        domain: str = "",
        service_scope: str = "",
        target_id: Optional[int] = None,
        notes: str = "",
    ) -> Credential:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO credentials (target_id, username, secret, cred_type, domain, service_scope, tested_targets, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (target_id, username, secret, cred_type.value, domain, service_scope, "{}", notes),
            )
            cred_id = cur.lastrowid
            conn.commit()
        finally:
            if self._mem_conn is None:
                conn.close()

        return self.get_credential_by_id(cred_id)  # type: ignore

    def get_credential_by_id(self, cred_id: int) -> Optional[Credential]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT c.*, t.ip as target_ip
                FROM credentials c
                LEFT JOIN targets t ON c.target_id = t.id
                WHERE c.id = ?
                """,
                (cred_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_credential(row)
        finally:
            if self._mem_conn is None:
                conn.close()

    def list_credentials(self) -> List[Credential]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT c.*, t.ip as target_ip
                FROM credentials c
                LEFT JOIN targets t ON c.target_id = t.id
                ORDER BY c.id ASC
                """
            )
            rows = cur.fetchall()
            return [self._row_to_credential(r) for r in rows]
        finally:
            if self._mem_conn is None:
                conn.close()

    def record_credential_test(
        self, cred_id: int, target_ip: str, service: str, valid: bool, admin: bool = False
    ) -> bool:
        cred = self.get_credential_by_id(cred_id)
        if not cred:
            return False
        matrix = cred.tested_targets
        matrix[target_ip] = {
            "service": service,
            "valid": valid,
            "admin": admin,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE credentials SET tested_targets = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (json.dumps(matrix), cred_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()

    def delete_credential(self, cred_id: int) -> bool:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()

    # -------------------------------------------------------------------------
    # Evidence / Proof Operations
    # -------------------------------------------------------------------------
    def add_evidence(
        self,
        target_id: int,
        title: str,
        proof_type: ProofType = ProofType.COMMAND_OUTPUT,
        command: str = "",
        output: str = "",
        flag_hash: str = "",
        screenshot_path: str = "",
        service_id: Optional[int] = None,
    ) -> Evidence:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO evidence (target_id, service_id, proof_type, title, command, output, flag_hash, screenshot_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target_id,
                    service_id,
                    proof_type.value,
                    title,
                    command,
                    output,
                    flag_hash,
                    screenshot_path,
                ),
            )
            evidence_id = cur.lastrowid
            conn.commit()
        finally:
            if self._mem_conn is None:
                conn.close()

        return self.get_evidence_by_id(evidence_id)  # type: ignore

    def get_evidence_by_id(self, evidence_id: int) -> Optional[Evidence]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT e.*, t.ip as target_ip
                FROM evidence e
                LEFT JOIN targets t ON e.target_id = t.id
                WHERE e.id = ?
                """,
                (evidence_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_evidence(row)
        finally:
            if self._mem_conn is None:
                conn.close()

    def list_evidence(self, target_id: Optional[int] = None) -> List[Evidence]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            if target_id is not None:
                cur.execute(
                    """
                    SELECT e.*, t.ip as target_ip
                    FROM evidence e
                    LEFT JOIN targets t ON e.target_id = t.id
                    WHERE e.target_id = ?
                    ORDER BY e.created_at DESC
                    """,
                    (target_id,),
                )
            else:
                cur.execute(
                    """
                    SELECT e.*, t.ip as target_ip
                    FROM evidence e
                    LEFT JOIN targets t ON e.target_id = t.id
                    ORDER BY e.created_at DESC
                    """
                )
            rows = cur.fetchall()
            return [self._row_to_evidence(r) for r in rows]
        finally:
            if self._mem_conn is None:
                conn.close()

    def delete_evidence(self, evidence_id: int) -> bool:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()

    # -------------------------------------------------------------------------
    # Pivot Routes Operations
    # -------------------------------------------------------------------------
    def add_pivot_route(
        self,
        name: str,
        jump_host_ip: str,
        target_subnet: str,
        tunnel_type: str = "ligolo_ng",
        local_bind: str = "127.0.0.1:1080",
        notes: str = "",
    ) -> PivotRoute:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO pivot_routes (name, jump_host_ip, target_subnet, tunnel_type, local_bind, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, jump_host_ip, target_subnet, tunnel_type, local_bind, notes),
            )
            route_id = cur.lastrowid
            conn.commit()
        finally:
            if self._mem_conn is None:
                conn.close()

        return self.get_pivot_route_by_id(route_id)  # type: ignore

    def get_pivot_route_by_id(self, route_id: int) -> Optional[PivotRoute]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM pivot_routes WHERE id = ?", (route_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_pivot_route(row)
        finally:
            if self._mem_conn is None:
                conn.close()

    def list_pivot_routes(self) -> List[PivotRoute]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM pivot_routes ORDER BY id ASC")
            rows = cur.fetchall()
            return [self._row_to_pivot_route(r) for r in rows]
        finally:
            if self._mem_conn is None:
                conn.close()

    def delete_pivot_route(self, route_id: int) -> bool:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM pivot_routes WHERE id = ?", (route_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            if self._mem_conn is None:
                conn.close()

    # -------------------------------------------------------------------------
    # Global Assessment Statistics
    # -------------------------------------------------------------------------
    def get_stats(self) -> Dict[str, Any]:
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM targets")
            total_targets = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM targets WHERE status = 'pwned'")
            pwned_targets = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM targets WHERE status = 'foothold'")
            foothold_targets = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM services")
            total_services = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM checklists WHERE status = 'checked'")
            completed_checks = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM checklists WHERE status = 'finding'")
            total_findings = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM credentials")
            total_creds = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM leads WHERE status IN ('backlog', 'in_progress')")
            active_leads = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM evidence WHERE proof_type IN ('user_flag', 'root_flag')")
            captured_flags = cur.fetchone()[0]

            return {
                "total_targets": total_targets,
                "pwned_targets": pwned_targets,
                "foothold_targets": foothold_targets,
                "total_services": total_services,
                "completed_checks": completed_checks,
                "total_findings": total_findings,
                "total_credentials": total_creds,
                "active_leads": active_leads,
                "captured_flags": captured_flags,
            }
        finally:
            if self._mem_conn is None:
                conn.close()

    # -------------------------------------------------------------------------
    # Row Helpers
    # -------------------------------------------------------------------------
    @staticmethod
    def _row_to_target(row: sqlite3.Row) -> Target:
        tags = []
        if row["tags"]:
            try:
                tags = json.loads(row["tags"])
            except Exception:
                tags = []
        return Target(
            id=row["id"],
            ip=row["ip"],
            hostname=row["hostname"] or "",
            os=row["os"] or "Unknown",
            status=TargetStatus(row["status"]),
            tags=tags,
            notes=row["notes"] or "",
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(timezone.utc),
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else datetime.now(timezone.utc),
        )

    @staticmethod
    def _row_to_service(row: sqlite3.Row) -> Service:
        return Service(
            id=row["id"],
            target_id=row["target_id"],
            port=row["port"],
            protocol=row["protocol"] or "tcp",
            name=row["name"] or "unknown",
            product=row["product"] or "",
            version=row["version"] or "",
            banner=row["banner"] or "",
            status=ServiceStatus(row["status"]),
            notes=row["notes"] or "",
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(timezone.utc),
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else datetime.now(timezone.utc),
        )

    @staticmethod
    def _row_to_checklist(row: sqlite3.Row) -> ChecklistItem:
        cve_refs = []
        if "cve_refs" in row.keys() and row["cve_refs"]:
            try:
                cve_refs = json.loads(row["cve_refs"])
            except Exception:
                cve_refs = []

        return ChecklistItem(
            id=row["id"],
            service_id=row["service_id"],
            category=row["category"] or "enum",
            title=row["title"],
            description=row["description"] or "",
            command_template=row["command_template"] or "",
            status=ChecklistStatus(row["status"]),
            severity=SeverityLevel(row["severity"]) if "severity" in row.keys() and row["severity"] else SeverityLevel.INFO,
            remediation=row["remediation"] if "remediation" in row.keys() and row["remediation"] else "",
            cve_refs=cve_refs,
            output_snippet=row["output_snippet"] or "",
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(timezone.utc),
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else datetime.now(timezone.utc),
        )

    @staticmethod
    def _row_to_lead(row: sqlite3.Row) -> Lead:
        return Lead(
            id=row["id"],
            target_id=row["target_id"],
            target_ip=row["target_ip"] if "target_ip" in row.keys() else None,
            title=row["title"],
            description=row["description"] or "",
            priority=LeadPriority(row["priority"]),
            severity=SeverityLevel(row["severity"]) if "severity" in row.keys() and row["severity"] else SeverityLevel.INFO,
            status=LeadStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(timezone.utc),
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else datetime.now(timezone.utc),
        )

    @staticmethod
    def _row_to_credential(row: sqlite3.Row) -> Credential:
        tested_targets = {}
        if row["tested_targets"]:
            try:
                tested_targets = json.loads(row["tested_targets"])
            except Exception:
                tested_targets = {}
        return Credential(
            id=row["id"],
            target_id=row["target_id"],
            target_ip=row["target_ip"] if "target_ip" in row.keys() else None,
            username=row["username"],
            secret=row["secret"],
            cred_type=CredentialType(row["cred_type"]),
            domain=row["domain"] or "",
            service_scope=row["service_scope"] or "",
            tested_targets=tested_targets,
            notes=row["notes"] or "",
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(timezone.utc),
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else datetime.now(timezone.utc),
        )

    @staticmethod
    def _row_to_evidence(row: sqlite3.Row) -> Evidence:
        return Evidence(
            id=row["id"],
            target_id=row["target_id"],
            target_ip=row["target_ip"] if "target_ip" in row.keys() else None,
            service_id=row["service_id"],
            proof_type=ProofType(row["proof_type"]),
            title=row["title"],
            command=row["command"] or "",
            output=row["output"] or "",
            flag_hash=row["flag_hash"] or "",
            screenshot_path=row["screenshot_path"] or "",
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(timezone.utc),
        )

    @staticmethod
    def _row_to_pivot_route(row: sqlite3.Row) -> PivotRoute:
        return PivotRoute(
            id=row["id"],
            name=row["name"],
            jump_host_ip=row["jump_host_ip"],
            target_subnet=row["target_subnet"],
            tunnel_type=row["tunnel_type"] or "ligolo_ng",
            local_bind=row["local_bind"] or "127.0.0.1:1080",
            notes=row["notes"] or "",
            status=row["status"] or "active",
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(timezone.utc),
        )
