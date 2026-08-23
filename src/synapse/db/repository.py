"""Repository for database operations and data persistence.

Performance notes:
- A single persistent SQLite connection is held per repository instance
  (thread-safe via an RLock) instead of opening/closing a connection for
  every operation.
- All writes run through a nested-safe ``transaction()`` context manager,
  enabling callers to batch thousands of writes into a single fsync.
- Writers return models constructed from known values instead of issuing
  follow-up SELECTs (no write-then-read-back round trips).
- Bulk loaders hydrate related rows in O(1) queries (no N+1).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
from datetime import datetime, timezone

from synapse.db.migrations import run_migrations
from synapse.db.schema import INDEXES_SQL, SCHEMA_SQL
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


def _parse_dt(val: Optional[str]) -> datetime:
    """Parses datetime strings from SQLite into timezone-aware UTC datetime objects."""
    if not val:
        return datetime.now(timezone.utc)
    try:
        clean_val = str(val).replace(" ", "T")
        dt = datetime.fromisoformat(clean_val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


class DatabaseRepository:
    """Handles all persistence and queries for Synapse workspaces."""

    def __init__(self, db_path: str | Path = ":memory:"):
        self._lock = threading.RLock()
        self.db_path = ":memory:" if db_path == ":memory:" else str(Path(db_path).absolute())
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

        # Connection-level PRAGMAs are applied exactly once here. journal_mode
        # is persistent for file databases; running it per call wasted cycles.
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON;")
            self._conn.execute("PRAGMA busy_timeout = 5000;")
            try:
                self._conn.execute("PRAGMA journal_mode = WAL;")
            except sqlite3.DatabaseError:
                pass  # e.g. in-memory DBs where WAL is unsupported
            self._conn.execute("PRAGMA synchronous = NORMAL;")
            try:
                self._conn.execute("PRAGMA mmap_size = 134217728;")  # 128 MB
            except sqlite3.DatabaseError:
                pass

        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Returns the repository's persistent connection (shared, thread-safe usage)."""
        return self._conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Nested-safe transaction scope: outermost caller controls commit/rollback."""
        with self._lock:
            nested = self._conn.in_transaction
            if not nested:
                self._conn.execute("BEGIN")
            try:
                yield self._conn
            except Exception:
                if not nested:
                    self._conn.rollback()
                raise
            else:
                if not nested:
                    self._conn.commit()

    def close(self) -> None:
        """Closes the underlying connection (optional; repositories close on GC)."""
        with self._lock:
            try:
                self._conn.commit()
            except sqlite3.Error:
                pass
            self._conn.close()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA_SQL)
            run_migrations(self._conn)
            self._conn.executescript(INDEXES_SQL)
            self._conn.commit()

    # -------------------------------------------------------------------------
    # Shared hydration helpers
    # -------------------------------------------------------------------------
    def _attach_checklists(self, services: Dict[int, Service], conn: sqlite3.Connection, service_ids: Optional[List[int]] = None) -> None:
        """Hydrates ``checklists`` onto the given services using a single query."""
        ids = list(services.keys()) if service_ids is None else service_ids
        if not ids:
            return
        placeholders = ",".join("?" * len(ids))
        cur = conn.execute(
            f"SELECT * FROM checklists WHERE service_id IN ({placeholders}) ORDER BY service_id ASC, id ASC",
            ids,
        )
        for row in cur.fetchall():
            svc = services.get(row["service_id"])
            if svc is not None:
                svc.checklists.append(self._row_to_checklist(row))

    # -------------------------------------------------------------------------
    # Target Operations
    # -------------------------------------------------------------------------
    def add_or_get_target(
        self,
        ip: str,
        hostname: str = "",
        os: str = "Unknown",
        status: TargetStatus = TargetStatus.DISCOVERED,
        in_scope: Optional[bool] = None,
        tags: Optional[List[str]] = None,
        notes: str = "",
    ) -> Target:
        """Inserts or merges a target.

        ``in_scope=None`` (the default) preserves the persisted scope flag on
        merge instead of silently re-scoping the host.
        """
        tags_json = json.dumps(tags or [])
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM targets WHERE ip = ?", (ip,)).fetchone()
            now = datetime.now(timezone.utc)
            if row:
                merged_hostname = hostname if hostname else row["hostname"]
                merged_os = os if (os != "Unknown" and os) else row["os"]
                merged_tags = tags_json if tags is not None else row["tags"]
                merged_notes = notes if notes else row["notes"]
                merged_status = status.value if status != TargetStatus.DISCOVERED else row["status"]
                merged_in_scope = row["in_scope"] if in_scope is None else (1 if in_scope else 0)
                conn.execute(
                    """
                    UPDATE targets
                    SET hostname = ?, os = ?, tags = ?, notes = ?, status = ?, in_scope = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (merged_hostname, merged_os, merged_tags, merged_notes, merged_status, merged_in_scope, row["id"]),
                )
                target_id = row["id"]
                created_at = _parse_dt(row["created_at"])
            else:
                cur = conn.execute(
                    """
                    INSERT INTO targets (ip, hostname, os, status, in_scope, tags, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ip, hostname, os, status.value, 1 if (in_scope is None or in_scope) else 0, tags_json, notes),
                )
                target_id = cur.lastrowid
                created_at = now
                merged_hostname, merged_os, merged_tags = hostname, os, tags_json
                merged_notes = notes
                merged_status = status.value
                merged_in_scope = 1 if (in_scope is None or in_scope) else 0

        try:
            parsed_tags = json.loads(merged_tags)
        except Exception:
            parsed_tags = []
        return Target(
            id=target_id,
            ip=ip,
            hostname=merged_hostname or "",
            os=merged_os or "Unknown",
            status=TargetStatus(merged_status),
            in_scope=bool(merged_in_scope),
            tags=parsed_tags,
            notes=merged_notes or "",
            services=[],
            created_at=created_at,
            updated_at=now,
        )

    def get_target_by_id(self, target_id: int) -> Optional[Target]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
            if not row:
                return None
            target = self._row_to_target(row)

            svc_rows = self._conn.execute(
                "SELECT * FROM services WHERE target_id = ? ORDER BY port ASC",
                (target_id,),
            ).fetchall()
            services_map: Dict[int, Service] = {}
            for sr in svc_rows:
                svc = self._row_to_service(sr)
                services_map[svc.id] = svc  # type: ignore
                target.services.append(svc)
            self._attach_checklists(services_map, self._conn)
        return target

    def get_target_by_ip(self, ip: str) -> Optional[Target]:
        with self._lock:
            row = self._conn.execute("SELECT id FROM targets WHERE ip = ?", (ip,)).fetchone()
        return self.get_target_by_id(row["id"]) if row else None

    def list_targets(self) -> List[Target]:
        """Batch-fetches all targets, services, and checklists in O(1) database round-trips."""
        with self._lock:
            target_rows = self._conn.execute("SELECT * FROM targets ORDER BY ip ASC").fetchall()
            if not target_rows:
                return []

            targets_map: Dict[int, Target] = {r["id"]: self._row_to_target(r) for r in target_rows}

            services_map: Dict[int, Service] = {}
            for r in self._conn.execute("SELECT * FROM services ORDER BY target_id ASC, port ASC"):
                svc = self._row_to_service(r)
                services_map[r["id"]] = svc
                t = targets_map.get(r["target_id"])
                if t is not None:
                    t.services.append(svc)

            for cr in self._conn.execute("SELECT * FROM checklists ORDER BY service_id ASC, id ASC"):
                svc = services_map.get(cr["service_id"])
                if svc is not None:
                    svc.checklists.append(self._row_to_checklist(cr))

            return list(targets_map.values())

    def update_target_status(self, target_id: int, status: TargetStatus) -> bool:
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE targets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status.value, target_id),
            )
            return cur.rowcount > 0

    def set_target_scope(self, target_id: int, in_scope: bool) -> bool:
        """Toggles the engagement scope flag for a host."""
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE targets SET in_scope = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (1 if in_scope else 0, target_id),
            )
            return cur.rowcount > 0

    def delete_target(self, target_id: int) -> bool:
        with self.transaction() as conn:
            cur = conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
            return cur.rowcount > 0

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
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM services WHERE target_id = ? AND port = ? AND protocol = ?",
                (target_id, port, protocol),
            ).fetchone()
            now = datetime.now(timezone.utc)
            if row:
                merged_name = name if name != "unknown" else row["name"]
                merged_product = product if product else row["product"]
                merged_version = version if version else row["version"]
                merged_banner = banner if banner else row["banner"]
                conn.execute(
                    """
                    UPDATE services
                    SET name = ?, product = ?, version = ?, banner = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (merged_name, merged_product, merged_version, merged_banner, row["id"]),
                )
                service_id = row["id"]
                created_at = _parse_dt(row["created_at"])
                final_status = ServiceStatus(row["status"])
                final_notes = row["notes"] or ""
            else:
                cur = conn.execute(
                    """
                    INSERT INTO services (target_id, port, protocol, name, product, version, banner, status, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (target_id, port, protocol, name, product, version, banner, status.value, notes),
                )
                service_id = cur.lastrowid
                created_at = now
                merged_name, merged_product, merged_version, merged_banner = name, product, version, banner
                final_status = status
                final_notes = notes

        return Service(
            id=service_id,
            target_id=target_id,
            port=port,
            protocol=protocol,
            name=merged_name or "unknown",
            product=merged_product or "",
            version=merged_version or "",
            banner=merged_banner or "",
            status=final_status,
            notes=final_notes,
            checklists=[],
            created_at=created_at,
            updated_at=now,
        )

    def get_service_by_id(self, service_id: int) -> Optional[Service]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
            if not row:
                return None
            service = self._row_to_service(row)
            self._attach_checklists({service.id: service}, self._conn)  # type: ignore
        return service

    def get_services_by_target(self, target_id: int) -> List[Service]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM services WHERE target_id = ? ORDER BY port ASC",
                (target_id,),
            ).fetchall()
            services_map: Dict[int, Service] = {}
            ordered: List[Service] = []
            for r in rows:
                svc = self._row_to_service(r)
                services_map[svc.id] = svc  # type: ignore
                ordered.append(svc)
            self._attach_checklists(services_map, self._conn)
        return ordered

    def update_service_status(self, service_id: int, status: ServiceStatus) -> bool:
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE services SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status.value, service_id),
            )
            return cur.rowcount > 0

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
        severity: SeverityLevel = SeverityLevel.INFO,
        remediation: str = "",
        cve_refs: Optional[List[str]] = None,
        output_snippet: str = "",
    ) -> ChecklistItem:
        cve_json = json.dumps(cve_refs or [])
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM checklists WHERE service_id = ? AND title = ?",
                (service_id, title),
            ).fetchone()
            now = datetime.now(timezone.utc)
            if row:
                conn.execute(
                    """
                    UPDATE checklists
                    SET category = ?, description = ?, command_template = ?, severity = ?, remediation = ?, cve_refs = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (category, description, command_template, severity.value, remediation, cve_json, row["id"]),
                )
                item_id = row["id"]
                created_at = _parse_dt(row["created_at"])
                final_status = ChecklistStatus(row["status"])
                final_snippet = row["output_snippet"] or ""
            else:
                cur = conn.execute(
                    """
                    INSERT INTO checklists (service_id, category, title, description, command_template, status, severity, remediation, cve_refs, output_snippet)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        service_id,
                        category,
                        title,
                        description,
                        command_template,
                        status.value,
                        severity.value,
                        remediation,
                        cve_json,
                        output_snippet,
                    ),
                )
                item_id = cur.lastrowid
                created_at = now
                final_status = status
                final_snippet = output_snippet

        return ChecklistItem(
            id=item_id,
            service_id=service_id,
            category=category,
            title=title,
            description=description,
            command_template=command_template,
            status=final_status,
            severity=severity,
            remediation=remediation,
            cve_refs=cve_refs or [],
            output_snippet=final_snippet,
            created_at=created_at,
            updated_at=now,
        )

    def get_checklist_by_id(self, item_id: int) -> Optional[ChecklistItem]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM checklists WHERE id = ?", (item_id,)).fetchone()
            return self._row_to_checklist(row) if row else None

    def get_checklists_by_service(self, service_id: int) -> List[ChecklistItem]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM checklists WHERE service_id = ? ORDER BY id ASC",
                (service_id,),
            ).fetchall()
            return [self._row_to_checklist(r) for r in rows]

    def update_checklist_status(
        self,
        item_id: int,
        status: ChecklistStatus,
        output_snippet: Optional[str] = None,
    ) -> bool:
        with self.transaction() as conn:
            if output_snippet is not None:
                cur = conn.execute(
                    """
                    UPDATE checklists
                    SET status = ?, output_snippet = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (status.value, output_snippet, item_id),
                )
            else:
                cur = conn.execute(
                    """
                    UPDATE checklists
                    SET status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (status.value, item_id),
                )
            return cur.rowcount > 0

    # -------------------------------------------------------------------------
    # Lead / Hypothesis Operations
    # -------------------------------------------------------------------------
    def add_lead(
        self,
        title: str,
        description: str = "",
        priority: LeadPriority = LeadPriority.MEDIUM,
        severity: SeverityLevel = SeverityLevel.INFO,
        status: LeadStatus = LeadStatus.BACKLOG,
        target_id: Optional[int] = None,
    ) -> Lead:
        with self.transaction() as conn:
            cur = conn.execute(
                """
                INSERT INTO leads (target_id, title, description, priority, severity, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (target_id, title, description, priority.value, severity.value, status.value),
            )
            lead_id = cur.lastrowid
            target_ip: Optional[str] = None
            if target_id is not None:
                t_row = conn.execute("SELECT ip FROM targets WHERE id = ?", (target_id,)).fetchone()
                target_ip = t_row["ip"] if t_row else None

        return Lead(
            id=lead_id,
            target_id=target_id,
            target_ip=target_ip,
            title=title,
            description=description,
            priority=priority,
            severity=severity,
            status=status,
        )

    def get_lead_by_id(self, lead_id: int) -> Optional[Lead]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT leads.*, targets.ip as target_ip
                FROM leads
                LEFT JOIN targets ON leads.target_id = targets.id
                WHERE leads.id = ?
                """,
                (lead_id,),
            ).fetchone()
            return self._row_to_lead(row) if row else None

    def list_leads(self, target_id: Optional[int] = None) -> List[Lead]:
        with self._lock:
            if target_id:
                rows = self._conn.execute(
                    """
                    SELECT leads.*, targets.ip as target_ip
                    FROM leads
                    LEFT JOIN targets ON leads.target_id = targets.id
                    WHERE leads.target_id = ?
                    ORDER BY leads.created_at DESC
                    """,
                    (target_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT leads.*, targets.ip as target_ip
                    FROM leads
                    LEFT JOIN targets ON leads.target_id = targets.id
                    ORDER BY leads.created_at DESC
                    """
                ).fetchall()
            return [self._row_to_lead(r) for r in rows]

    def update_lead_status(self, lead_id: int, status: LeadStatus) -> bool:
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE leads SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status.value, lead_id),
            )
            return cur.rowcount > 0

    def delete_lead(self, lead_id: int) -> bool:
        with self.transaction() as conn:
            cur = conn.execute("DELETE FROM leads WHERE id = ?", (lead_id,))
            return cur.rowcount > 0

    # -------------------------------------------------------------------------
    # Credential & Lateral Movement Matrix Operations
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
        with self.transaction() as conn:
            row = conn.execute(
                """
                SELECT id, tested_targets FROM credentials
                WHERE username = ? AND secret = ? AND domain = ?
                """,
                (username, secret, domain),
            ).fetchone()
            now = datetime.now(timezone.utc)
            target_ip: Optional[str] = None
            if target_id is not None:
                t_row = conn.execute("SELECT ip FROM targets WHERE id = ?", (target_id,)).fetchone()
                target_ip = t_row["ip"] if t_row else None
            if row:
                cred_id = row["id"]
                try:
                    tested_targets = json.loads(row["tested_targets"]) if row["tested_targets"] else {}
                except Exception:
                    tested_targets = {}
            else:
                cur = conn.execute(
                    """
                    INSERT INTO credentials (target_id, username, secret, cred_type, domain, service_scope, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (target_id, username, secret, cred_type.value, domain, service_scope, notes),
                )
                cred_id = cur.lastrowid
                tested_targets = {}

        return Credential(
            id=cred_id,
            target_id=target_id,
            target_ip=target_ip,
            username=username,
            secret=secret,
            cred_type=cred_type,
            domain=domain,
            service_scope=service_scope,
            tested_targets=tested_targets,
            notes=notes,
        )

    def get_credential_by_id(self, cred_id: int) -> Optional[Credential]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT credentials.*, targets.ip as target_ip
                FROM credentials
                LEFT JOIN targets ON credentials.target_id = targets.id
                WHERE credentials.id = ?
                """,
                (cred_id,),
            ).fetchone()
            return self._row_to_credential(row) if row else None

    def list_credentials(self) -> List[Credential]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT credentials.*, targets.ip as target_ip
                FROM credentials
                LEFT JOIN targets ON credentials.target_id = targets.id
                ORDER BY credentials.created_at DESC
                """
            ).fetchall()
            return [self._row_to_credential(r) for r in rows]

    def record_credential_test(
        self,
        cred_id: int,
        target_ip: str,
        service: str = "",
        valid: bool = True,
        admin: bool = False,
    ) -> bool:
        """Atomically records whether a credential was valid on a specific target."""
        with self.transaction() as conn:
            row = conn.execute("SELECT tested_targets FROM credentials WHERE id = ?", (cred_id,)).fetchone()
            if not row:
                return False

            tested: Dict[str, Any] = {}
            if row["tested_targets"]:
                try:
                    tested = json.loads(row["tested_targets"])
                except Exception:
                    tested = {}

            entry = {
                "target_ip": target_ip,
                "service": service,
                "valid": valid,
                "admin": admin,
                "tested_at": datetime.now(timezone.utc).isoformat(),
            }
            tested[target_ip] = entry
            if service:
                tested[f"{target_ip}:{service}"] = entry

            conn.execute(
                """
                UPDATE credentials
                SET tested_targets = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (json.dumps(tested), cred_id),
            )
            return True

    def update_credential_tested_targets(self, cred_id: int, tested_targets: Dict[str, Any]) -> bool:
        """Replaces the full tested-targets map (used to reset lifecycle state)."""
        with self.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE credentials
                SET tested_targets = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (json.dumps(tested_targets), cred_id),
            )
            return cur.rowcount > 0

    def delete_credential(self, cred_id: int) -> bool:
        with self.transaction() as conn:
            cur = conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
            return cur.rowcount > 0

    # -------------------------------------------------------------------------
    # Evidence & Proof Operations
    # -------------------------------------------------------------------------
    def add_evidence(
        self,
        target_id: int,
        title: str,
        proof_type: ProofType = ProofType.COMMAND_OUTPUT,
        service_id: Optional[int] = None,
        checklist_id: Optional[int] = None,
        command: str = "",
        output: str = "",
        flag_hash: str = "",
        screenshot_path: str = "",
    ) -> Evidence:
        with self.transaction() as conn:
            cur = conn.execute(
                """
                INSERT INTO evidence (target_id, service_id, checklist_id, proof_type, title, command, output, flag_hash, screenshot_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target_id,
                    service_id,
                    checklist_id,
                    proof_type.value,
                    title,
                    command,
                    output,
                    flag_hash,
                    screenshot_path,
                ),
            )
            evidence_id = cur.lastrowid

        return Evidence(
            id=evidence_id,
            target_id=target_id,
            service_id=service_id,
            checklist_id=checklist_id,
            proof_type=proof_type,
            title=title,
            command=command,
            output=output,
            flag_hash=flag_hash,
            screenshot_path=screenshot_path,
        )

    def get_evidence_by_id(self, evidence_id: int) -> Optional[Evidence]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT evidence.*, targets.ip as target_ip
                FROM evidence
                LEFT JOIN targets ON evidence.target_id = targets.id
                WHERE evidence.id = ?
                """,
                (evidence_id,),
            ).fetchone()
            return self._row_to_evidence(row) if row else None

    def list_evidence(self, target_id: Optional[int] = None) -> List[Evidence]:
        with self._lock:
            if target_id:
                rows = self._conn.execute(
                    """
                    SELECT evidence.*, targets.ip as target_ip
                    FROM evidence
                    LEFT JOIN targets ON evidence.target_id = targets.id
                    WHERE evidence.target_id = ?
                    ORDER BY evidence.created_at DESC
                    """,
                    (target_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT evidence.*, targets.ip as target_ip
                    FROM evidence
                    LEFT JOIN targets ON evidence.target_id = targets.id
                    ORDER BY evidence.created_at DESC
                    """
                ).fetchall()
            return [self._row_to_evidence(r) for r in rows]

    def delete_evidence(self, evidence_id: int) -> bool:
        with self.transaction() as conn:
            cur = conn.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
            return cur.rowcount > 0

    # -------------------------------------------------------------------------
    # Pivot Route Operations
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
        with self.transaction() as conn:
            cur = conn.execute(
                """
                INSERT INTO pivot_routes (name, jump_host_ip, target_subnet, tunnel_type, local_bind, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, jump_host_ip, target_subnet, tunnel_type, local_bind, notes),
            )
            route_id = cur.lastrowid

        return PivotRoute(
            id=route_id,
            name=name,
            jump_host_ip=jump_host_ip,
            target_subnet=target_subnet,
            tunnel_type=tunnel_type,
            local_bind=local_bind,
            notes=notes,
        )

    def get_pivot_route_by_id(self, route_id: int) -> Optional[PivotRoute]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM pivot_routes WHERE id = ?", (route_id,)).fetchone()
            return self._row_to_pivot_route(row) if row else None

    def list_pivot_routes(self) -> List[PivotRoute]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM pivot_routes ORDER BY created_at DESC").fetchall()
            return [self._row_to_pivot_route(r) for r in rows]

    def delete_pivot_route(self, route_id: int) -> bool:
        with self.transaction() as conn:
            cur = conn.execute("DELETE FROM pivot_routes WHERE id = ?", (route_id,))
            return cur.rowcount > 0

    # -------------------------------------------------------------------------
    # Engagement Statistics
    # -------------------------------------------------------------------------
    def get_engagement_stats(self) -> Dict[str, Any]:
        """Calculates global engagement metrics in a single query."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM targets) AS total_targets,
                    (SELECT COUNT(*) FROM targets WHERE status = 'pwned') AS pwned_targets,
                    (SELECT COUNT(*) FROM targets WHERE status = 'foothold') AS foothold_targets,
                    (SELECT COUNT(*) FROM services) AS total_services,
                    (SELECT COUNT(*) FROM checklists) AS total_checks,
                    (SELECT COUNT(*) FROM checklists WHERE status IN ('checked', 'finding')) AS completed_checks,
                    (SELECT COUNT(*) FROM checklists WHERE status = 'finding') AS total_findings,
                    (SELECT COUNT(*) FROM credentials) AS total_credentials,
                    (SELECT COUNT(*) FROM evidence WHERE flag_hash != '') AS captured_flags,
                    (SELECT COUNT(*) FROM leads WHERE status IN ('backlog', 'in_progress')) AS active_leads
                """
            ).fetchone()

        return {
            "total_targets": row["total_targets"],
            "pwned_targets": row["pwned_targets"],
            "foothold_targets": row["foothold_targets"],
            "total_services": row["total_services"],
            "total_checks": row["total_checks"],
            "completed_checks": row["completed_checks"],
            "total_findings": row["total_findings"],
            "total_credentials": row["total_credentials"],
            "captured_flags": row["captured_flags"],
            "active_leads": row["active_leads"],
        }

    def get_stats(self) -> Dict[str, Any]:
        """Alias for get_engagement_stats for backward compatibility."""
        return self.get_engagement_stats()

    # -------------------------------------------------------------------------
    # Row to Model Converters
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
            in_scope=bool(row["in_scope"]) if "in_scope" in row.keys() and row["in_scope"] is not None else True,
            tags=tags,
            notes=row["notes"] or "",
            services=[],
            created_at=_parse_dt(row["created_at"]),
            updated_at=_parse_dt(row["updated_at"]),
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
            created_at=_parse_dt(row["created_at"]),
            updated_at=_parse_dt(row["updated_at"]),
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
            created_at=_parse_dt(row["created_at"]),
            updated_at=_parse_dt(row["updated_at"]),
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
            created_at=_parse_dt(row["created_at"]),
            updated_at=_parse_dt(row["updated_at"]),
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
            created_at=_parse_dt(row["created_at"]),
            updated_at=_parse_dt(row["updated_at"]),
        )

    @staticmethod
    def _row_to_evidence(row: sqlite3.Row) -> Evidence:
        return Evidence(
            id=row["id"],
            target_id=row["target_id"],
            target_ip=row["target_ip"] if "target_ip" in row.keys() else None,
            service_id=row["service_id"],
            checklist_id=row["checklist_id"] if "checklist_id" in row.keys() else None,
            proof_type=ProofType(row["proof_type"]),
            title=row["title"],
            command=row["command"] or "",
            output=row["output"] or "",
            flag_hash=row["flag_hash"] or "",
            screenshot_path=row["screenshot_path"] or "",
            created_at=_parse_dt(row["created_at"]),
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
            created_at=_parse_dt(row["created_at"]),
        )
