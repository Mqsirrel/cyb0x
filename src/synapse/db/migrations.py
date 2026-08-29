"""Database migration and versioning manager for Synapse workspaces."""

from __future__ import annotations

import sqlite3
from typing import Set


CURRENT_SCHEMA_VERSION = 4


def table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    """Checks if a table exists in the database."""
    cur = conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?;",
        (table_name,),
    )
    return cur.fetchone() is not None


def get_existing_columns(conn: sqlite3.Connection, table_name: str) -> Set[str]:
    """Returns the set of column names for a given table."""
    if not table_exists(conn, table_name):
        return set()
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table_name});")
    rows = cur.fetchall()
    return {r["name"] if isinstance(r, sqlite3.Row) else r[1] for r in rows}


def run_migrations(conn: sqlite3.Connection) -> None:
    """Applies forward migrations safely to bring the database to the current schema version."""
    if not table_exists(conn, "metadata"):
        return  # Fresh DB, schema DDL will create everything

    cur = conn.cursor()

    # Check current schema version
    cur.execute("SELECT value FROM metadata WHERE key='schema_version';")
    ver_row = cur.fetchone()
    if ver_row:
        try:
            curr_ver = int(ver_row["value"] if isinstance(ver_row, sqlite3.Row) else ver_row[0])
            if curr_ver >= CURRENT_SCHEMA_VERSION:
                return  # Already at or ahead of current version, don't downgrade
        except (ValueError, TypeError):
            pass

    # 1. Targets table migration
    if table_exists(conn, "targets"):
        target_cols = get_existing_columns(conn, "targets")
        if "in_scope" not in target_cols:
            cur.execute("ALTER TABLE targets ADD COLUMN in_scope INTEGER DEFAULT 1;")

    # 2. Checklists table migration
    if table_exists(conn, "checklists"):
        checklist_cols = get_existing_columns(conn, "checklists")
        if "severity" not in checklist_cols:
            cur.execute("ALTER TABLE checklists ADD COLUMN severity TEXT DEFAULT 'info';")
        if "remediation" not in checklist_cols:
            cur.execute("ALTER TABLE checklists ADD COLUMN remediation TEXT DEFAULT '';")
        if "cve_refs" not in checklist_cols:
            cur.execute("ALTER TABLE checklists ADD COLUMN cve_refs TEXT DEFAULT '[]';")

    # 3. Leads table migration
    if table_exists(conn, "leads"):
        lead_cols = get_existing_columns(conn, "leads")
        if "severity" not in lead_cols:
            cur.execute("ALTER TABLE leads ADD COLUMN severity TEXT DEFAULT 'info';")

    # 4. Evidence table migration
    if table_exists(conn, "evidence"):
        evidence_cols = get_existing_columns(conn, "evidence")
        if "updated_at" not in evidence_cols:
            cur.execute("ALTER TABLE evidence ADD COLUMN updated_at TIMESTAMP;")
        if "checklist_id" not in evidence_cols:
            # v3: links captured command output back to the methodology check that produced it
            cur.execute("ALTER TABLE evidence ADD COLUMN checklist_id INTEGER REFERENCES checklists(id) ON DELETE SET NULL;")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_evidence_checklist ON evidence(checklist_id);")

    # 5. Commands table migration (v4)
    if not table_exists(conn, "commands"):
        cur.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            service_id INTEGER,
            checklist_id INTEGER,
            command TEXT NOT NULL,
            return_code INTEGER DEFAULT 0,
            stdout TEXT DEFAULT '',
            stderr TEXT DEFAULT '',
            duration_seconds REAL DEFAULT 0.0,
            extracted_flags TEXT DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE,
            FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE SET NULL,
            FOREIGN KEY(checklist_id) REFERENCES checklists(id) ON DELETE SET NULL
        );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_commands_target ON commands(target_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_commands_service ON commands(service_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_commands_created ON commands(created_at);")

    # 6. Set version in metadata
    cur.execute(
        "INSERT INTO metadata (key, value) VALUES ('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value=?;",
        (str(CURRENT_SCHEMA_VERSION), str(CURRENT_SCHEMA_VERSION)),
    )
    conn.commit()

