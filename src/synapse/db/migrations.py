"""Database migration and versioning manager for Synapse workspaces."""

from __future__ import annotations

import sqlite3
from typing import List, Set


CURRENT_SCHEMA_VERSION = 2


def get_existing_columns(conn: sqlite3.Connection, table_name: str) -> Set[str]:
    """Returns the set of column names for a given table."""
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table_name});")
    rows = cur.fetchall()
    return {r["name"] if isinstance(r, sqlite3.Row) else r[1] for r in rows}


def run_migrations(conn: sqlite3.Connection) -> None:
    """Applies forward migrations safely to bring the database to the current schema version."""
    cur = conn.cursor()

    # 1. Check metadata table
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='metadata';")
    if not cur.fetchone():
        return  # Fresh DB, initial schema will create everything

    # 2. Check and add missing columns to targets
    target_cols = get_existing_columns(conn, "targets")
    if "in_scope" not in target_cols:
        cur.execute("ALTER TABLE targets ADD COLUMN in_scope INTEGER DEFAULT 1;")

    # 3. Check and add missing columns to checklists
    checklist_cols = get_existing_columns(conn, "checklists")
    if "severity" not in checklist_cols:
        cur.execute("ALTER TABLE checklists ADD COLUMN severity TEXT DEFAULT 'info';")
    if "remediation" not in checklist_cols:
        cur.execute("ALTER TABLE checklists ADD COLUMN remediation TEXT DEFAULT '';")
    if "cve_refs" not in checklist_cols:
        cur.execute("ALTER TABLE checklists ADD COLUMN cve_refs TEXT DEFAULT '[]';")

    # 4. Check and add missing columns to leads
    lead_cols = get_existing_columns(conn, "leads")
    if "severity" not in lead_cols:
        cur.execute("ALTER TABLE leads ADD COLUMN severity TEXT DEFAULT 'info';")

    # 5. Check and add missing columns to evidence
    evidence_cols = get_existing_columns(conn, "evidence")
    if "updated_at" not in evidence_cols:
        cur.execute("ALTER TABLE evidence ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;")

    # 6. Set version in metadata
    cur.execute(
        "INSERT INTO metadata (key, value) VALUES ('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value=?;",
        (str(CURRENT_SCHEMA_VERSION), str(CURRENT_SCHEMA_VERSION)),
    )
    conn.commit()
