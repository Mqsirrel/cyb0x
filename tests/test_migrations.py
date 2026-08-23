"""Unit tests for SQLite database schema migrations."""

import sqlite3
from pathlib import Path
import pytest
from synapse.db.migrations import run_migrations, CURRENT_SCHEMA_VERSION
from synapse.db.repository import DatabaseRepository


def test_migrations_on_legacy_db(tmp_path: Path):
    # 1. Create a legacy database without newer columns
    legacy_db = tmp_path / "legacy.db"
    conn = sqlite3.connect(legacy_db)
    conn.executescript("""
    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    INSERT INTO metadata (key, value) VALUES ('schema_version', '1');
    
    CREATE TABLE targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL UNIQUE,
        hostname TEXT DEFAULT '',
        os TEXT DEFAULT 'Unknown',
        status TEXT DEFAULT 'discovered',
        tags TEXT DEFAULT '[]',
        notes TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE checklists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_id INTEGER NOT NULL,
        category TEXT DEFAULT 'enum',
        title TEXT NOT NULL,
        description TEXT DEFAULT '',
        command_template TEXT DEFAULT '',
        status TEXT DEFAULT 'todo',
        output_snippet TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()

    # 2. Open via DatabaseRepository (which automatically executes run_migrations)
    repo = DatabaseRepository(legacy_db)
    migrated_conn = repo.get_connection()
    cur = migrated_conn.cursor()

    # Verify target columns
    cur.execute("PRAGMA table_info(targets);")
    target_cols = {r[1] for r in cur.fetchall()}
    assert "in_scope" in target_cols

    # Verify checklist columns
    cur.execute("PRAGMA table_info(checklists);")
    chk_cols = {r[1] for r in cur.fetchall()}
    assert "severity" in chk_cols
    assert "remediation" in chk_cols
    assert "cve_refs" in chk_cols

    # Verify metadata version
    cur.execute("SELECT value FROM metadata WHERE key = 'schema_version';")
    row = cur.fetchone()
    assert row["value"] == str(CURRENT_SCHEMA_VERSION)


def test_migrations_v2_to_v3_adds_evidence_checklist_link(tmp_path: Path):
    """A v2 workspace (evidence without checklist_id) must upgrade losslessly."""
    legacy_db = tmp_path / "v2.db"
    conn = sqlite3.connect(legacy_db)
    conn.executescript("""
    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    INSERT INTO metadata (key, value) VALUES ('schema_version', '2');

    CREATE TABLE evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER NOT NULL,
        service_id INTEGER,
        proof_type TEXT DEFAULT 'command_output',
        title TEXT NOT NULL,
        command TEXT DEFAULT '',
        output TEXT DEFAULT '',
        flag_hash TEXT DEFAULT '',
        screenshot_path TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO evidence (target_id, title, command) VALUES (1, 'legacy proof', 'whoami');
    """)
    conn.commit()
    conn.close()

    repo = DatabaseRepository(legacy_db)
    migrated = repo.get_connection()
    cur = migrated.cursor()
    cur.execute("PRAGMA table_info(evidence);")
    cols = {r[1] for r in cur.fetchall()}
    assert "checklist_id" in cols

    # Pre-existing rows survive the migration and load with checklist_id=None
    evidence = repo.list_evidence()
    assert len(evidence) == 1
    assert evidence[0].checklist_id is None

    # New evidence can link to a check after migration
    t = repo.add_or_get_target("10.0.0.1")
    svc = repo.add_or_update_service(t.id, 80, "tcp", "http")
    chk = repo.add_checklist_item(svc.id, title="dirb")
    ev = repo.add_evidence(t.id, "linked output", checklist_id=chk.id)
    assert repo.get_evidence_by_id(ev.id).checklist_id == chk.id

    cur.execute("SELECT value FROM metadata WHERE key='schema_version';")
    assert cur.fetchone()["value"] == str(CURRENT_SCHEMA_VERSION)
