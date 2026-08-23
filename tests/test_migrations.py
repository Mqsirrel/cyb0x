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
