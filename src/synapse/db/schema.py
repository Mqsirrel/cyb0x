"""SQLite schema definition for Synapse."""

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    hostname TEXT DEFAULT '',
    os TEXT DEFAULT 'Unknown',
    status TEXT DEFAULT 'discovered',
    in_scope INTEGER DEFAULT 1,
    tags TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    name TEXT DEFAULT 'unknown',
    product TEXT DEFAULT '',
    version TEXT DEFAULT '',
    banner TEXT DEFAULT '',
    status TEXT DEFAULT 'untested',
    notes TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE,
    UNIQUE(target_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS checklists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    category TEXT DEFAULT 'enum',
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    command_template TEXT DEFAULT '',
    status TEXT DEFAULT 'todo',
    severity TEXT DEFAULT 'info',
    remediation TEXT DEFAULT '',
    cve_refs TEXT DEFAULT '[]',
    output_snippet TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    priority TEXT DEFAULT 'medium',
    severity TEXT DEFAULT 'info',
    status TEXT DEFAULT 'backlog',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    username TEXT NOT NULL,
    secret TEXT NOT NULL,
    cred_type TEXT DEFAULT 'password',
    domain TEXT DEFAULT '',
    service_scope TEXT DEFAULT '',
    tested_targets TEXT DEFAULT '{}',
    notes TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    service_id INTEGER,
    proof_type TEXT DEFAULT 'command_output',
    title TEXT NOT NULL,
    command TEXT DEFAULT '',
    output TEXT DEFAULT '',
    flag_hash TEXT DEFAULT '',
    screenshot_path TEXT DEFAULT '',
    checklist_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE SET NULL,
    FOREIGN KEY(checklist_id) REFERENCES checklists(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS pivot_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    jump_host_ip TEXT NOT NULL,
    target_subnet TEXT NOT NULL,
    tunnel_type TEXT DEFAULT 'ligolo_ng',
    local_bind TEXT DEFAULT '127.0.0.1:1080',
    notes TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

# Indexes are applied after schema migrations so that columns added by
# migrations (e.g. evidence.checklist_id) always exist before indexing.
INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_services_target ON services(target_id);
CREATE INDEX IF NOT EXISTS idx_checklists_service ON checklists(service_id);
CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence(target_id);
CREATE INDEX IF NOT EXISTS idx_evidence_checklist ON evidence(checklist_id);
CREATE INDEX IF NOT EXISTS idx_credentials_username ON credentials(username);
CREATE INDEX IF NOT EXISTS idx_leads_target ON leads(target_id);
CREATE INDEX IF NOT EXISTS idx_evidence_created ON evidence(created_at);
CREATE INDEX IF NOT EXISTS idx_credentials_identity ON credentials(username, secret, domain);
"""
