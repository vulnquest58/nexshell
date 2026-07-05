#!/usr/bin/env python3
"""
NexShell — Extended DB Schema  (db/schema_v2.py)
Additional tables: hosts, services, findings, operations, evidence.
Applied automatically on first import via NexDB.migrate_v2().
"""

SCHEMA_V2 = """
PRAGMA foreign_keys=ON;

-- Hosts (Asset Inventory)
CREATE TABLE IF NOT EXISTS hosts (
    id          TEXT    PRIMARY KEY,
    ip          TEXT    UNIQUE NOT NULL,
    hostname    TEXT    DEFAULT '',
    os          TEXT    DEFAULT 'Unknown',
    os_version  TEXT    DEFAULT '',
    domain      TEXT    DEFAULT '',
    tags        TEXT    DEFAULT '[]',
    notes       TEXT    DEFAULT '[]',
    risk        TEXT    DEFAULT 'unknown',
    in_scope    INTEGER DEFAULT 1,
    session_ids TEXT    DEFAULT '[]',
    service_ids TEXT    DEFAULT '[]',
    discovered  TEXT    DEFAULT (datetime('now'))
);

-- Services
CREATE TABLE IF NOT EXISTS services (
    id          TEXT    PRIMARY KEY,
    host_ip     TEXT    NOT NULL REFERENCES hosts(ip) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT    DEFAULT 'tcp',
    service     TEXT    DEFAULT '',
    version     TEXT    DEFAULT '',
    banner      TEXT    DEFAULT '',
    state       TEXT    DEFAULT 'open',
    discovered  TEXT    DEFAULT (datetime('now'))
);

-- Findings
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT    PRIMARY KEY,
    title           TEXT    NOT NULL,
    description     TEXT    DEFAULT '',
    severity        TEXT    DEFAULT 'info',
    cvss            REAL    DEFAULT 0.0,
    cvss_vector     TEXT    DEFAULT '',
    host            TEXT    DEFAULT '',
    session_id      INTEGER DEFAULT 0,
    evidence_ids    TEXT    DEFAULT '[]',
    recommendation  TEXT    DEFAULT '',
    mitre_id        TEXT    DEFAULT '',
    source          TEXT    DEFAULT 'manual',
    status          TEXT    DEFAULT 'open',
    created         TEXT    DEFAULT (datetime('now'))
);

-- Operations (Workspaces)
CREATE TABLE IF NOT EXISTS operations (
    id              TEXT    PRIMARY KEY,
    name            TEXT    UNIQUE NOT NULL,
    client          TEXT    DEFAULT '',
    description     TEXT    DEFAULT '',
    operator        TEXT    DEFAULT '',
    status          TEXT    DEFAULT 'active',
    scope_ips       TEXT    DEFAULT '[]',
    scope_domains   TEXT    DEFAULT '[]',
    objectives      TEXT    DEFAULT '[]',
    tags            TEXT    DEFAULT '[]',
    start_date      TEXT    DEFAULT (datetime('now')),
    end_date        TEXT    DEFAULT '',
    created         TEXT    DEFAULT (datetime('now'))
);

-- Evidence (Chain of Custody)
CREATE TABLE IF NOT EXISTS evidence (
    id          TEXT    PRIMARY KEY,
    type        TEXT    NOT NULL,
    sha256      TEXT    NOT NULL,
    data_text   TEXT    DEFAULT '',
    host        TEXT    DEFAULT '',
    session_id  INTEGER DEFAULT 0,
    operator    TEXT    DEFAULT '',
    filename    TEXT    DEFAULT '',
    note        TEXT    DEFAULT '',
    ts          TEXT    DEFAULT (datetime('now'))
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_hosts_ip        ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_services_host   ON services(host_ip);
CREATE INDEX IF NOT EXISTS idx_findings_sev    ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_host   ON findings(host);
CREATE INDEX IF NOT EXISTS idx_evidence_type   ON evidence(type);
CREATE INDEX IF NOT EXISTS idx_evidence_host   ON evidence(host);
"""
