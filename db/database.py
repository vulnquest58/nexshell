#!/usr/bin/env python3
"""
NexShell — Database Layer  (db/database.py)
SQLite-backed persistent storage for sessions, loot, command history,
notes, and listeners.  Zero external dependencies — stdlib only.

Usage:
    from db import get_db
    db = get_db()
    db.add_loot(session_id=1, host='10.0.0.1', category='credentials',
                source='/etc/passwd', data='root:x:0:0:...')
    rows = db.search_loot(category='credentials')
"""

import os
import sqlite3
import hashlib
import datetime
import json
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any

# ── v2 extended schema ─────────────────────────────────────────────────────────
try:
    from .schema_v2 import SCHEMA_V2
except ImportError:
    try:
        from db.schema_v2 import SCHEMA_V2
    except ImportError:
        SCHEMA_V2 = ""  # fallback — v2 tables won't be created


# ── Default DB path ────────────────────────────────────────────────────────────
_DEFAULT_DB_PATH = Path.home() / '.nexshell' / 'nexshell.db'


# ══════════════════════════════════════════════════════════════════════════════
#  SCHEMA
# ══════════════════════════════════════════════════════════════════════════════

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host         TEXT    NOT NULL,
    port         INTEGER,
    os           TEXT    DEFAULT 'Unknown',
    user         TEXT    DEFAULT '',
    is_root      INTEGER DEFAULT 0,
    shell_type   TEXT    DEFAULT 'dumb',
    tag          TEXT    DEFAULT '',
    connected_at TEXT    DEFAULT (datetime('now')),
    last_seen    TEXT,
    status       TEXT    DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS loot (
    id          TEXT    PRIMARY KEY,
    session_id  INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    host        TEXT    DEFAULT '',
    category    TEXT    NOT NULL,
    source      TEXT    DEFAULT '',
    data        TEXT    NOT NULL,
    confidence  TEXT    DEFAULT 'high',
    ts          TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS command_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    command     TEXT    NOT NULL,
    output      TEXT    DEFAULT '',
    ts          TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    text        TEXT    NOT NULL,
    ts          TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS listeners (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    port        INTEGER UNIQUE NOT NULL,
    interface   TEXT    DEFAULT '0.0.0.0',
    tls         INTEGER DEFAULT 0,
    transport   TEXT    DEFAULT 'tcp',
    started_at  TEXT    DEFAULT (datetime('now')),
    status      TEXT    DEFAULT 'active'
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_loot_category   ON loot(category);
CREATE INDEX IF NOT EXISTS idx_loot_host       ON loot(host);
CREATE INDEX IF NOT EXISTS idx_loot_session    ON loot(session_id);
CREATE INDEX IF NOT EXISTS idx_history_session ON command_history(session_id);
CREATE INDEX IF NOT EXISTS idx_notes_session   ON notes(session_id);
"""


# ══════════════════════════════════════════════════════════════════════════════
#  NexDB  — main database class
# ══════════════════════════════════════════════════════════════════════════════

class NexDB:
    """
    Thread-safe SQLite interface for NexShell.

    All write methods acquire the internal lock.
    Read methods return list-of-dicts for easy consumption.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._local = threading.local()
        self._init_schema()
        self._migrate_v2()  # Apply extended schema (hosts, findings, operations, evidence)

    # ── Connection (per-thread) ────────────────────────────────────────────────
    def _conn(self) -> sqlite3.Connection:
        if not getattr(self._local, 'conn', None):
            conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return self._local.conn

    def _init_schema(self):
        with self._lock:
            conn = self._conn()
            conn.executescript(_SCHEMA)
            conn.commit()

    def _migrate_v2(self):
        """Apply v2 extended schema (hosts, findings, operations, evidence)."""
        if not SCHEMA_V2:
            return
        with self._lock:
            conn = self._conn()
            try:
                conn.executescript(SCHEMA_V2)
                conn.commit()
            except Exception:
                pass   # Non-fatal — v2 tables are optional

    def _now(self) -> str:
        return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    def _rows_to_dicts(self, rows) -> List[Dict[str, Any]]:
        return [dict(r) for r in rows]

    def _json_col(self, value) -> str:
        """Serialize list/dict to JSON string for storage."""
        if isinstance(value, (list, dict)):
            return json.dumps(value, ensure_ascii=False)
        return value or '[]'

    def _from_json_col(self, value, default=None):
        """Deserialize JSON string column back to Python object."""
        if default is None:
            default = []
        if not value:
            return default
        try:
            return json.loads(value)
        except Exception:
            return default

    # ══════════════════════════════════════════════════════════════════════════
    #  V2 — HOSTS
    # ══════════════════════════════════════════════════════════════════════════

    def upsert_host(self, data: dict):
        """Insert or update a host record."""
        ip = data.get('ip', '')
        if not ip:
            return
        hid = data.get('id') or __import__('hashlib').md5(ip.encode()).hexdigest()[:12]
        with self._lock:
            conn = self._conn()
            conn.execute("""
                INSERT INTO hosts
                    (id, ip, hostname, os, os_version, domain, tags, notes,
                     risk, in_scope, session_ids, service_ids, discovered)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    hostname   = excluded.hostname,
                    os         = excluded.os,
                    os_version = excluded.os_version,
                    domain     = excluded.domain,
                    tags       = excluded.tags,
                    notes      = excluded.notes,
                    risk       = excluded.risk,
                    in_scope   = excluded.in_scope,
                    session_ids= excluded.session_ids,
                    service_ids= excluded.service_ids
            """, (
                hid, ip,
                data.get('hostname', ''),
                data.get('os', 'Unknown'),
                data.get('os_version', ''),
                data.get('domain', ''),
                self._json_col(data.get('tags', [])),
                self._json_col(data.get('notes', [])),
                data.get('risk', 'unknown'),
                int(data.get('in_scope', True)),
                self._json_col(data.get('session_ids', [])),
                self._json_col(data.get('service_ids', [])),
                data.get('discovered', self._now()),
            ))
            conn.commit()

    def list_hosts(self) -> List[Dict]:
        rows = self._conn().execute("SELECT * FROM hosts ORDER BY ip")
        result = []
        for r in rows:
            d = dict(r)
            d['tags']        = self._from_json_col(d.get('tags'), [])
            d['notes']       = self._from_json_col(d.get('notes'), [])
            d['session_ids'] = self._from_json_col(d.get('session_ids'), [])
            d['service_ids'] = self._from_json_col(d.get('service_ids'), [])
            result.append(d)
        return result

    def get_host(self, ip: str) -> Optional[Dict]:
        rows = self.list_hosts()
        return next((r for r in rows if r['ip'] == ip), None)

    # ══════════════════════════════════════════════════════════════════════════
    #  V2 — FINDINGS
    # ══════════════════════════════════════════════════════════════════════════

    def add_finding(self, data: dict) -> str:
        """Insert or update a finding. Returns finding ID."""
        title  = data.get('title', '')
        host   = data.get('host', '')
        fid    = data.get('id') or __import__('hashlib').md5(
            f"{title}{host}".encode()).hexdigest()[:12]
        with self._lock:
            conn = self._conn()
            conn.execute("""
                INSERT OR REPLACE INTO findings
                    (id, title, description, severity, cvss, cvss_vector,
                     host, session_id, evidence_ids, recommendation,
                     mitre_id, source, status, created)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                fid,
                title,
                data.get('description', ''),
                data.get('severity', 'info'),
                float(data.get('cvss', 0.0)),
                data.get('cvss_vector', ''),
                host,
                int(data.get('session_id', 0)),
                self._json_col(data.get('evidence_ids', [])),
                data.get('recommendation', ''),
                data.get('mitre_id', ''),
                data.get('source', 'manual'),
                data.get('status', 'open'),
                data.get('created', self._now()),
            ))
            conn.commit()
        return fid

    def list_findings(self, severity: Optional[str] = None,
                      host: Optional[str] = None) -> List[Dict]:
        query  = "SELECT * FROM findings WHERE 1=1"
        params = []
        if severity:
            query += " AND severity=?"; params.append(severity)
        if host:
            query += " AND host LIKE ?"; params.append(f'%{host}%')
        query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        rows = self._conn().execute(query, params)
        result = []
        for r in rows:
            d = dict(r)
            d['evidence_ids'] = self._from_json_col(d.get('evidence_ids'), [])
            result.append(d)
        return result

    # ══════════════════════════════════════════════════════════════════════════
    #  V2 — OPERATIONS
    # ══════════════════════════════════════════════════════════════════════════

    def upsert_operation(self, data: dict):
        """Insert or update an operation record."""
        name = data.get('name', '')
        if not name:
            return
        oid = data.get('id') or __import__('hashlib').md5(name.encode()).hexdigest()[:10]
        with self._lock:
            conn = self._conn()
            conn.execute("""
                INSERT INTO operations
                    (id, name, client, description, operator, status,
                     scope_ips, scope_domains, objectives, tags,
                     start_date, end_date, created)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET
                    status       = excluded.status,
                    scope_ips    = excluded.scope_ips,
                    scope_domains= excluded.scope_domains,
                    objectives   = excluded.objectives,
                    tags         = excluded.tags,
                    end_date     = excluded.end_date
            """, (
                oid, name,
                data.get('client', ''),
                data.get('description', ''),
                data.get('operator', ''),
                data.get('status', 'active'),
                self._json_col(data.get('scope_ips', [])),
                self._json_col(data.get('scope_domains', [])),
                self._json_col(data.get('objectives', [])),
                self._json_col(data.get('tags', [])),
                data.get('start_date', self._now()),
                data.get('end_date', ''),
                data.get('created', self._now()),
            ))
            conn.commit()

    def list_operations(self) -> List[Dict]:
        rows = self._conn().execute("SELECT * FROM operations ORDER BY created DESC")
        result = []
        for r in rows:
            d = dict(r)
            for col in ('scope_ips', 'scope_domains', 'objectives', 'tags'):
                d[col] = self._from_json_col(d.get(col), [])
            result.append(d)
        return result

    # ══════════════════════════════════════════════════════════════════════════
    #  V2 — EVIDENCE
    # ══════════════════════════════════════════════════════════════════════════

    def add_evidence(self, data: dict):
        """Insert an evidence record."""
        eid = data.get('id', '')
        if not eid:
            return
        with self._lock:
            conn = self._conn()
            conn.execute("""
                INSERT OR IGNORE INTO evidence
                    (id, type, sha256, data_text, host, session_id,
                     operator, filename, note, ts)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                eid,
                data.get('type', 'unknown'),
                data.get('sha256', ''),
                data.get('data_preview', data.get('data_text', ''))[:2000],
                data.get('host', ''),
                int(data.get('session_id', 0)),
                data.get('operator', ''),
                data.get('filename', ''),
                data.get('note', ''),
                data.get('ts', self._now()),
            ))
            conn.commit()

    def list_evidence(self, host: Optional[str] = None,
                      session_id: Optional[int] = None,
                      ev_type: Optional[str] = None) -> List[Dict]:
        query  = "SELECT * FROM evidence WHERE 1=1"
        params = []
        if host:
            query += " AND host LIKE ?"; params.append(f'%{host}%')
        if session_id is not None:
            query += " AND session_id=?"; params.append(session_id)
        if ev_type:
            query += " AND type=?"; params.append(ev_type)
        query += " ORDER BY ts DESC"
        return self._rows_to_dicts(self._conn().execute(query, params))

    # ══════════════════════════════════════════════════════════════════════════
    #  SESSIONS
    # ══════════════════════════════════════════════════════════════════════════

    def add_session(self, host: str, port: int = 0, os: str = 'Unknown',
                    user: str = '', is_root: bool = False,
                    shell_type: str = 'dumb', tag: str = '') -> int:
        """Insert a new session row. Returns the new session ID."""
        with self._lock:
            conn = self._conn()
            cur = conn.execute(
                """INSERT INTO sessions
                   (host, port, os, user, is_root, shell_type, tag, last_seen)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (host, port, os, user, int(is_root), shell_type, tag, self._now())
            )
            conn.commit()
            return cur.lastrowid

    def update_session(self, session_id: int, **kwargs):
        """Update any column of a session row."""
        allowed = {'host', 'port', 'os', 'user', 'is_root', 'shell_type',
                   'tag', 'last_seen', 'status'}
        fields = {k: v for k, v in kwargs.items() if k in allowed}
        if not fields:
            return
        fields['last_seen'] = self._now()
        sets  = ', '.join(f"{k}=?" for k in fields)
        vals  = list(fields.values()) + [session_id]
        with self._lock:
            conn = self._conn()
            conn.execute(f"UPDATE sessions SET {sets} WHERE id=?", vals)
            conn.commit()

    def get_session(self, session_id: int) -> Optional[Dict]:
        rows = self._rows_to_dicts(
            self._conn().execute("SELECT * FROM sessions WHERE id=?", (session_id,))
        )
        return rows[0] if rows else None

    def list_sessions(self, status: Optional[str] = None) -> List[Dict]:
        conn = self._conn()
        if status:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE status=? ORDER BY id DESC", (status,)
            )
        else:
            rows = conn.execute("SELECT * FROM sessions ORDER BY id DESC")
        return self._rows_to_dicts(rows)

    def kill_session(self, session_id: int):
        self.update_session(session_id, status='dead')

    def archive_session(self, session_id: int):
        self.update_session(session_id, status='archived')

    # ══════════════════════════════════════════════════════════════════════════
    #  LOOT
    # ══════════════════════════════════════════════════════════════════════════

    def add_loot(self, category: str, data: str, source: str = '',
                 host: str = '', session_id: Optional[int] = None,
                 confidence: str = 'high') -> str:
        """
        Insert a loot item. Returns the loot ID.
        Silently ignores duplicates (same data hash).
        """
        loot_id = hashlib.md5(data.encode()).hexdigest()[:12]
        with self._lock:
            conn = self._conn()
            conn.execute(
                """INSERT OR IGNORE INTO loot
                   (id, session_id, host, category, source, data, confidence)
                   VALUES (?,?,?,?,?,?,?)""",
                (loot_id, session_id, host, category, source, data, confidence)
            )
            conn.commit()
        return loot_id

    def search_loot(self, category: Optional[str] = None,
                    host: Optional[str] = None,
                    session_id: Optional[int] = None,
                    keyword: Optional[str] = None) -> List[Dict]:
        """Flexible loot search with optional filters."""
        query  = "SELECT * FROM loot WHERE 1=1"
        params = []
        if category:
            query += " AND category=?"; params.append(category)
        if host:
            query += " AND host LIKE ?"; params.append(f'%{host}%')
        if session_id is not None:
            query += " AND session_id=?"; params.append(session_id)
        if keyword:
            query += " AND (data LIKE ? OR source LIKE ?)"; params += [f'%{keyword}%', f'%{keyword}%']
        query += " ORDER BY ts DESC"
        return self._rows_to_dicts(self._conn().execute(query, params))

    def get_loot_summary(self) -> Dict[str, int]:
        """Returns count per category."""
        rows = self._conn().execute(
            "SELECT category, COUNT(*) as cnt FROM loot GROUP BY category"
        )
        return {r['category']: r['cnt'] for r in rows}

    def delete_loot(self, loot_id: str):
        with self._lock:
            conn = self._conn()
            conn.execute("DELETE FROM loot WHERE id=?", (loot_id,))
            conn.commit()

    # ══════════════════════════════════════════════════════════════════════════
    #  COMMAND HISTORY
    # ══════════════════════════════════════════════════════════════════════════

    def add_history(self, session_id: int, command: str, output: str = '') -> int:
        with self._lock:
            conn = self._conn()
            cur = conn.execute(
                "INSERT INTO command_history (session_id, command, output) VALUES (?,?,?)",
                (session_id, command, output)
            )
            conn.commit()
            return cur.lastrowid

    def get_history(self, session_id: int, limit: int = 100) -> List[Dict]:
        rows = self._conn().execute(
            """SELECT * FROM command_history WHERE session_id=?
               ORDER BY ts DESC LIMIT ?""",
            (session_id, limit)
        )
        return self._rows_to_dicts(rows)

    def search_history(self, keyword: str, session_id: Optional[int] = None) -> List[Dict]:
        query  = "SELECT * FROM command_history WHERE command LIKE ?"
        params: list = [f'%{keyword}%']
        if session_id is not None:
            query += " AND session_id=?"; params.append(session_id)
        query += " ORDER BY ts DESC LIMIT 200"
        return self._rows_to_dicts(self._conn().execute(query, params))

    # ══════════════════════════════════════════════════════════════════════════
    #  NOTES
    # ══════════════════════════════════════════════════════════════════════════

    def add_note(self, session_id: int, text: str) -> int:
        with self._lock:
            conn = self._conn()
            cur = conn.execute(
                "INSERT INTO notes (session_id, text) VALUES (?,?)",
                (session_id, text)
            )
            conn.commit()
            return cur.lastrowid

    def get_notes(self, session_id: int) -> List[Dict]:
        rows = self._conn().execute(
            "SELECT * FROM notes WHERE session_id=? ORDER BY ts ASC",
            (session_id,)
        )
        return self._rows_to_dicts(rows)

    # ══════════════════════════════════════════════════════════════════════════
    #  LISTENERS
    # ══════════════════════════════════════════════════════════════════════════

    def add_listener(self, port: int, interface: str = '0.0.0.0',
                     tls: bool = False, transport: str = 'tcp') -> int:
        with self._lock:
            conn = self._conn()
            try:
                cur = conn.execute(
                    """INSERT INTO listeners (port, interface, tls, transport)
                       VALUES (?,?,?,?)""",
                    (port, interface, int(tls), transport)
                )
                conn.commit()
                return cur.lastrowid
            except sqlite3.IntegrityError:
                # Port already exists — update status to active
                conn.execute(
                    "UPDATE listeners SET status='active', started_at=? WHERE port=?",
                    (self._now(), port)
                )
                conn.commit()
                row = conn.execute("SELECT id FROM listeners WHERE port=?", (port,)).fetchone()
                return row['id'] if row else -1

    def stop_listener(self, port: int):
        with self._lock:
            conn = self._conn()
            conn.execute("UPDATE listeners SET status='stopped' WHERE port=?", (port,))
            conn.commit()

    def list_listeners(self) -> List[Dict]:
        rows = self._conn().execute(
            "SELECT * FROM listeners ORDER BY started_at DESC"
        )
        return self._rows_to_dicts(rows)

    # ══════════════════════════════════════════════════════════════════════════
    #  EXPORT / WIPE
    # ══════════════════════════════════════════════════════════════════════════

    def export_json(self, path: str):
        """Export all tables to a single JSON file."""
        data = {
            'sessions':        self.list_sessions(),
            'loot':            self.search_loot(),
            'command_history': self._rows_to_dicts(
                                   self._conn().execute("SELECT * FROM command_history ORDER BY ts")),
            'notes':           self._rows_to_dicts(
                                   self._conn().execute("SELECT * FROM notes ORDER BY ts")),
            'listeners':       self.list_listeners(),
            'exported_at':     self._now(),
        }
        Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')

    def export_markdown(self, path: str):
        """Export loot + sessions summary as a Markdown report."""
        lines = [
            "# NexShell — Engagement Report",
            f"> Generated: {self._now()} UTC\n",
            "---\n",
            "## Sessions\n",
            "| ID | Host | OS | User | Root | Status |",
            "|---|---|---|---|---|---|",
        ]
        for s in self.list_sessions():
            root = "✅ ROOT" if s['is_root'] else "—"
            lines.append(
                f"| {s['id']} | `{s['host']}` | {s['os']} "
                f"| {s['user']} | {root} | {s['status']} |"
            )
        lines += ["", "---\n", "## Loot\n"]
        summary = self.get_loot_summary()
        if summary:
            lines += [
                "| Category | Count |", "|---|---|",
                *[f"| {cat} | {cnt} |" for cat, cnt in sorted(summary.items())]
            ]
            lines += ["", "### Loot Details\n"]
            for item in self.search_loot():
                lines.append(
                    f"**[{item['category']}]** `{item['host']}` — {item['source']}\n"
                    f"```\n{item['data']}\n```\n"
                )
        else:
            lines.append("*No loot collected.*")
        Path(path).write_text('\n'.join(lines), encoding='utf-8')

    def wipe(self, confirm: bool = False):
        """
        Permanently delete ALL data.
        Requires confirm=True to prevent accidental wipes.
        """
        if not confirm:
            raise ValueError("Pass confirm=True to wipe the database.")
        with self._lock:
            conn = self._conn()
            for table in ('command_history', 'notes', 'loot', 'sessions', 'listeners'):
                conn.execute(f"DELETE FROM {table}")
            conn.commit()
            conn.execute("VACUUM")
            conn.commit()

    def stats(self) -> Dict[str, Any]:
        """Quick stats for the banner/status line."""
        conn = self._conn()
        return {
            'sessions_active': conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE status='active'").fetchone()[0],
            'sessions_total':  conn.execute(
                "SELECT COUNT(*) FROM sessions").fetchone()[0],
            'loot_total':      conn.execute(
                "SELECT COUNT(*) FROM loot").fetchone()[0],
            'loot_creds':      conn.execute(
                "SELECT COUNT(*) FROM loot WHERE category='credentials'").fetchone()[0],
            'listeners_active': conn.execute(
                "SELECT COUNT(*) FROM listeners WHERE status='active'").fetchone()[0],
        }

    def close(self):
        conn = getattr(self._local, 'conn', None)
        if conn:
            conn.close()
            self._local.conn = None


# ══════════════════════════════════════════════════════════════════════════════
#  SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

_db_instance: Optional[NexDB] = None
_db_lock = threading.Lock()


def get_db(db_path: Optional[str] = None) -> NexDB:
    """Return the global NexDB singleton (thread-safe)."""
    global _db_instance
    with _db_lock:
        if _db_instance is None:
            _db_instance = NexDB(db_path)
    return _db_instance


def init_db(db_path: Optional[str] = None) -> NexDB:
    """(Re-)initialize the singleton with a specific path."""
    global _db_instance
    with _db_lock:
        if _db_instance:
            _db_instance.close()
        _db_instance = NexDB(db_path)
    return _db_instance
