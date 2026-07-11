#!/usr/bin/env python3
"""
NexShell Plugin — Command Queue v2.0 (2026 Edition)
Offline command queuing with SQLite persistence, priority execution,
retry logic, and auto-execution on session reconnect.

Features:
  - SQLite-backed queue (survives restarts)
  - Priority-based execution (1 = highest)
  - Per-session queues
  - Retry logic with max_retries
  - Command output capture and storage
  - Auto-execute on session connect
  - Dry-run mode (preview without execution)

MITRE ATT&CK:
  - T1651 (Cloud Administration Command)
  - T1059 (Command and Scripting Interpreter)

Usage:
    (NexShell)> plugins run command-queue --add "whoami" --session 1
    (NexShell)> plugins run command-queue --add "id" --session 1 --priority 1
    (NexShell)> plugins run command-queue --run --session 1
    (NexShell)> plugins run command-queue --list
    (NexShell)> plugins run command-queue --list --session 1
    (NexShell)> plugins run command-queue --clear --session 1
    (NexShell)> plugins run command-queue --dry-run --session 1
"""

import os
import time
import json
import sqlite3
import threading
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from datetime import datetime
from core.plugin import NexPlugin

# ── DB path inside project ───────────────────────────────────────────────────
_PLUGIN_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_PLUGIN_DIR)
_DB_PATH     = os.path.join(PROJECT_ROOT, "db", "command_queue.sqlite3")
os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class QueuedCommand:
    """A command waiting in the queue."""
    id: int
    session_id: int
    command: str
    priority: int = 5          # 1 = highest, 10 = lowest
    status: str = "pending"    # pending | running | done | failed
    retries: int = 0
    max_retries: int = 3
    output: str = ""
    error: str = ""
    added_at: str = ""
    executed_at: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


# ── SQLite Backend ───────────────────────────────────────────────────────────

class CommandQueueDB:
    """SQLite-backed command queue store."""

    _lock = threading.Lock()

    def __init__(self, db_path: str = _DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create tables if not exist."""
        with self._lock, self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS command_queue (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  INTEGER NOT NULL,
                    command     TEXT NOT NULL,
                    priority    INTEGER DEFAULT 5,
                    status      TEXT DEFAULT 'pending',
                    retries     INTEGER DEFAULT 0,
                    max_retries INTEGER DEFAULT 3,
                    output      TEXT DEFAULT '',
                    error       TEXT DEFAULT '',
                    added_at    TEXT,
                    executed_at TEXT DEFAULT '',
                    duration_ms INTEGER DEFAULT 0
                )
            """)
            conn.commit()

    def add(self, session_id: int, command: str,
            priority: int = 5, max_retries: int = 3) -> int:
        """Add command to queue. Returns new row id."""
        ts = datetime.utcnow().isoformat()
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO command_queue
                   (session_id, command, priority, max_retries, added_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (session_id, command, priority, max_retries, ts)
            )
            conn.commit()
            return cur.lastrowid

    def get_pending(self, session_id: int) -> List[QueuedCommand]:
        """Get all pending commands for session, ordered by priority."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM command_queue
                   WHERE session_id = ? AND status = 'pending'
                   ORDER BY priority ASC, id ASC""",
                (session_id,)
            ).fetchall()
        return [self._row_to_cmd(r) for r in rows]

    def get_all(self, session_id: Optional[int] = None) -> List[QueuedCommand]:
        """Get all commands, optionally filtered by session."""
        with self._lock, self._conn() as conn:
            if session_id is not None:
                rows = conn.execute(
                    "SELECT * FROM command_queue WHERE session_id = ? ORDER BY id DESC",
                    (session_id,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM command_queue ORDER BY id DESC LIMIT 100"
                ).fetchall()
        return [self._row_to_cmd(r) for r in rows]

    def update_status(self, cmd_id: int, status: str,
                      output: str = "", error: str = "",
                      duration_ms: int = 0):
        """Update command status and output."""
        ts = datetime.utcnow().isoformat() if status in ("done", "failed") else ""
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE command_queue
                   SET status=?, output=?, error=?, executed_at=?, duration_ms=?
                   WHERE id=?""",
                (status, output[:2000], error[:500], ts, duration_ms, cmd_id)
            )
            conn.commit()

    def increment_retry(self, cmd_id: int):
        """Increment retry counter."""
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE command_queue SET retries = retries + 1 WHERE id = ?",
                (cmd_id,)
            )
            conn.commit()

    def clear(self, session_id: Optional[int] = None, status: str = "all"):
        """Clear commands from queue."""
        with self._lock, self._conn() as conn:
            if session_id is not None and status == "all":
                conn.execute(
                    "DELETE FROM command_queue WHERE session_id = ?", (session_id,)
                )
            elif session_id is not None:
                conn.execute(
                    "DELETE FROM command_queue WHERE session_id = ? AND status = ?",
                    (session_id, status)
                )
            else:
                conn.execute("DELETE FROM command_queue")
            conn.commit()

    @staticmethod
    def _row_to_cmd(row) -> QueuedCommand:
        return QueuedCommand(
            id=row["id"],
            session_id=row["session_id"],
            command=row["command"],
            priority=row["priority"],
            status=row["status"],
            retries=row["retries"],
            max_retries=row["max_retries"],
            output=row["output"],
            error=row["error"],
            added_at=row["added_at"],
            executed_at=row["executed_at"],
            duration_ms=row["duration_ms"],
        )


# ── Queue Executor ───────────────────────────────────────────────────────────

class QueueExecutor:
    """Executes queued commands on a session."""

    @staticmethod
    def execute_queue(exec_fn, session, session_id: int,
                      db: CommandQueueDB,
                      dry_run: bool = False,
                      delay_between: float = 0.5) -> List[Dict]:
        """Execute all pending commands for a session. Returns results."""
        pending = db.get_pending(session_id)
        results = []

        for cmd in pending:
            if dry_run:
                results.append({
                    "id": cmd.id,
                    "command": cmd.command,
                    "priority": cmd.priority,
                    "dry_run": True,
                })
                continue

            # Mark as running
            db.update_status(cmd.id, "running")

            start = time.time()
            success = False
            output = ""
            error = ""

            for attempt in range(cmd.max_retries):
                try:
                    out = exec_fn(session, cmd.command) or ""
                    output = out
                    success = True
                    break
                except Exception as e:
                    error = str(e)
                    db.increment_retry(cmd.id)
                    if attempt < cmd.max_retries - 1:
                        time.sleep(2 ** attempt)   # exponential backoff

            duration_ms = int((time.time() - start) * 1000)
            status = "done" if success else "failed"
            db.update_status(cmd.id, status, output, error, duration_ms)

            results.append({
                "id":          cmd.id,
                "command":     cmd.command,
                "priority":    cmd.priority,
                "success":     success,
                "output":      output[:200],
                "duration_ms": duration_ms,
            })

            time.sleep(delay_between)

        return results


# ── Main Plugin ──────────────────────────────────────────────────────────────

class CommandQueue(NexPlugin):
    name        = "command-queue"
    description = "Offline command queue — SQLite persistence, priority, retry, auto-execute on reconnect"
    author      = "vulnquest58"
    version     = "2.0"
    platform    = "all"
    category    = "persist"
    mitre_id    = "T1651"

    # Shared DB instance across all plugin calls
    _db = CommandQueueDB()

    def run(self, session, args: list):
        # ── Parse args ───────────────────────────────────────────────────
        add_cmd      = None
        run_mode     = False
        list_mode    = False
        clear_mode   = False
        dry_run      = False
        session_id   = getattr(session, "id", 1) or 1
        priority     = 5
        max_retries  = 3
        delay        = 0.5
        clear_status = "all"

        i = 0
        arg_list = list(args or [])
        while i < len(arg_list):
            a = arg_list[i]
            if a.startswith("--add="):
                add_cmd = a.split("=", 1)[1]
            elif a == "--add" and i + 1 < len(arg_list):
                i += 1; add_cmd = arg_list[i]
            elif a.startswith("--session="):
                try: session_id = int(a.split("=", 1)[1])
                except: pass
            elif a.startswith("--priority="):
                try: priority = int(a.split("=", 1)[1])
                except: pass
            elif a.startswith("--retries="):
                try: max_retries = int(a.split("=", 1)[1])
                except: pass
            elif a.startswith("--delay="):
                try: delay = float(a.split("=", 1)[1])
                except: pass
            elif a.startswith("--clear-status="):
                clear_status = a.split("=", 1)[1]
            elif a == "--run":
                run_mode = True
            elif a == "--list":
                list_mode = True
            elif a == "--clear":
                clear_mode = True
            elif a == "--dry-run":
                dry_run = True
                run_mode = True
            i += 1

        self.info("Command Queue v2.0 started")
        sections = []
        sections.append("\n" + "━" * 64)
        sections.append("  [📋 Command Queue v2.0]")
        sections.append("━" * 64)
        sections.append(f"  DB Path    : {_DB_PATH}")
        sections.append(f"  Session ID : {session_id}")

        db = self._db

        # ── Add command ────────────────────────────────────────────────────
        if add_cmd:
            cmd_id = db.add(session_id, add_cmd, priority=priority, max_retries=max_retries)
            sections.append(f"\n  ✅ Command added to queue")
            sections.append(f"     ID       : #{cmd_id}")
            sections.append(f"     Command  : {add_cmd[:80]}")
            sections.append(f"     Priority : {priority}")
            sections.append(f"     Retries  : {max_retries}")
            sections.append(f"\n  Run queue: plugins run command-queue --run --session {session_id}")

        # ── Clear queue ────────────────────────────────────────────────────
        if clear_mode:
            db.clear(session_id=session_id, status=clear_status)
            sections.append(f"\n  🗑  Queue cleared for session {session_id}")

        # ── List mode ──────────────────────────────────────────────────────
        if list_mode:
            all_cmds = db.get_all(session_id=session_id if session_id else None)

            sections.append(f"\n[*] Command Queue (session={session_id or 'all'}):")
            sections.append("─" * 64)

            if not all_cmds:
                sections.append("  Queue is empty.")
            else:
                status_icons = {
                    "pending": "⏳",
                    "running": "🔄",
                    "done":    "✅",
                    "failed":  "❌",
                }
                for cmd in all_cmds[:30]:
                    icon = status_icons.get(cmd.status, "❓")
                    sections.append(
                        f"  {icon} #{cmd.id:<4d} [P{cmd.priority}] "
                        f"[sess={cmd.session_id}] {cmd.command[:60]}"
                    )
                    if cmd.status == "done" and cmd.output:
                        sections.append(f"         Output: {cmd.output[:60]}")
                    elif cmd.status == "failed" and cmd.error:
                        sections.append(f"         Error : {cmd.error[:60]}")
                if len(all_cmds) > 30:
                    sections.append(f"  ... {len(all_cmds) - 30} more entries")

        # ── Execute queue ──────────────────────────────────────────────────
        if run_mode:
            pending = db.get_pending(session_id)

            sections.append(f"\n[*] {'DRY RUN — ' if dry_run else ''}Executing Queue (session={session_id}):")
            sections.append("─" * 64)
            sections.append(f"  Pending commands : {len(pending)}")
            sections.append(f"  Delay between    : {delay}s")

            if not pending:
                sections.append("  ✅ Queue is empty — nothing to execute.")
            else:
                results = QueueExecutor.execute_queue(
                    self._exec, session, session_id, db,
                    dry_run=dry_run, delay_between=delay,
                )

                success_count = sum(1 for r in results if r.get("success", False))
                fail_count = len(results) - success_count

                if dry_run:
                    sections.append(f"\n  [DRY RUN] Would execute {len(results)} command(s):")
                    for r in results:
                        sections.append(f"    [P{r['priority']}] {r['command'][:70]}")
                else:
                    sections.append(f"\n  Results: ✅ {success_count} / ❌ {fail_count}")
                    for r in results:
                        icon = "✅" if r.get("success") else "❌"
                        sections.append(
                            f"  {icon} #{r['id']:<4d} {r['command'][:50]:<50} "
                            f"({r.get('duration_ms', 0)}ms)"
                        )
                        if r.get("output"):
                            sections.append(f"         → {r['output'][:80]}")

                    if success_count > 0:
                        self.loot(
                            f"Command queue executed: {success_count}/{len(results)} on session {session_id}",
                            category="ops",
                            source=self.name,
                        )
                        self.emit(
                            "timeline.event",
                            title=f"Command Queue: {success_count} commands executed",
                            type="ops",
                            plugin=self.name,
                        )

        if not any([add_cmd, run_mode, list_mode, clear_mode]):
            sections.append("\n  Usage:")
            sections.append("    > plugins run command-queue --add \"whoami\" --session 1")
            sections.append("    > plugins run command-queue --add \"id\" --priority 1")
            sections.append("    > plugins run command-queue --list")
            sections.append("    > plugins run command-queue --run --session 1")
            sections.append("    > plugins run command-queue --dry-run --session 1")
            sections.append("    > plugins run command-queue --clear --session 1")

        # ── Summary ───────────────────────────────────────────────────────
        all_cmds = db.get_all(session_id=session_id)
        pending_n = sum(1 for c in all_cmds if c.status == "pending")
        done_n    = sum(1 for c in all_cmds if c.status == "done")
        fail_n    = sum(1 for c in all_cmds if c.status == "failed")

        sections.append("\n" + "━" * 64)
        sections.append("  [📊 Queue Summary]")
        sections.append("━" * 64)
        sections.append(f"  Session {session_id}: ⏳ {pending_n} pending | ✅ {done_n} done | ❌ {fail_n} failed")

        self.info("Command Queue complete")
        return "\n".join(sections)
