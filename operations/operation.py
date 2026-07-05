#!/usr/bin/env python3
"""
NexShell — Operations Center  (operations/operation.py)
Manages pentest engagement workspaces: create, open, archive, objectives, scope.

CLI:
    operation new ACME_Internal
    operation open ACME_Internal
    operation archive
    operation status
    operation scope add 192.168.1.0/24
    operation objective add "Gain Domain Admin access"
"""

import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# DB integration
try:
    from db import get_db
    _DB_AVAILABLE = True
except ImportError:
    get_db = None
    _DB_AVAILABLE = False

from models import Operation


# ══════════════════════════════════════════════════════════════════════════════
#  OPERATION STORE  — file-based + DB-backed
# ══════════════════════════════════════════════════════════════════════════════

OPS_DIR = Path.home() / '.nexshell' / 'operations'


class OperationStore:
    """
    Manages all operations on disk and in DB.
    Each operation is stored as a JSON file + DB row.
    """

    def __init__(self, ops_dir: Optional[Path] = None):
        self._dir = ops_dir or OPS_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._active: Optional[Operation] = None
        self._load_active_from_marker()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _path(self, name: str) -> Path:
        safe = name.replace(' ', '_').replace('/', '_')
        return self._dir / f"{safe}.json"

    def _marker_path(self) -> Path:
        return self._dir / '.active_operation'

    def _save(self, op: Operation):
        self._path(op.name).write_text(
            json.dumps(op.to_dict(), indent=2), encoding='utf-8'
        )
        if _DB_AVAILABLE and get_db:
            try:
                db = get_db()
                if hasattr(db, 'upsert_operation'):
                    db.upsert_operation(op.to_dict())
            except Exception:
                pass

    def _load_active_from_marker(self):
        marker = self._marker_path()
        if marker.exists():
            name = marker.read_text().strip()
            if name:
                op = self.load(name)
                if op and op.status == 'active':
                    self._active = op

    def _write_marker(self, name: str):
        self._marker_path().write_text(name, encoding='utf-8')

    def _clear_marker(self):
        m = self._marker_path()
        if m.exists():
            m.unlink()

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def new(self, name: str, client: str = "", description: str = "",
            operator: str = "") -> Operation:
        """Create a new operation."""
        if self._path(name).exists():
            raise ValueError(f"Operation '{name}' already exists.")
        op = Operation(
            name=name, client=client,
            description=description, operator=operator,
        )
        self._save(op)
        return op

    def open(self, name: str) -> Operation:
        """Set an operation as active."""
        op = self.load(name)
        if not op:
            raise FileNotFoundError(f"Operation '{name}' not found.")
        op.status  = 'active'
        self._active = op
        self._save(op)
        self._write_marker(name)
        # Emit event
        try:
            from core.event_bus import bus, Events
            bus.emit(Events.OPERATION_OPENED, operation=name)
        except Exception:
            pass
        return op

    def load(self, name: str) -> Optional[Operation]:
        p = self._path(name)
        if not p.exists():
            return None
        data = json.loads(p.read_text())
        op   = Operation(name=data['name'])
        for k, v in data.items():
            if hasattr(op, k):
                setattr(op, k, v)
        return op

    def archive(self, name: Optional[str] = None) -> bool:
        """Archive an operation."""
        op_name = name or (self._active.name if self._active else None)
        if not op_name:
            return False
        op = self.load(op_name)
        if not op:
            return False
        op.status   = 'archived'
        op.end_date = datetime.datetime.utcnow().isoformat()
        self._save(op)
        if self._active and self._active.name == op_name:
            self._active = None
            self._clear_marker()
        try:
            from core.event_bus import bus, Events
            bus.emit(Events.OPERATION_ARCHIVED, operation=op_name)
        except Exception:
            pass
        return True

    def list_all(self) -> List[Dict[str, Any]]:
        """List all saved operations."""
        ops = []
        for p in sorted(self._dir.glob('*.json')):
            try:
                data = json.loads(p.read_text())
                ops.append(data)
            except Exception:
                pass
        return ops

    # ── Active operation helpers ───────────────────────────────────────────────

    @property
    def active(self) -> Optional[Operation]:
        return self._active

    def require_active(self) -> Operation:
        if not self._active:
            raise RuntimeError("No active operation. Run: operation new <name>")
        return self._active

    def add_objective(self, text: str):
        op = self.require_active()
        if text not in op.objectives:
            op.objectives.append(text)
            self._save(op)

    def add_scope_ip(self, ip_or_cidr: str):
        op = self.require_active()
        if ip_or_cidr not in op.scope_ips:
            op.scope_ips.append(ip_or_cidr)
            self._save(op)

    def add_scope_domain(self, domain: str):
        op = self.require_active()
        if domain not in op.scope_domains:
            op.scope_domains.append(domain)
            self._save(op)

    def is_in_scope(self, target: str) -> Optional[bool]:
        """Check if a target IP/domain is in scope. None = no scope defined."""
        op = self._active
        if not op:
            return None
        if not op.scope_ips and not op.scope_domains:
            return None  # no scope defined — assume all OK
        # Simple check (extend with CIDR parsing if needed)
        in_ip     = any(target.startswith(s.split('/')[0][:6]) for s in op.scope_ips)
        in_domain = any(target.endswith(d) for d in op.scope_domains)
        return in_ip or in_domain

    def status_summary(self) -> str:
        """Pretty status for CLI."""
        op = self._active
        if not op:
            return "  No active operation. Use: operation new <name>"
        lines = [
            f"  Operation : {op.name}",
            f"  Client    : {op.client or '—'}",
            f"  Status    : {op.status}",
            f"  Operator  : {op.operator or '—'}",
            f"  Started   : {op.start_date[:10]}",
        ]
        if op.objectives:
            lines.append(f"  Objectives ({len(op.objectives)}):")
            for obj in op.objectives:
                lines.append(f"    ○ {obj}")
        if op.scope_ips:
            lines.append(f"  Scope IPs : {', '.join(op.scope_ips)}")
        if op.scope_domains:
            lines.append(f"  Scope DOM : {', '.join(op.scope_domains)}")
        return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

ops = OperationStore()
