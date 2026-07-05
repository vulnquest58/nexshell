#!/usr/bin/env python3
"""
NexShell — Evidence Framework  (evidence/collector.py)
Chain-of-custody evidence collection: SHA256 + timestamp + operator + host.

CLI:
    evidence add command "cat /etc/passwd" --output "<output>"
    evidence add file /path/to/file.txt
    evidence list
    evidence export /path/to/evidence_bundle.zip
"""

import os
import io
import json
import hashlib
import zipfile
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from db import get_db
    _DB_AVAILABLE = True
except ImportError:
    get_db = None
    _DB_AVAILABLE = False

from models import Evidence

EVIDENCE_DIR = Path.home() / '.nexshell' / 'evidence'


# ══════════════════════════════════════════════════════════════════════════════
#  EVIDENCE COLLECTOR
# ══════════════════════════════════════════════════════════════════════════════

class EvidenceCollector:
    """
    Collects, hashes, and stores evidence with full chain of custody.
    Every piece of evidence has: SHA256 + timestamp + operator + host + session.
    """

    def __init__(self):
        self._items: Dict[str, Evidence] = {}   # id → Evidence
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        self._load_from_db()

    # ── Collection methods ────────────────────────────────────────────────────

    def add_command(self, command: str, output: str,
                    host: str = "", session_id: int = 0,
                    operator: str = "", note: str = "") -> Evidence:
        """Capture a command + its output as evidence."""
        data_text = f"Command: {command}\n{'─'*60}\n{output}"
        e = Evidence(
            type='command',
            data_text=data_text,
            host=host,
            session_id=session_id,
            operator=operator,
            filename=f"cmd_{datetime.datetime.utcnow():%Y%m%d_%H%M%S}.txt",
            note=note or command[:80],
        )
        return self._store(e)

    def add_file(self, path: str,
                 host: str = "", session_id: int = 0,
                 operator: str = "", note: str = "") -> Evidence:
        """Capture a local file as evidence."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {path}")
        data = p.read_bytes()
        e = Evidence(
            type='file',
            data=data,
            data_text=data.decode('utf-8', errors='replace')[:500],
            host=host,
            session_id=session_id,
            operator=operator,
            filename=p.name,
            note=note or str(p),
        )
        return self._store(e)

    def add_text(self, text: str, ev_type: str = "note",
                 host: str = "", session_id: int = 0,
                 operator: str = "", note: str = "") -> Evidence:
        """Capture any text snippet as evidence."""
        e = Evidence(
            type=ev_type,
            data_text=text,
            host=host,
            session_id=session_id,
            operator=operator,
            filename=f"{ev_type}_{datetime.datetime.utcnow():%Y%m%d_%H%M%S}.txt",
            note=note,
        )
        return self._store(e)

    def add_hash(self, hash_value: str, hash_type: str = "SHA256",
                 filename: str = "", host: str = "",
                 session_id: int = 0, operator: str = "") -> Evidence:
        """Record a file hash as evidence."""
        data_text = f"{hash_type}: {hash_value}\nFile: {filename}"
        e = Evidence(
            type='hash',
            data_text=data_text,
            host=host,
            session_id=session_id,
            operator=operator,
            filename=filename or f"hash_{hash_value[:8]}.txt",
            note=f"{hash_type} of {filename}",
        )
        return self._store(e)

    # ── Storage ───────────────────────────────────────────────────────────────

    def _store(self, e: Evidence) -> Evidence:
        self._items[e.id] = e
        # Save to disk
        ev_path = EVIDENCE_DIR / e.filename
        content = e.data or e.data_text.encode('utf-8', errors='replace')
        ev_path.write_bytes(content if isinstance(content, bytes) else content.encode())
        # Save metadata JSON
        meta_path = EVIDENCE_DIR / f"{e.id}_meta.json"
        meta_path.write_text(json.dumps(e.to_dict(), indent=2), encoding='utf-8')
        # Persist to DB
        self._persist(e)
        # Emit event
        try:
            from core.event_bus import bus, Events
            bus.emit(Events.EVIDENCE_ADDED,
                     ev_type=e.type, host=e.host, sha256=e.sha256[:16])
        except Exception:
            pass
        return e

    def _persist(self, e: Evidence):
        if not (_DB_AVAILABLE and get_db):
            return
        try:
            db = get_db()
            if hasattr(db, 'add_evidence'):
                db.add_evidence(e.to_dict())
        except Exception:
            pass

    def _load_from_db(self):
        if not (_DB_AVAILABLE and get_db):
            return
        try:
            db = get_db()
            if hasattr(db, 'list_evidence'):
                for row in db.list_evidence():
                    e = Evidence(type=row.get('type', 'unknown'))
                    for k, v in row.items():
                        if hasattr(e, k):
                            setattr(e, k, v)
                    self._items[e.id] = e
        except Exception:
            pass

    # ── Export ────────────────────────────────────────────────────────────────

    def export_bundle(self, output_path: str) -> str:
        """
        Export all evidence as a ZIP bundle with manifest.
        Each file is named by its SHA256 for integrity verification.
        """
        manifest = {
            'exported': datetime.datetime.utcnow().isoformat(),
            'count':    len(self._items),
            'items':    [e.to_dict() for e in self._items.values()],
        }
        out = Path(output_path)
        with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add manifest
            zf.writestr('MANIFEST.json', json.dumps(manifest, indent=2))
            # Add each evidence file
            for e in self._items.values():
                content = e.data or e.data_text.encode('utf-8', errors='replace')
                if isinstance(content, str):
                    content = content.encode('utf-8', errors='replace')
                fname = f"{e.type}/{e.sha256[:16]}_{e.filename}"
                zf.writestr(fname, content)
                # Add per-item meta
                zf.writestr(f"meta/{e.sha256[:16]}.json",
                             json.dumps(e.to_dict(), indent=2))
        return str(out)

    # ── Display ───────────────────────────────────────────────────────────────

    def list_all(self) -> str:
        if not self._items:
            return "  No evidence collected."
        lines = [
            f"\n  {'ID':<16} {'Type':<12} {'Host':<16} {'SHA256':<20} {'Note'}",
            f"  {'─'*16} {'─'*12} {'─'*16} {'─'*20} {'─'*30}",
        ]
        for e in sorted(self._items.values(), key=lambda x: x.ts):
            lines.append(
                f"  {e.id:<16} {e.type:<12} {(e.host or '—'):<16} "
                f"{e.sha256[:18]:<20} {(e.note or e.filename)[:30]}"
            )
        lines.append(f"\n  Total: {len(self._items)} items\n")
        return '\n'.join(lines)

    def get(self, ev_id: str) -> Optional[Evidence]:
        return self._items.get(ev_id)


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

collector = EvidenceCollector()
