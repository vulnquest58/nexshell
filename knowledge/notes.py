#!/usr/bin/env python3
"""
NexShell — Notes System  (knowledge/notes.py)
Persistent notes linked to sessions, hosts, findings, or operations.
Supports search, tags, and Markdown export.

CLI:
    note add [text]               — Add note to active session
    note add --host 10.0.0.1     — Add note to a host
    note list                    — List all notes
    note search <keyword>        — Search notes
    note export notes.md         — Export to Markdown
"""

import datetime
import json
import uuid
from pathlib import Path
from typing import List, Optional


NOTES_FILE = Path.home() / '.nexshell' / 'notes.json'


class Note:
    def __init__(self, text: str, context: str = "general",
                 session_id: int = 0, host: str = "", operation: str = "",
                 tags: List[str] = None):
        self.id        = str(uuid.uuid4())[:8]
        self.text      = text.strip()
        self.context   = context   # general | session | host | finding | operation
        self.session_id= session_id
        self.host      = host
        self.operation = operation
        self.tags      = tags or []
        self.ts        = datetime.datetime.utcnow().isoformat()
        self.pinned    = False

    def matches(self, keyword: str) -> bool:
        kw = keyword.lower()
        return (kw in self.text.lower() or
                kw in self.host.lower() or
                any(kw in t.lower() for t in self.tags))

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'text': self.text, 'context': self.context,
            'session_id': self.session_id, 'host': self.host,
            'operation': self.operation, 'tags': self.tags,
            'ts': self.ts, 'pinned': self.pinned,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'Note':
        n = cls.__new__(cls)
        n.id         = d.get('id', '')
        n.text       = d.get('text', '')
        n.context    = d.get('context', 'general')
        n.session_id = d.get('session_id', 0)
        n.host       = d.get('host', '')
        n.operation  = d.get('operation', '')
        n.tags       = d.get('tags', [])
        n.ts         = d.get('ts', '')
        n.pinned     = d.get('pinned', False)
        return n

    def render(self) -> str:
        ts   = self.ts[:16].replace('T', ' ')
        pin  = " 📌" if self.pinned else ""
        tags = f" [{', '.join(self.tags)}]" if self.tags else ""
        ctx  = ""
        if self.host:       ctx = f" — {self.host}"
        elif self.session_id: ctx = f" — Session [{self.session_id}]"
        return f"  [{ts}]{pin}{tags}{ctx}\n  {self.text}"


class NotesManager:
    """Persistent notes system with tagging and search."""

    def __init__(self):
        self._notes: List[Note] = []
        self._load()

    def _load(self):
        try:
            if NOTES_FILE.exists():
                data = json.loads(NOTES_FILE.read_text())
                self._notes = [Note.from_dict(d) for d in data.get('notes', [])]
        except Exception:
            pass

    def _save(self):
        try:
            NOTES_FILE.parent.mkdir(parents=True, exist_ok=True)
            NOTES_FILE.write_text(
                json.dumps({'notes': [n.to_dict() for n in self._notes]}, indent=2),
                encoding='utf-8',
            )
        except Exception:
            pass

    def add(self, text: str, context: str = "general", session_id: int = 0,
            host: str = "", operation: str = "",
            tags: List[str] = None) -> Note:
        """Add a new note."""
        # Auto-detect operation name
        if not operation:
            try:
                from operations import ops
                if ops.active:
                    operation = ops.active.name
            except Exception:
                pass
        note = Note(text=text, context=context, session_id=session_id,
                    host=host, operation=operation, tags=tags or [])
        self._notes.append(note)
        self._save()
        return note

    def add_to_session(self, text: str, session_id: int,
                       tags: List[str] = None) -> Note:
        return self.add(text, context='session', session_id=session_id,
                        tags=tags)

    def add_to_host(self, text: str, host: str,
                    tags: List[str] = None) -> Note:
        return self.add(text, context='host', host=host, tags=tags)

    def pin(self, note_id: str) -> bool:
        for n in self._notes:
            if n.id == note_id:
                n.pinned = not n.pinned
                self._save()
                return True
        return False

    def get(self, note_id: str) -> Optional['Note']:
        """Retrieve a single note by ID (or None if not found)."""
        for n in self._notes:
            if n.id == note_id:
                return n
        return None

    def count(self) -> int:
        return len(self._notes)

    def delete(self, note_id: str) -> bool:
        before = len(self._notes)
        self._notes = [n for n in self._notes if n.id != note_id]
        if len(self._notes) < before:
            self._save()
            return True
        return False

    def search(self, keyword: str) -> List[Note]:
        return [n for n in self._notes if n.matches(keyword)]

    def by_session(self, session_id: int) -> List[Note]:
        return [n for n in self._notes if n.session_id == session_id]

    def by_host(self, host: str) -> List[Note]:
        return [n for n in self._notes if n.host == host]

    def by_tag(self, tag: str) -> List[Note]:
        tag = tag.lower()
        return [n for n in self._notes if any(tag == t.lower() for t in n.tags)]

    def pinned(self) -> List[Note]:
        return [n for n in self._notes if n.pinned]

    def recent(self, limit: int = 10) -> List[Note]:
        return sorted(self._notes, key=lambda n: n.ts, reverse=True)[:limit]

    def list_all(self, context: Optional[str] = None) -> List[Note]:
        if context:
            return [n for n in self._notes if n.context == context]
        return sorted(self._notes, key=lambda n: (not n.pinned, n.ts), reverse=True)

    def render(self, notes: Optional[List[Note]] = None, limit: int = 20) -> str:
        ns = notes if notes is not None else self.list_all()
        if not ns:
            return "\n  No notes found.\n"
        lines = [f"\n  Notes ({len(ns)} total):"]
        # Pinned first
        pinned = [n for n in ns if n.pinned]
        rest   = [n for n in ns if not n.pinned]
        for n in pinned[:5]:
            lines.append("")
            lines.append(n.render())
        for n in rest[:limit]:
            lines.append("")
            lines.append(n.render())
        lines.append("")
        return '\n'.join(lines)

    def export_markdown(self, path: str = None) -> str:
        lines = ["# Notes", ""]
        by_ctx: dict = {}
        for n in self.list_all():
            by_ctx.setdefault(n.context, []).append(n)
        for ctx, notes in by_ctx.items():
            lines.append(f"## {ctx.title()}")
            lines.append("")
            for n in notes:
                ts   = n.ts[:16].replace('T', ' ')
                pin  = " 📌" if n.pinned else ""
                tags = f" `{', '.join(n.tags)}`" if n.tags else ""
                lines.append(f"### [{ts}]{pin}{tags}")
                if n.host:
                    lines.append(f"*Host: {n.host}*")
                lines.append("")
                lines.append(n.text)
                lines.append("")
        result = '\n'.join(lines)
        if path:
            Path(path).write_text(result, encoding='utf-8')
        return result


# Global singleton
notes = NotesManager()
