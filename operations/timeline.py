#!/usr/bin/env python3
"""
NexShell — Engagement Timeline  (operations/timeline.py)
Tracks key events during an engagement with timestamps.
Produces ASCII timeline visualization.

Usage:
    from operations.timeline import Timeline
    tl = Timeline()
    tl.add("Initial access", "session established on 10.0.0.1", type="compromise")
    tl.add("Lateral movement", "pivoted to 10.0.0.5 via SMB", type="lateral")
    print(tl.render())
"""

import datetime
import json
from pathlib import Path
from typing import List, Optional


EVENT_TYPES = {
    'info':       ('ℹ️ ', '─'),
    'recon':      ('🔎', '─'),
    'access':     ('🔓', '═'),
    'compromise': ('💀', '═'),
    'lateral':    ('➡️ ', '─'),
    'escalation': ('⬆️ ', '═'),
    'persistence':('🔒', '─'),
    'exfil':      ('📤', '─'),
    'evidence':   ('🗂️ ', '─'),
    'finding':    ('🎯', '─'),
    'milestone':  ('⭐', '═'),
}


class TimelineEvent:
    def __init__(self, title: str, detail: str = "", ev_type: str = "info",
                 operator: str = "", session_id: int = 0):
        self.ts         = datetime.datetime.utcnow().isoformat()
        self.title      = title
        self.detail     = detail
        self.type       = ev_type if ev_type in EVENT_TYPES else 'info'
        self.operator   = operator
        self.session_id = session_id

    def to_dict(self) -> dict:
        return {
            'ts': self.ts, 'title': self.title, 'detail': self.detail,
            'type': self.type, 'operator': self.operator,
            'session_id': self.session_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'TimelineEvent':
        ev = cls.__new__(cls)
        ev.ts         = d.get('ts', '')
        ev.title      = d.get('title', '')
        ev.detail     = d.get('detail', '')
        ev.type       = d.get('type', 'info')
        ev.operator   = d.get('operator', '')
        ev.session_id = d.get('session_id', 0)
        return ev


class Timeline:
    """Engagement timeline — ordered list of timestamped events."""

    def __init__(self, operator: str = ""):
        self._events: List[TimelineEvent] = []
        self._operator = operator

    def add(self, title: str, detail: str = "", ev_type: str = "info",
            session_id: int = 0) -> TimelineEvent:
        ev = TimelineEvent(
            title=title, detail=detail, ev_type=ev_type,
            operator=self._operator, session_id=session_id,
        )
        self._events.append(ev)
        # Emit event
        try:
            from core.event_bus import bus
            bus.emit('timeline.event', title=title, type=ev_type)
        except Exception:
            pass
        return ev

    def list_all(self) -> List[dict]:
        return [e.to_dict() for e in self._events]

    def render(self, limit: int = 30) -> str:
        """Render an ASCII timeline."""
        if not self._events:
            return "\n  (no timeline events)\n"

        events = self._events[-limit:]
        lines  = ["\n  ╔══════════════════════════════════════════════════════╗",
                    "  ║              Engagement Timeline                    ║",
                    "  ╚══════════════════════════════════════════════════════╝", ""]

        for i, ev in enumerate(events):
            icon, bar = EVENT_TYPES.get(ev.type, ('· ', '─'))
            ts_short  = ev.ts[5:16].replace('T', ' ')
            is_last   = (i == len(events) - 1)
            connector = '└' if is_last else '├'

            lines.append(f"  {connector}{bar*2} {icon} [{ts_short}] {ev.title}")
            if ev.detail:
                pad = '    ' if is_last else '  │  '
                lines.append(f"  {pad}   {ev.detail[:70]}")
            if ev.session_id:
                pad = '    ' if is_last else '  │  '
                lines.append(f"  {pad}   Session [{ev.session_id}]")
            if not is_last:
                lines.append("  │")

        lines.append("")
        return '\n'.join(lines)

    @property
    def events(self) -> list:
        """Public read-only view of internal _events list."""
        return self._events

    def count(self) -> int:
        return len(self._events)

    def to_dict(self) -> dict:
        return {'events': [e.to_dict() for e in self._events]}

    def from_dict(self, data: dict):
        self._events = [TimelineEvent.from_dict(d) for d in data.get('events', [])]

    def export_markdown(self) -> str:
        lines = ["## Engagement Timeline", ""]
        for ev in self._events:
            icon = EVENT_TYPES.get(ev.type, ('·', ''))[0]
            ts   = ev.ts[:16].replace('T', ' ')
            lines.append(f"- `{ts}` {icon} **{ev.title}**")
            if ev.detail:
                lines.append(f"  - {ev.detail}")
        return '\n'.join(lines)
