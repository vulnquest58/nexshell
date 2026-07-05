#!/usr/bin/env python3
"""
NexShell — Asset Inventory  (inventory/hosts.py)
Full Host object registry: each IP becomes a rich asset with services,
credentials, findings, notes, and risk score.

CLI:
    host add 192.168.1.10
    host show 192.168.1.10
    host list
    host tag 192.168.1.10 DC01
    host risk 192.168.1.10 high
"""

import json
import hashlib
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from db import get_db
    _DB_AVAILABLE = True
except ImportError:
    get_db = None
    _DB_AVAILABLE = False

from models import Host, Service, Finding


# ══════════════════════════════════════════════════════════════════════════════
#  HOST INVENTORY
# ══════════════════════════════════════════════════════════════════════════════

class HostInventory:
    """
    In-memory + DB-backed registry of all discovered hosts.
    Each host is the central object linking sessions, services, findings.
    """

    def __init__(self):
        self._hosts: Dict[str, Host] = {}    # ip → Host
        self._load_from_db()

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def add(self, ip: str, hostname: str = "", os: str = "Unknown",
            os_version: str = "", domain: str = "",
            in_scope: bool = True) -> Host:
        """Add or update a host. Returns the Host object."""
        if ip in self._hosts:
            h = self._hosts[ip]
            if hostname: h.hostname   = hostname
            if os != "Unknown": h.os = os
            if os_version: h.os_version = os_version
            if domain: h.domain       = domain
        else:
            h = Host(ip=ip, hostname=hostname, os=os,
                     os_version=os_version, domain=domain, in_scope=in_scope)
            self._hosts[ip] = h
        self._persist(h)
        # Emit event
        try:
            from core.event_bus import bus
            bus.emit('host.added', ip=ip, hostname=hostname, os=os)
        except Exception:
            pass
        return h

    def get(self, ip: str) -> Optional[Host]:
        return self._hosts.get(ip)

    def all(self) -> List[Host]:
        return list(self._hosts.values())

    def tag(self, ip: str, tag: str):
        h = self._hosts.get(ip)
        if h and tag not in h.tags:
            h.tags.append(tag)
            self._persist(h)

    def set_risk(self, ip: str, risk: str):
        """risk: low | medium | high | critical"""
        h = self._hosts.get(ip)
        if h:
            h.risk = risk
            self._persist(h)

    def add_note(self, ip: str, note: str):
        h = self._hosts.get(ip)
        if h:
            h.notes.append(f"[{datetime.datetime.utcnow():%H:%M}] {note}")
            self._persist(h)

    def link_session(self, ip: str, session_id: int):
        """Link a session ID to a host."""
        h = self._hosts.get(ip)
        if h and session_id not in h.session_ids:
            h.session_ids.append(session_id)
            self._persist(h)

    # ── Attack Graph ──────────────────────────────────────────────────────────

    def attack_graph_ascii(self) -> str:
        """
        Render ASCII attack graph showing host relationships.
        Pwned hosts shown with ★, root with ◆.
        """
        hosts = self.all()
        if not hosts:
            return "  No hosts discovered yet."

        lines = ["", "  ╔═══════════════════════════════╗",
                     "  ║     NexShell Attack Graph     ║",
                     "  ╚═══════════════════════════════╝", ""]

        # Group by domain/network
        by_network: Dict[str, List[Host]] = {}
        for h in hosts:
            net = h.domain or h.ip.rsplit('.', 1)[0] + '.x'
            by_network.setdefault(net, []).append(h)

        for net, net_hosts in by_network.items():
            lines.append(f"  [{net}]")
            for i, h in enumerate(net_hosts):
                connector = "└──" if i == len(net_hosts) - 1 else "├──"
                pwned = "★" if h.session_ids else "○"
                root  = "◆" if any(s in h.tags for s in ['root', 'SYSTEM']) else ""
                risk_color = {'critical': '!', 'high': '!', 'medium': '~', 'low': '-'}.get(h.risk, ' ')
                label = h.hostname or h.ip
                os_short = h.os[:3].upper() if h.os else "???"
                lines.append(
                    f"  {connector} {pwned}{root} {label:<20} "
                    f"[{os_short}] [{risk_color}] "
                    f"{'Sessions:' + str(len(h.session_ids)) if h.session_ids else 'no shell'}"
                )
            lines.append("")
        return '\n'.join(lines)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _persist(self, host: Host):
        if not (_DB_AVAILABLE and get_db):
            return
        try:
            db = get_db()
            if hasattr(db, 'upsert_host'):
                db.upsert_host(host.to_dict())
        except Exception:
            pass

    def _load_from_db(self):
        if not (_DB_AVAILABLE and get_db):
            return
        try:
            db = get_db()
            if hasattr(db, 'list_hosts'):
                for row in db.list_hosts():
                    h = Host(ip=row['ip'])
                    for k, v in row.items():
                        if hasattr(h, k):
                            setattr(h, k, v)
                    self._hosts[h.ip] = h
        except Exception:
            pass

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self) -> str:
        hosts = self.all()
        if not hosts:
            return "  No hosts in inventory."
        lines = [
            f"\n  {'IP':<18} {'Hostname':<20} {'OS':<12} {'Sessions':<10} {'Risk':<10} {'Tags'}",
            f"  {'─'*18} {'─'*20} {'─'*12} {'─'*10} {'─'*10} {'─'*20}",
        ]
        for h in sorted(hosts, key=lambda x: x.ip):
            tags_str = ', '.join(h.tags[:3]) if h.tags else '—'
            lines.append(
                f"  {h.ip:<18} {(h.hostname or '—'):<20} {h.os:<12} "
                f"{len(h.session_ids):<10} {h.risk:<10} {tags_str}"
            )
        lines.append(f"\n  Total: {len(hosts)} hosts\n")
        return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  FINDINGS MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class FindingsManager:
    """
    Central findings registry.
    Findings → DB → Report generation.
    """

    SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

    def __init__(self):
        self._findings: Dict[str, Finding] = {}   # id → Finding
        self._load_from_db()

    def add(self, title: str, description: str = "", severity: str = "info",
            cvss: float = 0.0, host: str = "", session_id: int = 0,
            recommendation: str = "", mitre_id: str = "",
            source: str = "manual") -> Finding:
        f = Finding(
            title=title, description=description, severity=severity,
            cvss=cvss, host=host, session_id=session_id,
            recommendation=recommendation, mitre_id=mitre_id, source=source,
        )
        self._findings[f.id] = f
        self._persist(f)
        try:
            from core.event_bus import bus, Events
            bus.emit(Events.FINDING_CREATED,
                     title=title, severity=severity, host=host)
        except Exception:
            pass
        return f

    def list_by_severity(self) -> List[Finding]:
        order = {s: i for i, s in enumerate(self.SEVERITY_ORDER)}
        return sorted(self._findings.values(),
                      key=lambda f: order.get(f.severity, 99))

    def by_host(self, ip: str) -> List[Finding]:
        return [f for f in self._findings.values() if f.host == ip]

    def _persist(self, f: Finding):
        if not (_DB_AVAILABLE and get_db):
            return
        try:
            db = get_db()
            if hasattr(db, 'add_finding'):
                db.add_finding(f.to_dict())
        except Exception:
            pass

    def _load_from_db(self):
        if not (_DB_AVAILABLE and get_db):
            return
        try:
            db = get_db()
            if hasattr(db, 'list_findings'):
                for row in db.list_findings():
                    f = Finding(title=row.get('title', ''))
                    for k, v in row.items():
                        if hasattr(f, k):
                            setattr(f, k, v)
                    self._findings[f.id] = f
        except Exception:
            pass

    def summary(self) -> str:
        by_sev = {}
        for f in self._findings.values():
            by_sev.setdefault(f.severity, []).append(f)
        if not by_sev:
            return "  No findings recorded."
        lines = ["\n  Findings Summary:"]
        for sev in self.SEVERITY_ORDER:
            items = by_sev.get(sev, [])
            if items:
                icon = Finding(title='').severity_icon
                f_temp = Finding(title='', severity=sev)
                lines.append(f"  {f_temp.severity_icon} {sev.upper():<10} {len(items)}")
        lines.append(f"\n  Total: {len(self._findings)} findings\n")
        return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL SINGLETONS
# ══════════════════════════════════════════════════════════════════════════════

inventory = HostInventory()
findings  = FindingsManager()
