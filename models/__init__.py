#!/usr/bin/env python3
"""
NexShell — Data Models  (models/__init__.py)
Structured Python dataclasses for all core entities.
These are in-memory representations; persistence is via db/database.py.
"""

import datetime
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ══════════════════════════════════════════════════════════════════════════════
#  HOST
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Host:
    """
    A discovered/compromised network host.
    One Host can have many Sessions, Services, Credentials, Findings.
    """
    ip:          str
    hostname:    str              = ""
    os:          str              = "Unknown"
    os_version:  str              = ""
    domain:      str              = ""
    tags:        List[str]        = field(default_factory=list)
    notes:       List[str]        = field(default_factory=list)
    risk:        str              = "unknown"    # low | medium | high | critical
    in_scope:    bool             = True
    discovered   : str            = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    # Relationships (populated at runtime, not stored directly)
    session_ids: List[int]        = field(default_factory=list)
    service_ids: List[int]        = field(default_factory=list)

    @property
    def id(self) -> str:
        return hashlib.md5(self.ip.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            'ip': self.ip, 'hostname': self.hostname, 'os': self.os,
            'os_version': self.os_version, 'domain': self.domain,
            'tags': self.tags, 'risk': self.risk,
            'in_scope': self.in_scope, 'discovered': self.discovered,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  SERVICE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Service:
    """A network service discovered on a host."""
    host_ip:  str
    port:     int
    protocol: str     = "tcp"
    service:  str     = ""
    version:  str     = ""
    banner:   str     = ""
    state:    str     = "open"

    @property
    def id(self) -> str:
        return hashlib.md5(f"{self.host_ip}:{self.port}/{self.protocol}".encode()).hexdigest()[:10]


# ══════════════════════════════════════════════════════════════════════════════
#  FINDING
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """
    A security finding (vulnerability, misconfiguration, etc.).
    The foundation of the final pentest report.
    """
    title:          str
    description:    str           = ""
    severity:       str           = "info"      # info | low | medium | high | critical
    cvss:           float         = 0.0
    cvss_vector:    str           = ""
    host:           str           = ""
    session_id:     int           = 0
    evidence_ids:   List[str]     = field(default_factory=list)
    recommendation: str           = ""
    mitre_id:       str           = ""          # e.g. T1078
    source:         str           = "manual"    # manual | auto | rule | plugin
    status:         str           = "open"      # open | confirmed | false_positive | fixed
    created:        str           = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

    @property
    def id(self) -> str:
        return hashlib.md5(f"{self.title}{self.host}".encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'title': self.title,
            'description': self.description, 'severity': self.severity,
            'cvss': self.cvss, 'host': self.host,
            'recommendation': self.recommendation,
            'mitre_id': self.mitre_id, 'source': self.source,
            'status': self.status, 'created': self.created,
        }

    @property
    def severity_icon(self) -> str:
        return {
            'critical': '🔴', 'high': '🟠', 'medium': '🟡',
            'low': '🟢', 'info': '⚪',
        }.get(self.severity, '⚫')


# ══════════════════════════════════════════════════════════════════════════════
#  EVIDENCE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Evidence:
    """
    A piece of evidence collected during the engagement.
    Maintains chain of custody: SHA256 + timestamp + operator + host + session.
    """
    type:       str               # screenshot | file | command | hash | network
    data:       bytes             = field(default_factory=bytes)
    data_text:  str               = ""
    host:       str               = ""
    session_id: int               = 0
    operator:   str               = ""
    filename:   str               = ""
    note:       str               = ""
    ts:         str               = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

    @property
    def sha256(self) -> str:
        content = self.data or self.data_text.encode()
        return hashlib.sha256(content).hexdigest()

    @property
    def id(self) -> str:
        return self.sha256[:16]

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'type': self.type,
            'sha256': self.sha256, 'host': self.host,
            'session_id': self.session_id, 'operator': self.operator,
            'filename': self.filename, 'note': self.note, 'ts': self.ts,
            'data_preview': self.data_text[:200] if self.data_text else '',
        }


# ══════════════════════════════════════════════════════════════════════════════
#  OPERATION
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Operation:
    """
    A pentest engagement / red team operation.
    Isolates all data (hosts, sessions, loot, findings) into a workspace.
    """
    name:        str
    client:      str              = ""
    description: str              = ""
    operator:    str              = ""
    status:      str              = "active"    # active | paused | archived | completed
    scope_ips:   List[str]        = field(default_factory=list)
    scope_domains: List[str]      = field(default_factory=list)
    objectives:  List[str]        = field(default_factory=list)
    tags:        List[str]        = field(default_factory=list)
    start_date:  str              = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    end_date:    str              = ""
    created:     str              = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

    @property
    def id(self) -> str:
        return hashlib.md5(self.name.encode()).hexdigest()[:10]

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'name': self.name, 'client': self.client,
            'description': self.description, 'operator': self.operator,
            'status': self.status, 'scope_ips': self.scope_ips,
            'scope_domains': self.scope_domains,
            'objectives': self.objectives, 'tags': self.tags,
            'start_date': self.start_date, 'end_date': self.end_date,
            'created': self.created,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK GRAPH NODE / EDGE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class GraphNode:
    """A node in the attack graph (host/network segment)."""
    ip:       str
    label:    str     = ""
    type:     str     = "host"    # host | gateway | internet | domain | cloud
    pwned:    bool    = False
    root:     bool    = False
    os:       str     = "Unknown"

@dataclass
class GraphEdge:
    """A directed relationship between two nodes (pivot path)."""
    src:    str   # source IP
    dst:    str   # destination IP
    method: str   = ""    # ssh | smb | rdp | exploit | credential
    port:   int   = 0
    label:  str   = ""


__all__ = [
    'Host', 'Service', 'Finding', 'Evidence', 'Operation',
    'GraphNode', 'GraphEdge',
]
