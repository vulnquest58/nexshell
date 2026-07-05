#!/usr/bin/env python3
"""
NexShell — Service Inventory  (inventory/services.py)
Tracks open ports, services, and version banners per host.

Usage:
    from inventory.services import ServiceInventory
    svc = ServiceInventory()
    svc.add("10.0.0.1", port=22,  service="ssh",   version="OpenSSH 8.2")
    svc.add("10.0.0.1", port=80,  service="http",  version="nginx/1.18")
    svc.add("10.0.0.1", port=443, service="https", version="nginx/1.18")
    print(svc.show("10.0.0.1"))
    print(svc.by_service("ssh"))
"""

import datetime
import json
import uuid
from pathlib import Path
from typing import Dict, List, Optional


# Common port → service name map
PORT_MAP = {
    21:   'ftp',      22:   'ssh',      23:   'telnet',
    25:   'smtp',     53:   'dns',      80:   'http',
    88:   'kerberos', 110:  'pop3',     111:  'rpcbind',
    135:  'msrpc',    139:  'netbios',  143:  'imap',
    389:  'ldap',     443:  'https',    445:  'smb',
    465:  'smtps',    514:  'syslog',   587:  'submission',
    636:  'ldaps',    873:  'rsync',    993:  'imaps',
    995:  'pop3s',    1433: 'mssql',    1521: 'oracle',
    2049: 'nfs',      2375: 'docker',   3000: 'web',
    3306: 'mysql',    3389: 'rdp',      4444: 'shell',
    5432: 'postgres', 5900: 'vnc',      6379: 'redis',
    7070: 'web',      8080: 'http-alt', 8443: 'https-alt',
    8888: 'web',      9200: 'elasticsearch', 27017: 'mongodb',
}

# Services that often have weak auth
HIGH_INTEREST = {'ssh', 'ftp', 'telnet', 'smb', 'rdp', 'vnc', 'mysql',
                 'postgres', 'mssql', 'redis', 'mongodb', 'elasticsearch',
                 'docker', 'http', 'https'}


class Service:
    def __init__(self, host_ip: str, port: int, protocol: str = 'tcp',
                 service: str = '', version: str = '', banner: str = '',
                 state: str = 'open'):
        self.id        = str(uuid.uuid4())[:8]
        self.host_ip   = host_ip
        self.port      = port
        self.protocol  = protocol
        self.service   = service or PORT_MAP.get(port, 'unknown')
        self.version   = version
        self.banner    = banner[:200] if banner else ''
        self.state     = state
        self.interest  = self.service.lower() in HIGH_INTEREST
        self.discovered= datetime.datetime.utcnow().isoformat()

    @property
    def label(self) -> str:
        svc = self.service or '?'
        ver = f" ({self.version})" if self.version else ""
        return f"{self.port}/{self.protocol} {svc}{ver}"

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'host_ip': self.host_ip,
            'port': self.port, 'protocol': self.protocol,
            'service': self.service, 'version': self.version,
            'banner': self.banner, 'state': self.state,
            'interest': self.interest, 'discovered': self.discovered,
        }


class ServiceInventory:
    """
    Per-host service tracker.
    Persists to DB and to a JSON cache.
    """

    def __init__(self):
        self._svcs: Dict[str, List[Service]] = {}  # host_ip → list of Services
        self._load_from_db()

    def _load_from_db(self):
        try:
            from db import get_db
            db = get_db()
            rows = db._conn().execute("SELECT * FROM services ORDER BY host_ip, port")
            for r in rows:
                d   = dict(r)
                svc = Service.__new__(Service)
                svc.id         = d['id']
                svc.host_ip    = d['host_ip']
                svc.port       = d['port']
                svc.protocol   = d.get('protocol', 'tcp')
                svc.service    = d.get('service', '')
                svc.version    = d.get('version', '')
                svc.banner     = d.get('banner', '')
                svc.state      = d.get('state', 'open')
                svc.interest   = svc.service.lower() in HIGH_INTEREST
                svc.discovered = d.get('discovered', '')
                self._svcs.setdefault(svc.host_ip, []).append(svc)
        except Exception:
            pass

    def _save_to_db(self, svc: 'Service'):
        try:
            from db import get_db
            db = get_db()
            with db._lock:
                conn = db._conn()
                conn.execute("""
                    INSERT OR IGNORE INTO services
                        (id, host_ip, port, protocol, service, version, banner, state, discovered)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (svc.id, svc.host_ip, svc.port, svc.protocol,
                      svc.service, svc.version, svc.banner, svc.state, svc.discovered))
                conn.commit()
        except Exception:
            pass

    def add(self, host_ip: str, port: int, protocol: str = 'tcp',
            service: str = '', version: str = '', banner: str = '',
            state: str = 'open') -> Service:
        """Add or update a service entry for a host."""
        # Avoid duplicate port entries
        existing = self._svcs.get(host_ip, [])
        for s in existing:
            if s.port == port and s.protocol == protocol:
                s.service = service or s.service
                s.version = version or s.version
                s.banner  = banner  or s.banner
                return s
        svc = Service(host_ip=host_ip, port=port, protocol=protocol,
                      service=service, version=version, banner=banner, state=state)
        self._svcs.setdefault(host_ip, []).append(svc)
        self._save_to_db(svc)
        # Update host's service_ids
        try:
            from inventory import inventory
            h = inventory.get(host_ip)
            if h:
                if svc.id not in h.service_ids:
                    h.service_ids.append(svc.id)
                    inventory._save(h)
        except Exception:
            pass
        return svc

    def add_from_nmap(self, host_ip: str, nmap_output: str):
        """Parse nmap -sV output and add discovered services."""
        import re
        # Pattern: PORT/PROTOCOL STATE SERVICE VERSION
        pattern = re.compile(
            r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?', re.MULTILINE
        )
        for m in pattern.finditer(nmap_output):
            port     = int(m.group(1))
            proto    = m.group(2)
            service  = m.group(3)
            version  = (m.group(4) or '').strip()
            self.add(host_ip, port=port, protocol=proto,
                     service=service, version=version)

    def get(self, host_ip: str) -> List[Service]:
        return self._svcs.get(host_ip, [])

    def all(self) -> List[Service]:
        result = []
        for svcs in self._svcs.values():
            result.extend(svcs)
        return result

    def by_service(self, service_name: str) -> List[Service]:
        """Find all services by name across all hosts."""
        s = service_name.lower()
        return [svc for svc in self.all() if s in svc.service.lower()]

    def by_port(self, port: int) -> List[Service]:
        """Find all services on a specific port."""
        return [svc for svc in self.all() if svc.port == port]

    def by_host(self, host_ip: str) -> List[Service]:
        """Alias for get() — returns all services for a host."""
        return self.get(host_ip)

    def count(self) -> int:
        """Total number of services across all hosts."""
        return sum(len(v) for v in self._svcs.values())

    def interesting(self) -> List[Service]:
        """Return services of high interest (SSH, SMB, RDP, etc.)"""
        return [svc for svc in self.all() if svc.interest]

    def show(self, host_ip: str) -> str:
        svcs = self.get(host_ip)
        if not svcs:
            return f"\n  No services recorded for {host_ip}\n"
        lines = [f"\n  Services — {host_ip}:", ""]
        for s in sorted(svcs, key=lambda x: x.port):
            star = " ★" if s.interest else ""
            lines.append(f"  {s.port:>5}/{s.protocol:<4}  {s.service:<15} "
                         f"{s.version[:40]:<40}{star}")
        lines.append("")
        return '\n'.join(lines)

    def summary(self) -> str:
        all_svcs = self.all()
        hosts    = len(self._svcs)
        if not all_svcs:
            return "\n  No services in inventory.\n"
        lines = [
            f"\n  Service Inventory — {hosts} hosts, {len(all_svcs)} services",
            "",
            f"  {'HOST':<16} {'PORT':>5}  {'SVC':<15} {'VERSION':<35}",
            "  " + "─" * 72,
        ]
        for ip, svcs in sorted(self._svcs.items()):
            for s in sorted(svcs, key=lambda x: x.port):
                star = " ★" if s.interest else ""
                lines.append(
                    f"  {ip:<16} {s.port:>5}/{s.protocol:<4}  "
                    f"{s.service:<15} {s.version[:30]:<30}{star}"
                )
        lines.append("")
        return '\n'.join(lines)


# Global singleton
services = ServiceInventory()
