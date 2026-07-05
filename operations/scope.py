#!/usr/bin/env python3
"""
NexShell — Operation Scope Manager  (operations/scope.py)
Manages in-scope and out-of-scope targets for an engagement.
Supports IP addresses, CIDR ranges, domains, and exclusions.

Usage:
    from operations.scope import ScopeManager
    scope = ScopeManager()
    scope.add_ip("192.168.1.0/24")
    scope.add_domain("acme.internal")
    scope.add_exclusion("192.168.1.254")  # router — out of scope
    print(scope.is_in_scope("192.168.1.10"))  # True
    print(scope.check("8.8.8.8"))             # False
"""

import re
import ipaddress
from typing import List, Optional


class ScopeManager:
    """
    Validates targets against a scope whitelist and exclusion blacklist.
    Supports IPv4, CIDR ranges, and domain wildcards.
    """

    def __init__(self):
        self._ip_ranges: List[ipaddress.IPv4Network]  = []
        self._domains:   List[str]                    = []
        self._exclusions:List[ipaddress.IPv4Address]  = []
        self._excl_cidrs:List[ipaddress.IPv4Network]  = []

    # ── Add to Scope ──────────────────────────────────────────────────────────

    def add_ip(self, target: str):
        """Add IP address or CIDR range to scope."""
        target = target.strip()
        if '/' not in target:
            # Single IP → /32
            target = target + '/32'
        try:
            net = ipaddress.IPv4Network(target, strict=False)
            if net not in self._ip_ranges:
                self._ip_ranges.append(net)
        except ValueError as e:
            raise ValueError(f"Invalid IP/CIDR: {target} — {e}")

    def add_domain(self, domain: str):
        """Add domain or wildcard (e.g. *.acme.internal) to scope."""
        domain = domain.strip().lower()
        if domain not in self._domains:
            self._domains.append(domain)

    def add_exclusion(self, target: str):
        """Exclude an IP or CIDR from scope (out-of-scope)."""
        target = target.strip()
        try:
            if '/' in target:
                net = ipaddress.IPv4Network(target, strict=False)
                if net not in self._excl_cidrs:
                    self._excl_cidrs.append(net)
            else:
                addr = ipaddress.IPv4Address(target)
                if addr not in self._exclusions:
                    self._exclusions.append(addr)
        except ValueError as e:
            raise ValueError(f"Invalid exclusion target: {target} — {e}")

    # ── Validation ────────────────────────────────────────────────────────────

    def is_in_scope(self, target: str) -> bool:
        """Check whether a target IP or domain is in scope."""
        target = target.strip()
        # Try as IP
        try:
            addr = ipaddress.IPv4Address(target)
            # Check exclusions first
            if addr in self._exclusions:
                return False
            if any(addr in net for net in self._excl_cidrs):
                return False
            # Check inclusions
            return any(addr in net for net in self._ip_ranges)
        except ValueError:
            pass
        # Try as domain
        t_lower = target.lower()
        for domain in self._domains:
            if domain.startswith('*.'):
                suffix = domain[2:]
                if t_lower.endswith(suffix) or t_lower == suffix:
                    return True
            elif t_lower == domain or t_lower.endswith('.' + domain):
                return True
        return False

    def check(self, target: str) -> str:
        """Return 'IN_SCOPE', 'EXCLUDED', or 'OUT_OF_SCOPE'."""
        target = target.strip()
        try:
            addr = ipaddress.IPv4Address(target)
            if addr in self._exclusions or any(addr in n for n in self._excl_cidrs):
                return 'EXCLUDED'
            if any(addr in n for n in self._ip_ranges):
                return 'IN_SCOPE'
            return 'OUT_OF_SCOPE'
        except ValueError:
            pass
        if self.is_in_scope(target):
            return 'IN_SCOPE'
        return 'OUT_OF_SCOPE'

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            'ip_ranges':  [str(n) for n in self._ip_ranges],
            'domains':    list(self._domains),
            'exclusions': [str(a) for a in self._exclusions] +
                          [str(n) for n in self._excl_cidrs],
        }

    def from_dict(self, data: dict):
        for ip in data.get('ip_ranges', []):
            try: self.add_ip(ip)
            except Exception: pass
        for d in data.get('domains', []):
            self.add_domain(d)
        for ex in data.get('exclusions', []):
            try: self.add_exclusion(ex)
            except Exception: pass

    def summary(self) -> str:
        lines = ["\n  Scope Summary:"]
        if self._ip_ranges:
            lines.append(f"    IP Ranges  : {', '.join(str(n) for n in self._ip_ranges)}")
        if self._domains:
            lines.append(f"    Domains    : {', '.join(self._domains)}")
        excl = [str(a) for a in self._exclusions] + [str(n) for n in self._excl_cidrs]
        if excl:
            lines.append(f"    Exclusions : {', '.join(excl)}")
        if not self._ip_ranges and not self._domains:
            lines.append("    (no scope defined — all targets accepted)")
        lines.append("")
        return '\n'.join(lines)

    def validate_all(self, targets: List[str]) -> dict:
        """Batch validate a list of targets."""
        return {t: self.check(t) for t in targets}
