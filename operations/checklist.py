#!/usr/bin/env python3
"""
NexShell — Engagement Checklist  (operations/checklist.py)
Pre-engagement, during-engagement, and post-engagement checklists.
Tracks completion per phase.

Usage:
    from operations.checklist import Checklist, BUILTIN_CHECKLISTS
    cl = Checklist.from_template("pentest")
    cl.complete("rules_of_engagement")
    print(cl.render())
"""

import datetime
import json
from typing import Dict, List, Optional


# ── Built-in checklist templates ──────────────────────────────────────────────

BUILTIN_CHECKLISTS = {
    "pentest": {
        "name": "Internal Pentest",
        "phases": {
            "Pre-Engagement": [
                ("rules_of_engagement",   "Rules of Engagement signed"),
                ("scope_defined",         "Scope defined (IPs/domains)"),
                ("emergency_contacts",    "Emergency contacts documented"),
                ("vpn_access",            "VPN/access credentials received"),
                ("backup_verified",       "Client backups verified"),
                ("testing_window",        "Testing window agreed"),
                ("tools_ready",           "Tools and payloads prepared"),
            ],
            "Reconnaissance": [
                ("passive_recon",         "Passive recon complete (OSINT)"),
                ("dns_enum",              "DNS enumeration performed"),
                ("port_scan",             "Port scanning complete"),
                ("service_enum",          "Service enumeration performed"),
                ("vuln_scan",             "Vulnerability scan run"),
            ],
            "Initial Access": [
                ("entry_point_found",     "Entry point identified"),
                ("exploit_tested",        "Exploit tested in safe environment"),
                ("shell_obtained",        "Shell/access obtained"),
                ("shell_stabilized",      "Shell stabilized (PTY/pty upgrade)"),
            ],
            "Post-Exploitation": [
                ("whoami_verified",       "User context verified (whoami/id)"),
                ("network_mapped",        "Internal network mapped"),
                ("privesc_attempted",     "Privilege escalation attempted"),
                ("creds_harvested",       "Credentials harvested"),
                ("lateral_movement",      "Lateral movement performed"),
                ("persistence_set",       "Persistence established"),
            ],
            "Evidence & Reporting": [
                ("screenshots_taken",     "Screenshots/evidence captured"),
                ("loot_exported",         "Loot exported and organized"),
                ("findings_documented",   "All findings documented"),
                ("mitre_mapped",          "MITRE ATT&CK techniques mapped"),
                ("report_drafted",        "Draft report generated"),
                ("remediation_added",     "Remediation recommendations added"),
            ],
            "Post-Engagement": [
                ("backdoors_removed",     "All backdoors/persistence removed"),
                ("tools_cleaned",         "Uploaded tools removed from target"),
                ("logs_reviewed",         "Log artifacts reviewed with client"),
                ("report_delivered",      "Final report delivered"),
                ("debrief_conducted",     "Client debrief conducted"),
            ],
        }
    },
    "quick": {
        "name": "Quick CTF / HackTheVM",
        "phases": {
            "Initial": [
                ("nmap_scan",   "Nmap scan performed"),
                ("web_enum",    "Web enumeration (gobuster/feroxbuster)"),
                ("foothold",    "Foothold obtained"),
            ],
            "Privilege Escalation": [
                ("sudo_l",      "sudo -l checked"),
                ("suid_search", "SUID binaries identified"),
                ("cron_check",  "Cron jobs reviewed"),
                ("lse_run",     "LinPEAS/LSE run"),
                ("root",        "Root / SYSTEM obtained"),
            ],
            "Flags": [
                ("user_flag",   "user.txt captured"),
                ("root_flag",   "root.txt captured"),
                ("writeup",     "Writeup drafted"),
            ],
        }
    },
}


class ChecklistItem:
    def __init__(self, key: str, description: str):
        self.key         = key
        self.description = description
        self.completed   = False
        self.completed_at: Optional[str] = None
        self.note        = ""

    def complete(self, note: str = ""):
        self.completed    = True
        self.completed_at = datetime.datetime.utcnow().isoformat()
        self.note         = note

    def to_dict(self) -> dict:
        return {
            'key': self.key, 'description': self.description,
            'completed': self.completed, 'completed_at': self.completed_at,
            'note': self.note,
        }


class Checklist:
    """Engagement phase checklist with progress tracking."""

    def __init__(self, name: str = "Engagement"):
        self.name   = name
        self.phases: Dict[str, List[ChecklistItem]] = {}

    @classmethod
    def from_template(cls, template_name: str = "pentest") -> 'Checklist':
        tpl = BUILTIN_CHECKLISTS.get(template_name, BUILTIN_CHECKLISTS['pentest'])
        cl  = cls(name=tpl['name'])
        for phase_name, items in tpl['phases'].items():
            cl.phases[phase_name] = [ChecklistItem(k, d) for k, d in items]
        return cl

    def complete(self, key: str, note: str = "") -> bool:
        for items in self.phases.values():
            for item in items:
                if item.key == key:
                    item.complete(note)
                    return True
        return False

    def uncomplete(self, key: str) -> bool:
        for items in self.phases.values():
            for item in items:
                if item.key == key:
                    item.completed    = False
                    item.completed_at = None
                    return True
        return False

    def progress(self) -> dict:
        total     = sum(len(items) for items in self.phases.values())
        completed = sum(
            sum(1 for i in items if i.completed)
            for items in self.phases.values()
        )
        pct = int((completed / total * 100) if total else 0)
        return {'total': total, 'completed': completed, 'pct': pct}

    def render(self) -> str:
        prog  = self.progress()
        bar_w = 30
        done  = int(bar_w * prog['pct'] / 100)
        bar   = '█' * done + '░' * (bar_w - done)
        lines = [
            f"\n  Checklist: {self.name}",
            f"  Progress : [{bar}] {prog['pct']}% "
            f"({prog['completed']}/{prog['total']})",
            "",
        ]
        for phase, items in self.phases.items():
            phase_done = sum(1 for i in items if i.completed)
            phase_total = len(items)
            lines.append(f"  ── {phase} ({phase_done}/{phase_total}) ──────────────")
            for item in items:
                mark = '✅' if item.completed else '⬜'
                ts   = f" [{item.completed_at[:10]}]" if item.completed_at else ""
                lines.append(f"    {mark} {item.key:<30} {item.description}{ts}")
            lines.append("")
        return '\n'.join(lines)

    def to_dict(self) -> dict:
        return {
            'name':   self.name,
            'phases': {
                phase: [i.to_dict() for i in items]
                for phase, items in self.phases.items()
            }
        }

    def from_dict(self, data: dict):
        self.name   = data.get('name', self.name)
        self.phases = {}
        for phase, items in data.get('phases', {}).items():
            self.phases[phase] = []
            for d in items:
                ci = ChecklistItem(d['key'], d['description'])
                ci.completed    = d.get('completed', False)
                ci.completed_at = d.get('completed_at')
                ci.note         = d.get('note', '')
                self.phases[phase].append(ci)

    def export_markdown(self) -> str:
        prog  = self.progress()
        lines = [
            f"## Checklist: {self.name}",
            f"**Progress:** {prog['pct']}% ({prog['completed']}/{prog['total']})", "",
        ]
        for phase, items in self.phases.items():
            lines.append(f"### {phase}")
            for item in items:
                mark = "[x]" if item.completed else "[ ]"
                lines.append(f"- {mark} {item.description}")
            lines.append("")
        return '\n'.join(lines)
