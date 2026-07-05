#!/usr/bin/env python3
"""
NexShell — Example Plugin  (plugins/example_quickenum.py)
Demonstrates the NexPlugin API: runs quick recon commands on a session,
saves output to loot, creates a finding.

Usage:
    (NexShell)> plugins list
    (NexShell)> plugins run quick-enum-linux
"""

from core.plugin import NexPlugin


class QuickEnumLinuxPlugin(NexPlugin):
    name        = "quick-enum-linux"
    description = "Fast Linux post-exploitation: user, OS, network, writable paths"
    author      = "vulnquest58"
    version     = "1.0"
    platform    = "linux"
    category    = "recon"
    mitre_id    = "T1018"

    COMMANDS = [
        ("id",          "credentials",  "Current user identity"),
        ("uname -a",    "custom",       "Kernel version"),
        ("ip addr",     "network",      "Network interfaces"),
        ("ip route",    "network",      "Routing table"),
        ("ss -tlnp",    "network",      "Listening ports"),
        ("ps aux | head -20", "custom", "Running processes"),
        ("cat /etc/passwd | grep -v nologin", "credentials", "Valid system users"),
        ("find / -perm -4000 2>/dev/null | head -20", "privesc", "SUID binaries"),
        ("env | grep -iE 'pass|key|secret|token'", "credentials", "Env variable secrets"),
    ]

    def run(self, session, args: list):
        self.info("Starting quick-enum-linux plugin...")
        results = []

        for cmd, category, label in self.COMMANDS:
            try:
                output = ""
                if hasattr(session, 'exec'):
                    output = session.exec(cmd) or ''
                elif hasattr(session, 'run'):
                    output = session.run(cmd) or ''

                if not output:
                    continue

                results.append(f"\n{'─'*60}")
                results.append(f"[{label}] $ {cmd}")
                results.append('─'*60)
                results.append(output.strip())

                # Persist to loot
                self.loot(output, category=category, source=f"plugin:{cmd}")

            except Exception as e:
                self.warn(f"Command failed: {cmd}: {e}")

        # Create a finding if we found something in privesc
        suid_output = ""
        for cmd, cat, _ in self.COMMANDS:
            if cat == "privesc" and results:
                suid_output = "SUID binaries found — assess for privilege escalation."
                break

        if suid_output:
            self.finding(
                title="SUID/SGID Binaries Detected",
                description=suid_output,
                severity="medium",
                recommendation="Review each SUID binary against GTFOBins for privilege escalation paths.",
            )
            self.emit('finding.created', severity='medium', source=self.name)

        summary = '\n'.join(results) if results else "No output collected."
        self.info("quick-enum-linux complete.")
        return summary
