#!/usr/bin/env python3
"""
NexShell Plugin — Persistence Check v3.0 (2026 Edition)
Detect attacker-planted and misconfigured persistence mechanisms.

Checks (Linux):
  - Crontab + systemd timers
  - Shell profiles & aliases (bash/zsh/fish)
  - systemd (system + user services, timers, sockets, paths)
  - /etc/rc.local, init.d
  - SSH authorized_keys & forced commands
  - PAM modules (pam_exec, pam_env)
  - MOTD scripts
  - LD_PRELOAD & /etc/ld.so.preload
  - D-Bus services
  - Polkit rules
  - udev rules
  - logrotate hooks
  - apt/dpkg hooks
  - Python sitecustomize.py
  - Cloud-init configs
  - Git hooks
  - Kernel modules
  - Bootloader (GRUB)
  - eBPF programs
  - At jobs

Checks (Windows):
  - Registry Run/RunOnce keys (HKLM + HKCU + WOW64)
  - Active Setup
  - Startup folders
  - Scheduled tasks (non-Microsoft)
  - Services (non-system)
  - WMI subscriptions
  - Winlogon hijacking & Notify
  - AppInit DLLs
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
  - Web shells (IIS)
  - Cloud persistence (Azure AD/Entra ID)

Usage:
    (NexShell)> plugins run persistence-check
    (NexShell)> plugins run persistence-check --deep
"""

import re
from core.plugin import NexPlugin


class PersistenceCheck(NexPlugin):
    name        = "persistence-check"
    description = "Modern persistence detection — systemd/COM/SSP/Cloud/eBPF/WMI"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "recon"
    mitre_id    = "T1547"

    LINUX_CHECKS = [
        # Cron & Systemd Timers
        ("crontab -l 2>/dev/null", "cron_user", "User Crontab"),
        ("cat /etc/crontab 2>/dev/null", "cron_system", "/etc/crontab"),
        ("ls -la /etc/cron.d/ 2>/dev/null", "cron_d", "/etc/cron.d/"),
        ("cat /etc/cron.d/* 2>/dev/null", "cron_d_files", "Cron.d Contents"),
        ("cat /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null | grep -v '^#'", "cron_periodic", "Periodic Cron Scripts"),
        ("ls -la /var/spool/cron/crontabs/ 2>/dev/null", "cron_spool", "Cron Spool"),
        ("systemctl list-timers --all 2>/dev/null | head -30", "systemd_timers", "Systemd Timers"),
        ("find /etc/systemd/system /lib/systemd/system ~/.config/systemd /usr/lib/systemd -name '*.timer' 2>/dev/null", "systemd_timer_files", "Systemd Timer Files"),

        # Shell profile
        ("cat ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile /etc/bash.bashrc /etc/profile /etc/zsh/zshrc 2>/dev/null", "shell_profiles", "Shell Profiles"),
        ("cat /etc/environment 2>/dev/null", "env_file", "/etc/environment"),
        ("alias 2>/dev/null", "aliases", "Shell Aliases"),
        ("cat ~/.bash_aliases ~/.zsh_aliases 2>/dev/null", "bash_aliases", "Aliases Files"),

        # systemd (system + user)
        ("systemctl list-units --type=service --state=enabled 2>/dev/null", "systemd_enabled", "Enabled Systemd Services"),
        ("find /etc/systemd/system /lib/systemd/system /usr/lib/systemd -name '*.service' 2>/dev/null | xargs ls -la 2>/dev/null", "systemd_files", "Systemd Unit Files (System)"),
        ("systemctl --user list-units --type=service --state=enabled 2>/dev/null", "systemd_user_enabled", "User Systemd Services"),
        ("find ~/.config/systemd/user /etc/systemd/user -name '*.service' 2>/dev/null | xargs ls -la 2>/dev/null", "systemd_user_files", "User Systemd Unit Files"),
        ("find /etc/systemd/system /lib/systemd/system ~/.config/systemd -name '*.socket' -o -name '*.path' 2>/dev/null", "systemd_socket_path", "Systemd Socket/Path Units"),
        ("cat /etc/rc.local 2>/dev/null", "rc_local", "/etc/rc.local"),
        ("ls -la /etc/init.d/ 2>/dev/null", "init_d", "Init.d Scripts"),

        # SSH
        ("find / -name 'authorized_keys' -readable 2>/dev/null | xargs cat 2>/dev/null", "auth_keys", "Authorized Keys"),
        ("cat /etc/ssh/sshd_config 2>/dev/null | grep -iE 'AuthorizedKeysFile|ForceCommand|PermitUserEnvironment'", "sshd_config", "SSHd Config"),

        # PAM
        ("cat /etc/pam.d/sshd /etc/pam.d/login /etc/pam.d/common-auth /etc/pam.d/su 2>/dev/null", "pam", "PAM Config"),
        ("find /lib/security /lib64/security /usr/lib/security -name '*.so' 2>/dev/null", "pam_modules", "PAM Modules"),
        ("grep -rE 'pam_exec|pam_env|pam_script' /etc/pam.d/ 2>/dev/null", "pam_exec", "PAM Exec/Env Modules"),

        # At jobs
        ("atq 2>/dev/null", "at_jobs", "At Jobs Queue"),
        ("ls /var/spool/at 2>/dev/null", "at_spool", "At Spool"),

        # MOTD
        ("ls -la /etc/update-motd.d/ 2>/dev/null", "motd", "MOTD Scripts"),
        ("cat /etc/update-motd.d/* 2>/dev/null | grep -v '^#'", "motd_content", "MOTD Content"),

        # LD_PRELOAD persistence
        ("grep -r 'LD_PRELOAD' /etc/profile /etc/environment ~/.bashrc ~/.profile /etc/ld.so.preload 2>/dev/null", "ld_preload", "LD_PRELOAD in Profiles"),
        ("cat /etc/ld.so.preload 2>/dev/null", "ld_so_preload", "/etc/ld.so.preload"),

        # D-Bus services
        ("find /usr/share/dbus-1/system-services /usr/share/dbus-1/services ~/.local/share/dbus-1/services -name '*.service' 2>/dev/null | xargs ls -la 2>/dev/null", "dbus_services", "D-Bus Services"),

        # Polkit rules
        ("find /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d -name '*.rules' 2>/dev/null | xargs ls -la 2>/dev/null", "polkit_rules", "Polkit Rules"),
        ("cat /etc/polkit-1/rules.d/*.rules 2>/dev/null", "polkit_rules_content", "Polkit Rules Content"),

        # udev rules
        ("find /etc/udev/rules.d /lib/udev/rules.d -name '*.rules' 2>/dev/null | xargs ls -la 2>/dev/null", "udev_rules", "udev Rules"),
        ("grep -lE 'RUN\\+=' /etc/udev/rules.d/*.rules /lib/udev/rules.d/*.rules 2>/dev/null", "udev_run_rules", "udev RUN Rules"),

        # logrotate configs
        ("find /etc/logrotate.d -type f 2>/dev/null | xargs grep -lE 'postrotate|prerotate' 2>/dev/null", "logrotate_hooks", "logrotate Hooks"),

        # apt/dpkg hooks
        ("grep -rE 'DPkg::Post-Invoke|APT::Update::Pre-Invoke' /etc/apt/apt.conf.d/ 2>/dev/null", "apt_hooks", "APT/DPKG Hooks"),

        # Python sitecustomize
        ("find / -name 'sitecustomize.py' -o -name 'usercustomize.py' 2>/dev/null | head -10", "python_sitecustomize", "Python sitecustomize"),

        # Cloud-init
        ("find /etc/cloud/cloud.cfg.d /var/lib/cloud -name '*.cfg' -o -name '*.yaml' 2>/dev/null | head -10", "cloud_init", "Cloud-init Configs"),
        ("cat /etc/cloud/cloud.cfg 2>/dev/null | grep -iE 'bootcmd|runcmd|ssh_authorized_keys'", "cloud_init_content", "Cloud-init Content"),

        # Git hooks
        ("find /home /root /opt /var/www -maxdepth 5 -name '.git/hooks' -type d 2>/dev/null | head -10", "git_hooks_dirs", "Git Hooks Directories"),

        # Kernel modules
        ("ls -la /etc/modules-load.d/ 2>/dev/null", "modules_load", "Kernel Modules Load"),
        ("cat /etc/modules-load.d/*.conf 2>/dev/null", "modules_load_content", "Kernel Modules Content"),
        ("ls -la /etc/modprobe.d/ 2>/dev/null", "modprobe", "modprobe Configs"),

        # Bootloader
        ("cat /etc/default/grub 2>/dev/null", "grub_config", "GRUB Config"),
        ("ls -la /boot/grub/grub.cfg /boot/efi/EFI/*/grub.cfg 2>/dev/null", "grub_files", "GRUB Files"),

        # eBPF
        ("bpftool prog list 2>/dev/null | head -20", "ebpf_progs", "eBPF Programs"),

        # Recent modifications
        ("find /etc /bin /sbin /usr/bin /usr/sbin -newer /etc/passwd -type f 2>/dev/null | head -20", "recent_changes", "Recently Modified System Files"),
        ("find /home /root -mtime -7 -name '*.sh' -o -name '*.py' -o -name '*.pl' 2>/dev/null | head -10", "recent_scripts", "Recently Modified Scripts"),
    ]

    WINDOWS_CHECKS = [
        # Registry Run keys
        ("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "reg_run_hklm", "HKLM Run"),
        ("reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "reg_run_hkcu", "HKCU Run"),
        ("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "reg_runonce_hklm", "HKLM RunOnce"),
        ("reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "reg_runonce_hkcu", "HKCU RunOnce"),
        ("reg query HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "reg_run32", "WOW64 Run"),
        ("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjects", "reg_shell_svc", "Shell Service Objects"),
        ("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", "reg_shell_delay", "Shell Service Object Delay Load"),

        # Active Setup
        ("reg query \"HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\" /s", "active_setup", "Active Setup"),

        # Startup folders
        ("dir /b \"C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"", "user_startup", "User Startup Folder"),
        ("dir /b \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"", "common_startup", "Common Startup Folder"),

        # Scheduled tasks
        ("schtasks /query /fo LIST /v | findstr /i /v \"\\Microsoft\\\"", "schtasks_custom", "Non-Microsoft Scheduled Tasks"),
        ("powershell -c \"Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\Microsoft\\*'} | Select-Object TaskName,TaskPath,State | Format-Table\"", "schtasks_ps", "Scheduled Tasks (PS)"),

        # Services
        ("sc query type= all state= running | findstr -i \"SERVICE_NAME\\|BINARY\"", "running_services", "Running Services"),
        ("wmic service get Name,PathName,StartMode | findstr /i /v \"C:\\\\Windows\\\\system32\"", "non_system_svc", "Non-System Services"),
        ("powershell -c \"Get-Service | Where-Object {$_.PathName -notlike '*Windows*'} | Select-Object Name,DisplayName,Status,StartType | Format-Table\"", "non_system_svc_ps", "Non-System Services (PS)"),

        # WMI subscriptions
        ("powershell -c Get-WMIObject -Namespace root\\subscription -Class __EventFilter 2>nul", "wmi_filters", "WMI Event Filters"),
        ("powershell -c Get-WMIObject -Namespace root\\subscription -Class __EventConsumer 2>nul", "wmi_consumers", "WMI Event Consumers"),
        ("powershell -c Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding 2>nul", "wmi_bindings", "WMI Filter Bindings"),

        # Winlogon hijacking
        ("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\"", "winlogon", "Winlogon Keys"),
        ("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\"", "winlogon_notify", "Winlogon Notify"),

        # AppInit DLLs
        ("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\" /v AppInit_DLLs", "appinit", "AppInit DLLs"),

        # COM Hijacking
        ("powershell -c \"Get-ChildItem -Path 'HKLM:\\SOFTWARE\\Classes\\CLSID' -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -like '*\\InprocServer32' -or $_.Name -like '*\\LocalServer32'} | Select-Object -First 30\"", "com_hijack", "COM InprocServer32/LocalServer32"),
        ("reg query HKCR\\clsid /s 2>nul | findstr /i \"InprocServer32\\|LocalServer32\"", "com_reg", "COM Registry"),

        # Time Providers
        ("reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\" /s", "time_providers", "Time Providers"),

        # Print Processors
        ("reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\Windows x64\\Print Processors\" /s", "print_processors", "Print Processors"),

        # Terminal Server
        ("reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v InitialProgram 2>nul", "terminal_server", "Terminal Server InitialProgram"),

        # SSP / LSA
        ("reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v Security Packages 2>nul", "lsa_packages", "LSA Security Packages"),
        ("reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig\" /v Security Packages 2>nul", "lsa_os_packages", "LSA OS Security Packages"),

        # PowerShell Profiles
        ("powershell -c \"Get-Content $PROFILE.AllUsersAllHosts -ErrorAction SilentlyContinue\"", "ps_profile_all", "PowerShell Profile (All Users)"),
        ("powershell -c \"Get-Content $PROFILE.CurrentUserAllHosts -ErrorAction SilentlyContinue\"", "ps_profile_user", "PowerShell Profile (Current User)"),
        ("powershell -c \"Get-Content $PROFILE.AllUsersCurrentHost -ErrorAction SilentlyContinue\"", "ps_profile_allhost", "PowerShell Profile (All Users Current Host)"),
        ("dir /b \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\*profile*\" 2>nul", "ps_profile_files", "PowerShell Profile Files"),

        # BITS Jobs
        ("powershell -c \"Get-BitsTransfer -AllUsers | Select-Object DisplayName,JobState,FileList | Format-Table\"", "bits_jobs", "BITS Jobs"),

        # Windows Terminal
        ("type \"%LOCALAPPDATA%\\Microsoft\\Windows Terminal\\settings.json\" 2>nul", "wt_settings", "Windows Terminal Settings"),
        ("type \"%LOCALAPPDATA%\\Packages\\Microsoft.WindowsTerminal_8wekyb3d8bbwe\\LocalState\\settings.json\" 2>nul", "wt_settings2", "Windows Terminal Settings (Alt)"),

        # WSL
        ("wsl --list --verbose 2>nul", "wsl_dists", "WSL Distributions"),
        ("dir /b \"C:\\Users\\%USERNAME%\\AppData\\Local\\Packages\\*Ubuntu*\" 2>nul", "wsl_ubuntu", "WSL Ubuntu Packages"),

        # Edge/Chrome extension policies
        ("reg query \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\Extensions\" 2>nul", "chrome_ext", "Chrome Extension Policies"),
        ("reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\Extensions\" 2>nul", "edge_ext", "Edge Extension Policies"),

        # Web Shells (IIS)
        ("dir /s /b C:\\inetpub\\wwwroot\\*.aspx C:\\inetpub\\wwwroot\\*.asp C:\\inetpub\\wwwroot\\*.php 2>nul | findstr /i /v \"default\\|index\"", "iis_webshells", "IIS Web Shells"),
        ("dir /s /b C:\\inetpub\\wwwroot\\web.config 2>nul", "iis_webconfig", "IIS web.config Files"),

        # Cloud Persistence (Azure AD / Entra ID)
        ("dsregcmd /status", "dsreg", "Azure AD / Entra ID Status"),
        ("reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\TenantInfo\" /s 2>nul", "cloud_tenant", "Cloud Tenant Info"),

        # Recent files
        ("dir /s /b /o-d C:\\Users\\%USERNAME%\\AppData\\Roaming 2>nul | head", "recent_appdata", "Recent AppData Files"),
        ("powershell -c \"Get-ChildItem -Path 'C:\\ProgramData' -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select FullName,LastWriteTime | Select-Object -First 20\"", "recent_programdata", "Recent ProgramData Files"),
    ]

    # ── Suspicious patterns to flag ───────────────────────────────────────────
    SUSPICIOUS_PATTERNS = {
        # Linux patterns
        "shell_profiles": [
            (r"(?i)(curl|wget|nc|bash|python|perl|ruby)\s.*\|.*bash",
             "High", "Reverse Shell in Shell Profile",
             "Shell profile contains code that downloads and executes a remote payload."),
            (r"(?i)base64\s*-d\s*\|",
             "High", "Base64 Decode Pipeline in Profile",
             "Obfuscated command execution detected in shell profile."),
            (r"(?i)eval\s*\(",
             "High", "Eval in Shell Profile",
             "Dynamic code execution detected in shell profile."),
        ],
        "cron_user": [
            (r"(?i)(curl|wget)\s.*\|\s*(bash|sh)",
             "High", "Download-and-Execute in Crontab",
             "Crontab downloads and executes remote code — typical backdoor pattern."),
            (r"(?i)(nc\s.*-e|ncat\s.*-e|bash\s.*-i)",
             "High", "Reverse Shell in Crontab",
             "Crontab contains a reverse shell command."),
        ],
        "auth_keys": [
            (r"command=\"[^\"]+\"\s+ssh-(rsa|ed25519|ecdsa)",
             "High", "SSH Forced Command Detected",
             "SSH authorized_keys contains forced command — potential backdoor."),
            (r"ssh-rsa|ssh-ed25519",
             "Medium", "SSH Authorized Key Found",
             "Review authorized_keys for unauthorized public keys."),
        ],
        "ld_preload": [
            (r"LD_PRELOAD",
             "High", "LD_PRELOAD Persistence",
             "LD_PRELOAD set in shell profile — can load malicious shared libraries."),
        ],
        "ld_so_preload": [
            (r"\S",
             "Critical", "/etc/ld.so.preload Configured",
             "/etc/ld.so.preload contains entries — all processes will load these libraries."),
        ],
        "pam_exec": [
            (r"pam_exec\.so",
             "High", "PAM exec Module Detected",
             "PAM configured to execute external scripts on authentication."),
        ],
        "polkit_rules_content": [
            (r"polkit\.allowAdministrator|polkit\.Result\s*=\s*YES",
             "High", "Permissive Polkit Rules",
             "Polkit rules grant elevated privileges without authentication."),
        ],
        "udev_run_rules": [
            (r"RUN\+=\"[^\"]+\"",
             "High", "udev RUN Rules Detected",
             "udev rules execute commands when devices are connected — potential persistence."),
        ],
        "apt_hooks": [
            (r"DPkg::Post-Invoke|APT::Update::Pre-Invoke",
             "High", "APT/DPKG Hooks Detected",
             "APT hooks execute commands during package operations."),
        ],
        "python_sitecustomize": [
            (r"\S",
             "High", "Python sitecustomize.py Detected",
             "Python sitecustomize.py can execute code on every Python invocation."),
        ],
        "cloud_init_content": [
            (r"(?i)(runcmd|bootcmd)",
             "Medium", "Cloud-init Commands Detected",
             "Cloud-init configured to run commands at boot — potential persistence in cloud environments."),
        ],
        "logrotate_hooks": [
            (r"(?i)(postrotate|prerotate)\s*\n\s*[^#]",
             "Medium", "logrotate Hooks Detected",
             "logrotate configured to execute scripts — potential persistence vector."),
        ],

        # Windows patterns
        "reg_run_hklm": [
            (r"REG_SZ.*=.*(?i)(temp|tmp|appdata|public|downloads|programdata).*\.exe",
             "High", "Suspicious Run Key from Temp/Downloads",
             "Registry Run key points to executable in suspicious directory."),
            (r"REG_SZ.*=.*(?i)(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)",
             "High", "Suspicious Interpreter in Run Key",
             "Registry Run key uses scripting interpreter — potential LOLBIN abuse."),
        ],
        "wmi_filters": [
            (r"\S",
             "High", "WMI Event Subscription Detected",
             "WMI subscriptions found — common APT persistence mechanism. Verify legitimacy."),
        ],
        "appinit": [
            (r"AppInit_DLLs\s+REG_SZ\s+\S",
             "High", "AppInit DLL Persistence",
             "AppInit_DLLs set — loads DLL into every process using User32.dll."),
        ],
        "winlogon": [
            (r"(?i)(userinit|shell)\s+REG_SZ\s+(?!.*winlogon\.exe)(?!.*explorer\.exe).*",
             "Critical", "Winlogon Hijack Detected",
             "Winlogon key modified — potential DLL hijacking or backdoor at login."),
        ],
        "winlogon_notify": [
            (r"\S",
             "High", "Winlogon Notify Key Detected",
             "Winlogon Notify configured — DLLs loaded at logon/logoff events."),
        ],
        "time_providers": [
            (r"(?i)DllName.*REG_SZ.*\S",
             "High", "Custom Time Provider Detected",
             "Custom W32Time provider DLL — can execute code as SYSTEM."),
        ],
        "print_processors": [
            (r"(?i)(?!.*winspool\.v2\.dll)\S+\.dll",
             "High", "Custom Print Processor Detected",
             "Custom print processor DLL — executes when print jobs are processed."),
        ],
        "terminal_server": [
            (r"InitialProgram\s+REG_SZ\s+\S",
             "High", "Terminal Server InitialProgram Set",
             "Custom InitialProgram configured — executes on RDP connection."),
        ],
        "lsa_packages": [
            (r"(?i)(?!.*rassfm\.dll)(?!.*sceclt\.dll)(?!.*msv1_0\.dll)\S+\.dll",
             "Critical", "Custom LSA Security Package Detected",
             "Custom LSA security package — executes in LSASS process (credential theft risk)."),
        ],
        "ps_profile_all": [
            (r"(?i)(Invoke-Expression|IEX|DownloadString|DownloadFile|Start-Process)",
             "High", "Suspicious PowerShell Profile",
             "PowerShell profile contains suspicious commands — executes on every PS session."),
        ],
        "bits_jobs": [
            (r"\S",
             "Medium", "BITS Jobs Detected",
             "BITS jobs found — can be used for persistent downloads."),
        ],
        "chrome_ext": [
            (r"\S",
             "Medium", "Chrome Extension Policies Detected",
             "Chrome extension policies configured — can force-install malicious extensions."),
        ],
        "iis_webshells": [
            (r"\S",
             "Critical", "Potential Web Shell Detected",
             "Web shell files found in IIS root — indicates compromise."),
        ],
        "com_reg": [
            (r"(?i)(temp|tmp|appdata|public|downloads).*\.dll",
             "High", "COM Hijacking from Suspicious Path",
             "COM object points to DLL in suspicious directory — potential hijacking."),
        ],
    }

    def run(self, session, args: list):
        deep = '--deep' in (args or [])
        platform = self._detect_platform(session)
        self.info(f"Starting persistence-check v3.0 (platform: {platform}, deep: {deep})...")

        checks = self.LINUX_CHECKS if platform == 'linux' else self.WINDOWS_CHECKS
        sections  = []
        collected = {}
        findings_created = 0

        for cmd, key, label in checks:
            try:
                out = self._exec(session, cmd)
                if not out.strip():
                    continue
                collected[key] = out
                self.loot(out, category='custom', source=f"persistence:{key}")
                sections.append(f"\n{'━'*64}")
                sections.append(f"  [{label}]")
                sections.append('━'*64)
                sections.append(out.strip()[:500])
            except Exception as e:
                self.warn(f"Check failed [{label}]: {e}")

        # ── Pattern-based findings ─────────────────────────────────────────────
        for key, patterns in self.SUSPICIOUS_PATTERNS.items():
            text = collected.get(key, '')
            if not text:
                continue
            for pattern, severity, title, recommendation in patterns:
                if re.search(pattern, text, re.MULTILINE | re.IGNORECASE):
                    self.finding(
                        title          = title,
                        description    = f"Found in [{key}]:\n\n{text[:400]}",
                        severity       = severity,
                        recommendation = recommendation,
                        mitre_id       = self.mitre_id,
                    )
                    self.emit('finding.created', severity=severity, title=title, plugin=self.name)
                    findings_created += 1

        # ── Non-Microsoft scheduled tasks ─────────────────────────────────────
        if platform == 'windows':
            schtask = collected.get('schtasks_custom', '')
            if schtask.strip():
                self.finding(
                    title          = "Non-Microsoft Scheduled Tasks Detected",
                    description    = schtask[:500],
                    severity       = "Medium",
                    recommendation = "Review all non-Microsoft scheduled tasks for legitimacy. Remove unauthorized entries.",
                    mitre_id       = "T1053.005",
                )
                findings_created += 1

        # ── Recently modified system files (Linux) ────────────────────────────
        if platform == 'linux':
            recent = collected.get('recent_changes', '')
            if recent.strip():
                count = len(recent.strip().splitlines())
                if count > 3:
                    self.finding(
                        title          = f"Recently Modified System Files ({count} files)",
                        description    = recent[:400],
                        severity       = "Medium",
                        recommendation = "Investigate recent modifications to system binaries — may indicate trojanized binaries or backdoors.",
                        mitre_id       = "T1554",
                    )
                    findings_created += 1

        # ── Systemd user services (Linux) ─────────────────────────────────────
        if platform == 'linux':
            systemd_user = collected.get('systemd_user_enabled', '')
            if systemd_user.strip():
                self.finding(
                    title          = "User Systemd Services Detected",
                    description    = systemd_user[:500],
                    severity       = "Medium",
                    recommendation = "Review user systemd services for legitimacy. These run without root privileges.",
                    mitre_id       = "T1543.002",
                )
                findings_created += 1

        # ── Azure AD / Entra ID joined device ─────────────────────────────────
        if platform == 'windows':
            dsreg = collected.get('dsreg', '')
            if 'AzureAdJoined' in dsreg and 'YES' in dsreg:
                self.finding(
                    title          = "Device Joined to Azure AD / Entra ID",
                    description    = "Device is joined to Azure AD — check for cloud-based persistence (PRT, OAuth apps, service principals).",
                    severity       = "Info",
                    recommendation = "Audit Azure AD device registrations, app consents, and service principal credentials.",
                    mitre_id       = "T1098.005",
                )
                findings_created += 1

        # ── WSL distributions ─────────────────────────────────────────────────
        if platform == 'windows':
            wsl = collected.get('wsl_dists', '')
            if wsl.strip():
                self.finding(
                    title          = "WSL Distributions Detected",
                    description    = wsl[:500],
                    severity       = "Info",
                    recommendation = "WSL distributions can be used for Linux-based persistence on Windows. Audit WSL filesystems.",
                    mitre_id       = "T1547.001",
                )
                findings_created += 1

        self.info(f"persistence-check complete — {findings_created} findings created.")
        return '\n'.join(sections) if sections else "No persistence mechanisms found."

    def _detect_platform(self, session) -> str:
        """Detect the remote platform from session metadata or probing."""
        for attr in ('OS', 'os', '_os', 'platform'):
            val = getattr(session, attr, None)
            if val and isinstance(val, str):
                val_l = val.lower()
                if 'windows' in val_l:
                    return 'windows'
                if 'linux' in val_l or 'unix' in val_l:
                    return 'linux'
        try:
            out = self._exec(session, 'echo %OS%', timeout=5) or ''
            if 'Windows' in out:
                return 'windows'
        except Exception:
            pass
        return 'linux'