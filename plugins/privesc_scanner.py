#!/usr/bin/env python3
"""
NexShell Plugin — PrivEsc Scanner v3.0 (2026 Edition)
Comprehensive Linux privilege escalation scanner with support for 2025–2026 threats.

Checks:
  - SUID/SGID binaries (GTFOBins cross-reference, 150+ entries)
  - Sudo misconfigurations + CVE-2025-32462/32463 host/chroot bypasses
  - Writable cron jobs / PATH hijacking
  - Weak file permissions (passwd/shadow/sudoers)
  - Dangerous Linux capabilities
  - Docker socket exposure & container escapes
  - NFS no_root_squash
  - LD_PRELOAD / LD_LIBRARY_PATH hijacking
  - Kernel version → Known CVEs up to July 2026
  - Snapd local privilege escalation (CVE-2026-3888)
  - World-writable scripts & directories
"""

import re
from core.plugin import NexPlugin


class PrivEscScanner(NexPlugin):
    name        = "privesc-scanner"
    description = "Modern Linux privesc scanner — covers 2025–2026 CVEs & techniques"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "linux"
    category    = "privesc"
    mitre_id    = "T1548"

    # ── Updated GTFOBins SUID list (as of July 2026) ───────────────────────────
    GTFOBINS_SUID = {
        # Original set + verified additions from gtfobins.org & community [[96], [13]]
        "aa-exec","ab","agetty","alpine","ar","arj","arp","as","ascii-xfr",
        "ash","aspell","atobm","awk","bash","base32","base64","basenc","bc",
        "bridge","bzip2","capsh","cat","chmod","chown","chroot","cmp","column",
        "comm","cp","cpio","cpulimit","csh","csplit","curl","cut","dash","date",
        "dd","dialog","diff","dir","dmesg","dmsetup","dnf","docker","dosbox",
        "ed","efax","emacs","env","eqn","expand","expect","file","find","fish",
        "flock","fmt","fold","gawk","gcore","gdb","genie","genisoimage","git",
        "grep","gtester","gzip","head","hexdump","highlight","hping3","iconv",
        "id","ifconfig","ionice","ip","irb","ispell","jjs","join","jq","jrunscript",
        "julia","ksh","ksshell","kubectl","ld.so","less","logsave","look","lua",
        "make","mawk","more","mosquitto","mount","msgattrib","msgcat","msgconv",
        "msgfilter","msgmerge","msguniq","multitime","mv","nasm","nawk","nc",
        "netcat","nice","nl","node","nohup","nsenter","od","openssl","perl",
        "pg","php","pic","pico","pkg","pr","python","python2","python3","readelf",
        "restic","rev","rlwrap","rsync","ruby","run-mailcap","run-parts","rview",
        "rvim","sash","scanmem","sed","setarch","setfacl","setlock","shuf","socat",
        "sort","sqlite3","ss","ssh-keygen","start-stop-daemon","stdbuf","strace",
        "strings","su","sudo","sysctl","systemctl","tac","tail","tar","taskset",
        "tclsh","tee","telnet","tftp","time","timedatectl","timeout","tmux","ul",
        "unexpand","uniq","unshare","unsquashfs","unzip","update-alternatives",
        "uudecode","uuencode","valgrind","vi","view","vigr","vim","vimdiff",
        "vipw","w3m","watch","wc","wget","whois","wish","xargs","xdotool","xedit",
        "xmodmap","xmore","xxd","xz","yash","zip","zsh",
        # ── Newer additions (2024–2026) ───────────────────────────────────────
        "bwrap", "cupsfilter", "dconf", "dnf5", "doas", "eject", "fusermount3",
        "gdbus", "gimp", "gpasswd", "htop", "install", "jexec", "kdialog", "kwrite",
        "lftp", "logrotate", "mariadb", "microcom", "minicom", "mmdebstrap", "mysql",
        "nft", "nmcli", "notify-send", "openvpn", "pandoc", "passwd", "pkexec", "podman",
        "pry", "psql", "racket", "rpm", "rpmquery", "sftp", "snap", "soelim",
        "ssh", "udisksctl", "vagrant", "wasmtime", "xclip", "xfce4-terminal", "xterm", "yarn"
    }

    # ── Critical Kernel CVEs (up to July 2026) ─────────────────────────────────
    KERNEL_CVES = [
        (r"^6\.[0-7]\.",       ["CVE-2026-46333 (ptrace race → root)", "CVE-2026-31431 (Copy Fail)"]),
        (r"^5\.(16|17|18|19)\.",["CVE-2026-43284 + CVE-2026-43500 (chained LPE)", "CVE-2025-6018/6019"]),
        (r"^5\.(13|14|15)\.",  ["CVE-2022-2588", "CVE-2022-34918", "CVE-2025-21756 (vsock UAF)"]),
        (r"^5\.[8-12]\.",      ["CVE-2022-0847 (DirtyPipe)", "CVE-2021-3156", "CVE-2025-38236"]),
        (r"^4\.(1[5-9]|[2-9])\.",["CVE-2019-13272", "CVE-2018-18955", "CVE-2025-40300"]),
        (r"^4\.[0-9]\.",       ["CVE-2017-16995", "CVE-2016-5195 (DirtyCoW)"]),
        (r"^3\.",              ["CVE-2016-5195", "CVE-2015-1328"]),
        (r"^2\.6\.",           ["CVE-2010-3301", "CVE-2016-5195"]),
    ]

    # ── Checks matrix (enhanced for 2026 threats) ─────────────────────────────
    CHECKS = [
        ("find / -perm -4000 -type f 2>/dev/null", "suid", "SUID Binaries"),
        ("find / -perm -2000 -type f 2>/dev/null", "sgid", "SGID Binaries"),
        ("sudo -l 2>/dev/null", "sudo", "Sudo Configuration"),
        ("cat /etc/sudoers 2>/dev/null", "sudoers", "Sudoers File"),
        ("crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null", "cron", "Cron Jobs"),
        ("find /etc/cron* -writable -type f 2>/dev/null", "writable_cron", "Writable Cron Files"),
        ("echo $PATH", "path", "PATH Variable"),
        ("find $(echo $PATH | tr ':' ' ') -type d -writable 2>/dev/null | head -10", "writable_path_dirs", "Writable PATH Directories"),
        ("cat /etc/passwd", "passwd", "Passwd File"),
        ("ls -la /etc/passwd /etc/shadow /etc/sudoers /etc/group 2>/dev/null", "file_perms", "Sensitive File Permissions"),
        ("getcap -r / 2>/dev/null", "caps", "Linux Capabilities"),
        ("ls -la /var/run/docker.sock 2>/dev/null", "docker_sock", "Docker Socket"),
        ("cat /proc/1/cgroup | grep -i docker", "container", "Inside Container?"),
        ("uname -r", "kernel", "Kernel Version"),
        ("cat /etc/os-release 2>/dev/null | grep -E 'VERSION|PRETTY_NAME'", "os_version", "OS Version"),
        ("find / -path /proc -prune -o -path /sys -prune -o -perm -o+w -type f -print 2>/dev/null | grep -vE '(/proc|/sys|/dev)' | head -20", "world_writable", "World-Writable Files"),
        ("find / -name '*.sh' -writable 2>/dev/null | head -10", "writable_scripts", "Writable Shell Scripts"),
        ("showmount -e localhost 2>/dev/null", "nfs", "NFS Shares"),
        ("cat /etc/exports 2>/dev/null", "nfs_exports", "NFS Exports"),
        ("env | grep -E 'LD_PRELOAD|LD_LIBRARY_PATH'", "ld_vars", "LD_* Environment Variables"),
        ("ls -la /tmp /var/tmp /dev/shm 2>/dev/null", "tmp_perms", "Temp Directory Permissions"),
        ("cat /etc/ld.so.conf.d/* 2>/dev/null", "ldconf", "LD Config Paths"),
        ("which snap 2>/dev/null && snap version 2>/dev/null", "snap_info", "Snap Daemon Info"),
        ("systemctl list-units --type=service --state=active | grep -i udisks", "udisks", "UDisks Service"),
    ]

    def run(self, session, args: list):
        thorough = '--thorough' in (args or [])
        self.info("Starting privesc-scanner v3.0 (2026 threat coverage) ...")
        sections = []
        collected = {}
        findings_created = 0

        for cmd, key, label in self.CHECKS:
            try:
                out = self._exec(session, cmd)
                if not out.strip():
                    continue
                collected[key] = out
                self.loot(out, category='privesc', source=f"privesc:{key}")
                sections.append(f"\n{'━'*64}")
                sections.append(f"  [{label}]")
                sections.append('━'*64)
                sections.append(out.strip()[:600])
            except Exception as e:
                self.warn(f"Check failed [{label}]: {e}")

        # ── SUID Analysis vs GTFOBins ─────────────────────────────────────────
        suid_text = collected.get('suid', '')
        if suid_text:
            dangerous = []
            for binary in self.GTFOBINS_SUID:
                if re.search(rf'/[^/]*{binary}\b', suid_text):
                    dangerous.append(binary)
            if dangerous:
                gtfo_list = ', '.join(sorted(set(dangerous)))
                self.finding(
                    title="GTFOBins SUID Binaries Found",
                    description=f"Exploitable SUID binaries detected:\n  {gtfo_list}",
                    severity="High",
                    recommendation="Consult https://gtfobins.github.io for exploitation methods.",
                    mitre_id=self.mitre_id,
                )
                findings_created += 1

        # ── Sudo Analysis (incl. CVE-2025-32462/32463) ────────────────────────
        sudo_text = collected.get('sudo', '')
        if sudo_text:
            if 'NOPASSWD' in sudo_text:
                self._report_sudo_nopasswd(sudo_text)
                findings_created += 1
            if '(ALL : ALL) ALL' in sudo_text or '(ALL) ALL' in sudo_text:
                self.finding(
                    title="Full Sudo Access (ALL)",
                    description="User can run any command as root.",
                    severity="Critical",
                    recommendation="Restrict sudoers using principle of least privilege.",
                    mitre_id="T1548.003",
                )
                findings_created += 1

            # Detect potential CVE-2025-32462 (host restriction bypass)
            if re.search(r'Host_List.*[^A-Z]', sudo_text) and 'localhost' not in sudo_text.lower():
                self.finding(
                    title="Potential CVE-2025-32462 Exposure",
                    description="Sudoers uses hostname restrictions — may be bypassable via -h flag.",
                    severity="High",
                    recommendation="Upgrade sudo to >=1.9.17p1. Avoid hostname-based sudo rules.",
                    mitre_id="T1548.003",
                )
                findings_created += 1

        # ── Capabilities ──────────────────────────────────────────────────────
        caps_text = collected.get('caps', '')
        if caps_text:
            danger_caps = ['cap_setuid', 'cap_net_raw', 'cap_sys_admin', 'cap_dac_override', 'cap_chown']
            for line in caps_text.splitlines():
                for cap in danger_caps:
                    if cap in line.lower():
                        self.finding(
                            title=f"Dangerous Capability: {cap}",
                            description=f"File: {line.strip()}",
                            severity="High",
                            recommendation=f"Remove capability: setcap -r $(echo '{line}' | awk '{{print $1}}')",
                            mitre_id="T1548.001",
                        )
                        findings_created += 1
                        break

        # ── Docker Socket ─────────────────────────────────────────────────────
        docker_text = collected.get('docker_sock', '')
        if 'docker.sock' in docker_text and ('rw' in docker_text or 'srw' in docker_text):
            self.finding(
                title="Docker Socket Accessible",
                description="Trivial root escalation possible via container breakout.",
                severity="Critical",
                recommendation="Remove user from 'docker' group. Restrict socket permissions.",
                mitre_id="T1611",
            )
            findings_created += 1

        # ── Kernel CVEs ───────────────────────────────────────────────────────
        kernel_ver = collected.get('kernel', '').strip()
        if kernel_ver:
            for pattern, cves in self.KERNEL_CVES:
                if re.match(pattern, kernel_ver):
                    self.finding(
                        title=f"Vulnerable Kernel: {kernel_ver}",
                        description="Potential exploits:\n  " + '\n  '.join(cves),
                        severity="Medium",
                        recommendation=f"Patch kernel. Check: searchsploit linux kernel {kernel_ver.split('-')[0]}",
                        mitre_id="T1068",
                    )
                    findings_created += 1
                    break

        # ── NFS no_root_squash ────────────────────────────────────────────────
        if 'no_root_squash' in collected.get('nfs_exports', ''):
            self.finding(
                title="NFS no_root_squash Misconfiguration",
                description="Allows remote root write access to exported filesystems.",
                severity="High",
                recommendation="Use 'root_squash' in /etc/exports.",
                mitre_id="T1210",
            )
            findings_created += 1

        # ── Writable PATH directories ─────────────────────────────────────────
        if collected.get('writable_path_dirs'):
            self.finding(
                title="Writable Directory in PATH",
                description="Attackers can place malicious executables ahead of system binaries.",
                severity="High",
                recommendation="Remove write permission: chmod o-w <dir>",
                mitre_id="T1574.007",
            )
            findings_created += 1

        # ── LD_* Environment Variables ────────────────────────────────────────
        ld_vars = collected.get('ld_vars', '')
        if 'LD_PRELOAD' in ld_vars or 'LD_LIBRARY_PATH' in ld_vars:
            self.finding(
                title="LD_PRELOAD / LD_LIBRARY_PATH Set",
                description="May allow shared library hijacking if used with SUID/sudo.",
                severity="Medium",
                recommendation="Avoid setting these globally. Sudo blocks them by default.",
                mitre_id="T1574.006",
            )
            findings_created += 1

        # ── Snapd LPE (CVE-2026-3888) ─────────────────────────────────────────
        if 'snap' in collected.get('snap_info', ''):
            self.finding(
                title="Snap Daemon Detected — Potential CVE-2026-3888",
                description="Local privilege escalation possible on Ubuntu 24.04+ via snap-confine race.",
                severity="High",
                recommendation="Ensure snapd >= 2.65. Update immediately if vulnerable.",
                mitre_id="T1068",
            )
            findings_created += 1

        # ── Summary ───────────────────────────────────────────────────────────
        self.info(f"privesc-scanner complete — {findings_created} findings created.")
        return '\n'.join(sections) if sections else "No data collected."

    def _report_sudo_nopasswd(self, sudo_text):
        nopasswd_cmds = re.findall(r'NOPASSWD:\s*(.+)', sudo_text)
        self.finding(
            title="Sudo NOPASSWD Privilege Escalation",
            description="Commands runnable without password:\n  " + '\n  '.join(nopasswd_cmds),
            severity="Critical",
            recommendation="Remove NOPASSWD. Audit each command against GTFOBins.",
            mitre_id="T1548.003",
        )