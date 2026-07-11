#!/usr/bin/env python3
"""
NexShell Plugin — Network Scout v4.0 (Network Intelligence Engine)
Smart network discovery with adaptive scanning, risk scoring, and auto-chaining.

Features:
  - SmartContext: OS/privilege/network_type/previous_loot awareness
  - Adaptive Scanning: stealth/balanced/aggressive modes
  - Risk Scoring Engine: calculates risk per host/service
  - Decision Engine: auto-recommends next actions
  - Plugin Chaining: triggers smb-enum, cred-harvest, etc.
  - Memory System: learns from previous scans
  - Structured Loot: JSON schema instead of strings
  - Smart Output: tables + colors + next actions
  - Confidence System: low/medium/high/verified
  - Noise Budget: prevents overload
  - Environment Detection: K8s/Cloud/DevOps auto-detection
  - MITRE Dynamic Mapping: auto-maps findings to tactics

Usage:
    (NexShell)> plugins run network-scout
    (NexShell)> plugins run network-scout --mode stealth
    (NexShell)> plugins run network-scout --mode aggressive
    (NexShell)> plugins run network-scout --subnet 192.168.1.0/24
    (NexShell)> plugins run network-scout --auto-chain
"""

import re
import json
import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes (Structured Data) ──────────────────────────────────────────

@dataclass
class Service:
    """Structured service profile."""
    port: int
    name: str
    banner: str = ""
    auth: str = "unknown"  # none, basic, strong, unknown
    exposure: str = "internal"  # internal, external, cloud
    risk_score: int = 0
    confidence: str = "medium"  # low, medium, high, verified
    mitre_id: str = "T1046"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Host:
    """Structured host profile."""
    ip: str
    os: str = "unknown"
    role: str = "unknown"  # server, workstation, dc, container, unknown
    services: List[Service] = field(default_factory=list)
    risk_score: int = 0
    environment: str = "unknown"  # on-prem, cloud, k8s, container
    confidence: str = "medium"
    first_seen: str = ""
    last_seen: str = ""
    
    def __post_init__(self):
        if not self.first_seen:
            self.first_seen = datetime.utcnow().isoformat()
        self.last_seen = datetime.utcnow().isoformat()
    
    def to_dict(self) -> dict:
        d = asdict(self)
        d['services'] = [s.to_dict() if hasattr(s, 'to_dict') else s for s in self.services]
        return d


@dataclass
class Action:
    """Recommended next action."""
    plugin: str
    priority: str  # low, medium, high, critical
    reason: str
    target: str = ""
    confidence: str = "medium"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SmartFinding:
    """Enhanced finding with confidence & evidence."""
    title: str
    severity: str
    description: str
    recommendation: str
    mitre_id: str
    host: str = ""
    service: str = ""
    confidence: str = "medium"
    evidence: str = ""
    next_actions: List[Action] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        d = asdict(self)
        d['next_actions'] = [a.to_dict() for a in self.next_actions]
        return d


# ── Risk Scoring Engine ─────────────────────────────────────────────────────

class RiskEngine:
    """Calculates risk scores for hosts and services."""
    
    # Base risk scores by service
    SERVICE_RISK = {
        'Telnet': 90, 'FTP': 70, 'rexec': 85, 'rlogin': 85, 'rsh': 85,
        'Redis': 80, 'Memcached': 85, 'Elasticsearch': 75,
        'MongoDB': 80, 'CouchDB': 80, 'Kubelet-API': 95,
        'etcd': 95, 'ClickHouse': 70, 'InfluxDB': 75,
        'SMB': 60, 'RDP': 65, 'SSH': 30, 'HTTP': 40, 'HTTPS': 30,
        'MySQL': 50, 'PostgreSQL': 50, 'MSSQL': 55,
        'Docker-Socket': 100, 'K8s-API': 90,
    }
    
    # Modifiers
    AUTH_MODIFIER = {'none': 1.5, 'basic': 1.0, 'strong': 0.5, 'unknown': 1.2}
    EXPOSURE_MODIFIER = {'external': 1.5, 'internal': 1.0, 'cloud': 1.3}
    ROLE_MODIFIER = {'dc': 1.5, 'server': 1.2, 'workstation': 1.0, 'container': 1.3}
    
    @classmethod
    def score_service(cls, service: Service) -> int:
        base = cls.SERVICE_RISK.get(service.name, 50)
        auth_mult = cls.AUTH_MODIFIER.get(service.auth, 1.0)
        exp_mult = cls.EXPOSURE_MODIFIER.get(service.exposure, 1.0)
        score = int(base * auth_mult * exp_mult)
        return min(100, score)
    
    @classmethod
    def score_host(cls, host: Host) -> int:
        if not host.services:
            return 0
        role_mult = cls.ROLE_MODIFIER.get(host.role, 1.0)
        avg_service = sum(s.risk_score for s in host.services) / len(host.services)
        max_service = max(s.risk_score for s in host.services)
        # Weighted: 60% max, 40% average
        score = int((0.6 * max_service + 0.4 * avg_service) * role_mult)
        return min(100, score)
    
    @classmethod
    def classify_risk(cls, score: int) -> str:
        if score >= 80: return "critical"
        if score >= 60: return "high"
        if score >= 40: return "medium"
        if score >= 20: return "low"
        return "info"


# ── Memory System ───────────────────────────────────────────────────────────

class MemorySystem:
    """Persists knowledge across scans."""
    
    def __init__(self):
        self._hosts: Dict[str, Host] = {}
        self._patterns: Set[str] = set()
        self._tags: Set[str] = set()
    
    def remember_host(self, host: Host):
        key = host.ip
        if key in self._hosts:
            # Merge: update last_seen, append new services
            existing = self._hosts[key]
            existing.last_seen = host.last_seen
            existing_ports = {s.port for s in existing.services}
            for s in host.services:
                if s.port not in existing_ports:
                    existing.services.append(s)
            existing.risk_score = max(existing.risk_score, host.risk_score)
        else:
            self._hosts[key] = host
    
    def get_host(self, ip: str) -> Optional[Host]:
        return self._hosts.get(ip)
    
    def has_scanned(self, ip: str) -> bool:
        return ip in self._hosts
    
    def add_tag(self, tag: str):
        self._tags.add(tag)
    
    def get_tags(self) -> Set[str]:
        return self._tags
    
    def detect_patterns(self, hosts: List[Host]):
        """Auto-detect network patterns."""
        ips = [h.ip for h in hosts]
        
        # Cloud network patterns
        if any(ip.startswith('10.0.') for ip in ips):
            self.add_tag("cloud-vpc")
        if any(ip.startswith('172.16.') or ip.startswith('172.31.') for ip in ips):
            self.add_tag("aws-vpc")
        if any(ip.startswith('192.168.') for ip in ips):
            self.add_tag("internal-network")
        
        # Service patterns
        services = [s.name for h in hosts for s in h.services]
        if services.count('K8s-API') > 0:
            self.add_tag("kubernetes-cluster")
        if services.count('etcd') > 0:
            self.add_tag("etcd-cluster")
        if services.count('Consul') > 0:
            self.add_tag("service-mesh")
        if services.count('Prometheus') > 0:
            self.add_tag("observability-stack")
        if services.count('Jenkins') > 0 or services.count('GitLab') > 0:
            self.add_tag("cicd-pipeline")
    
    def summary(self) -> dict:
        return {
            "hosts_known": len(self._hosts),
            "tags": list(self._tags),
            "high_risk_hosts": [
                h.ip for h in self._hosts.values() if h.risk_score >= 80
            ]
        }


# ── Decision Engine ─────────────────────────────────────────────────────────

class DecisionEngine:
    """Recommends next actions based on discovered services — mapped to actual plugins."""
    
    # Rules: (service_name, plugin, priority, reason, args)
    RULES = [
        # ── Lateral Movement ────────────────────────────────────────────
        ('SMB', 'lateral_mover', 'high', 
         'SMB detected — enumerate shares, NTLM relay, lateral movement',
         ['--target', '{host}', '--focus', 'smb']),
        ('RDP', 'lateral_mover', 'medium',
         'RDP detected — check NLA, credentials, lateral movement',
         ['--target', '{host}', '--focus', 'rdp']),
        ('SSH', 'lateral_mover', 'medium',
         'SSH detected — check keys, password auth, pivot',
         ['--target', '{host}', '--focus', 'ssh']),
        ('Telnet', 'lateral_mover', 'critical',
         'Telnet detected — insecure, likely default credentials',
         ['--target', '{host}', '--focus', 'telnet']),
        
        # ── Active Directory ────────────────────────────────────────────
        ('LDAP', 'ad_attack', 'critical',
         'LDAP detected — AD enumeration, Kerberoast, DCSync paths',
         ['--enumerate-only']),
        ('LDAPS', 'ad_attack', 'critical',
         'LDAPS detected — secure AD, check for misconfigs',
         ['--enumerate-only']),
        ('MSRPC', 'ad_attack', 'high',
         'MSRPC detected — potential AD RPC services',
         ['--enumerate-only']),
        
        # ── Credential Hunting (Web/DB) ─────────────────────────────────
        ('HTTP', 'cred_hunter', 'high',
         'HTTP detected — hunt for web configs, .env, credentials',
         ['--target', '{host}']),
        ('HTTPS', 'cred_hunter', 'high',
         'HTTPS detected — hunt for web configs, secrets',
         ['--target', '{host}']),
        ('HTTP-Alt', 'cred_hunter', 'medium',
         'Alt HTTP detected — may be Jenkins/GitLab/DevOps',
         ['--target', '{host}']),
        ('MySQL', 'cred_hunter', 'high',
         'MySQL detected — hunt for DB credentials in configs',
         ['--target', '{host}']),
        ('PostgreSQL', 'cred_hunter', 'high',
         'PostgreSQL detected — hunt for DB credentials',
         ['--target', '{host}']),
        ('MSSQL', 'cred_hunter', 'high',
         'MSSQL detected — hunt for DB credentials',
         ['--target', '{host}']),
        ('MongoDB', 'cred_hunter', 'critical',
         'MongoDB exposed — check for auth bypass, credentials',
         ['--target', '{host}']),
        ('Redis', 'cred_hunter', 'critical',
         'Redis exposed — check for AUTH bypass, data exfil',
         ['--target', '{host}']),
        ('Elasticsearch', 'cred_hunter', 'high',
         'Elasticsearch exposed — check for credentials, data leak',
         ['--target', '{host}']),
        ('Jenkins', 'cred_hunter', 'critical',
         'Jenkins detected — hunt for CI/CD secrets, credentials',
         ['--target', '{host}']),
        ('Prometheus', 'cred_hunter', 'medium',
         'Prometheus exposed — check metrics, auth',
         ['--target', '{host}']),
        ('Grafana', 'cred_hunter', 'medium',
         'Grafana exposed — check default credentials (admin/admin)',
         ['--target', '{host}']),
        ('Vault', 'cred_hunter', 'critical',
         'Vault detected — secrets exposure risk',
         ['--target', '{host}']),
        ('Consul', 'cred_hunter', 'high',
         'Consul exposed — check for KV secrets',
         ['--target', '{host}']),
        
        # ── Container & K8s Escape ──────────────────────────────────────
        ('K8s-API', 'container_escape', 'critical',
         'K8s API exposed — check RBAC, SA token, cluster-admin',
         ['--k8s-only']),
        ('K8s-Kubelet', 'container_escape', 'critical',
         'Kubelet API exposed — unauthenticated RCE risk',
         ['--k8s-only']),
        ('K8s-Kubelet-RO', 'container_escape', 'critical',
         'Kubelet read-only API exposed — info leak',
         ['--k8s-only']),
        ('etcd', 'container_escape', 'critical',
         'etcd exposed — full cluster takeover possible',
         ['--k8s-only']),
        ('Docker-Socket', 'container_escape', 'critical',
         'Docker socket exposed — trivial host escape',
         []),
        ('Istio-Envoy', 'container_escape', 'high',
         'Istio Envoy exposed — service mesh abuse',
         ['--k8s-only']),
        
        # ── Cloud Recon ─────────────────────────────────────────────────
        ('AWS-IMDS', 'cloud_recon', 'critical',
         'AWS IMDS accessible — IAM role credential theft',
         ['--provider', 'aws']),
        ('GCP-IMDS', 'cloud_recon', 'critical',
         'GCP IMDS accessible — service account token theft',
         ['--provider', 'gcp']),
        ('Azure-IMDS', 'cloud_recon', 'critical',
         'Azure IMDS accessible — managed identity theft',
         ['--provider', 'azure']),
    ]
    
    # Host-level rules (based on OS/role detection)
    HOST_RULES = [
        # (role, plugin, priority, reason, args)
        ('dc', 'ad_attack', 'critical',
         'Domain Controller detected — full AD attack suite',
         ['--full']),
        ('k8s-node', 'container_escape', 'critical',
         'K8s node detected — container escape assessment',
         ['--k8s-only']),
        ('web-server', 'cred_hunter', 'high',
         'Web server detected — hunt for credentials in web configs',
         ['--target', '{host}']),
        ('db-server', 'cred_hunter', 'high',
         'Database server detected — hunt for DB credentials',
         ['--target', '{host}']),
    ]
    
    # Post-exploitation chain (after initial access)
    POST_EXPLOIT_CHAIN = [
        ('windows', 'auto_enum_windows', 'high',
         'Windows host — run post-exploitation enumeration',
         ['--ps']),
        ('linux', 'auto_enum_linux', 'high',
         'Linux host — run post-exploitation enumeration',
         []),
        ('linux', 'privesc_scanner', 'high',
         'Linux host — run privilege escalation scanner',
         ['--thorough']),
        ('any', 'persistence_check', 'medium',
         'Check for persistence mechanisms',
         []),
    ]
    
    @classmethod
    def recommend(cls, host: Host, context: dict = None) -> List[Action]:
        """Recommend plugins based on discovered services and host role."""
        actions = []
        seen_plugins = set()
        context = context or {}
        
        # Service-based rules
        for service in host.services:
            for svc_name, plugin, priority, reason, args_template in cls.RULES:
                if svc_name.lower() == service.name.lower() and plugin not in seen_plugins:
                    # Replace {host} in args
                    args = [a.format(host=host.ip) if '{host}' in a else a for a in args_template]
                    actions.append(Action(
                        plugin=plugin,
                        priority=priority,
                        reason=reason,
                        target=f"{host.ip}:{service.port}",
                        confidence=service.confidence,
                        args=args
                    ))
                    seen_plugins.add(plugin)
        
        # Host role-based rules
        for role, plugin, priority, reason, args_template in cls.HOST_RULES:
            if role == host.role and plugin not in seen_plugins:
                args = [a.format(host=host.ip) if '{host}' in a else a for a in args_template]
                actions.append(Action(
                    plugin=plugin,
                    priority=priority,
                    reason=reason,
                    target=host.ip,
                    confidence=host.confidence,
                    args=args
                ))
                seen_plugins.add(plugin)
        
        # Post-exploitation chain (if context indicates compromised)
        if context.get('post_exploit', False):
            for os_type, plugin, priority, reason, args in cls.POST_EXPLOIT_CHAIN:
                if (os_type == 'any' or os_type == host.os) and plugin not in seen_plugins:
                    actions.append(Action(
                        plugin=plugin,
                        priority=priority,
                        reason=reason,
                        target=host.ip,
                        confidence='medium',
                        args=args
                    ))
                    seen_plugins.add(plugin)
        
        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        actions.sort(key=lambda a: priority_order.get(a.priority, 99))
        return actions[:10]  # Top 10 actions

# ── Smart Output Formatter ──────────────────────────────────────────────────

class SmartOutput:
    """Formats output as structured tables with colors."""
    
    @staticmethod
    def host_table(hosts: List[Host]) -> str:
        if not hosts:
            return "No hosts discovered."
        
        lines = []
        lines.append("\n╔════════════════════════════════════════════════════════════════════╗")
        lines.append("║                    HOST DISCOVERY SUMMARY                          ║")
        lines.append("╠════════════════════════════════════════════════════════════════════╣")
        
        for host in hosts:
            risk_class = RiskEngine.classify_risk(host.risk_score)
            risk_icon = {
                'critical': '🔴', 'high': '🟠', 'medium': '🟡',
                'low': '🟢', 'info': '⚪'
            }.get(risk_class, '⚪')
            
            lines.append(f"║ HOST: {host.ip:<20} ROLE: {host.role:<15} {risk_icon} RISK: {risk_class.upper():<8} ║")
            lines.append(f"║ ENV: {host.environment:<18} OS: {host.os:<18} SCORE: {host.risk_score:<3}        ║")
            
            if host.services:
                lines.append("║ SERVICES:                                                          ║")
                for s in host.services:
                    s_risk = RiskEngine.classify_risk(s.risk_score)
                    s_icon = {
                        'critical': '🔴', 'high': '🟠', 'medium': '🟡',
                        'low': '🟢', 'info': '⚪'
                    }.get(s_risk, '⚪')
                    lines.append(f"║   {s_icon} {s.port:<5} {s.name:<20} auth={s.auth:<8} conf={s.confidence:<8} ║")
            
            lines.append("╠════════════════════════════════════════════════════════════════════╣")
        
        lines.append("╚════════════════════════════════════════════════════════════════════╝")
        return '\n'.join(lines)
    
    @staticmethod
    def actions_table(actions: List[Action]) -> str:
        if not actions:
            return "No next actions recommended."
        
        lines = []
        lines.append("\n╔════════════════════════════════════════════════════════════════════╗")
        lines.append("║                    RECOMMENDED NEXT ACTIONS                        ║")
        lines.append("╠════════════════════════════════════════════════════════════════════╣")
        
        priority_icons = {
            'critical': '🚨', 'high': '⚠️', 'medium': '📋', 'low': '📝'
        }
        
        for action in actions[:10]:
            icon = priority_icons.get(action.priority, '•')
            lines.append(f"║ {icon} [{action.priority.upper():<8}] {action.plugin:<20}              ║")
            lines.append(f"║     Target: {action.target:<30}                           ║")
            lines.append(f"║     Reason: {action.reason:<50} ║")
            lines.append("╠────────────────────────────────────────────────────────────────────╣")
        
        lines.append("╚════════════════════════════════════════════════════════════════════╝")
        return '\n'.join(lines)
    
    @staticmethod
    def metrics_table(metrics: dict) -> str:
        lines = []
        lines.append("\n╔════════════════════════════════════════════════════════════════════╗")
        lines.append("║                         SCAN METRICS                               ║")
        lines.append("╠════════════════════════════════════════════════════════════════════╣")
        for key, value in metrics.items():
            lines.append(f"║ {key:<30}: {str(value):<30} ║")
        lines.append("╚════════════════════════════════════════════════════════════════════╝")
        return '\n'.join(lines)


# ── Main Plugin ─────────────────────────────────────────────────────────────

class NetworkScout(NexPlugin):
    name        = "network-scout"
    description = "Smart network intelligence engine — adaptive scanning, risk scoring, auto-chaining"
    author      = "vulnquest58"
    version     = "4.0"
    platform    = "all"
    category    = "recon"
    mitre_id    = "T1046"
    
    # ── Port configurations by mode ─────────────────────────────────────────
    PORT_MODES = {
        'stealth': [22, 80, 443, 445, 3389],
        'balanced': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                     1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                     9200, 27017],
        'aggressive': None,  # Will use INTERESTING_PORTS
        'k8s': [6443, 10250, 10255, 10256, 2379, 2380, 30000, 30001, 30002],
        'devops': [8080, 9090, 3000, 5601, 8200, 8500, 4646, 16686, 9092,
                   4222, 5672, 15672, 1883],
        'cloud': [169, 2379, 6443, 8200, 8500, 9090, 3000, 5601],
    }
    
    # ── Comprehensive port list (2025/2026 services) ──────────────────────────
    INTERESTING_PORTS = {
        # Traditional Services
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 79: "Finger",
        80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
        143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 512: "Rexec", 513: "Rlogin", 514: "RSH/Syslog", 515: "LPD",
        587: "SMTP-Sub", 631: "IPP", 636: "LDAPS", 873: "Rsync", 993: "IMAPS",
        995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
        2049: "NFS", 2222: "Alt-SSH", 3306: "MySQL", 3389: "RDP",
        4369: "RabbitMQ-EPM", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
        6379: "Redis", 7001: "WebLogic", 7077: "Spark", 8009: "AJP",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter", 9000: "PHP-FPM",
        9200: "Elasticsearch", 9300: "ES-Cluster", 11211: "Memcached",
        27017: "MongoDB", 50000: "SAP",
        
        # Kubernetes & Cloud Native
        6443: "K8s-API", 10250: "K8s-Kubelet", 10255: "K8s-Kubelet-RO",
        10256: "K8s-Kube-Proxy", 2379: "etcd", 2380: "etcd-Peer",
        30000: "K8s-NodePort",
        
        # DevOps & CI/CD
        9090: "Prometheus", 3000: "Grafana", 5601: "Kibana",
        9093: "Alertmanager", 9094: "Alertmanager-Cluster",
        8200: "Vault", 8500: "Consul", 8300: "Consul-gRPC",
        4646: "Nomad", 16686: "Jaeger-UI", 14268: "Jaeger-Collector",
        
        # Message Brokers
        9092: "Kafka", 4222: "NATS", 5672: "RabbitMQ-AMQP",
        15672: "RabbitMQ-Mgmt", 1883: "MQTT",
        
        # Modern Databases
        8123: "ClickHouse", 9042: "Cassandra", 8086: "InfluxDB",
        
        # API & Service Mesh
        50051: "gRPC", 15001: "Istio-Envoy", 15006: "Istio-Inbound",
        15090: "Istio-Prom", 4317: "OTLP-gRPC", 4318: "OTLP-HTTP",
        
        # Legacy
        137: "NetBIOS-NS", 138: "NetBIOS-DG",
    }
    
    # ── Noise Budget ─────────────────────────────────────────────────────────
    NOISE_BUDGET = {
        'stealth': {'max_hosts': 5, 'max_ports': 10, 'timeout': 3, 'delay': 2.0},
        'balanced': {'max_hosts': 20, 'max_ports': 50, 'timeout': 5, 'delay': 0.5},
        'aggressive': {'max_hosts': 100, 'max_ports': 200, 'timeout': 10, 'delay': 0.1},
    }
    
    def __init__(self):
        super().__init__()
        self.memory = MemorySystem()
        self.metrics = {
            'scan_start': None,
            'scan_end': None,
            'hosts_found': 0,
            'services_found': 0,
            'high_risk_hosts': 0,
            'critical_findings': 0,
            'actions_recommended': 0,
        }
    
    def run(self, session, args: list):
        self.metrics['scan_start'] = time.time()
        
        # Parse args
        mode = 'balanced'
        subnet = None
        ports = None
        ipv6 = False
        auto_chain = False
        custom_ports = None
        
        for a in (args or []):
            if a.startswith('--mode='):
                mode = a.split('=', 1)[1]
            elif a == '--mode' and args and args.index(a) + 1 < len(args):
                mode = args[args.index(a) + 1]
            elif a.startswith('--subnet='):
                subnet = a.split('=', 1)[1]
            elif a.startswith('--ports='):
                try:
                    custom_ports = [int(p) for p in a.split('=', 1)[1].split(',')]
                except ValueError:
                    pass
            elif a == '--ipv6':
                ipv6 = True
            elif a == '--auto-chain':
                auto_chain = True
        
        # Validate mode
        if mode not in self.PORT_MODES and mode not in self.NOISE_BUDGET:
            mode = 'balanced'
        
        self.info(f"🧠 Starting network-scout v4.0 (mode={mode}, auto-chain={auto_chain})")
        
        # ── Step 1: Build SmartContext ─────────────────────────────────────
        platform = self._detect_platform(session)
        budget = self.NOISE_BUDGET.get(mode, self.NOISE_BUDGET['balanced'])
        
        context = {
            'platform': platform,
            'mode': mode,
            'budget': budget,
            'ipv6': ipv6,
            'auto_chain': auto_chain,
        }
        
        sections = []
        sections.append(f"\n[*] Mode: {mode.upper()}")
        sections.append(f"[*] Platform: {platform}")
        sections.append(f"[*] Budget: max_hosts={budget['max_hosts']}, max_ports={budget['max_ports']}, timeout={budget['timeout']}s")
        
        # ── Step 2: Determine subnet ─────────────────────────────────────
        if not subnet:
            subnet = self._get_local_subnet(session, platform)
        sections.append(f"[*] Target subnet: {subnet}")
        
        # ── Step 3: Check for nmap ───────────────────────────────────────
        nmap_available = self._check_nmap(session, platform)
        if nmap_available:
            sections.append("[+] nmap detected — using advanced scanning")
        
        # ── Step 4: Ping sweep ─────────────────────────────────────────
        ping_cmd = self._build_ping_sweep(subnet, platform, mode == 'aggressive')
        sections.append(f"[*] Ping sweep: {ping_cmd[:80]}...")
        
        hosts_found = []
        try:
            ping_out = self._exec(session, ping_cmd)
            if ping_out:
                ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ping_out)
                hosts_found = list(dict.fromkeys(ips))[:budget['max_hosts']]
                self.loot(
                    {"type": "ping_sweep", "subnet": subnet, "hosts": hosts_found},
                    category='network',
                    source='network-scout:ping-sweep',
                    confidence='high'
                )
                sections.append(f"[+] Alive hosts ({len(hosts_found)}): {', '.join(hosts_found[:20])}")
        except Exception as e:
            self.warn(f"Ping sweep failed: {e}")
        
        # ── Step 5: IPv6 discovery ─────────────────────────────────────
        ipv6_hosts = []
        if ipv6:
            ipv6_cmd = self._build_ipv6_sweep(platform)
            ipv6_out = self._exec(session, ipv6_cmd)
            if ipv6_out:
                ipv6_addrs = re.findall(r'([0-9a-fA-F:]{7,})', ipv6_out)
                ipv6_hosts = list(dict.fromkeys(ipv6_addrs))[:budget['max_hosts']]
                sections.append(f"[+] IPv6 hosts ({len(ipv6_hosts)}): {', '.join(ipv6_hosts[:10])}")
        
        # ── Step 6: ARP/NDP discovery ─────────────────────────────────
        arp_cmd = "ip neigh 2>/dev/null || arp -a 2>/dev/null" if platform == 'linux' else "arp -a"
        arp_out = self._exec(session, arp_cmd)
        if arp_out:
            arp_ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', arp_out)
            for ip in arp_ips:
                if ip not in hosts_found:
                    hosts_found.append(ip)
            hosts_found = hosts_found[:budget['max_hosts']]
            sections.append(f"[+] ARP/NDP table ({len(arp_ips)} entries)")
        
        # ── Step 7: Determine ports to scan ───────────────────────────
        if custom_ports:
            scan_ports = custom_ports
        elif mode in self.PORT_MODES and self.PORT_MODES[mode]:
            scan_ports = self.PORT_MODES[mode]
        else:
            scan_ports = list(self.INTERESTING_PORTS.keys())
        
        scan_ports = scan_ports[:budget['max_ports']]
        
        # ── Step 8: Port sweep ────────────────────────────────────────
        discovered_hosts: List[Host] = []
        all_actions: List[Action] = []
        
        for ip in hosts_found:
            # Skip if already scanned and recent
            if self.memory.has_scanned(ip):
                cached = self.memory.get_host(ip)
                if cached:
                    discovered_hosts.append(cached)
                    actions = DecisionEngine.recommend(cached)
                    all_actions.extend(actions)
                    continue
            
            # Scan
            if nmap_available:
                open_ports, banners = self._nmap_scan(session, ip, scan_ports, platform)
            else:
                open_ports = self._port_sweep(session, ip, scan_ports, platform)
                banners = {}
            
            if open_ports:
                # Build services
                services = []
                for port in open_ports:
                    service_name = self.INTERESTING_PORTS.get(port, f"Unknown-{port}")
                    banner = banners.get(port, "")
                    
                    service = Service(
                        port=port,
                        name=service_name,
                        banner=banner,
                        auth=self._guess_auth(service_name),
                        exposure=self._guess_exposure(ip),
                        confidence='medium'
                    )
                    service.risk_score = RiskEngine.score_service(service)
                    services.append(service)
                
                # Build host
                host = Host(
                    ip=ip,
                    os=self._guess_os(services),
                    role=self._guess_role(services),
                    services=services,
                    environment=self._detect_environment(services)
                )
                host.risk_score = RiskEngine.score_host(host)
                
                discovered_hosts.append(host)
                self.memory.remember_host(host)
                
                # Get actions
                actions = DecisionEngine.recommend(host)
                all_actions.extend(actions)
                
                # Structured loot
                self.loot(
                    host.to_dict(),
                    category='network',
                    source=f'network-scout:host:{ip}',
                    confidence='high'
                )
        
        # ── Step 9: Detect patterns ─────────────────────────────────
        self.memory.detect_patterns(discovered_hosts)
        tags = self.memory.get_tags()
        
        if tags:
            sections.append(f"\n[+] Network patterns detected: {', '.join(tags)}")
        
        # ── Step 10: Create findings ────────────────────────────────
        findings_created = 0
        critical_findings = 0
        
        danger_services = {
            'Telnet', 'FTP', 'rexec', 'rlogin', 'rsh',
            'Redis', 'Memcached', 'Elasticsearch',
            'MongoDB', 'CouchDB', 'Kubelet-API',
            'etcd', 'ClickHouse', 'InfluxDB'
        }
        
        for host in discovered_hosts:
            for service in host.services:
                if service.name in danger_services:
                    finding = SmartFinding(
                        title=f"Insecure Service: {service.name} on {host.ip}:{service.port}",
                        severity=RiskEngine.classify_risk(service.risk_score),
                        description=f"{service.name} detected on {host.ip}:{service.port} — commonly unauthenticated or exposes sensitive data.",
                        recommendation=f"Restrict {service.name} access with firewall rules. Enable authentication. Use TLS encryption.",
                        mitre_id=self.mitre_id,
                        host=host.ip,
                        service=service.name,
                        confidence=service.confidence,
                        evidence=f"Port {service.port} open, banner: {service.banner[:100] if service.banner else 'N/A'}",
                        next_actions=DecisionEngine.recommend(host)
                    )
                    
                    self.finding(
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity,
                        recommendation=finding.recommendation,
                        mitre_id=finding.mitre_id,
                    )
                    self.emit(
                        'finding.created',
                        severity=finding.severity,
                        title=finding.title,
                        plugin=self.name,
                        confidence=finding.confidence,
                        host=finding.host
                    )
                    
                    findings_created += 1
                    if finding.severity in ('critical', 'high'):
                        critical_findings += 1
                    
                    # Structured finding loot
                    self.loot(
                        finding.to_dict(),
                        category='findings',
                        source=f'network-scout:finding:{host.ip}:{service.port}',
                        confidence=finding.confidence
                    )
        
        # ── Step 11: SMB enumeration ────────────────────────────────
        for host in discovered_hosts:
            smb_service = next((s for s in host.services if s.port == 445), None)
            if smb_service:
                smb_cmd = self._build_smb_enum(host.ip, platform)
                smb_out = self._exec(session, smb_cmd)
                if smb_out:
                    self.loot(
                        {"type": "smb_enum", "host": host.ip, "output": smb_out[:500]},
                        category='network',
                        source=f'network-scout:smb:{host.ip}'
                    )
                    sections.append(f"[+] SMB ({host.ip}):\n{smb_out[:400]}")
                    
                    # SMBv1 detection
                    if 'dialect' in smb_out.lower() and 'nt lm 0.12' in smb_out.lower():
                        self.finding(
                            title=f"SMBv1 Enabled on {host.ip}",
                            description=f"SMBv1 detected on {host.ip} — vulnerable to EternalBlue (CVE-2017-0144).",
                            severity="Critical",
                            recommendation="Disable SMBv1 immediately. Upgrade to SMBv3 with encryption.",
                            mitre_id="T1210",
                        )
                        findings_created += 1
                        critical_findings += 1
        
        # ── Step 12: Smart Output ─────────────────────────────────
        sections.append(SmartOutput.host_table(discovered_hosts))
        sections.append(SmartOutput.actions_table(all_actions[:10]))
        
        # ── Step 13: Metrics ──────────────────────────────────────
        self.metrics['scan_end'] = time.time()
        self.metrics['hosts_found'] = len(discovered_hosts)
        self.metrics['services_found'] = sum(len(h.services) for h in discovered_hosts)
        self.metrics['high_risk_hosts'] = sum(1 for h in discovered_hosts if h.risk_score >= 60)
        self.metrics['critical_findings'] = critical_findings
        self.metrics['actions_recommended'] = len(all_actions)
        self.metrics['scan_duration'] = round(self.metrics['scan_end'] - self.metrics['scan_start'], 2)
        
        sections.append(SmartOutput.metrics_table(self.metrics))
        
        # ── Step 14: Auto-chain ─────────────────────────────────
        if auto_chain and all_actions:
            sections.append("\n[*] Auto-chaining enabled — triggering next plugins...")
            triggered = set()
            for action in all_actions[:5]:
                if action.plugin not in triggered and action.priority in ('critical', 'high'):
                    sections.append(f"  → Triggering: {action.plugin} (target: {action.target})")
                    try:
                        self._trigger_plugin(session, action.plugin, action.target)
                        triggered.add(action.plugin)
                    except Exception as e:
                        self.warn(f"Failed to trigger {action.plugin}: {e}")
        
        # ── Summary ─────────────────────────────────────────────
        self.info(
            f"🧠 network-scout complete — "
            f"{len(discovered_hosts)} hosts, "
            f"{self.metrics['services_found']} services, "
            f"{findings_created} findings, "
            f"{len(all_actions)} actions recommended"
        )
        
        return '\n'.join(sections)
    
    # ── Helpers ────────────────────────────────────────────────────────────────
    
    def _guess_auth(self, service_name: str) -> str:
        """Guess authentication level based on service."""
        no_auth = {'Redis', 'Memcached', 'MongoDB', 'Elasticsearch',
                   'CouchDB', 'Kubelet-API', 'etcd', 'ClickHouse', 'InfluxDB'}
        if service_name in no_auth:
            return 'none'
        if service_name in {'SSH', 'HTTPS', 'LDAPS'}:
            return 'strong'
        if service_name in {'HTTP', 'FTP', 'Telnet', 'SMTP'}:
            return 'basic'
        return 'unknown'
    
    def _guess_exposure(self, ip: str) -> str:
        """Guess exposure based on IP."""
        if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
            return 'internal'
        if ip.startswith('169.254.'):
            return 'cloud'
        return 'external'
    
    def _guess_os(self, services: List[Service]) -> str:
        """Guess OS based on services."""
        service_names = {s.name for s in services}
        if 'SMB' in service_names or 'MSRPC' in service_names:
            return 'windows'
        if 'SSH' in service_names:
            return 'linux'
        return 'unknown'
    
    def _guess_role(self, services: List[Service]) -> str:
        """Guess role based on services."""
        service_names = {s.name for s in services}
        if 'K8s-API' in service_names or 'etcd' in service_names:
            return 'k8s-node'
        if 'SMB' in service_names and 'MSRPC' in service_names:
            return 'dc' if 'LDAP' in service_names else 'server'
        if 'HTTP' in service_names or 'HTTPS' in service_names:
            return 'web-server'
        if 'MySQL' in service_names or 'PostgreSQL' in service_names or 'MSSQL' in service_names:
            return 'db-server'
        return 'server'
    
    def _detect_environment(self, services: List[Service]) -> str:
        """Detect environment type."""
        service_names = {s.name for s in services}
        if 'K8s-API' in service_names or 'Kubelet-API' in service_names:
            return 'kubernetes'
        if 'etcd' in service_names or 'Consul' in service_names:
            return 'cloud-native'
        if 'Prometheus' in service_names or 'Grafana' in service_names:
            return 'devops'
        return 'on-prem'
    
    def _check_nmap(self, session, platform: str) -> bool:
        try:
            if platform == 'windows':
                cmd = "where.exe nmap 2>nul"
            else:
                cmd = "which nmap 2>/dev/null"
            out = self._exec(session, cmd)
            return 'nmap' in out.lower()
        except Exception:
            return False
    
    def _get_local_subnet(self, session, platform: str) -> str:
        try:
            if platform == 'linux':
                out = self._exec(session, "ip addr show | grep 'inet ' | grep -v '127.0.0.1'")
            else:
                out = self._exec(session, "ipconfig | findstr IPv4")
            ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}', out)
            if ips:
                return f"{ips[0]}.0/24"
        except Exception:
            pass
        return "192.168.1.0/24"
    
    def _build_ping_sweep(self, subnet: str, platform: str, aggressive: bool) -> str:
        base = '.'.join(subnet.split('.')[:3])
        if platform == 'linux':
            if aggressive:
                return f"for i in $(seq 1 254); do ping -c1 -W1 {base}.$i &>/dev/null && echo {base}.$i & done; wait"
            return f"for i in $(seq 1 254); do (ping -c1 -W1 {base}.$i &>/dev/null && echo {base}.$i) & done; wait"
        else:
            return (
                f'powershell -nop -c "$sub=\\"{base}.\\"; '
                '1..254 | % { (New-Object System.Net.NetworkInformation.Ping).SendAsync($sub + $_, 100) }; '
                'Start-Sleep -m 200; arp -a | Select-String -Pattern $sub"'
            )
    
    def _build_ipv6_sweep(self, platform: str) -> str:
        if platform == 'linux':
            return "ip -6 neigh show | awk '{print $1}'"
        else:
            return "powershell -c \"Get-NetNeighbor -AddressFamily IPv6 | Select-Object IPAddress\""
    
    def _nmap_scan(self, session, host: str, ports: list, platform: str) -> tuple:
        port_list = ','.join(str(p) for p in ports)
        cmd = f"nmap -sV -sC -p {port_list} --open -T4 {host} 2>/dev/null"
        out = self._exec(session, cmd)
        
        open_ports = []
        banners = {}
        
        for line in out.splitlines():
            match = re.search(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?', line)
            if match:
                port = int(match.group(1))
                service = match.group(2)
                banner = match.group(3) or service
                open_ports.append(port)
                banners[port] = banner
        
        return open_ports, banners
    
    def _port_sweep(self, session, host: str, ports: list, platform: str) -> list:
        open_ports = []
        if platform == 'linux':
            port_list = ' '.join(str(p) for p in ports)
            cmd = (
                f"for p in {port_list}; do "
                f"(echo >/dev/tcp/{host}/$p) 2>/dev/null && echo $p; "
                f"done"
            )
            out = self._exec(session, cmd)
            for line in out.splitlines():
                line = line.strip()
                if line.isdigit():
                    open_ports.append(int(line))
        else:
            for port in ports[:15]:
                cmd = f"powershell -c (Test-NetConnection {host} -Port {port}).TcpTestSucceeded 2>nul"
                out = self._exec(session, cmd)
                if 'True' in out:
                    open_ports.append(port)
        return open_ports
    
    def _build_smb_enum(self, host: str, platform: str) -> str:
        if platform == 'linux':
            return f"smbclient -L {host} -N 2>/dev/null || nmblookup -A {host} 2>/dev/null"
        else:
            return f"net view \\\\{host} 2>nul"
    
    def _trigger_plugin(self, session, plugin_name: str, target: str):
        """Trigger another plugin with target."""
        try:
            # Try to access plugin manager
            if hasattr(session, 'plugin_manager'):
                session.plugin_manager.run(plugin_name, [f'--target={target}'])
            elif hasattr(self, 'chain'):
                self.chain([plugin_name], args=[f'--target={target}'])
        except Exception as e:
            self.warn(f"Plugin chaining failed for {plugin_name}: {e}")
    
    def _detect_platform(self, session) -> str:
        for attr in ('OS', 'os', '_os', 'platform'):
            val = getattr(session, attr, None)
            if val and isinstance(val, str):
                val_l = val.lower()
                if 'windows' in val_l:
                    return 'windows'
                if 'linux' in val_l or 'unix' in val_l:
                    return 'linux'
        try:
            out = self._exec(session, 'echo %OS%') or ''
            if 'Windows' in out:
                return 'windows'
        except Exception:
            pass
        return 'linux'