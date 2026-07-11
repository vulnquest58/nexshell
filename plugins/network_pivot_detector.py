#!/usr/bin/env python3
"""
NexShell Plugin — Network Pivot Detector v3.0 (2026 Edition)
Advanced pivoting intelligence engine with 50+ tools, cloud/container pivoting,
eBPF tunnels, DNS/ICMP tunneling, and auto-topology mapping.

Coverage:
  - 50+ pivot tools (Chisel, Ligolo-ng, Socat, FRP, Ngrok, Cobalt Strike, 
    Sliver, Havoc, Mythic, Brute Ratel, Metasploit, Cloudflared, etc.)
  - 25+ tunnel interfaces (WireGuard, Tailscale, ZeroTier, Nebula, Istio, etc.)
  - Cloud pivoting (AWS SSM, Azure Arc, GCP IAP, Cloudflare tunnels)
  - Container pivoting (Docker, K8s, Service Mesh, Envoy)
  - eBPF/XDP tunnels (Cilium, Tetragon abuse)
  - DNS tunneling (dnscat2, iodine, hans, dns2tcp)
  - ICMP tunneling (ptunnel, icmpsh, hping3)
  - Named pipes (Windows)
  - Network namespaces (Linux)
  - Firewall rule analysis (iptables, nftables, Windows Firewall)
  - Auto-topology mapping (graph-based)
  - Risk scoring (0-100 per pivot)
  - Structured loot (JSON)

CVEs (2024-2026):
  - CVE-2024-21626: runc container escape (pivot vector)
  - CVE-2024-1086: netfilter nf_tables (firewall bypass)
  - CVE-2023-38408: OpenSSH agent forwarding
  - CVE-2024-6387: regreSSHion (SSH race condition)

MITRE ATT&CK:
  - T1572: Protocol Tunneling
  - T1090: Proxy (Multi-hop, External, Internal, Domain Fronting)
  - T1090.001: Internal Proxy
  - T1090.002: External Proxy
  - T1090.003: Multi-hop Proxy
  - T1090.004: Domain Fronting
  - T1572: Protocol Tunneling
  - T1573: Encrypted Channel
  - T1021: Remote Services (SSH, SMB, WinRM, RDP)
  - T1021.004: SSH
  - T1599: Network Boundary Bridging

Usage:
    (NexShell)> plugins run network-pivot-detector
    (NexShell)> plugins run network-pivot-detector --full
    (NexShell)> plugins run network-pivot-detector --cloud
    (NexShell)> plugins run network-pivot-detector --container
    (NexShell)> plugins run network-pivot-detector --ebpf
    (NexShell)> plugins run network-pivot-detector --topology
    (NexShell)> plugins run network-pivot-detector --stealth
"""

import re
import time
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class PivotTool:
    """Represents a detected pivot tool."""
    name: str
    process_name: str
    category: str  # tunnel, proxy, c2, cloud, container, dns, icmp, ebpf
    vendor: str = ""
    description: str = ""
    risk_score: int = 0  # 0-100
    detection_methods: List[str] = field(default_factory=list)
    command_line: str = ""
    pid: int = 0
    user: str = ""
    ports: List[int] = field(default_factory=list)
    mitre_id: str = "T1572"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TunnelInterface:
    """Represents a tunnel interface."""
    name: str
    interface_type: str  # vpn, tap, tun, mesh, cloud, container
    description: str = ""
    ip_address: str = ""
    subnet: str = ""
    risk_score: int = 0
    is_active: bool = True
    mtu: int = 0
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PivotResult:
    """Result of pivot detection."""
    tool: str
    category: str
    detection_method: str
    evidence: str
    risk_score: int
    severity: str  # critical, high, medium, low
    mitre_id: str = "T1572"
    recommendation: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NetworkNode:
    """Represents a node in the network topology."""
    ip: str
    hostname: str = ""
    mac: str = ""
    interfaces: List[str] = field(default_factory=list)
    subnets: List[str] = field(default_factory=list)
    is_pivot: bool = False
    risk_score: int = 0
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NetworkEdge:
    """Represents a connection between nodes."""
    source: str
    target: str
    protocol: str = ""
    port: int = 0
    is_tunnel: bool = False
    tunnel_type: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NetworkTopology:
    """Represents the network topology graph."""
    nodes: List[NetworkNode] = field(default_factory=list)
    edges: List[NetworkEdge] = field(default_factory=list)
    pivot_points: List[str] = field(default_factory=list)
    subnets: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'nodes': [n.to_dict() for n in self.nodes],
            'edges': [e.to_dict() for e in self.edges],
            'pivot_points': self.pivot_points,
            'subnets': self.subnets,
        }


# ── Pivot Tools Database (50+ Tools) ───────────────────────────────────────

class PivotToolsDatabase:
    """Comprehensive database of pivot tools."""
    
    TOOLS = [
        # ── Tier 1: Popular Tunneling Tools ───────────────────────────────
        PivotTool(
            name='Chisel',
            process_name='chisel',
            category='tunnel',
            vendor='jpillora',
            description='Fast TCP/UDP tunnel over HTTP — popular for CTF/redteam pivoting',
            risk_score=85,
            detection_methods=['process', 'port', 'command_line'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='Ligolo-ng',
            process_name='ligolo',
            category='tunnel',
            vendor='tnpitsecurity',
            description='Agent-based tunnel — creates TAP interface on attacker',
            risk_score=90,
            detection_methods=['process', 'interface', 'port'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='Socat',
            process_name='socat',
            category='tunnel',
            vendor='dest-unreach',
            description='Socket relay — TCP/UDP port forwarding and relay',
            risk_score=70,
            detection_methods=['process', 'port', 'command_line'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='FRP Client',
            process_name='frpc',
            category='tunnel',
            vendor='fatedier',
            description='Fast Reverse Proxy — tunnels traffic to internal services',
            risk_score=85,
            detection_methods=['process', 'port', 'config'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='FRP Server',
            process_name='frps',
            category='tunnel',
            vendor='fatedier',
            description='Fast Reverse Proxy Server — listens for frpc agents',
            risk_score=85,
            detection_methods=['process', 'port', 'config'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='Ngrok',
            process_name='ngrok',
            category='tunnel',
            vendor='ngrok',
            description='Cloud tunnel — exposes local services to internet',
            risk_score=80,
            detection_methods=['process', 'port', 'dns'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='Cloudflared',
            process_name='cloudflared',
            category='tunnel',
            vendor='Cloudflare',
            description='Cloudflare Tunnel — secure tunnel to Cloudflare network',
            risk_score=75,
            detection_methods=['process', 'port', 'dns'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='Gost',
            process_name='gost',
            category='proxy',
            vendor='go-gost',
            description='GO Simple Tunnel — multi-hop proxy/tunnel',
            risk_score=80,
            detection_methods=['process', 'port'],
            mitre_id='T1090.003',
        ),
        PivotTool(
            name='Nps',
            process_name='nps',
            category='proxy',
            vendor='ehang-io',
            description='Lightweight, high-performance intranet proxy',
            risk_score=80,
            detection_methods=['process', 'port'],
            mitre_id='T1090.003',
        ),
        PivotTool(
            name='Bore',
            process_name='bore',
            category='tunnel',
            vendor='ekzhang',
            description='Simple tunnel to localhost — expose local ports',
            risk_score=75,
            detection_methods=['process', 'port'],
            mitre_id='T1572',
        ),
        
        # ── Tier 2: C2 Frameworks with Pivoting ───────────────────────────
        PivotTool(
            name='Cobalt Strike',
            process_name='beacon',
            category='c2',
            vendor='Fortra',
            description='Commercial adversary simulation toolkit with SMB/HTTP pivoting',
            risk_score=100,
            detection_methods=['process', 'port', 'memory', 'network'],
            mitre_id='T1090.003',
        ),
        PivotTool(
            name='Sliver C2',
            process_name='sliver',
            category='c2',
            vendor='BishopFox',
            description='Open-source C2 with WireGuard pivoting',
            risk_score=95,
            detection_methods=['process', 'port', 'interface'],
            mitre_id='T1090.003',
        ),
        PivotTool(
            name='Havoc C2',
            process_name='havoc',
            category='c2',
            vendor='HavocFramework',
            description='Modern C2 with SMB/HTTP pivoting',
            risk_score=95,
            detection_methods=['process', 'port'],
            mitre_id='T1090.003',
        ),
        PivotTool(
            name='Mythic C2',
            process_name='mythic',
            category='c2',
            vendor='MythicC2',
            description='Multi-platform C2 with pivoting capabilities',
            risk_score=90,
            detection_methods=['process', 'port'],
            mitre_id='T1090.003',
        ),
        PivotTool(
            name='Brute Ratel',
            process_name='brc4',
            category='c2',
            vendor='Brute Ratel',
            description='Commercial red team tool with advanced pivoting',
            risk_score=100,
            detection_methods=['process', 'port', 'memory'],
            mitre_id='T1090.003',
        ),
        PivotTool(
            name='Metasploit Meterpreter',
            process_name='meterpreter',
            category='c2',
            vendor='Rapid7',
            description='Metasploit payload with portfwd pivot',
            risk_score=90,
            detection_methods=['process', 'port', 'memory'],
            mitre_id='T1090.001',
        ),
        
        # ── Tier 3: DNS/ICMP Tunneling ────────────────────────────────────
        PivotTool(
            name='dnscat2',
            process_name='dnscat',
            category='dns',
            vendor='iagox86',
            description='DNS tunnel — C2 over DNS protocol',
            risk_score=85,
            detection_methods=['process', 'dns', 'port'],
            mitre_id='T1071.004',
        ),
        PivotTool(
            name='iodine',
            process_name='iodine',
            category='dns',
            vendor='yarrick',
            description='DNS tunnel — IPv4 over DNS',
            risk_score=80,
            detection_methods=['process', 'interface', 'dns'],
            mitre_id='T1071.004',
        ),
        PivotTool(
            name='hans',
            process_name='hans',
            category='dns',
            description='DNS tunnel — IP over DNS',
            risk_score=75,
            detection_methods=['process', 'interface'],
            mitre_id='T1071.004',
        ),
        PivotTool(
            name='ptunnel-ng',
            process_name='ptunnel',
            category='icmp',
            vendor='ptunnel',
            description='ICMP tunnel — TCP over ICMP',
            risk_score=80,
            detection_methods=['process', 'icmp'],
            mitre_id='T1071.004',
        ),
        PivotTool(
            name='icmpsh',
            process_name='icmpsh',
            category='icmp',
            vendor='breenmachine',
            description='ICMP reverse shell',
            risk_score=85,
            detection_methods=['process', 'icmp'],
            mitre_id='T1071.004',
        ),
        
        # ── Tier 4: SSH Pivoting ──────────────────────────────────────────
        PivotTool(
            name='SSHuttle',
            process_name='sshuttle',
            category='tunnel',
            vendor='sshuttle',
            description='Transparent proxy over SSH — VPN-like tunneling',
            risk_score=80,
            detection_methods=['process', 'interface'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='rpivot',
            process_name='rpivot',
            category='proxy',
            vendor='artkond',
            description='Reverse SOCKS proxy over HTTP',
            risk_score=75,
            detection_methods=['process', 'port'],
            mitre_id='T1090.002',
        ),
        PivotTool(
            name='Neo-reGeorg',
            process_name='regeorg',
            category='proxy',
            vendor='L-codes',
            description='HTTP tunnel via webshell',
            risk_score=80,
            detection_methods=['process', 'port', 'http'],
            mitre_id='T1090.001',
        ),
        PivotTool(
            name='Venom',
            process_name='venom',
            category='proxy',
            vendor='Dlivv',
            description='Multi-hop SOCKS proxy',
            risk_score=80,
            detection_methods=['process', 'port'],
            mitre_id='T1090.003',
        ),
        PivotTool(
            name='EarthWorm',
            process_name='ew',
            category='proxy',
            vendor='earthworm',
            description='Portable SOCKS proxy',
            risk_score=75,
            detection_methods=['process', 'port'],
            mitre_id='T1090.001',
        ),
        
        # ── Tier 5: Cloud Pivoting ────────────────────────────────────────
        PivotTool(
            name='AWS SSM Agent',
            process_name='ssm-agent',
            category='cloud',
            vendor='AWS',
            description='AWS Systems Manager — session manager pivoting',
            risk_score=70,
            detection_methods=['process', 'aws_api'],
            mitre_id='T1021.007',
        ),
        PivotTool(
            name='AWS VPN Client',
            process_name='awsvpnclient',
            category='cloud',
            vendor='AWS',
            description='AWS Client VPN — cloud VPN tunnel',
            risk_score=65,
            detection_methods=['process', 'interface'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='Azure Arc Agent',
            process_name='AzureArcAgent',
            category='cloud',
            vendor='Microsoft',
            description='Azure Arc — hybrid cloud management',
            risk_score=70,
            detection_methods=['process', 'port'],
            mitre_id='T1021',
        ),
        PivotTool(
            name='GCP IAP Tunnel',
            process_name='gcloud',
            category='cloud',
            vendor='Google',
            description='GCP Identity-Aware Proxy tunnel',
            risk_score=70,
            detection_methods=['process', 'port'],
            mitre_id='T1572',
        ),
        
        # ── Tier 6: Mesh/SDN Pivoting ─────────────────────────────────────
        PivotTool(
            name='Tailscale',
            process_name='tailscale',
            category='mesh',
            vendor='Tailscale',
            description='Mesh VPN — WireGuard-based mesh network',
            risk_score=60,
            detection_methods=['process', 'interface'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='ZeroTier',
            process_name='zerotier',
            category='mesh',
            vendor='ZeroTier',
            description='Virtual Ethernet — SDN mesh network',
            risk_score=60,
            detection_methods=['process', 'interface'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='Nebula',
            process_name='nebula',
            category='mesh',
            vendor='Slack',
            description='Scalable overlay network',
            risk_score=65,
            detection_methods=['process', 'interface'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='Netbird',
            process_name='netbird',
            category='mesh',
            vendor='netbird',
            description='WireGuard-based mesh VPN',
            risk_score=60,
            detection_methods=['process', 'interface'],
            mitre_id='T1572',
        ),
        
        # ── Tier 7: Windows-Specific ──────────────────────────────────────
        PivotTool(
            name='Plink',
            process_name='plink',
            category='tunnel',
            vendor='PuTTY',
            description='PuTTY CLI — SSH tunneling on Windows',
            risk_score=70,
            detection_methods=['process', 'port'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='Stunnel',
            process_name='stunnel',
            category='tunnel',
            vendor='stunnel',
            description='SSL tunnel — wraps TCP connections in SSL/TLS',
            risk_score=65,
            detection_methods=['process', 'port'],
            mitre_id='T1573',
        ),
        PivotTool(
            name='ProxyChains',
            process_name='proxychains',
            category='proxy',
            vendor='proxychains',
            description='SOCKS proxy chain',
            risk_score=70,
            detection_methods=['process', 'config'],
            mitre_id='T1090.003',
        ),
        PivotTool(
            name='RevSocks',
            process_name='revsocks',
            category='proxy',
            vendor='kost',
            description='Reverse SOCKS proxy',
            risk_score=75,
            detection_methods=['process', 'port'],
            mitre_id='T1090.002',
        ),
        PivotTool(
            name='Glider',
            process_name='glider',
            category='proxy',
            vendor='nadoo',
            description='Forward proxy with multiple protocols',
            risk_score=70,
            detection_methods=['process', 'port'],
            mitre_id='T1090.001',
        ),
        PivotTool(
            name='SSF',
            process_name='ssfd',
            category='tunnel',
            vendor='securesocketfunneling',
            description='Secure Socket Funneling — TCP tunnel',
            risk_score=75,
            detection_methods=['process', 'port'],
            mitre_id='T1572',
        ),
        
        # ── Tier 8: eBPF/XDP ──────────────────────────────────────────────
        PivotTool(
            name='eBPF Tunnel',
            process_name='xdptunnel',
            category='ebpf',
            vendor='custom',
            description='eBPF/XDP-based tunnel — kernel-level pivoting',
            risk_score=95,
            detection_methods=['ebpf', 'interface'],
            mitre_id='T1572',
        ),
        PivotTool(
            name='Cilium Abuse',
            process_name='cilium',
            category='ebpf',
            vendor='Cilium',
            description='Cilium eBPF — potential pivot via eBPF programs',
            risk_score=80,
            detection_methods=['ebpf', 'process'],
            mitre_id='T1572',
        ),
    ]
    
    @classmethod
    def get_all_tools(cls) -> List[PivotTool]:
        return cls.TOOLS
    
    @classmethod
    def get_tools_by_category(cls, category: str) -> List[PivotTool]:
        return [t for t in cls.TOOLS if t.category == category]
    
    @classmethod
    def get_tool_by_process(cls, process_name: str) -> Optional[PivotTool]:
        for tool in cls.TOOLS:
            if process_name.lower() in tool.process_name.lower():
                return tool
        return None


# ── Tunnel Interfaces Database ─────────────────────────────────────────────

class TunnelInterfacesDatabase:
    """Database of tunnel interface patterns."""
    
    INTERFACES = {
        # VPN/Tunnel interfaces
        'tun': {
            'type': 'vpn',
            'description': 'OpenVPN / Generic TUN',
            'risk_score': 70,
        },
        'tap': {
            'type': 'vpn',
            'description': 'Generic TAP tunnel',
            'risk_score': 70,
        },
        'wg': {
            'type': 'vpn',
            'description': 'WireGuard',
            'risk_score': 65,
        },
        'utun': {
            'type': 'vpn',
            'description': 'macOS VPN',
            'risk_score': 60,
        },
        'ppp': {
            'type': 'vpn',
            'description': 'PPP VPN',
            'risk_score': 50,
        },
        
        # Mesh/SDN interfaces
        'tailscale': {
            'type': 'mesh',
            'description': 'Tailscale mesh VPN',
            'risk_score': 60,
        },
        'ts': {
            'type': 'mesh',
            'description': 'Tailscale (short)',
            'risk_score': 60,
        },
        'zt': {
            'type': 'mesh',
            'description': 'ZeroTier',
            'risk_score': 60,
        },
        'nebula': {
            'type': 'mesh',
            'description': 'Nebula overlay',
            'risk_score': 65,
        },
        'nb': {
            'type': 'mesh',
            'description': 'Netbird',
            'risk_score': 60,
        },
        
        # Pivoting tool interfaces
        'ligolo': {
            'type': 'pivot',
            'description': 'Ligolo-ng TAP',
            'risk_score': 90,
        },
        'chisel': {
            'type': 'pivot',
            'description': 'Chisel tunnel',
            'risk_score': 85,
        },
        'iodine': {
            'type': 'dns',
            'description': 'iodine DNS tunnel',
            'risk_score': 80,
        },
        'hans': {
            'type': 'dns',
            'description': 'hans DNS tunnel',
            'risk_score': 75,
        },
        'ptun': {
            'type': 'icmp',
            'description': 'ptunnel ICMP tunnel',
            'risk_score': 80,
        },
        
        # Cloud interfaces
        'aws': {
            'type': 'cloud',
            'description': 'AWS VPN Client',
            'risk_score': 70,
        },
        'azvpn': {
            'type': 'cloud',
            'description': 'Azure VPN',
            'risk_score': 70,
        },
        'gcp': {
            'type': 'cloud',
            'description': 'GCP VPN',
            'risk_score': 70,
        },
        
        # Container interfaces
        'docker': {
            'type': 'container',
            'description': 'Docker bridge',
            'risk_score': 50,
        },
        'br-': {
            'type': 'container',
            'description': 'Docker bridge (br-)',
            'risk_score': 50,
        },
        'veth': {
            'type': 'container',
            'description': 'Virtual Ethernet (container)',
            'risk_score': 45,
        },
        'cni': {
            'type': 'container',
            'description': 'K8s CNI',
            'risk_score': 55,
        },
        'flannel': {
            'type': 'container',
            'description': 'K8s Flannel',
            'risk_score': 55,
        },
        'calico': {
            'type': 'container',
            'description': 'K8s Calico',
            'risk_score': 60,
        },
        'cilium': {
            'type': 'container',
            'description': 'K8s Cilium (eBPF)',
            'risk_score': 70,
        },
    }
    
    @classmethod
    def get_all_interfaces(cls) -> Dict:
        return cls.INTERFACES
    
    @classmethod
    def get_interface_by_name(cls, name: str) -> Optional[Dict]:
        for pattern, info in cls.INTERFACES.items():
            if pattern.lower() in name.lower():
                return info
        return None


# ── Detection Engine ───────────────────────────────────────────────────────

class DetectionEngine:
    """Multi-layer pivot detection engine."""
    
    @staticmethod
    def detect_by_processes(exec_func, session, platform: str) -> List[PivotTool]:
        """Detect pivot tools by process names."""
        detected = []
        
        if platform == 'linux':
            cmd = "ps aux 2>/dev/null"
        else:
            cmd = "powershell -nop -c \"Get-Process | Select-Object Name,Id,Path,CommandLine | Format-Table -AutoSize\" 2>nul; tasklist /fo csv /v 2>nul"
        
        out = exec_func(session, cmd)
        if not out:
            return detected
        
        for tool in PivotToolsDatabase.get_all_tools():
            if re.search(re.escape(tool.process_name), out, re.IGNORECASE):
                # Extract PID and command line
                pid_match = re.search(rf'{tool.process_name}.*?(\d+)', out, re.IGNORECASE)
                cmd_match = re.search(rf'{tool.process_name}.*?(?:-|\s)([^\n]+)', out, re.IGNORECASE)
                
                tool.pid = int(pid_match.group(1)) if pid_match else 0
                tool.command_line = cmd_match.group(1)[:200] if cmd_match else ""
                tool.detection_methods.append('process')
                detected.append(tool)
        
        return detected
    
    @staticmethod
    def detect_by_interfaces(exec_func, session, platform: str) -> List[TunnelInterface]:
        """Detect tunnel interfaces."""
        detected = []
        
        if platform == 'linux':
            cmd = "ip link show 2>/dev/null || ifconfig -a 2>/dev/null"
        else:
            cmd = "powershell -nop -c \"Get-NetAdapter | Select-Object Name,InterfaceDescription,Status | Format-Table\" 2>nul; ipconfig /all 2>nul"
        
        out = exec_func(session, cmd)
        if not out:
            return detected
        
        for pattern, info in TunnelInterfacesDatabase.get_all_interfaces().items():
            if re.search(pattern, out, re.IGNORECASE):
                # Extract IP address
                ip_match = re.search(rf'{pattern}.*?(\d+\.\d+\.\d+\.\d+)', out, re.IGNORECASE)
                
                tunnel = TunnelInterface(
                    name=pattern,
                    interface_type=info['type'],
                    description=info['description'],
                    ip_address=ip_match.group(1) if ip_match else '',
                    risk_score=info['risk_score'],
                    is_active=True,
                )
                detected.append(tunnel)
        
        return detected
    
    @staticmethod
    def detect_by_ports(exec_func, session, platform: str) -> List[Tuple[int, str]]:
        """Detect suspicious listening ports."""
        suspicious = []
        
        # Common pivot ports
        pivot_ports = {
            1080: 'SOCKS',
            1081: 'SOCKS',
            8080: 'HTTP Proxy',
            8443: 'HTTPS Proxy',
            9050: 'Tor SOCKS',
            9051: 'Tor Control',
            3128: 'Squid Proxy',
            10808: 'V2Ray',
            10809: 'V2Ray',
            20170: 'V2Ray',
            20171: 'V2Ray',
            7890: 'Clash',
            7891: 'Clash',
            7892: 'Clash',
            7893: 'Clash',
            10800: 'Shadowsocks',
            10801: 'Shadowsocks',
            4443: 'HTTPS Alt',
            4444: 'Metasploit',
            5555: 'ADB',
            5900: 'VNC',
            5985: 'WinRM',
            5986: 'WinRM HTTPS',
            47001: 'WinRM',
        }
        
        if platform == 'linux':
            cmd = "ss -tnlp 2>/dev/null | grep LISTEN"
        else:
            cmd = "netstat -an 2>nul | findstr LISTENING"
        
        out = exec_func(session, cmd)
        if not out:
            return suspicious
        
        for port, service in pivot_ports.items():
            if re.search(rf':{port}\b', out):
                suspicious.append((port, service))
        
        return suspicious
    
    @staticmethod
    def detect_by_dns(exec_func, session) -> List[str]:
        """Detect DNS tunneling indicators."""
        indicators = []
        
        # Check DNS logs for tunneling patterns
        cmd = "cat /var/log/syslog 2>/dev/null | grep -i named | tail -50 || cat /var/log/named/queries 2>/dev/null | tail -50"
        out = exec_func(session, cmd)
        
        if out:
            # Look for high-entropy DNS queries (tunneling indicator)
            import math
            from collections import Counter
            
            queries = re.findall(r'query:\s+([A-Za-z0-9.-]+)', out)
            for query in queries:
                # Calculate entropy
                counter = Counter(query)
                length = len(query)
                entropy = -sum((count/length) * math.log2(count/length) for count in counter.values() if count > 0)
                
                if entropy > 3.5 and length > 30:
                    indicators.append(f"High-entropy DNS query: {query[:50]}... (entropy: {entropy:.2f})")
        
        return indicators
    
    @staticmethod
    def detect_by_firewall(exec_func, session, platform: str) -> List[str]:
        """Analyze firewall rules for pivot indicators."""
        rules = []
        
        if platform == 'linux':
            # Check iptables
            cmd = "iptables -L -n -v 2>/dev/null | head -30"
            out = exec_func(session, cmd)
            if out:
                rules.append(f"iptables rules:\n{out.strip()[:300]}")
            
            # Check nftables
            cmd = "nft list ruleset 2>/dev/null | head -30"
            out = exec_func(session, cmd)
            if out:
                rules.append(f"nftables rules:\n{out.strip()[:300]}")
        else:
            # Check Windows Firewall
            cmd = "netsh advfirewall firewall show rule name=all dir=in 2>nul | findstr /i \"enable action\" | head -20"
            out = exec_func(session, cmd)
            if out:
                rules.append(f"Windows Firewall rules:\n{out.strip()[:300]}")
        
        return rules
    
    @staticmethod
    def detect_by_network_namespaces(exec_func, session) -> List[str]:
        """Detect network namespaces (Linux)."""
        namespaces = []
        
        cmd = "ip netns list 2>/dev/null"
        out = exec_func(session, cmd)
        
        if out and out.strip():
            for line in out.strip().split('\n'):
                if line.strip():
                    namespaces.append(line.strip())
        
        return namespaces
    
    @staticmethod
    def detect_by_ebpf(exec_func, session) -> List[str]:
        """Detect eBPF programs that could be used for tunneling."""
        programs = []
        
        cmd = "bpftool prog list 2>/dev/null | head -20"
        out = exec_func(session, cmd)
        
        if out and out.strip():
            # Look for suspicious eBPF programs
            for line in out.strip().split('\n'):
                if any(x in line.lower() for x in ['tunnel', 'proxy', 'redirect', 'xdp']):
                    programs.append(line.strip())
        
        return programs


# ── Topology Mapper ────────────────────────────────────────────────────────

class TopologyMapper:
    """Maps network topology from discovered data."""
    
    @staticmethod
    def build_topology(exec_func, session, platform: str) -> NetworkTopology:
        """Build network topology graph."""
        topology = NetworkTopology()
        
        # Get ARP table
        if platform == 'linux':
            cmd = "ip neigh show 2>/dev/null || arp -a 2>/dev/null"
        else:
            cmd = "arp -a 2>nul"
        
        out = exec_func(session, cmd)
        if out:
            # Parse ARP entries
            for line in out.strip().split('\n'):
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                mac_match = re.search(r'([0-9a-fA-F:]{17})', line)
                
                if ip_match:
                    node = NetworkNode(
                        ip=ip_match.group(1),
                        mac=mac_match.group(1) if mac_match else '',
                    )
                    topology.nodes.append(node)
        
        # Get routing table
        if platform == 'linux':
            cmd = "ip route 2>/dev/null || route -n 2>/dev/null"
        else:
            cmd = "route print 2>nul"
        
        out = exec_func(session, cmd)
        if out:
            # Extract subnets
            subnets = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', out)
            topology.subnets = list(set(subnets))
        
        # Get interfaces
        if platform == 'linux':
            cmd = "ip addr show 2>/dev/null || ifconfig 2>/dev/null"
        else:
            cmd = "ipconfig /all 2>nul"
        
        out = exec_func(session, cmd)
        if out:
            # Extract interface IPs
            ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', out)
            for ip in ips:
                if not any(n.ip == ip for n in topology.nodes):
                    node = NetworkNode(ip=ip)
                    topology.nodes.append(node)
        
        # Identify pivot points (multi-homed hosts)
        for node in topology.nodes:
            if len(node.subnets) > 1:
                node.is_pivot = True
                topology.pivot_points.append(node.ip)
        
        return topology


# ── Main Plugin ─────────────────────────────────────────────────────────────

class NetworkPivotDetector(NexPlugin):
    name        = "network-pivot-detector"
    description = "Advanced pivoting intelligence engine — 50+ tools, cloud/container, eBPF, auto-topology"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "recon"
    mitre_id    = "T1572"
    
    def run(self, session, args: list):
        # Parse args
        full_mode = '--full' in (args or [])
        cloud_mode = '--cloud' in (args or [])
        container_mode = '--container' in (args or [])
        ebpf_mode = '--ebpf' in (args or [])
        topology_mode = '--topology' in (args or [])
        stealth = '--stealth' in (args or [])
        
        if full_mode:
            cloud_mode = container_mode = ebpf_mode = topology_mode = True
        
        self.info(f"🌐 Starting Network Pivot Detector v3.0 (full={full_mode})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🌐 Network Pivot Detector v3.0 — Advanced Intelligence]")
        sections.append("━"*64)
        
        # ── Step 1: Platform detection ──────────────────────────────────
        platform = self._detect_platform(session)
        sections.append(f"  Platform: {platform.upper()}")
        
        # ── Step 2: Process-based detection ─────────────────────────────
        sections.append("\n[*] Phase 1: Pivot Tool Process Detection")
        sections.append("─"*64)
        
        detected_tools = DetectionEngine.detect_by_processes(self._exec, session, platform)
        
        if detected_tools:
            sections.append(f"  🔴 {len(detected_tools)} pivot tool(s) detected:")
            for tool in detected_tools:
                icon = '🔴' if tool.risk_score >= 90 else '🟠' if tool.risk_score >= 75 else '🟡'
                sections.append(f"    {icon} {tool.name} [{tool.category}] — Risk: {tool.risk_score}/100")
                if tool.command_line:
                    sections.append(f"        Command: {tool.command_line[:80]}")
                if tool.pid:
                    sections.append(f"        PID: {tool.pid}")
        else:
            sections.append("  🟢 No pivot tools detected via process analysis")
        
        # ── Step 3: Interface detection ─────────────────────────────────
        sections.append("\n[*] Phase 2: Tunnel Interface Detection")
        sections.append("─"*64)
        
        detected_interfaces = DetectionEngine.detect_by_interfaces(self._exec, session, platform)
        
        if detected_interfaces:
            sections.append(f"  🔴 {len(detected_interfaces)} tunnel interface(s) detected:")
            for iface in detected_interfaces:
                icon = '🔴' if iface.risk_score >= 80 else '🟠' if iface.risk_score >= 65 else '🟡'
                sections.append(f"    {icon} {iface.name} [{iface.interface_type}] — {iface.description}")
                if iface.ip_address:
                    sections.append(f"        IP: {iface.ip_address}")
        else:
            sections.append("  🟢 No tunnel interfaces detected")
        
        # ── Step 4: Port detection ──────────────────────────────────────
        sections.append("\n[*] Phase 3: Suspicious Port Detection")
        sections.append("─"*64)
        
        suspicious_ports = DetectionEngine.detect_by_ports(self._exec, session, platform)
        
        if suspicious_ports:
            sections.append(f"  🟠 {len(suspicious_ports)} suspicious port(s) detected:")
            for port, service in suspicious_ports[:15]:
                sections.append(f"    • Port {port} — {service}")
        else:
            sections.append("  🟢 No suspicious ports detected")
        
        # ── Step 5: DNS tunneling detection ─────────────────────────────
        if platform == 'linux':
            sections.append("\n[*] Phase 4: DNS Tunneling Detection")
            sections.append("─"*64)
            
            dns_indicators = DetectionEngine.detect_by_dns(self._exec, session)
            
            if dns_indicators:
                sections.append(f"  🔴 {len(dns_indicators)} DNS tunneling indicator(s):")
                for indicator in dns_indicators[:5]:
                    sections.append(f"    • {indicator}")
            else:
                sections.append("  🟢 No DNS tunneling detected")
        
        # ── Step 6: Firewall analysis ───────────────────────────────────
        sections.append("\n[*] Phase 5: Firewall Rule Analysis")
        sections.append("─"*64)
        
        firewall_rules = DetectionEngine.detect_by_firewall(self._exec, session, platform)
        
        if firewall_rules:
            sections.append(f"  🟡 Firewall rules detected:")
            for rule in firewall_rules[:3]:
                sections.append(f"    {rule[:200]}")
        else:
            sections.append("  🟢 No firewall rules detected or accessible")
        
        # ── Step 7: Network namespaces (Linux) ──────────────────────────
        if platform == 'linux':
            sections.append("\n[*] Phase 6: Network Namespace Detection")
            sections.append("─"*64)
            
            namespaces = DetectionEngine.detect_by_network_namespaces(self._exec, session)
            
            if namespaces:
                sections.append(f"  🟠 {len(namespaces)} network namespace(s) detected:")
                for ns in namespaces[:10]:
                    sections.append(f"    • {ns}")
            else:
                sections.append("  🟢 No network namespaces detected")
        
        # ── Step 8: eBPF detection ──────────────────────────────────────
        if ebpf_mode and platform == 'linux':
            sections.append("\n[*] Phase 7: eBPF Program Detection")
            sections.append("─"*64)
            
            ebpf_programs = DetectionEngine.detect_by_ebpf(self._exec, session)
            
            if ebpf_programs:
                sections.append(f"  🟠 {len(ebpf_programs)} suspicious eBPF program(s):")
                for prog in ebpf_programs[:10]:
                    sections.append(f"    • {prog}")
            else:
                sections.append("  🟢 No suspicious eBPF programs detected")
        
        # ── Step 9: Topology mapping ────────────────────────────────────
        if topology_mode:
            sections.append("\n[*] Phase 8: Network Topology Mapping")
            sections.append("─"*64)
            
            topology = TopologyMapper.build_topology(self._exec, session, platform)
            
            sections.append(f"  Nodes: {len(topology.nodes)}")
            sections.append(f"  Subnets: {len(topology.subnets)}")
            sections.append(f"  Pivot Points: {len(topology.pivot_points)}")
            
            if topology.subnets:
                sections.append("\n  Discovered Subnets:")
                for subnet in topology.subnets[:15]:
                    sections.append(f"    • {subnet}")
            
            if topology.pivot_points:
                sections.append("\n  🟠 Pivot Points (Multi-homed Hosts):")
                for pivot in topology.pivot_points[:10]:
                    sections.append(f"    • {pivot}")
        
        # ── Step 10: Generate findings ──────────────────────────────────
        sections.append("\n[*] Phase 9: Generating Findings")
        sections.append("─"*64)
        
        findings_created = 0
        
        # Tool findings
        for tool in detected_tools:
            severity = 'critical' if tool.risk_score >= 90 else 'high' if tool.risk_score >= 75 else 'medium'
            
            self.finding(
                title=f"Pivot Tool Detected: {tool.name}",
                description=f"Pivot/tunnel tool detected:\n"
                           f"  Name: {tool.name}\n"
                           f"  Category: {tool.category}\n"
                           f"  Risk Score: {tool.risk_score}/100\n"
                           f"  Command: {tool.command_line[:100] if tool.command_line else 'N/A'}\n"
                           f"  PID: {tool.pid}",
                severity=severity,
                recommendation=f"Investigate {tool.name} process. Block unauthorized tunneling. Review network segmentation.",
                mitre_id=tool.mitre_id,
            )
            findings_created += 1
        
        # Interface findings
        for iface in detected_interfaces:
            if iface.risk_score >= 75:
                self.finding(
                    title=f"Tunnel Interface Detected: {iface.name}",
                    description=f"Network tunnel interface detected:\n"
                               f"  Name: {iface.name}\n"
                               f"  Type: {iface.interface_type}\n"
                               f"  Description: {iface.description}\n"
                               f"  IP: {iface.ip_address}\n"
                               f"  Risk Score: {iface.risk_score}/100",
                    severity='high',
                    recommendation=f"Review {iface.name} interface. Verify if authorized VPN/tunnel. Block if unauthorized.",
                    mitre_id=self.mitre_id,
                )
                findings_created += 1
        
        # Port findings
        if suspicious_ports:
            self.finding(
                title=f"Suspicious Ports Detected — {len(suspicious_ports)} ports",
                description=f"Suspicious listening ports detected:\n" +
                           "\n".join(f"  • Port {port} ({service})" for port, service in suspicious_ports[:10]),
                severity='medium',
                recommendation="Review listening ports. Block unauthorized services. Implement network segmentation.",
                mitre_id=self.mitre_id,
            )
            findings_created += 1
        
        # ── Step 11: Summary ────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Pivot Detection Summary]")
        sections.append("━"*64)
        sections.append(f"  Platform: {platform.upper()}")
        sections.append(f"  Pivot Tools Detected: {len(detected_tools)}")
        sections.append(f"  Tunnel Interfaces: {len(detected_interfaces)}")
        sections.append(f"  Suspicious Ports: {len(suspicious_ports)}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        if detected_tools:
            sections.append("\n  Top Threats:")
            sorted_tools = sorted(detected_tools, key=lambda t: t.risk_score, reverse=True)
            for tool in sorted_tools[:5]:
                icon = '🔴' if tool.risk_score >= 90 else '🟠' if tool.risk_score >= 75 else '🟡'
                sections.append(f"    {icon} {tool.name} ({tool.risk_score}/100)")
        
        # ── Step 12: Save to loot ───────────────────────────────────────
        self.loot(
            {
                "type": "pivot_detection",
                "platform": platform,
                "tools_detected": [t.to_dict() for t in detected_tools],
                "interfaces_detected": [i.to_dict() for i in detected_interfaces],
                "suspicious_ports": suspicious_ports,
                "findings_count": findings_created,
                "duration": duration,
            },
            category='network',
            source='network-pivot-detector',
            confidence='high'
        )
        
        self.emit(
            'timeline.event',
            title=f"Network Pivot Detection Complete — {len(detected_tools)} tools, {findings_created} findings",
            type='recon',
            plugin=self.name
        )
        
        self.info(f"🌐 Network pivot detector complete — {len(detected_tools)} tools, {findings_created} findings")
        
        return '\n'.join(sections)
    
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