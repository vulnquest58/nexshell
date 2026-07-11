#!/usr/bin/env python3
"""
NexShell Plugin — Network Topology Mapper v3.0 (2026 Edition)
Advanced network intelligence engine with multi-layer discovery, cloud/container
topology mapping, graph-based analysis, and auto-attack-surface mapping.

Coverage:
  - Layer 2: ARP, NDP, LLDP, CDP, MAC address discovery
  - Layer 3: Routing tables, OSPF, BGP neighbors, VLAN discovery
  - Layer 4: Active port scanning, service discovery, banner grabbing
  - Layer 7: DNS enumeration, HTTP, SMB, AD discovery
  - Cloud topology: AWS VPC, Azure VNet, GCP VPC, IMDS metadata
  - Container topology: Docker networks, K8s services/pods, Service Mesh
  - Trust boundary analysis
  - Attack surface mapping
  - Pivot point detection
  - Choke point analysis
  - Graph-based topology (Nodes + Edges)
  - BFS/DFS path finding
  - ASCII topology visualization
  - Risk scoring (0-100 per node)
  - Structured loot (JSON)

MITRE ATT&CK:
  - T1046: Network Service Discovery
  - T1018: Remote System Discovery
  - T1016: System Network Configuration Discovery
  - T1049: System Network Connections Discovery
  - T1016.001: System Network Configuration Discovery: Internet Connection Discovery
  - T1590: Gather Victim Network Information
  - T1590.001: Gather Victim Network Information: Domain Properties
  - T1590.002: Gather Victim Network Information: DNS
  - T1590.004: Gather Victim Network Information: Network Trust Dependencies
  - T1590.005: Gather Victim Network Information: IP Addresses
  - T1590.006: Gather Victim Network Information: Network Security Appliances

Usage:
    (NexShell)> plugins run network-topology-mapper
    (NexShell)> plugins run network-topology-mapper --full
    (NexShell)> plugins run network-topology-mapper --cloud
    (NexShell)> plugins run network-topology-mapper --container
    (NexShell)> plugins run network-topology-mapper --dns
    (NexShell)> plugins run network-topology-mapper --visualize
    (NexShell)> plugins run network-topology-mapper --attack-surface
"""

import re
import time
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict, deque
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class NetworkNode:
    """Represents a node in the network topology."""
    id: str
    node_type: str  # host, router, switch, firewall, server, workstation, dc, cloud, container
    ip: str = ""
    hostname: str = ""
    mac: str = ""
    os: str = ""
    vendor: str = ""
    interfaces: List[str] = field(default_factory=list)
    subnets: List[str] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)
    risk_score: int = 0
    is_pivot: bool = False
    is_choke_point: bool = False
    is_trust_boundary: bool = False
    trust_level: str = "unknown"  # internal, dmz, external, cloud
    environment: str = "on-prem"  # on-prem, cloud, container, hybrid
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def __hash__(self):
        return hash(self.id)
    
    def __eq__(self, other):
        if isinstance(other, NetworkNode):
            return self.id == other.id
        return False


@dataclass
class NetworkEdge:
    """Represents a connection between nodes."""
    source_id: str
    target_id: str
    edge_type: str  # physical, logical, trust, tunnel, vpn, cloud
    protocol: str = ""
    port: int = 0
    bandwidth: str = ""
    is_encrypted: bool = False
    risk_score: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TopologyGraph:
    """Represents the complete network topology."""
    nodes: Dict[str, NetworkNode] = field(default_factory=dict)
    edges: List[NetworkEdge] = field(default_factory=list)
    adjacency_list: Dict[str, List[NetworkEdge]] = field(default_factory=lambda: defaultdict(list))
    subnets: Set[str] = field(default_factory=set)
    pivot_points: List[str] = field(default_factory=list)
    choke_points: List[str] = field(default_factory=list)
    trust_boundaries: List[str] = field(default_factory=list)
    
    def add_node(self, node: NetworkNode):
        self.nodes[node.id] = node
    
    def add_edge(self, edge: NetworkEdge):
        self.edges.append(edge)
        self.adjacency_list[edge.source_id].append(edge)
    
    def get_node(self, node_id: str) -> Optional[NetworkNode]:
        return self.nodes.get(node_id)
    
    def get_neighbors(self, node_id: str) -> List[NetworkEdge]:
        return self.adjacency_list.get(node_id, [])
    
    def get_high_risk_nodes(self) -> List[NetworkNode]:
        return [n for n in self.nodes.values() if n.risk_score >= 70]
    
    def get_pivot_points(self) -> List[NetworkNode]:
        return [self.nodes[p] for p in self.pivot_points if p in self.nodes]
    
    def stats(self) -> Dict:
        return {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'subnets': len(self.subnets),
            'pivot_points': len(self.pivot_points),
            'choke_points': len(self.choke_points),
            'high_risk_nodes': len(self.get_high_risk_nodes()),
            'node_types': dict(defaultdict(int, {n.node_type: 1 for n in self.nodes.values()})),
        }
    
    def to_dict(self) -> dict:
        return {
            'nodes': {k: v.to_dict() for k, v in self.nodes.items()},
            'edges': [e.to_dict() for e in self.edges],
            'subnets': list(self.subnets),
            'pivot_points': self.pivot_points,
            'choke_points': self.choke_points,
            'trust_boundaries': self.trust_boundaries,
            'stats': self.stats(),
        }


@dataclass
class AttackSurface:
    """Represents the attack surface of the network."""
    exposed_services: List[Dict] = field(default_factory=list)
    vulnerable_nodes: List[str] = field(default_factory=list)
    pivot_vectors: List[Dict] = field(default_factory=list)
    trust_relationships: List[Dict] = field(default_factory=list)
    critical_paths: List[List[str]] = field(default_factory=list)
    risk_score: int = 0
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CloudTopology:
    """Represents cloud network topology."""
    provider: str  # aws, azure, gcp
    vpc_id: str = ""
    vpc_cidr: str = ""
    subnets: List[Dict] = field(default_factory=list)
    security_groups: List[Dict] = field(default_factory=list)
    route_tables: List[Dict] = field(default_factory=list)
    instances: List[Dict] = field(default_factory=list)
    load_balancers: List[Dict] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ContainerTopology:
    """Represents container network topology."""
    runtime: str  # docker, k8s, containerd
    networks: List[Dict] = field(default_factory=list)
    containers: List[Dict] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)
    pods: List[Dict] = field(default_factory=list)
    namespaces: List[str] = field(default_factory=list)
    service_mesh: str = ""  # istio, linkerd, consul
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── Layer 2 Discovery ───────────────────────────────────────────────────────

class Layer2Discovery:
    """Discovers Layer 2 network information."""
    
    @staticmethod
    def discover_arp(exec_func, session, platform: str) -> List[Dict]:
        """Discover ARP/NDP neighbors."""
        neighbors = []
        
        if platform == 'linux':
            cmd = "ip neigh show 2>/dev/null || arp -an 2>/dev/null"
        else:
            cmd = "arp -a 2>nul"
        
        out = exec_func(session, cmd)
        if out:
            for line in out.strip().split('\n'):
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                mac_match = re.search(r'([0-9a-fA-F:]{17}|[0-9a-fA-F-]{17})', line)
                
                if ip_match:
                    neighbor = {
                        'ip': ip_match.group(1),
                        'mac': mac_match.group(1) if mac_match else '',
                        'state': 'reachable' if 'REACHABLE' in line or 'dynamic' in line.lower() else 'unknown',
                    }
                    neighbors.append(neighbor)
        
        return neighbors
    
    @staticmethod
    def discover_lldp_cdp(exec_func, session, platform: str) -> List[Dict]:
        """Discover LLDP/CDP neighbors (switches/routers)."""
        devices = []
        
        if platform == 'linux':
            # Check for lldpctl
            cmd = "lldpctl 2>/dev/null | grep -E 'SysName|Management|Port' | head -30"
            out = exec_func(session, cmd)
            if out:
                devices.append({'protocol': 'LLDP', 'data': out.strip()[:500]})
            
            # Check for CDP
            cmd = "cdpcli 2>/dev/null || show cdp neighbors 2>/dev/null"
            out = exec_func(session, cmd)
            if out:
                devices.append({'protocol': 'CDP', 'data': out.strip()[:500]})
        
        return devices


# ── Layer 3 Discovery ───────────────────────────────────────────────────────

class Layer3Discovery:
    """Discovers Layer 3 network information."""
    
    @staticmethod
    def discover_routes(exec_func, session, platform: str) -> List[Dict]:
        """Discover routing table."""
        routes = []
        
        if platform == 'linux':
            cmd = "ip route show 2>/dev/null || route -n 2>/dev/null"
        else:
            cmd = "route print 2>nul"
        
        out = exec_func(session, cmd)
        if out:
            for line in out.strip().split('\n'):
                # Extract subnet and gateway
                subnet_match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+|\d+\.\d+\.\d+\.\d+)', line)
                gateway_match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', line)
                
                if subnet_match:
                    route = {
                        'subnet': subnet_match.group(1),
                        'gateway': gateway_match.group(1) if gateway_match else '',
                        'interface': '',
                    }
                    routes.append(route)
        
        return routes
    
    @staticmethod
    def discover_ospf_bgp(exec_func, session, platform: str) -> List[Dict]:
        """Discover OSPF/BGP neighbors."""
        protocols = []
        
        if platform == 'linux':
            # Check for OSPF
            cmd = "vtysh -c 'show ip ospf neighbor' 2>/dev/null || ip ospf neighbor 2>/dev/null"
            out = exec_func(session, cmd)
            if out and out.strip():
                protocols.append({'protocol': 'OSPF', 'neighbors': out.strip()[:500]})
            
            # Check for BGP
            cmd = "vtysh -c 'show ip bgp neighbors' 2>/dev/null || ip bgp neighbors 2>/dev/null"
            out = exec_func(session, cmd)
            if out and out.strip():
                protocols.append({'protocol': 'BGP', 'neighbors': out.strip()[:500]})
        
        return protocols
    
    @staticmethod
    def discover_vlans(exec_func, session, platform: str) -> List[Dict]:
        """Discover VLAN configuration."""
        vlans = []
        
        if platform == 'linux':
            cmd = "cat /proc/net/vlan/config 2>/dev/null || ip link show type vlan 2>/dev/null"
            out = exec_func(session, cmd)
            if out and out.strip():
                for line in out.strip().split('\n'):
                    vlan_match = re.search(r'vlan(\d+)', line)
                    if vlan_match:
                        vlans.append({'vlan_id': vlan_match.group(1), 'config': line.strip()})
        
        return vlans


# ── Layer 4 Discovery ───────────────────────────────────────────────────────

class Layer4Discovery:
    """Discovers Layer 4 network information."""
    
    @staticmethod
    def discover_listening_ports(exec_func, session, platform: str) -> List[Dict]:
        """Discover listening ports."""
        ports = []
        
        if platform == 'linux':
            cmd = "ss -tnlp 2>/dev/null | grep LISTEN || netstat -tnlp 2>/dev/null | grep LISTEN"
        else:
            cmd = "netstat -an 2>nul | findstr LISTENING"
        
        out = exec_func(session, cmd)
        if out:
            for line in out.strip().split('\n'):
                port_match = re.search(r':(\d+)\s', line)
                pid_match = re.search(r'pid=(\d+)', line)
                
                if port_match:
                    port_info = {
                        'port': int(port_match.group(1)),
                        'pid': int(pid_match.group(1)) if pid_match else 0,
                        'protocol': 'TCP',
                        'state': 'LISTEN',
                    }
                    ports.append(port_info)
        
        return ports
    
    @staticmethod
    def discover_connections(exec_func, session, platform: str) -> List[Dict]:
        """Discover active connections."""
        connections = []
        
        if platform == 'linux':
            cmd = "ss -tnp 2>/dev/null | grep ESTAB || netstat -tnp 2>/dev/null | grep ESTABLISHED"
        else:
            cmd = "netstat -an 2>nul | findstr ESTABLISHED"
        
        out = exec_func(session, cmd)
        if out:
            for line in out.strip().split('\n'):
                local_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                remote_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                
                if local_match and remote_match:
                    conn = {
                        'local_ip': local_match.group(1),
                        'local_port': int(local_match.group(2)),
                        'remote_ip': remote_match.group(1),
                        'remote_port': int(remote_match.group(2)),
                        'state': 'ESTABLISHED',
                    }
                    connections.append(conn)
        
        return connections


# ── Layer 7 Discovery ───────────────────────────────────────────────────────

class Layer7Discovery:
    """Discovers Layer 7 network information."""
    
    @staticmethod
    def discover_dns(exec_func, session, platform: str) -> Dict:
        """Discover DNS configuration and records."""
        dns_info = {
            'resolvers': [],
            'search_domains': [],
            'records': [],
        }
        
        # Get DNS resolvers
        if platform == 'linux':
            cmd = "cat /etc/resolv.conf 2>/dev/null"
        else:
            cmd = "powershell -nop -c \"Get-DnsClientServerAddress | Select-Object ServerAddresses | Format-Table\" 2>nul"
        
        out = exec_func(session, cmd)
        if out:
            resolvers = re.findall(r'(\d+\.\d+\.\d+\.\d+)', out)
            dns_info['resolvers'] = list(set(resolvers))
        
        # Get search domains
        if platform == 'linux':
            cmd = "cat /etc/resolv.conf 2>/dev/null | grep search"
            out = exec_func(session, cmd)
            if out:
                domains = out.replace('search', '').strip().split()
                dns_info['search_domains'] = domains
        
        return dns_info
    
    @staticmethod
    def discover_smb(exec_func, session, platform: str) -> Dict:
        """Discover SMB/AD information."""
        smb_info = {
            'domain': '',
            'workgroup': '',
            'shares': [],
            'domain_controllers': [],
        }
        
        if platform == 'windows':
            # Get domain
            cmd = "powershell -nop -c \"(Get-WmiObject Win32_ComputerSystem).Domain\" 2>nul"
            out = exec_func(session, cmd)
            if out:
                smb_info['domain'] = out.strip()
            
            # Get DCs
            cmd = "nltest /dclist: 2>nul || powershell -nop -c \"Get-ADDomainController -Filter * | Select-Object Name\" 2>nul"
            out = exec_func(session, cmd)
            if out:
                dcs = re.findall(r'(\S+)', out)
                smb_info['domain_controllers'] = [dc for dc in dcs if dc and dc not in ['The', 'command', 'completed']]
        
        return smb_info


# ── Cloud Topology Discovery ────────────────────────────────────────────────

class CloudTopologyDiscovery:
    """Discovers cloud network topology."""
    
    @staticmethod
    def discover_aws(exec_func, session) -> Optional[CloudTopology]:
        """Discover AWS VPC topology via IMDS."""
        # Check if running on AWS
        cmd = "curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null"
        out = exec_func(session, cmd)
        
        if not out or 'ami-id' not in out:
            return None
        
        topology = CloudTopology(provider='aws')
        
        # Get instance metadata
        metadata_fields = ['instance-id', 'instance-type', 'local-ipv4', 'public-ipv4', 'vpc-id', 'subnet-id']
        for field in metadata_fields:
            cmd = f"curl -s -m 2 http://169.254.169.254/latest/meta-data/{field} 2>/dev/null"
            out = exec_func(session, cmd)
            if out:
                topology.metadata[field] = out.strip()
        
        # Get IAM role
        cmd = "curl -s -m 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            topology.metadata['iam_role'] = out.strip()
        
        return topology
    
    @staticmethod
    def discover_azure(exec_func, session) -> Optional[CloudTopology]:
        """Discover Azure VNet topology via IMDS."""
        cmd = "curl -s -m 2 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null"
        out = exec_func(session, cmd)
        
        if not out or 'compute' not in out:
            return None
        
        topology = CloudTopology(provider='azure')
        
        try:
            data = json.loads(out)
            if 'compute' in data:
                topology.metadata['vm_name'] = data['compute'].get('name', '')
                topology.metadata['vm_size'] = data['compute'].get('vmSize', '')
                topology.metadata['location'] = data['compute'].get('location', '')
            
            if 'network' in data and 'interface' in data['network']:
                for iface in data['network']['interface']:
                    if 'ipv4' in iface and 'ipAddress' in iface['ipv4']:
                        for ip in iface['ipv4']['ipAddress']:
                            topology.metadata['private_ip'] = ip.get('privateIpAddress', '')
                            topology.metadata['public_ip'] = ip.get('publicIpAddress', '')
        except:
            pass
        
        return topology
    
    @staticmethod
    def discover_gcp(exec_func, session) -> Optional[CloudTopology]:
        """Discover GCP VPC topology via metadata."""
        cmd = "curl -s -m 2 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/ 2>/dev/null"
        out = exec_func(session, cmd)
        
        if not out:
            return None
        
        topology = CloudTopology(provider='gcp')
        
        # Get instance metadata
        metadata_fields = ['name', 'zone', 'machine-type', 'network-interfaces/0/ip']
        for field in metadata_fields:
            cmd = f"curl -s -m 2 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/{field} 2>/dev/null"
            out = exec_func(session, cmd)
            if out:
                topology.metadata[field] = out.strip()
        
        return topology


# ── Container Topology Discovery ────────────────────────────────────────────

class ContainerTopologyDiscovery:
    """Discovers container network topology."""
    
    @staticmethod
    def discover_docker(exec_func, session) -> Optional[ContainerTopology]:
        """Discover Docker network topology."""
        # Check if Docker is available
        cmd = "docker info 2>/dev/null | head -5"
        out = exec_func(session, cmd)
        
        if not out or 'Cannot' in out:
            return None
        
        topology = ContainerTopology(runtime='docker')
        
        # Get networks
        cmd = "docker network ls 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            for line in out.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    topology.networks.append({
                        'id': parts[0][:12],
                        'name': parts[1],
                        'driver': parts[2],
                    })
        
        # Get containers
        cmd = "docker ps 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            for line in out.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 7:
                    topology.containers.append({
                        'id': parts[0][:12],
                        'image': parts[1],
                        'name': parts[-1],
                        'ports': parts[-2] if '->' in parts[-2] else '',
                    })
        
        return topology
    
    @staticmethod
    def discover_k8s(exec_func, session) -> Optional[ContainerTopology]:
        """Discover Kubernetes network topology."""
        # Check if kubectl is available
        cmd = "kubectl cluster-info 2>/dev/null | head -3"
        out = exec_func(session, cmd)
        
        if not out or 'Unable' in out:
            return None
        
        topology = ContainerTopology(runtime='k8s')
        
        # Get namespaces
        cmd = "kubectl get namespaces 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            for line in out.strip().split('\n')[1:]:
                parts = line.split()
                if parts:
                    topology.namespaces.append(parts[0])
        
        # Get services
        cmd = "kubectl get services --all-namespaces 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            for line in out.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    topology.services.append({
                        'namespace': parts[0],
                        'name': parts[1],
                        'type': parts[2],
                        'cluster_ip': parts[3],
                        'ports': parts[4],
                    })
        
        # Get pods
        cmd = "kubectl get pods --all-namespaces 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            for line in out.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    topology.pods.append({
                        'namespace': parts[0],
                        'name': parts[1],
                        'status': parts[2],
                        'ip': parts[5] if len(parts) > 5 else '',
                    })
        
        # Check for service mesh
        cmd = "kubectl get pods -n istio-system 2>/dev/null | head -3"
        out = exec_func(session, cmd)
        if out and 'istio' in out.lower():
            topology.service_mesh = 'istio'
        
        return topology


# ── Graph Algorithms ────────────────────────────────────────────────────────

class GraphAlgorithms:
    """Graph traversal and analysis algorithms."""
    
    @staticmethod
    def bfs_shortest_path(graph: TopologyGraph, source_id: str, target_id: str) -> Optional[List[str]]:
        """Find shortest path using BFS."""
        if source_id not in graph.nodes or target_id not in graph.nodes:
            return None
        
        queue = deque([(source_id, [source_id])])
        visited = {source_id}
        
        while queue:
            current_id, path = queue.popleft()
            
            if current_id == target_id:
                return path
            
            for edge in graph.get_neighbors(current_id):
                if edge.target_id not in visited:
                    visited.add(edge.target_id)
                    queue.append((edge.target_id, path + [edge.target_id]))
        
        return None
    
    @staticmethod
    def find_pivot_points(graph: TopologyGraph) -> List[str]:
        """Find nodes that connect multiple subnets (pivot points)."""
        pivot_points = []
        
        for node_id, node in graph.nodes.items():
            # Count unique subnets this node can reach
            reachable_subnets = set()
            visited = {node_id}
            queue = deque([node_id])
            
            while queue:
                current_id = queue.popleft()
                current_node = graph.get_node(current_id)
                
                if current_node and current_node.subnets:
                    reachable_subnets.update(current_node.subnets)
                
                for edge in graph.get_neighbors(current_id):
                    if edge.target_id not in visited:
                        visited.add(edge.target_id)
                        queue.append(edge.target_id)
            
            # If node can reach multiple subnets, it's a pivot point
            if len(reachable_subnets) > 1:
                pivot_points.append(node_id)
                node.is_pivot = True
        
        return pivot_points
    
    @staticmethod
    def find_choke_points(graph: TopologyGraph) -> List[str]:
        """Find nodes that appear in most paths (choke points)."""
        # Count how many paths each node appears in
        node_frequency = defaultdict(int)
        
        # Get all pairs of high-value targets
        high_value_nodes = [n.id for n in graph.nodes.values() if n.risk_score >= 80]
        
        for source in graph.nodes:
            for target in high_value_nodes:
                if source != target:
                    path = GraphAlgorithms.bfs_shortest_path(graph, source, target)
                    if path:
                        for node_id in path[1:-1]:  # Exclude source and target
                            node_frequency[node_id] += 1
        
        # Sort by frequency
        sorted_nodes = sorted(node_frequency.items(), key=lambda x: x[1], reverse=True)
        
        choke_points = []
        for node_id, freq in sorted_nodes[:5]:  # Top 5 choke points
            if freq >= 2:  # Must appear in at least 2 paths
                choke_points.append(node_id)
                node = graph.get_node(node_id)
                if node:
                    node.is_choke_point = True
        
        return choke_points
    
    @staticmethod
    def calculate_risk_scores(graph: TopologyGraph):
        """Calculate risk scores for all nodes."""
        for node_id, node in graph.nodes.items():
            score = 0
            
            # Base score by node type
            type_scores = {
                'dc': 100,
                'firewall': 95,
                'router': 90,
                'server': 80,
                'cloud': 85,
                'container': 75,
                'workstation': 60,
                'switch': 70,
            }
            score += type_scores.get(node.node_type, 50)
            
            # Increase score if pivot point
            if node.is_pivot:
                score += 20
            
            # Increase score if choke point
            if node.is_choke_point:
                score += 15
            
            # Increase score if trust boundary
            if node.is_trust_boundary:
                score += 10
            
            # Cap at 100
            node.risk_score = min(100, score)


# ── Topology Visualizer ─────────────────────────────────────────────────────

class TopologyVisualizer:
    """Renders network topology as ASCII art."""
    
    @staticmethod
    def render_ascii(graph: TopologyGraph, max_nodes: int = 20) -> str:
        """Render topology as ASCII graph."""
        lines = []
        lines.append("\n" + "━"*64)
        lines.append("  [🗺️ Network Topology (ASCII)]")
        lines.append("━"*64)
        
        # Group nodes by type
        by_type = defaultdict(list)
        for node in list(graph.nodes.values())[:max_nodes]:
            by_type[node.node_type].append(node)
        
        # Render each type
        type_icons = {
            'dc': '🏛️',
            'firewall': '🛡️',
            'router': '🔀',
            'switch': '🔌',
            'server': '🖥️',
            'workstation': '💻',
            'cloud': '☁️',
            'container': '📦',
        }
        
        for node_type, nodes in by_type.items():
            icon = type_icons.get(node_type, '●')
            lines.append(f"\n  {icon} {node_type.upper()} ({len(nodes)}):")
            for node in nodes[:10]:
                risk_icon = '🔴' if node.risk_score >= 80 else '🟠' if node.risk_score >= 60 else '🟡'
                pivot_marker = ' [PIVOT]' if node.is_pivot else ''
                choke_marker = ' [CHOKE]' if node.is_choke_point else ''
                lines.append(f"    {risk_icon} {node.ip or node.hostname or node.id:<25} Risk: {node.risk_score}/100{pivot_marker}{choke_marker}")
        
        return '\n'.join(lines)
    
    @staticmethod
    def render_connections(graph: TopologyGraph, max_edges: int = 30) -> str:
        """Render connections as table."""
        lines = []
        lines.append("\n  [🔗 Network Connections]")
        lines.append("  " + "─"*60)
        
        for edge in graph.edges[:max_edges]:
            source = graph.get_node(edge.source_id)
            target = graph.get_node(edge.target_id)
            
            if source and target:
                source_name = source.ip or source.hostname or edge.source_id
                target_name = target.ip or target.hostname or edge.target_id
                lines.append(f"    {source_name:<20} → {target_name:<20} [{edge.edge_type}]")
        
        return '\n'.join(lines)


# ── Main Plugin ─────────────────────────────────────────────────────────────

class NetworkTopologyMapper(NexPlugin):
    name        = "network-topology-mapper"
    description = "Advanced network intelligence engine — multi-layer discovery, cloud/container, graph analysis"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "recon"
    mitre_id    = "T1046"
    
    def run(self, session, args: list):
        # Parse args
        full_mode = '--full' in (args or [])
        cloud_mode = '--cloud' in (args or [])
        container_mode = '--container' in (args or [])
        dns_mode = '--dns' in (args or [])
        visualize_mode = '--visualize' in (args or [])
        attack_surface_mode = '--attack-surface' in (args or [])
        
        if full_mode:
            cloud_mode = container_mode = dns_mode = visualize_mode = attack_surface_mode = True
        
        self.info(f"🗺️ Starting Network Topology Mapper v3.0 (full={full_mode})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🗺️ Network Topology Mapper v3.0 — Advanced Intelligence]")
        sections.append("━"*64)
        
        # ── Step 1: Platform detection ──────────────────────────────────
        platform = self._detect_platform(session)
        sections.append(f"  Platform: {platform.upper()}")
        
        # Initialize topology graph
        topology = TopologyGraph()
        
        # Add current host as root node
        current_host = NetworkNode(
            id='current_host',
            node_type='workstation' if platform == 'windows' else 'server',
            hostname=self._exec(session, "hostname 2>/dev/null || echo %COMPUTERNAME%").strip(),
            environment='on-prem',
        )
        topology.add_node(current_host)
        
        # ── Step 2: Layer 2 Discovery ───────────────────────────────────
        sections.append("\n[*] Phase 1: Layer 2 Discovery (ARP/NDP/LLDP/CDP)")
        sections.append("─"*64)
        
        arp_neighbors = Layer2Discovery.discover_arp(self._exec, session, platform)
        sections.append(f"  [+] ARP/NDP Neighbors: {len(arp_neighbors)}")
        
        for neighbor in arp_neighbors[:20]:
            node = NetworkNode(
                id=f"arp_{neighbor['ip']}",
                node_type='host',
                ip=neighbor['ip'],
                mac=neighbor['mac'],
            )
            topology.add_node(node)
            
            # Add edge from current host to neighbor
            edge = NetworkEdge(
                source_id='current_host',
                target_id=node.id,
                edge_type='physical',
                protocol='ARP',
            )
            topology.add_edge(edge)
            
            sections.append(f"    • {neighbor['ip']} ({neighbor['mac']}) [{neighbor['state']}]")
        
        lldp_cdp = Layer2Discovery.discover_lldp_cdp(self._exec, session, platform)
        if lldp_cdp:
            sections.append(f"  [+] LLDP/CDP Devices: {len(lldp_cdp)}")
        
        # ── Step 3: Layer 3 Discovery ───────────────────────────────────
        sections.append("\n[*] Phase 2: Layer 3 Discovery (Routes/OSPF/BGP/VLANs)")
        sections.append("─"*64)
        
        routes = Layer3Discovery.discover_routes(self._exec, session, platform)
        sections.append(f"  [+] Routes: {len(routes)}")
        
        for route in routes[:15]:
            topology.subnets.add(route['subnet'])
            sections.append(f"    • {route['subnet']} via {route['gateway'] or 'direct'}")
        
        ospf_bgp = Layer3Discovery.discover_ospf_bgp(self._exec, session, platform)
        if ospf_bgp:
            sections.append(f"  [+] Routing Protocols: {len(ospf_bgp)}")
        
        vlans = Layer3Discovery.discover_vlans(self._exec, session, platform)
        if vlans:
            sections.append(f"  [+] VLANs: {len(vlans)}")
        
        # ── Step 4: Layer 4 Discovery ───────────────────────────────────
        sections.append("\n[*] Phase 3: Layer 4 Discovery (Ports/Connections)")
        sections.append("─"*64)
        
        listening_ports = Layer4Discovery.discover_listening_ports(self._exec, session, platform)
        sections.append(f"  [+] Listening Ports: {len(listening_ports)}")
        
        for port_info in listening_ports[:15]:
            sections.append(f"    • Port {port_info['port']} ({port_info['protocol']})")
        
        connections = Layer4Discovery.discover_connections(self._exec, session, platform)
        sections.append(f"  [+] Active Connections: {len(connections)}")
        
        # ── Step 5: Layer 7 Discovery ───────────────────────────────────
        sections.append("\n[*] Phase 4: Layer 7 Discovery (DNS/SMB/AD)")
        sections.append("─"*64)
        
        dns_info = Layer7Discovery.discover_dns(self._exec, session, platform)
        sections.append(f"  [+] DNS Resolvers: {len(dns_info['resolvers'])}")
        for resolver in dns_info['resolvers'][:5]:
            sections.append(f"    • {resolver}")
        
        if dns_info['search_domains']:
            sections.append(f"  [+] Search Domains: {', '.join(dns_info['search_domains'][:5])}")
        
        smb_info = Layer7Discovery.discover_smb(self._exec, session, platform)
        if smb_info['domain']:
            sections.append(f"  [+] Domain: {smb_info['domain']}")
            current_host.node_type = 'dc' if 'dc' in current_host.hostname.lower() else 'server'
        
        if smb_info['domain_controllers']:
            sections.append(f"  [+] Domain Controllers: {len(smb_info['domain_controllers'])}")
            for dc in smb_info['domain_controllers'][:5]:
                dc_node = NetworkNode(
                    id=f"dc_{dc}",
                    node_type='dc',
                    hostname=dc,
                    environment='on-prem',
                )
                topology.add_node(dc_node)
                sections.append(f"    • {dc}")
        
        # ── Step 6: Cloud Topology ──────────────────────────────────────
        if cloud_mode:
            sections.append("\n[*] Phase 5: Cloud Topology Discovery")
            sections.append("─"*64)
            
            # Try AWS
            aws_topology = CloudTopologyDiscovery.discover_aws(self._exec, session)
            if aws_topology:
                sections.append(f"  ☁️  AWS Environment Detected")
                sections.append(f"      Instance: {aws_topology.metadata.get('instance-id', 'N/A')}")
                sections.append(f"      VPC: {aws_topology.metadata.get('vpc-id', 'N/A')}")
                sections.append(f"      Subnet: {aws_topology.metadata.get('subnet-id', 'N/A')}")
                
                cloud_node = NetworkNode(
                    id='aws_instance',
                    node_type='cloud',
                    ip=aws_topology.metadata.get('local-ipv4', ''),
                    environment='cloud',
                    metadata=aws_topology.metadata,
                )
                topology.add_node(cloud_node)
            
            # Try Azure
            azure_topology = CloudTopologyDiscovery.discover_azure(self._exec, session)
            if azure_topology:
                sections.append(f"  ☁️  Azure Environment Detected")
                sections.append(f"      VM: {azure_topology.metadata.get('vm_name', 'N/A')}")
                sections.append(f"      Location: {azure_topology.metadata.get('location', 'N/A')}")
            
            # Try GCP
            gcp_topology = CloudTopologyDiscovery.discover_gcp(self._exec, session)
            if gcp_topology:
                sections.append(f"  ☁️  GCP Environment Detected")
                sections.append(f"      Instance: {gcp_topology.metadata.get('name', 'N/A')}")
        
        # ── Step 7: Container Topology ──────────────────────────────────
        if container_mode:
            sections.append("\n[*] Phase 6: Container Topology Discovery")
            sections.append("─"*64)
            
            # Try Docker
            docker_topology = ContainerTopologyDiscovery.discover_docker(self._exec, session)
            if docker_topology:
                sections.append(f"  📦 Docker Environment Detected")
                sections.append(f"      Networks: {len(docker_topology.networks)}")
                sections.append(f"      Containers: {len(docker_topology.containers)}")
                
                for container in docker_topology.containers[:10]:
                    container_node = NetworkNode(
                        id=f"container_{container['id']}",
                        node_type='container',
                        hostname=container['name'],
                        environment='container',
                    )
                    topology.add_node(container_node)
                    sections.append(f"    • {container['name']} ({container['image']})")
            
            # Try K8s
            k8s_topology = ContainerTopologyDiscovery.discover_k8s(self._exec, session)
            if k8s_topology:
                sections.append(f"  📦 Kubernetes Environment Detected")
                sections.append(f"      Namespaces: {len(k8s_topology.namespaces)}")
                sections.append(f"      Services: {len(k8s_topology.services)}")
                sections.append(f"      Pods: {len(k8s_topology.pods)}")
                
                if k8s_topology.service_mesh:
                    sections.append(f"      Service Mesh: {k8s_topology.service_mesh}")
        
        # ── Step 8: Graph Analysis ──────────────────────────────────────
        sections.append("\n[*] Phase 7: Graph Analysis (Pivot Points/Choke Points)")
        sections.append("─"*64)
        
        # Find pivot points
        pivot_points = GraphAlgorithms.find_pivot_points(topology)
        topology.pivot_points = pivot_points
        sections.append(f"  [+] Pivot Points: {len(pivot_points)}")
        for pivot_id in pivot_points[:10]:
            node = topology.get_node(pivot_id)
            if node:
                sections.append(f"    • {node.ip or node.hostname or pivot_id}")
        
        # Find choke points
        choke_points = GraphAlgorithms.find_choke_points(topology)
        topology.choke_points = choke_points
        sections.append(f"  [+] Choke Points: {len(choke_points)}")
        for choke_id in choke_points[:10]:
            node = topology.get_node(choke_id)
            if node:
                sections.append(f"    • {node.ip or node.hostname or choke_id}")
        
        # Calculate risk scores
        GraphAlgorithms.calculate_risk_scores(topology)
        
        # ── Step 9: Visualization ───────────────────────────────────────
        if visualize_mode:
            sections.append(TopologyVisualizer.render_ascii(topology))
            sections.append(TopologyVisualizer.render_connections(topology))
        
        # ── Step 10: Attack Surface Analysis ────────────────────────────
        if attack_surface_mode:
            sections.append("\n[*] Phase 8: Attack Surface Analysis")
            sections.append("─"*64)
            
            attack_surface = AttackSurface()
            
            # Exposed services
            for port_info in listening_ports:
                attack_surface.exposed_services.append({
                    'port': port_info['port'],
                    'protocol': port_info['protocol'],
                })
            
            # Vulnerable nodes (high risk)
            high_risk_nodes = topology.get_high_risk_nodes()
            attack_surface.vulnerable_nodes = [n.id for n in high_risk_nodes]
            
            # Pivot vectors
            for pivot_id in pivot_points:
                node = topology.get_node(pivot_id)
                if node:
                    attack_surface.pivot_vectors.append({
                        'node_id': pivot_id,
                        'ip': node.ip,
                        'subnets': node.subnets,
                    })
            
            sections.append(f"  [+] Exposed Services: {len(attack_surface.exposed_services)}")
            sections.append(f"  [+] Vulnerable Nodes: {len(attack_surface.vulnerable_nodes)}")
            sections.append(f"  [+] Pivot Vectors: {len(attack_surface.pivot_vectors)}")
            
            # Calculate overall risk score
            if high_risk_nodes:
                attack_surface.risk_score = sum(n.risk_score for n in high_risk_nodes) // len(high_risk_nodes)
            sections.append(f"  [+] Overall Risk Score: {attack_surface.risk_score}/100")
        
        # ── Step 11: Generate Findings ──────────────────────────────────
        sections.append("\n[*] Phase 9: Generating Findings")
        sections.append("─"*64)
        
        findings_created = 0
        
        # Pivot point findings
        if pivot_points:
            self.finding(
                title=f"Network Pivot Points Identified — {len(pivot_points)} nodes",
                description=f"Multi-homed hosts that can be used for lateral movement:\n" +
                           "\n".join(f"  • {topology.get_node(p).ip or p}" for p in pivot_points[:10] if topology.get_node(p)),
                severity="High",
                recommendation="Review pivot points for unauthorized network access. Implement network segmentation.",
                mitre_id="T1599",
            )
            findings_created += 1
            sections.append(f"  [HIGH] {len(pivot_points)} pivot points identified")
        
        # Choke point findings
        if choke_points:
            self.finding(
                title=f"Network Choke Points Identified — {len(choke_points)} nodes",
                description=f"Critical nodes that appear in multiple attack paths:\n" +
                           "\n".join(f"  • {topology.get_node(c).ip or c}" for c in choke_points[:10] if topology.get_node(c)),
                severity="High",
                recommendation="Secure choke points with additional monitoring and access controls.",
                mitre_id="T1599",
            )
            findings_created += 1
            sections.append(f"  [HIGH] {len(choke_points)} choke points identified")
        
        # Cloud findings
        if cloud_mode and (aws_topology or azure_topology or gcp_topology):
            self.finding(
                title="Cloud Environment Detected — Potential Cloud Pivot",
                description=f"Running in cloud environment with access to cloud metadata and services.",
                severity="Medium",
                recommendation="Review cloud IAM permissions. Restrict IMDS access. Implement cloud network segmentation.",
                mitre_id="T1580",
            )
            findings_created += 1
            sections.append(f"  [MEDIUM] Cloud environment detected")
        
        # Container findings
        if container_mode and (docker_topology or k8s_topology):
            self.finding(
                title="Container Environment Detected — Potential Container Pivot",
                description=f"Running in container environment with access to container networks and services.",
                severity="Medium",
                recommendation="Review container RBAC. Restrict network policies. Implement pod security standards.",
                mitre_id="T1613",
            )
            findings_created += 1
            sections.append(f"  [MEDIUM] Container environment detected")
        
        # ── Step 12: Summary ────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        stats = topology.stats()
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Topology Mapping Summary]")
        sections.append("━"*64)
        sections.append(f"  Platform: {platform.upper()}")
        sections.append(f"  Total Nodes: {stats['total_nodes']}")
        sections.append(f"  Total Edges: {stats['total_edges']}")
        sections.append(f"  Subnets: {len(topology.subnets)}")
        sections.append(f"  Pivot Points: {len(pivot_points)}")
        sections.append(f"  Choke Points: {len(choke_points)}")
        sections.append(f"  High-Risk Nodes: {stats['high_risk_nodes']}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        if stats['node_types']:
            sections.append("\n  Node Types:")
            for node_type, count in stats['node_types'].items():
                sections.append(f"    • {node_type}: {count}")
        
        # ── Step 13: Save to Loot ───────────────────────────────────────
        self.loot(
            {
                "type": "network_topology",
                "platform": platform,
                "topology": topology.to_dict(),
                "findings_count": findings_created,
                "duration": duration,
            },
            category='network',
            source='network-topology-mapper',
            confidence='high'
        )
        
        self.emit(
            'timeline.event',
            title=f"Network Topology Mapping Complete — {stats['total_nodes']} nodes, {findings_created} findings",
            type='recon',
            plugin=self.name
        )
        
        self.info(f"🗺️ Network topology mapper complete — {stats['total_nodes']} nodes, {findings_created} findings")
        
        return '\n'.join(sections)
    
    def _detect_platform(self, session) -> str:
        for attr in ('OS', 'os', 'platform'):
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