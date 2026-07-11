#!/usr/bin/env python3
"""
NexShell Plugin — Attack Path Analyzer v3.0 (2026 Edition)
BloodHound-style attack path analysis with graph algorithms and multi-source data.

Core Features:
  - Directed graph construction (Nodes + Edges)
  - Multi-source data collection (AD, Local, K8s, Cloud, Findings DB)
  - Graph algorithms: BFS shortest path, DFS all paths, Dijkstra weighted
  - Path scoring by risk, exploitability, and complexity
  - ASCII graph visualization for terminal
  - MITRE ATT&CK chain mapping per path
  - High-value target identification (DA, SYSTEM, ClusterAdmin)
  - Choke point analysis (critical nodes)
  - Integration with Decision Engine for auto-remediation

MITRE ATT&CK Coverage:
  - TA0007: Discovery (T1087, T1069, T1018, T1482)
  - TA0008: Credential Access (T1003, T1558, T1552)
  - TA0004: Privilege Escalation (T1548, T1068, T1134)
  - TA0008: Lateral Movement (T1021, T1550, T1570)
  - TA0040: Impact (T1486, T1490)

Usage:
    (NexShell)> plugins run attack-path-analyzer
    (NexShell)> plugins run attack-path-analyzer --scenario ad
    (NexShell)> plugins run attack-path-analyzer --scenario k8s
    (NexShell)> plugins run attack-path-analyzer --target "Domain Admins"
    (NexShell)> plugins run attack-path-analyzer --depth 5
    (NexShell)> plugins run attack-path-analyzer --visualize
"""

import re
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from collections import defaultdict, deque
from datetime import datetime
from core.plugin import NexPlugin


# ── Graph Data Structures ───────────────────────────────────────────────────

@dataclass
class Node:
    """Represents an entity in the attack graph."""
    id: str
    node_type: str  # user, group, computer, gpo, role, pod, iam_user, service
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0  # 0-100
    is_high_value: bool = False  # DA, SYSTEM, ClusterAdmin
    environment: str = "unknown"  # ad, local, k8s, cloud
    mitre_ids: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def __hash__(self):
        return hash(self.id)
    
    def __eq__(self, other):
        if isinstance(other, Node):
            return self.id == other.id
        return False


@dataclass
class Edge:
    """Represents a relationship between two nodes."""
    source_id: str
    target_id: str
    relationship: str  # member_of, admin_to, has_session, can_rdp, contains, etc.
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_score: int = 50  # 0-100 (higher = easier/more dangerous)
    exploitability: str = "medium"  # low, medium, high, critical
    mitre_id: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackPath:
    """Represents a complete attack path from entry to target."""
    path_id: str
    source_node: Node
    target_node: Node
    nodes: List[Node]
    edges: List[Edge]
    total_risk_score: int = 0
    complexity: str = "medium"  # low, medium, high
    exploitability: str = "medium"
    mitre_chain: List[str] = field(default_factory=list)
    description: str = ""
    recommendations: List[str] = field(default_factory=list)
    choke_points: List[Node] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'path_id': self.path_id,
            'source': self.source_node.to_dict(),
            'target': self.target_node.to_dict(),
            'path_length': len(self.nodes),
            'total_risk_score': self.total_risk_score,
            'complexity': self.complexity,
            'exploitability': self.exploitability,
            'mitre_chain': self.mitre_chain,
            'description': self.description,
            'recommendations': self.recommendations,
            'nodes': [n.to_dict() for n in self.nodes],
            'edges': [e.to_dict() for e in self.edges],
        }


@dataclass
class AttackGraph:
    """Directed graph representing the attack surface."""
    nodes: Dict[str, Node] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)
    adjacency_list: Dict[str, List[Edge]] = field(default_factory=lambda: defaultdict(list))
    
    def add_node(self, node: Node):
        self.nodes[node.id] = node
    
    def add_edge(self, edge: Edge):
        self.edges.append(edge)
        self.adjacency_list[edge.source_id].append(edge)
    
    def get_node(self, node_id: str) -> Optional[Node]:
        return self.nodes.get(node_id)
    
    def get_neighbors(self, node_id: str) -> List[Edge]:
        return self.adjacency_list.get(node_id, [])
    
    def get_high_value_targets(self) -> List[Node]:
        return [n for n in self.nodes.values() if n.is_high_value]
    
    def stats(self) -> Dict:
        return {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'high_value_targets': len(self.get_high_value_targets()),
            'node_types': dict(defaultdict(int, {n.node_type: 1 for n in self.nodes.values()})),
        }


# ── Graph Algorithms ────────────────────────────────────────────────────────

class GraphAlgorithms:
    """Graph traversal and path-finding algorithms."""
    
    @staticmethod
    def bfs_shortest_path(graph: AttackGraph, source_id: str, target_id: str) -> Optional[AttackPath]:
        """Find shortest path using BFS."""
        if source_id not in graph.nodes or target_id not in graph.nodes:
            return None
        
        queue = deque([(source_id, [source_id], [])])
        visited = {source_id}
        
        while queue:
            current_id, path_nodes, path_edges = queue.popleft()
            
            if current_id == target_id:
                nodes = [graph.nodes[nid] for nid in path_nodes]
                return AttackPath(
                    path_id=f"bfs_{source_id}_{target_id}",
                    source_node=nodes[0],
                    target_node=nodes[-1],
                    nodes=nodes,
                    edges=path_edges,
                )
            
            for edge in graph.get_neighbors(current_id):
                if edge.target_id not in visited:
                    visited.add(edge.target_id)
                    queue.append((
                        edge.target_id,
                        path_nodes + [edge.target_id],
                        path_edges + [edge]
                    ))
        
        return None
    
    @staticmethod
    def dfs_all_paths(graph: AttackGraph, source_id: str, target_id: str, max_depth: int = 10) -> List[AttackPath]:
        """Find all paths using DFS with depth limit."""
        paths = []
        
        def dfs(current_id, path_nodes, path_edges, depth):
            if depth > max_depth:
                return
            
            if current_id == target_id:
                nodes = [graph.nodes[nid] for nid in path_nodes]
                paths.append(AttackPath(
                    path_id=f"dfs_{len(paths)}",
                    source_node=nodes[0],
                    target_node=nodes[-1],
                    nodes=nodes,
                    edges=path_edges,
                ))
                return
            
            for edge in graph.get_neighbors(current_id):
                if edge.target_id not in path_nodes:  # Avoid cycles
                    dfs(
                        edge.target_id,
                        path_nodes + [edge.target_id],
                        path_edges + [edge],
                        depth + 1
                    )
        
        if source_id in graph.nodes and target_id in graph.nodes:
            dfs(source_id, [source_id], [], 0)
        
        return paths
    
    @staticmethod
    def dijkstra_weighted(graph: AttackGraph, source_id: str, target_id: str) -> Optional[AttackPath]:
        """Find lowest-risk path using Dijkstra's algorithm."""
        if source_id not in graph.nodes or target_id not in graph.nodes:
            return None
        
        # Priority queue: (risk_score, current_id, path_nodes, path_edges)
        import heapq
        pq = [(0, source_id, [source_id], [])]
        visited = {}
        
        while pq:
            current_risk, current_id, path_nodes, path_edges = heapq.heappop(pq)
            
            if current_id == target_id:
                nodes = [graph.nodes[nid] for nid in path_nodes]
                path = AttackPath(
                    path_id=f"dijkstra_{source_id}_{target_id}",
                    source_node=nodes[0],
                    target_node=nodes[-1],
                    nodes=nodes,
                    edges=path_edges,
                    total_risk_score=current_risk,
                )
                return path
            
            if current_id in visited and visited[current_id] <= current_risk:
                continue
            visited[current_id] = current_risk
            
            for edge in graph.get_neighbors(current_id):
                new_risk = current_risk + edge.risk_score
                if edge.target_id not in visited or visited[edge.target_id] > new_risk:
                    heapq.heappush(pq, (
                        new_risk,
                        edge.target_id,
                        path_nodes + [edge.target_id],
                        path_edges + [edge]
                    ))
        
        return None
    
    @staticmethod
    def find_choke_points(graph: AttackGraph, paths: List[AttackPath]) -> List[Node]:
        """Find nodes that appear in most paths (critical choke points)."""
        node_frequency = defaultdict(int)
        for path in paths:
            for node in path.nodes[1:-1]:  # Exclude source and target
                node_frequency[node.id] += 1
        
        # Sort by frequency
        sorted_nodes = sorted(node_frequency.items(), key=lambda x: x[1], reverse=True)
        
        choke_points = []
        for node_id, freq in sorted_nodes[:5]:  # Top 5 choke points
            if freq >= 2:  # Must appear in at least 2 paths
                node = graph.get_node(node_id)
                if node:
                    choke_points.append(node)
        
        return choke_points


# ── Data Collectors ─────────────────────────────────────────────────────────

class DataCollectors:
    """Collect data from various sources to build the attack graph."""
    
    @staticmethod
    def collect_from_findings_db(plugin, graph: AttackGraph) -> int:
        """Collect relationships from existing findings database."""
        edges_added = 0
        
        try:
            db = plugin._db
            if not db or not hasattr(db, 'get_findings'):
                return 0
            
            findings = db.get_findings()
            current_user = "current_user"
            
            # Add current user node
            graph.add_node(Node(
                id=current_user,
                node_type="user",
                name="Current User",
                properties={"source": "session"},
                environment="local"
            ))
            
            for finding in findings:
                title = finding.get('title', '').lower()
                severity = finding.get('severity', 'medium').lower()
                
                # Map findings to graph relationships
                if 'credential' in title or 'password' in title:
                    cred_node_id = f"cred_{len(graph.nodes)}"
                    graph.add_node(Node(
                        id=cred_node_id,
                        node_type="credential",
                        name=finding.get('title', 'Credential'),
                        properties={"severity": severity},
                        risk_score=80 if severity == 'critical' else 60,
                        environment="local"
                    ))
                    graph.add_edge(Edge(
                        source_id=current_user,
                        target_id=cred_node_id,
                        relationship="has_access_to",
                        risk_score=80,
                        exploitability="high",
                        mitre_id="T1552"
                    ))
                    edges_added += 1
                
                if 'privesc' in title or 'privilege' in title:
                    priv_node_id = f"privesc_{len(graph.nodes)}"
                    graph.add_node(Node(
                        id=priv_node_id,
                        node_type="privilege",
                        name=finding.get('title', 'Privilege Escalation'),
                        properties={"severity": severity},
                        risk_score=90 if severity == 'critical' else 70,
                        is_high_value=(severity == 'critical'),
                        environment="local"
                    ))
                    graph.add_edge(Edge(
                        source_id=current_user,
                        target_id=priv_node_id,
                        relationship="can_exploit",
                        risk_score=85,
                        exploitability="high",
                        mitre_id="T1548"
                    ))
                    edges_added += 1
                
                if 'smb' in title or 'lateral' in title:
                    host_node_id = f"host_{len(graph.nodes)}"
                    graph.add_node(Node(
                        id=host_node_id,
                        node_type="computer",
                        name=finding.get('title', 'Remote Host'),
                        properties={"severity": severity},
                        risk_score=70,
                        environment="ad"
                    ))
                    graph.add_edge(Edge(
                        source_id=current_user,
                        target_id=host_node_id,
                        relationship="can_access",
                        risk_score=70,
                        exploitability="medium",
                        mitre_id="T1021"
                    ))
                    edges_added += 1
                
                if 'domain admin' in title or 'da' in title:
                    da_node_id = "domain_admins"
                    graph.add_node(Node(
                        id=da_node_id,
                        node_type="group",
                        name="Domain Admins",
                        properties={"type": "high_value_group"},
                        risk_score=100,
                        is_high_value=True,
                        environment="ad"
                    ))
                    edges_added += 1
                
                if 'kerberoast' in title or 'asrep' in title:
                    svc_node_id = f"service_account_{len(graph.nodes)}"
                    graph.add_node(Node(
                        id=svc_node_id,
                        node_type="user",
                        name="Service Account",
                        properties={"vulnerability": title},
                        risk_score=85,
                        environment="ad"
                    ))
                    graph.add_edge(Edge(
                        source_id=current_user,
                        target_id=svc_node_id,
                        relationship="can_roast",
                        risk_score=85,
                        exploitability="high",
                        mitre_id="T1558"
                    ))
                    edges_added += 1
        
        except Exception as e:
            plugin.warn(f"Error collecting from findings DB: {e}")
        
        return edges_added
    
    @staticmethod
    def collect_local_system(plugin, session, graph: AttackGraph) -> int:
        """Collect local system relationships."""
        edges_added = 0
        
        try:
            # Get current user info
            whoami_out = plugin._exec(session, "whoami 2>/dev/null || echo %USERNAME%")
            username = whoami_out.strip() if whoami_out else "unknown"
            
            user_node_id = f"user_{username}"
            graph.add_node(Node(
                id=user_node_id,
                node_type="user",
                name=username,
                properties={"source": "local"},
                environment="local"
            ))
            
            # Check for admin/root
            is_admin = False
            privs_out = plugin._exec(session, "whoami /priv 2>nul")
            if privs_out and 'SeDebugPrivilege' in privs_out:
                is_admin = True
            
            id_out = plugin._exec(session, "id 2>/dev/null")
            if id_out and ('uid=0' in id_out or 'sudo' in id_out or 'wheel' in id_out):
                is_admin = True
            
            if is_admin:
                admin_node_id = "local_admin"
                graph.add_node(Node(
                    id=admin_node_id,
                    node_type="privilege",
                    name="Local Admin/Root",
                    properties={"type": "high_value"},
                    risk_score=100,
                    is_high_value=True,
                    environment="local"
                ))
                graph.add_edge(Edge(
                    source_id=user_node_id,
                    target_id=admin_node_id,
                    relationship="has_privilege",
                    risk_score=100,
                    exploitability="critical",
                    mitre_id="T1548"
                ))
                edges_added += 1
            
            # Check for SUID/capabilities (Linux)
            suid_out = plugin._exec(session, "find /usr/bin -perm -4000 -type f 2>/dev/null | head -10")
            if suid_out and suid_out.strip():
                for binary in suid_out.strip().split('\n')[:5]:
                    binary = binary.strip()
                    if not binary:
                        continue
                    suid_node_id = f"suid_{binary.replace('/', '_')}"
                    graph.add_node(Node(
                        id=suid_node_id,
                        node_type="binary",
                        name=binary,
                        properties={"type": "suid"},
                        risk_score=75,
                        environment="local"
                    ))
                    graph.add_edge(Edge(
                        source_id=user_node_id,
                        target_id=suid_node_id,
                        relationship="can_execute_suid",
                        risk_score=75,
                        exploitability="high",
                        mitre_id="T1548.001"
                    ))
                    edges_added += 1
            
            # Check for services (Windows)
            svc_out = plugin._exec(session, "sc query type= service state= all 2>nul | findstr SERVICE_NAME")
            if svc_out:
                for line in svc_out.strip().split('\n')[:5]:
                    if 'SERVICE_NAME' in line:
                        svc_name = line.split(':')[-1].strip()
                        if svc_name:
                            svc_node_id = f"service_{svc_name}"
                            graph.add_node(Node(
                                id=svc_node_id,
                                node_type="service",
                                name=svc_name,
                                properties={"type": "windows_service"},
                                risk_score=60,
                                environment="local"
                            ))
                            graph.add_edge(Edge(
                                source_id=user_node_id,
                                target_id=svc_node_id,
                                relationship="can_query",
                                risk_score=60,
                                exploitability="medium",
                                mitre_id="T1007"
                            ))
                            edges_added += 1
        
        except Exception as e:
            plugin.warn(f"Error collecting local system data: {e}")
        
        return edges_added
    
    @staticmethod
    def collect_from_network_scout(plugin, graph: AttackGraph) -> int:
        """Collect relationships from network scout loot."""
        edges_added = 0
        
        try:
            # Try to get network scout data from loot
            db = plugin._db
            if not db or not hasattr(db, 'get_loot'):
                return 0
            
            loot_items = db.get_loot(category='network')
            for loot in loot_items[:20]:
                data = loot.get('data', {})
                if isinstance(data, dict) and 'host' in data:
                    host_ip = data['host']
                    host_node_id = f"host_{host_ip}"
                    graph.add_node(Node(
                        id=host_node_id,
                        node_type="computer",
                        name=host_ip,
                        properties=data,
                        risk_score=data.get('risk_score', 50),
                        environment="network"
                    ))
                    edges_added += 1
        
        except Exception as e:
            plugin.warn(f"Error collecting from network scout: {e}")
        
        return edges_added


# ── Path Scorer ─────────────────────────────────────────────────────────────

class PathScorer:
    """Scores attack paths based on multiple factors."""
    
    @staticmethod
    def score_path(path: AttackPath) -> AttackPath:
        """Calculate comprehensive path score."""
        if not path.edges:
            return path
        
        # Calculate total risk score (average of edge risks)
        path.total_risk_score = int(sum(e.risk_score for e in path.edges) / len(path.edges))
        
        # Determine complexity based on path length
        path_length = len(path.nodes)
        if path_length <= 2:
            path.complexity = "low"
        elif path_length <= 4:
            path.complexity = "medium"
        else:
            path.complexity = "high"
        
        # Determine exploitability based on minimum edge exploitability
        exploitability_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        min_exploit = min(exploitability_scores.get(e.exploitability, 2) for e in path.edges)
        path.exploitability = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}.get(min_exploit, 'medium')
        
        # Build MITRE chain
        path.mitre_chain = list(dict.fromkeys([e.mitre_id for e in path.edges if e.mitre_id]))
        
        # Generate description
        path.description = PathScorer.generate_description(path)
        
        # Generate recommendations
        path.recommendations = PathScorer.generate_recommendations(path)
        
        return path
    
    @staticmethod
    def generate_description(path: AttackPath) -> str:
        """Generate human-readable path description."""
        steps = []
        for i, edge in enumerate(path.edges):
            source = path.nodes[i].name
            target = path.nodes[i + 1].name
            rel = edge.relationship.replace('_', ' ')
            steps.append(f"{source} → [{rel}] → {target}")
        
        return "Attack Path: " + " | ".join(steps)
    
    @staticmethod
    def generate_recommendations(path: AttackPath) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []
        
        for edge in path.edges:
            if edge.relationship == "has_access_to":
                recommendations.append("Rotate credentials and restrict access to sensitive data")
            elif edge.relationship == "can_exploit":
                recommendations.append("Patch vulnerability and apply least privilege")
            elif edge.relationship == "can_access":
                recommendations.append("Implement network segmentation and access controls")
            elif edge.relationship == "can_roast":
                recommendations.append("Use strong passwords (25+ chars) for service accounts")
            elif edge.relationship == "member_of":
                recommendations.append("Review group membership and apply least privilege")
            elif edge.relationship == "admin_to":
                recommendations.append("Remove local admin rights and use tiered administration")
        
        return list(dict.fromkeys(recommendations))  # Deduplicate


# ── Path Visualizer ─────────────────────────────────────────────────────────

class PathVisualizer:
    """Renders attack paths as ASCII art for terminal display."""
    
    @staticmethod
    def render_path(path: AttackPath, max_width: int = 80) -> str:
        """Render a single attack path as ASCII."""
        lines = []
        
        # Header
        risk_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(path.exploitability, '⚪')
        lines.append(f"\n{risk_icon} Path: {path.source_node.name} → {path.target_node.name}")
        lines.append(f"   Length: {len(path.nodes)} nodes | Risk: {path.total_risk_score}/100 | Complexity: {path.complexity}")
        
        # Path visualization
        path_str = "   "
        for i, node in enumerate(path.nodes):
            node_icon = {'user': '👤', 'group': '👥', 'computer': '💻', 'credential': '🔑', 
                        'privilege': '⚡', 'binary': '⚙️', 'service': '🔧'}.get(node.node_type, '●')
            
            if node.is_high_value:
                node_icon = '🏆'
            
            path_str += f"{node_icon} {node.name}"
            
            if i < len(path.edges):
                edge = path.edges[i]
                rel_short = edge.relationship[:15].replace('_', ' ')
                path_str += f" ──[{rel_short}]──▶ "
        
        # Wrap long paths
        while len(path_str) > max_width:
            lines.append(path_str[:max_width])
            path_str = "   " + path_str[max_width:]
        lines.append(path_str)
        
        # MITRE chain
        if path.mitre_chain:
            lines.append(f"   MITRE: {' → '.join(path.mitre_chain)}")
        
        return '\n'.join(lines)
    
    @staticmethod
    def render_graph_summary(graph: AttackGraph) -> str:
        """Render a summary of the entire graph."""
        lines = []
        lines.append("\n" + "━"*64)
        lines.append("  [📊 Attack Graph Summary]")
        lines.append("━"*64)
        
        stats = graph.stats()
        lines.append(f"  Total Nodes: {stats['total_nodes']}")
        lines.append(f"  Total Edges: {stats['total_edges']}")
        lines.append(f"  High-Value Targets: {stats['high_value_targets']}")
        
        lines.append("\n  Node Types:")
        for node_type, count in stats['node_types'].items():
            lines.append(f"    • {node_type}: {count}")
        
        # List high-value targets
        hvt_list = graph.get_high_value_targets()
        if hvt_list:
            lines.append("\n  🏆 High-Value Targets:")
            for node in hvt_list[:10]:
                lines.append(f"    • {node.name} ({node.node_type}) — Risk: {node.risk_score}")
        
        return '\n'.join(lines)
    
    @staticmethod
    def render_paths_table(paths: List[AttackPath]) -> str:
        """Render all paths in a table format."""
        lines = []
        lines.append("\n" + "━"*64)
        lines.append("  [🎯 Attack Paths Identified]")
        lines.append("━"*64)
        
        if not paths:
            lines.append("  No attack paths found.")
            return '\n'.join(lines)
        
        lines.append(f"\n  {'#':<3} {'Source':<20} {'Target':<20} {'Risk':<6} {'Complexity':<12} {'Exploit':<10}")
        lines.append("  " + "─"*75)
        
        for i, path in enumerate(paths[:10], 1):
            risk_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(path.exploitability, '⚪')
            source = path.source_node.name[:18]
            target = path.target_node.name[:18]
            lines.append(
                f"  {i:<3} {source:<20} {target:<20} "
                f"{risk_icon}{path.total_risk_score:<5} {path.complexity:<12} {path.exploitability:<10}"
            )
        
        return '\n'.join(lines)


# ── Main Plugin ─────────────────────────────────────────────────────────────

class AttackPathAnalyzer(NexPlugin):
    name        = "attack-path-analyzer"
    description = "BloodHound-style attack path analysis with graph algorithms and multi-source data"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "recon"
    mitre_id    = "T1087"
    
    def run(self, session, args: list):
        # Parse args
        scenario = None
        target_name = None
        max_depth = 10
        visualize = '--visualize' in (args or [])
        
        for a in (args or []):
            if a.startswith('--scenario='):
                scenario = a.split('=', 1)[1]
            elif a.startswith('--target='):
                target_name = a.split('=', 1)[1]
            elif a.startswith('--depth='):
                try:
                    max_depth = int(a.split('=', 1)[1])
                except:
                    pass
        
        self.info(f"🎯 Starting Attack Path Analyzer v3.0 (scenario={scenario or 'auto'})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🎯 Attack Path Analyzer v3.0 — Graph-Based Analysis]")
        sections.append("━"*64)
        
        # ── Step 1: Build Attack Graph ──────────────────────────────────
        sections.append("\n[*] Phase 1: Building Attack Graph")
        sections.append("─"*64)
        
        graph = AttackGraph()
        
        # Collect data from multiple sources
        collectors = [
            ("Findings Database", DataCollectors.collect_from_findings_db),
            ("Local System", lambda p, s, g: DataCollectors.collect_local_system(p, s, g)),
            ("Network Scout", DataCollectors.collect_from_network_scout),
        ]
        
        total_edges = 0
        for name, collector in collectors:
            try:
                edges = collector(self, session, graph) if 'local' in name.lower() else collector(self, graph)
                total_edges += edges
                sections.append(f"  [+] {name}: {edges} relationships collected")
            except Exception as e:
                sections.append(f"  [!] {name}: Failed ({e})")
        
        sections.append(f"\n  Graph Stats: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
        
        if not graph.nodes:
            sections.append("\n  [!] No data collected. Run other plugins first (network-scout, ad-attack, etc.)")
            return '\n'.join(sections)
        
        # ── Step 2: Identify High-Value Targets ─────────────────────────
        sections.append("\n[*] Phase 2: Identifying High-Value Targets")
        sections.append("─"*64)
        
        hvt_list = graph.get_high_value_targets()
        if hvt_list:
            sections.append(f"  Found {len(hvt_list)} high-value targets:")
            for hvt in hvt_list[:10]:
                sections.append(f"    🏆 {hvt.name} ({hvt.node_type}) — Risk: {hvt.risk_score}")
        else:
            sections.append("  [!] No high-value targets identified")
            # Add default targets
            if 'domain_admins' not in graph.nodes:
                graph.add_node(Node(
                    id='domain_admins',
                    node_type='group',
                    name='Domain Admins',
                    is_high_value=True,
                    risk_score=100,
                    environment='ad'
                ))
            hvt_list = graph.get_high_value_targets()
        
        # ── Step 3: Find Attack Paths ───────────────────────────────────
        sections.append("\n[*] Phase 3: Finding Attack Paths")
        sections.append("─"*64)
        
        # Determine source node (current user)
        source_node = None
        for node in graph.nodes.values():
            if node.node_type == 'user' and 'current' in node.name.lower():
                source_node = node
                break
        
        if not source_node and graph.nodes:
            # Use first user node
            for node in graph.nodes.values():
                if node.node_type == 'user':
                    source_node = node
                    break
        
        if not source_node:
            # Create a default source
            source_node = Node(
                id='unknown_user',
                node_type='user',
                name='Unknown User',
                environment='local'
            )
            graph.add_node(source_node)
        
        sections.append(f"  Source: {source_node.name}")
        sections.append(f"  Targets: {len(hvt_list)} high-value targets")
        
        # Find paths to each high-value target
        all_paths = []
        algorithms = GraphAlgorithms()
        
        for target in hvt_list:
            if target.id == source_node.id:
                continue
            
            # Try BFS first (shortest path)
            path = algorithms.bfs_shortest_path(graph, source_node.id, target.id)
            if path:
                path = PathScorer.score_path(path)
                all_paths.append(path)
                sections.append(f"  [+] Path to {target.name}: {len(path.nodes)} nodes, Risk {path.total_risk_score}")
            else:
                # Try DFS with depth limit
                paths = algorithms.dfs_all_paths(graph, source_node.id, target.id, max_depth)
                if paths:
                    # Score and take best
                    for p in paths:
                        p = PathScorer.score_path(p)
                    best_path = min(paths, key=lambda p: p.total_risk_score)
                    all_paths.append(best_path)
                    sections.append(f"  [+] Path to {target.name}: {len(best_path.nodes)} nodes (via DFS)")
        
        # Sort paths by risk score (highest first)
        all_paths.sort(key=lambda p: p.total_risk_score, reverse=True)
        
        # ── Step 4: Find Choke Points ───────────────────────────────────
        sections.append("\n[*] Phase 4: Identifying Choke Points")
        sections.append("─"*64)
        
        choke_points = algorithms.find_choke_points(graph, all_paths)
        if choke_points:
            sections.append(f"  Found {len(choke_points)} critical choke points:")
            for cp in choke_points:
                sections.append(f"    ⚠️  {cp.name} ({cp.node_type}) — appears in multiple paths")
        else:
            sections.append("  No significant choke points identified")
        
        # ── Step 5: Visualize ───────────────────────────────────────────
        if visualize or True:  # Always visualize for now
            sections.append(PathVisualizer.render_graph_summary(graph))
            sections.append(PathVisualizer.render_paths_table(all_paths))
            
            # Render top 3 paths in detail
            if all_paths:
                sections.append("\n[*] Detailed Path Visualization (Top 3):")
                sections.append("─"*64)
                for path in all_paths[:3]:
                    sections.append(PathVisualizer.render_path(path))
        
        # ── Step 6: Generate Findings ───────────────────────────────────
        sections.append("\n[*] Phase 5: Generating Findings")
        sections.append("─"*64)
        
        findings_created = 0
        for path in all_paths[:5]:  # Top 5 paths
            severity = 'critical' if path.total_risk_score >= 80 else 'high' if path.total_risk_score >= 60 else 'medium'
            
            self.finding(
                title=f"Attack Path: {path.source_node.name} → {path.target_node.name}",
                description=f"{path.description}\n\n"
                           f"Path Length: {len(path.nodes)} nodes\n"
                           f"Risk Score: {path.total_risk_score}/100\n"
                           f"Complexity: {path.complexity}\n"
                           f"Exploitability: {path.exploitability}\n"
                           f"MITRE Chain: {' → '.join(path.mitre_chain)}",
                severity=severity,
                recommendation='\n'.join(path.recommendations) if path.recommendations else "Review and remediate attack path",
                mitre_id=', '.join(path.mitre_chain) if path.mitre_chain else self.mitre_id,
            )
            self.emit(
                'finding.created',
                severity=severity,
                title=f"Attack Path to {path.target_node.name}",
                plugin=self.name,
                confidence='high'
            )
            findings_created += 1
            sections.append(f"  [{severity.upper()}] {path.source_node.name} → {path.target_node.name}")
        
        # ── Step 7: Summary ─────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Analysis Summary]")
        sections.append("━"*64)
        sections.append(f"  Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
        sections.append(f"  High-Value Targets: {len(hvt_list)}")
        sections.append(f"  Attack Paths Found: {len(all_paths)}")
        sections.append(f"  Choke Points: {len(choke_points)}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Step 8: Save to Loot ────────────────────────────────────────
        self.loot(
            {
                "type": "attack_path_analysis",
                "graph_stats": graph.stats(),
                "high_value_targets": [n.to_dict() for n in hvt_list],
                "paths": [p.to_dict() for p in all_paths],
                "choke_points": [n.to_dict() for n in choke_points],
                "duration": duration,
            },
            category='attack_paths',
            source='attack-path-analyzer',
            confidence='high'
        )
        
        self.info(f"🎯 Attack Path Analyzer complete — {len(all_paths)} paths, {findings_created} findings")
        
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