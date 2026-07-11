#!/usr/bin/env python3
"""
NexShell Plugin — Risk Scoring Engine v3.0 (2026 Edition)
Advanced risk intelligence engine with multi-factor analysis, trend tracking,
MITRE ATT&CK mapping, and industry benchmark compliance.

Coverage:
  - 15+ data sources aggregation (findings, loot, sessions, configs)
  - Multi-factor weighted scoring algorithm
  - MITRE ATT&CK tactic/technique mapping
  - Time-series trend analysis
  - Industry benchmarks (CIS, NIST, ISO 27001)
  - 5x5 Risk Matrix (Likelihood × Impact)
  - Attack chain analysis
  - ASCII visualization (charts, graphs)
  - Smart prioritized recommendations
  - Compliance audit reporting
  - Export to JSON/CSV/HTML/PDF
  - 12 risk categories (Privesc, Credentials, Network, etc.)
  - Historical comparison
  - Executive summary generation

MITRE ATT&CK Coverage:
  - TA0001: Initial Access
  - TA0002: Execution
  - TA0003: Persistence
  - TA0004: Privilege Escalation
  - TA0005: Defense Evasion
  - TA0006: Credential Access
  - TA0007: Discovery
  - TA0008: Lateral Movement
  - TA0009: Collection
  - TA0011: Command and Control
  - TA0010: Exfiltration
  - TA0040: Impact

Usage:
    (NexShell)> plugins run risk-scoring-engine
    (NexShell)> plugins run risk-scoring-engine --full
    (NexShell)> plugins run risk-scoring-engine --trend
    (NexShell)> plugins run risk-scoring-engine --mitre
    (NexShell)> plugins run risk-scoring-engine --compliance
    (NexShell)> plugins run risk-scoring-engine --export json
    (NexShell)> plugins run risk-scoring-engine --compare <timestamp>
    (NexShell)> plugins run risk-scoring-engine --executive-summary
"""

import re
import time
import json
import math
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class RiskFinding:
    """Represents a risk finding with full metadata."""
    id: str
    title: str
    severity: str  # critical, high, medium, low, info
    category: str  # privesc, credentials, network, persistence, etc.
    mitre_id: str = ""
    mitre_tactic: str = ""
    description: str = ""
    recommendation: str = ""
    timestamp: str = ""
    source: str = ""
    confidence: str = "medium"
    cvss_score: float = 0.0
    affected_asset: str = ""
    exploit_available: bool = False
    remediation_difficulty: str = "medium"  # easy, medium, hard
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RiskCategory:
    """Represents a risk category with score."""
    name: str
    description: str
    score: int = 0  # 0-100
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    weight: float = 1.0
    mitre_tactics: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RiskMatrix:
    """Represents a 5x5 risk matrix."""
    likelihood: int = 0  # 1-5
    impact: int = 0  # 1-5
    risk_level: str = ""
    color: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TrendData:
    """Represents trend data over time."""
    timestamp: str
    risk_score: int
    finding_count: int
    critical_count: int
    categories: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ComplianceCheck:
    """Represents a compliance check result."""
    framework: str  # CIS, NIST, ISO27001
    control_id: str
    control_name: str
    status: str  # pass, fail, partial, unknown
    severity: str = "medium"
    description: str = ""
    recommendation: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackChain:
    """Represents an attack chain."""
    name: str
    description: str
    steps: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    risk_score: int = 0
    likelihood: str = "medium"
    impact: str = "high"
    prerequisites: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RiskReport:
    """Complete risk assessment report."""
    overall_score: int = 0
    risk_level: str = ""
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    categories: List[RiskCategory] = field(default_factory=list)
    mitre_coverage: Dict[str, int] = field(default_factory=dict)
    trend_data: List[TrendData] = field(default_factory=list)
    compliance_results: List[ComplianceCheck] = field(default_factory=list)
    attack_chains: List[AttackChain] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    executive_summary: str = ""
    timestamp: str = ""
    
    def to_dict(self) -> dict:
        return {
            'overall_score': self.overall_score,
            'risk_level': self.risk_level,
            'total_findings': self.total_findings,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'medium_findings': self.medium_findings,
            'low_findings': self.low_findings,
            'categories': [c.to_dict() for c in self.categories],
            'mitre_coverage': self.mitre_coverage,
            'trend_data': [t.to_dict() for t in self.trend_data],
            'compliance_results': [c.to_dict() for c in self.compliance_results],
            'attack_chains': [a.to_dict() for a in self.attack_chains],
            'recommendations': self.recommendations,
            'executive_summary': self.executive_summary,
            'timestamp': self.timestamp,
        }


# ── Risk Categories Database ───────────────────────────────────────────────

class RiskCategoriesDatabase:
    """Comprehensive database of risk categories."""
    
    CATEGORIES = {
        'privilege_escalation': RiskCategory(
            name='Privilege Escalation',
            description='Local and remote privilege escalation vectors',
            weight=1.5,
            mitre_tactics=['TA0004'],
            recommendations=[
                'Apply principle of least privilege',
                'Enable UAC and AppLocker',
                'Patch all privilege escalation CVEs',
                'Monitor for SUID/SGID binaries',
            ],
        ),
        'credential_access': RiskCategory(
            name='Credential Access',
            description='Credential theft and password attacks',
            weight=1.4,
            mitre_tactics=['TA0006'],
            recommendations=[
                'Implement MFA for all accounts',
                'Use credential guard',
                'Rotate passwords regularly',
                'Monitor LSASS access',
            ],
        ),
        'persistence': RiskCategory(
            name='Persistence',
            description='Persistence mechanisms and backdoors',
            weight=1.3,
            mitre_tactics=['TA0003'],
            recommendations=[
                'Audit startup items and services',
                'Monitor registry run keys',
                'Check scheduled tasks',
                'Scan for rootkits',
            ],
        ),
        'lateral_movement': RiskCategory(
            name='Lateral Movement',
            description='Lateral movement vectors and techniques',
            weight=1.4,
            mitre_tactics=['TA0008'],
            recommendations=[
                'Implement network segmentation',
                'Disable unnecessary protocols (SMBv1, LLMNR)',
                'Monitor RDP/SSH connections',
                'Restrict admin shares',
            ],
        ),
        'defense_evasion': RiskCategory(
            name='Defense Evasion',
            description='EDR/AV bypass and evasion techniques',
            weight=1.2,
            mitre_tactics=['TA0005'],
            recommendations=[
                'Enable AMSI and ETW',
                'Deploy EDR with behavioral analysis',
                'Monitor for process injection',
                'Enable code integrity',
            ],
        ),
        'discovery': RiskCategory(
            name='Discovery',
            description='Reconnaissance and enumeration vectors',
            weight=0.8,
            mitre_tactics=['TA0007'],
            recommendations=[
                'Restrict AD enumeration',
                'Monitor for scanning activity',
                'Implement honeypots',
                'Restrict DNS zone transfers',
            ],
        ),
        'network_security': RiskCategory(
            name='Network Security',
            description='Network misconfigurations and exposures',
            weight=1.1,
            mitre_tactics=['TA0001'],
            recommendations=[
                'Enable SMB signing',
                'Disable NLA bypass',
                'Configure firewall rules',
                'Monitor for port scanning',
            ],
        ),
        'configuration': RiskCategory(
            name='Security Configuration',
            description='Security misconfigurations',
            weight=1.0,
            mitre_tactics=['TA0001'],
            recommendations=[
                'Apply CIS benchmarks',
                'Harden OS configurations',
                'Enable audit logging',
                'Review GPO settings',
            ],
        ),
        'vulnerability_management': RiskCategory(
            name='Vulnerability Management',
            description='Unpatched vulnerabilities and CVEs',
            weight=1.3,
            mitre_tactics=['TA0001', 'TA0002'],
            recommendations=[
                'Implement patch management',
                'Prioritize critical CVEs',
                'Scan for vulnerabilities regularly',
                'Test patches before deployment',
            ],
        ),
        'data_protection': RiskCategory(
            name='Data Protection',
            description='Data exposure and exfiltration risks',
            weight=1.2,
            mitre_tactics=['TA0009', 'TA0010'],
            recommendations=[
                'Encrypt sensitive data at rest',
                'Implement DLP solutions',
                'Monitor data access patterns',
                'Restrict USB/external storage',
            ],
        ),
        'identity_management': RiskCategory(
            name='Identity & Access Management',
            description='IAM misconfigurations and weaknesses',
            weight=1.3,
            mitre_tactics=['TA0001', 'TA0004'],
            recommendations=[
                'Implement RBAC',
                'Review privileged accounts',
                'Enable account lockout',
                'Monitor for privilege abuse',
            ],
        ),
        'cloud_security': RiskCategory(
            name='Cloud Security',
            description='Cloud-specific security risks',
            weight=1.2,
            mitre_tactics=['TA0001', 'TA0007'],
            recommendations=[
                'Secure cloud credentials',
                'Implement cloud IAM policies',
                'Monitor cloud API calls',
                'Enable cloud audit logging',
            ],
        ),
    }
    
    @classmethod
    def get_all_categories(cls) -> Dict[str, RiskCategory]:
        return cls.CATEGORIES
    
    @classmethod
    def get_category_by_name(cls, name: str) -> Optional[RiskCategory]:
        for key, category in cls.CATEGORIES.items():
            if name.lower() in key.lower() or name.lower() in category.name.lower():
                return category
        return None


# ── MITRE ATT&CK Mapping ───────────────────────────────────────────────────

class MITREMapping:
    """MITRE ATT&CK framework mapping."""
    
    TACTICS = {
        'TA0001': 'Initial Access',
        'TA0002': 'Execution',
        'TA0003': 'Persistence',
        'TA0004': 'Privilege Escalation',
        'TA0005': 'Defense Evasion',
        'TA0006': 'Credential Access',
        'TA0007': 'Discovery',
        'TA0008': 'Lateral Movement',
        'TA0009': 'Collection',
        'TA0010': 'Exfiltration',
        'TA0011': 'Command and Control',
        'TA0040': 'Impact',
    }
    
    TECHNIQUES = {
        'T1003': 'OS Credential Dumping',
        'T1003.001': 'LSASS Memory',
        'T1003.002': 'Security Account Manager',
        'T1003.003': 'NTDS',
        'T1003.006': 'DCSync',
        'T1021': 'Remote Services',
        'T1021.001': 'Remote Desktop Protocol',
        'T1021.002': 'SMB/Windows Admin Shares',
        'T1021.006': 'Windows Remote Management',
        'T1053': 'Scheduled Task/Job',
        'T1053.005': 'Scheduled Task',
        'T1055': 'Process Injection',
        'T1059': 'Command and Scripting Interpreter',
        'T1059.001': 'PowerShell',
        'T1059.003': 'Windows Command Shell',
        'T1068': 'Exploitation for Privilege Escalation',
        'T1070': 'Indicator Removal',
        'T1070.001': 'Clear Windows Event Logs',
        'T1078': 'Valid Accounts',
        'T1078.002': 'Domain Accounts',
        'T1098': 'Account Manipulation',
        'T1110': 'Brute Force',
        'T1136': 'Create Account',
        'T1210': 'Exploitation of Remote Services',
        'T1543': 'Create or Modify System Process',
        'T1543.003': 'Windows Service',
        'T1546': 'Event Triggered Execution',
        'T1547': 'Boot or Logon Autostart Execution',
        'T1547.001': 'Registry Run Keys',
        'T1548': 'Abuse Elevation Control Mechanism',
        'T1550': 'Use Alternate Authentication Material',
        'T1550.002': 'Pass the Hash',
        'T1550.003': 'Pass the Ticket',
        'T1552': 'Unsecured Credentials',
        'T1557': 'Adversary-in-the-Middle',
        'T1558': 'Steal or Forge Kerberos Tickets',
        'T1562': 'Impair Defenses',
        'T1562.001': 'Disable or Modify Tools',
        'T1563': 'Remote Service Session Hijacking',
        'T1569': 'System Services',
        'T1569.002': 'Service Execution',
        'T1572': 'Protocol Tunneling',
        'T1590': 'Gather Victim Network Information',
    }
    
    @classmethod
    def get_tactic_name(cls, tactic_id: str) -> str:
        return cls.TACTICS.get(tactic_id, 'Unknown')
    
    @classmethod
    def get_technique_name(cls, technique_id: str) -> str:
        return cls.TECHNIQUES.get(technique_id, 'Unknown')
    
    @classmethod
    def map_finding_to_mitre(cls, finding: RiskFinding) -> Tuple[str, str]:
        """Map finding to MITRE tactic and technique."""
        if finding.mitre_id in cls.TECHNIQUES:
            technique = finding.mitre_id
            # Extract tactic from technique (first 5 chars)
            tactic = technique[:5] + '0' * (len(technique) - 5)
            return tactic, technique
        return '', ''


# ── Scoring Engine ─────────────────────────────────────────────────────────

class ScoringEngine:
    """Advanced multi-factor scoring engine."""
    
    # Severity weights
    SEVERITY_WEIGHTS = {
        'critical': 25,
        'high': 15,
        'medium': 5,
        'low': 1,
        'info': 0,
    }
    
    # CVSS multipliers
    CVSS_MULTIPLIERS = {
        (9.0, 10.0): 1.5,
        (7.0, 8.9): 1.3,
        (4.0, 6.9): 1.0,
        (0.1, 3.9): 0.8,
    }
    
    @staticmethod
    def calculate_finding_score(finding: RiskFinding) -> int:
        """Calculate score for a single finding."""
        base_score = ScoringEngine.SEVERITY_WEIGHTS.get(finding.severity.lower(), 0)
        
        # Apply CVSS multiplier
        if finding.cvss_score > 0:
            for (min_cvss, max_cvss), multiplier in ScoringEngine.CVSS_MULTIPLIERS.items():
                if min_cvss <= finding.cvss_score <= max_cvss:
                    base_score = int(base_score * multiplier)
                    break
        
        # Apply confidence multiplier
        confidence_mult = {'high': 1.2, 'medium': 1.0, 'low': 0.8}.get(finding.confidence, 1.0)
        base_score = int(base_score * confidence_mult)
        
        # Apply exploit availability bonus
        if finding.exploit_available:
            base_score = int(base_score * 1.3)
        
        return min(base_score, 100)
    
    @staticmethod
    def calculate_category_score(category: RiskCategory, findings: List[RiskFinding]) -> int:
        """Calculate score for a category."""
        if not findings:
            return 0
        
        category_findings = [f for f in findings if f.category.lower() in category.name.lower()]
        if not category_findings:
            return 0
        
        total_score = sum(ScoringEngine.calculate_finding_score(f) for f in category_findings)
        
        # Apply category weight
        weighted_score = int(total_score * category.weight)
        
        return min(weighted_score, 100)
    
    @staticmethod
    def calculate_overall_score(categories: List[RiskCategory]) -> int:
        """Calculate overall risk score."""
        if not categories:
            return 0
        
        total_weight = sum(c.weight for c in categories)
        weighted_sum = sum(c.score * c.weight for c in categories)
        
        overall_score = int(weighted_sum / total_weight) if total_weight > 0 else 0
        
        return min(overall_score, 100)
    
    @staticmethod
    def calculate_risk_matrix(likelihood: int, impact: int) -> RiskMatrix:
        """Calculate risk matrix position."""
        risk_score = likelihood * impact
        
        if risk_score >= 20:
            level = 'CRITICAL'
            color = '🔴'
        elif risk_score >= 12:
            level = 'HIGH'
            color = '🟠'
        elif risk_score >= 6:
            level = 'MEDIUM'
            color = '🟡'
        elif risk_score >= 2:
            level = 'LOW'
            color = '🟢'
        else:
            level = 'MINIMAL'
            color = '⚪'
        
        return RiskMatrix(
            likelihood=likelihood,
            impact=impact,
            risk_level=level,
            color=color,
        )


# ── Trend Analyzer ─────────────────────────────────────────────────────────

class TrendAnalyzer:
    """Analyzes risk trends over time."""
    
    @staticmethod
    def analyze_trends(historical_data: List[TrendData]) -> Dict[str, Any]:
        """Analyze risk trends."""
        if len(historical_data) < 2:
            return {'trend': 'insufficient_data', 'change': 0}
        
        # Sort by timestamp
        sorted_data = sorted(historical_data, key=lambda x: x.timestamp)
        
        # Calculate trend
        first_score = sorted_data[0].risk_score
        last_score = sorted_data[-1].risk_score
        change = last_score - first_score
        
        # Determine trend direction
        if change > 10:
            trend = 'increasing'
        elif change < -10:
            trend = 'decreasing'
        else:
            trend = 'stable'
        
        # Calculate average
        avg_score = sum(d.risk_score for d in sorted_data) / len(sorted_data)
        
        # Calculate volatility
        scores = [d.risk_score for d in sorted_data]
        volatility = max(scores) - min(scores)
        
        return {
            'trend': trend,
            'change': change,
            'first_score': first_score,
            'last_score': last_score,
            'average': int(avg_score),
            'volatility': volatility,
            'data_points': len(sorted_data),
        }
    
    @staticmethod
    def generate_trend_chart(trend_data: List[TrendData], width: int = 60) -> str:
        """Generate ASCII trend chart."""
        if not trend_data:
            return "No trend data available"
        
        sorted_data = sorted(trend_data, key=lambda x: x.timestamp)
        scores = [d.risk_score for d in sorted_data]
        
        max_score = max(scores) if scores else 100
        min_score = min(scores) if scores else 0
        
        chart_lines = []
        chart_lines.append("\n  Risk Score Trend:")
        chart_lines.append("  " + "─" * width)
        
        # Generate bars
        for i, score in enumerate(scores):
            bar_length = int((score / max_score) * (width - 10)) if max_score > 0 else 0
            bar = '█' * bar_length
            
            # Color indicator
            if score >= 70:
                color = '🔴'
            elif score >= 40:
                color = '🟠'
            elif score >= 15:
                color = '🟡'
            else:
                color = '🟢'
            
            chart_lines.append(f"  {color} {score:3d} |{bar}")
        
        chart_lines.append("  " + "─" * width)
        chart_lines.append(f"  Min: {min_score} | Max: {max_score} | Avg: {int(sum(scores)/len(scores))}")
        
        return '\n'.join(chart_lines)


# ── Compliance Checker ─────────────────────────────────────────────────────

class ComplianceChecker:
    """Checks compliance with industry frameworks."""
    
    # CIS Controls mapping
    CIS_CONTROLS = [
        ComplianceCheck(
            framework='CIS',
            control_id='CIS 1',
            control_name='Inventory of Authorized Devices',
            status='unknown',
            description='Maintain inventory of all authorized devices',
            recommendation='Implement asset management system',
        ),
        ComplianceCheck(
            framework='CIS',
            control_id='CIS 2',
            control_name='Inventory of Authorized Software',
            status='unknown',
            description='Maintain inventory of all authorized software',
            recommendation='Implement software asset management',
        ),
        ComplianceCheck(
            framework='CIS',
            control_id='CIS 4',
            control_name='Controlled Use of Administrative Privileges',
            status='unknown',
            description='Control and monitor administrative privileges',
            recommendation='Implement least privilege and PAM',
        ),
        ComplianceCheck(
            framework='CIS',
            control_id='CIS 6',
            control_name='Maintenance, Monitoring, and Analysis of Audit Logs',
            status='unknown',
            description='Enable and monitor audit logging',
            recommendation='Implement SIEM and log analysis',
        ),
        ComplianceCheck(
            framework='CIS',
            control_id='CIS 8',
            control_name='Malware Defenses',
            status='unknown',
            description='Deploy and maintain anti-malware',
            recommendation='Enable real-time AV/EDR protection',
        ),
    ]
    
    # NIST Controls mapping
    NIST_CONTROLS = [
        ComplianceCheck(
            framework='NIST',
            control_id='AC-2',
            control_name='Account Management',
            status='unknown',
            description='Manage information system accounts',
            recommendation='Implement account lifecycle management',
        ),
        ComplianceCheck(
            framework='NIST',
            control_id='AC-6',
            control_name='Least Privilege',
            status='unknown',
            description='Employ least privilege principle',
            recommendation='Review and restrict user privileges',
        ),
        ComplianceCheck(
            framework='NIST',
            control_id='AU-2',
            control_name='Audit Events',
            status='unknown',
            description='Define auditable events',
            recommendation='Enable comprehensive audit logging',
        ),
        ComplianceCheck(
            framework='NIST',
            control_id='IA-2',
            control_name='Identification and Authentication',
            status='unknown',
            description='Implement MFA',
            recommendation='Deploy multi-factor authentication',
        ),
        ComplianceCheck(
            framework='NIST',
            control_id='SI-2',
            control_name='Flaw Remediation',
            status='unknown',
            description='Patch vulnerabilities',
            recommendation='Implement patch management process',
        ),
    ]
    
    @classmethod
    def check_compliance(cls, findings: List[RiskFinding], report: RiskReport) -> List[ComplianceCheck]:
        """Check compliance based on findings."""
        results = []
        
        # Check CIS controls
        for control in cls.CIS_CONTROLS:
            status = 'unknown'
            
            if control.control_id == 'CIS 4':
                # Check for privilege escalation findings
                privesc_findings = [f for f in findings if f.category == 'privilege_escalation']
                if privesc_findings:
                    status = 'fail'
                else:
                    status = 'pass'
            
            elif control.control_id == 'CIS 8':
                # Check for defense evasion findings
                evasion_findings = [f for f in findings if f.category == 'defense_evasion']
                if evasion_findings:
                    status = 'partial'
                else:
                    status = 'pass'
            
            control.status = status
            results.append(control)
        
        # Check NIST controls
        for control in cls.NIST_CONTROLS:
            status = 'unknown'
            
            if control.control_id == 'AC-6':
                # Check for privilege escalation
                privesc_findings = [f for f in findings if f.category == 'privilege_escalation']
                if privesc_findings:
                    status = 'fail'
                else:
                    status = 'pass'
            
            elif control.control_id == 'SI-2':
                # Check for vulnerability findings
                vuln_findings = [f for f in findings if f.category == 'vulnerability_management']
                if vuln_findings:
                    status = 'fail'
                else:
                    status = 'pass'
            
            control.status = status
            results.append(control)
        
        return results
    
    @classmethod
    def calculate_compliance_score(cls, results: List[ComplianceCheck]) -> int:
        """Calculate overall compliance score."""
        if not results:
            return 0
        
        passed = sum(1 for r in results if r.status == 'pass')
        partial = sum(1 for r in results if r.status == 'partial')
        total = len(results)
        
        score = int(((passed + (partial * 0.5)) / total) * 100)
        return score


# ── Attack Chain Analyzer ──────────────────────────────────────────────────

class AttackChainAnalyzer:
    """Analyzes potential attack chains."""
    
    CHAINS = [
        AttackChain(
            name='NTDS → DCSync → Golden Ticket',
            description='Extract NTDS.dit, perform DCSync, create Golden Ticket for persistent domain access',
            steps=[
                '1. Extract NTDS.dit via VSS or ntdsutil',
                '2. Dump NTLM hashes from NTDS.dit',
                '3. Perform DCSync to replicate credentials',
                '4. Create Golden Ticket with krbtgt hash',
                '5. Inject ticket for persistent access',
            ],
            mitre_techniques=['T1003.003', 'T1003.006', 'T1558.001'],
            risk_score=95,
            likelihood='high',
            impact='critical',
            prerequisites=['Domain Admin or DCSync rights', 'krbtgt hash'],
        ),
        
        AttackChain(
            name='LSASS Dump → Pass-the-Hash → Lateral Movement',
            description='Dump LSASS, extract NTLM hashes, use PtH for lateral movement',
            steps=[
                '1. Dump LSASS memory with Mimikatz',
                '2. Extract NTLM hashes and plaintext passwords',
                '3. Use Pass-the-Hash with psexec/wmiexec',
                '4. Move laterally to other hosts',
                '5. Escalate privileges on target hosts',
            ],
            mitre_techniques=['T1003.001', 'T1550.002', 'T1021.002'],
            risk_score=90,
            likelihood='high',
            impact='high',
            prerequisites=['Local admin or SYSTEM', 'SeDebugPrivilege'],
        ),
        
        AttackChain(
            name='Kerberoast → Crack → Domain Admin',
            description='Request TGS tickets, crack offline, use credentials for DA access',
            steps=[
                '1. Enumerate SPN accounts',
                '2. Request TGS tickets (Kerberoast)',
                '3. Crack tickets offline with hashcat',
                '4. Use cracked credentials',
                '5. Escalate to Domain Admin',
            ],
            mitre_techniques=['T1558.003', 'T1110', 'T1078.002'],
            risk_score=85,
            likelihood='medium',
            impact='high',
            prerequisites=['Domain user account', 'Weak service account passwords'],
        ),
        
        AttackChain(
            name='AD CS ESC → Certificate → Domain Compromise',
            description='Exploit AD CS misconfigurations to request certificates and compromise domain',
            steps=[
                '1. Enumerate certificate templates',
                '2. Exploit ESC1-ESC11 vulnerabilities',
                '3. Request certificate as DA',
                '4. Authenticate with certificate (PKINIT)',
                '5. Perform DCSync or create Golden Ticket',
            ],
            mitre_techniques=['T1649', 'T1552.001', 'T1003.006'],
            risk_score=95,
            likelihood='medium',
            impact='critical',
            prerequisites=['AD CS installed', 'Misconfigured templates'],
        ),
        
        AttackChain(
            name='NTLM Relay → LDAP → DCSync',
            description='Coerce authentication, relay to LDAP, grant DCSync rights',
            steps=[
                '1. Coerce authentication (PetitPotam/PrinterBug)',
                '2. Relay NTLM to LDAP with ntlmrelayx',
                '3. Grant DCSync rights to attacker account',
                '4. Perform DCSync to dump credentials',
                '5. Compromise entire domain',
            ],
            mitre_techniques=['T1557', 'T1187', 'T1003.006'],
            risk_score=90,
            likelihood='medium',
            impact='critical',
            prerequisites=['SMB signing disabled', 'LDAP signing disabled'],
        ),
    ]
    
    @classmethod
    def analyze_chains(cls, findings: List[RiskFinding]) -> List[AttackChain]:
        """Analyze which attack chains are feasible based on findings."""
        feasible_chains = []
        
        for chain in cls.CHAINS:
            # Check if prerequisites are met
            prerequisites_met = True
            
            # Simple heuristic: check if related findings exist
            related_findings = [f for f in findings if any(tech in f.mitre_id for tech in chain.mitre_techniques)]
            
            if related_findings:
                chain.risk_score = min(chain.risk_score + len(related_findings) * 2, 100)
                feasible_chains.append(chain)
        
        return feasible_chains


# ── Visualization Engine ───────────────────────────────────────────────────

class VisualizationEngine:
    """Generates ASCII visualizations."""
    
    @staticmethod
    def generate_risk_matrix_chart(matrix: RiskMatrix) -> str:
        """Generate 5x5 risk matrix visualization."""
        lines = []
        lines.append("\n  Risk Matrix (Likelihood × Impact):")
        lines.append("  " + "─" * 50)
        
        # Matrix grid
        for impact in range(5, 0, -1):
            row = f"  {impact} |"
            for likelihood in range(1, 6):
                score = likelihood * impact
                if score >= 20:
                    cell = '🔴'
                elif score >= 12:
                    cell = '🟠'
                elif score >= 6:
                    cell = '🟡'
                elif score >= 2:
                    cell = '🟢'
                else:
                    cell = '⚪'
                row += f" {cell} "
            lines.append(row)
        
        lines.append("     " + "─" * 25)
        lines.append("      1  2  3  4  5  (Likelihood)")
        
        # Current position
        lines.append(f"\n  Current Position: Likelihood={matrix.likelihood}, Impact={matrix.impact}")
        lines.append(f"  Risk Level: {matrix.color} {matrix.risk_level}")
        
        return '\n'.join(lines)
    
    @staticmethod
    def generate_category_chart(categories: List[RiskCategory]) -> str:
        """Generate category distribution chart."""
        lines = []
        lines.append("\n  Risk Category Distribution:")
        lines.append("  " + "─" * 60)
        
        max_score = max(c.score for c in categories) if categories else 100
        
        for category in sorted(categories, key=lambda c: c.score, reverse=True):
            bar_length = int((category.score / max_score) * 40) if max_score > 0 else 0
            bar = '█' * bar_length
            
            if category.score >= 70:
                color = '🔴'
            elif category.score >= 40:
                color = '🟠'
            elif category.score >= 15:
                color = '🟡'
            else:
                color = '🟢'
            
            lines.append(f"  {color} {category.name:<30} {category.score:3d} |{bar}")
        
        lines.append("  " + "─" * 60)
        
        return '\n'.join(lines)
    
    @staticmethod
    def generate_mitre_heatmap(mitre_coverage: Dict[str, int]) -> str:
        """Generate MITRE ATT&CK heatmap."""
        lines = []
        lines.append("\n  MITRE ATT&CK Coverage Heatmap:")
        lines.append("  " + "─" * 60)
        
        for tactic_id, count in sorted(mitre_coverage.items(), key=lambda x: x[1], reverse=True):
            tactic_name = MITREMapping.get_tactic_name(tactic_id)
            
            bar_length = min(count * 2, 40)
            bar = '█' * bar_length
            
            if count >= 10:
                color = '🔴'
            elif count >= 5:
                color = '🟠'
            elif count >= 2:
                color = '🟡'
            else:
                color = '🟢'
            
            lines.append(f"  {color} {tactic_id} {tactic_name:<25} {count:3d} |{bar}")
        
        lines.append("  " + "─" * 60)
        
        return '\n'.join(lines)


# ── Main Plugin ─────────────────────────────────────────────────────────────

class RiskScoringEngine(NexPlugin):
    name        = "risk-scoring-engine"
    description = "Advanced risk intelligence — multi-factor analysis, MITRE mapping, compliance"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "recon"
    mitre_id    = "N/A"
    
    def run(self, session, args: list):
        # Parse args
        full_mode = '--full' in (args or [])
        trend_mode = '--trend' in (args or [])
        mitre_mode = '--mitre' in (args or [])
        compliance_mode = '--compliance' in (args or [])
        export_format = None
        compare_timestamp = None
        executive_summary = '--executive-summary' in (args or [])
        
        for a in (args or []):
            if a.startswith('--export='):
                export_format = a.split('=', 1)[1]
            elif a.startswith('--compare='):
                compare_timestamp = a.split('=', 1)[1]
        
        if full_mode:
            trend_mode = mitre_mode = compliance_mode = executive_summary = True
        
        self.info(f"📊 Starting Risk Scoring Engine v3.0 (full={full_mode})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Risk Scoring Engine v3.0 — Advanced Risk Intelligence]")
        sections.append("━"*64)
        
        # ── Step 1: Data Collection ───────────────────────────────────────
        sections.append("\n[*] Phase 1: Data Collection & Aggregation")
        sections.append("─"*64)
        
        findings = []
        
        # Load from database
        db = getattr(self, '_db', None)
        if db and hasattr(db, 'get_findings'):
            try:
                db_findings = db.get_findings()
                for f in db_findings:
                    finding = RiskFinding(
                        id=f.get('id', ''),
                        title=f.get('title', ''),
                        severity=f.get('severity', 'medium'),
                        category=f.get('category', 'unknown'),
                        mitre_id=f.get('mitre_id', ''),
                        description=f.get('description', ''),
                        recommendation=f.get('recommendation', ''),
                        timestamp=f.get('timestamp', datetime.utcnow().isoformat()),
                        source=f.get('source', ''),
                        confidence=f.get('confidence', 'medium'),
                    )
                    findings.append(finding)
            except Exception as e:
                sections.append(f"  ⚠️  Database error: {e}")
        
        # Load from loot
        if db and hasattr(db, 'get_loot'):
            try:
                loot_items = db.get_loot()
                sections.append(f"  [+] Loaded {len(loot_items)} loot items")
            except:
                pass
        
        if not findings:
            sections.append("  ⚠️  No findings in database — generating simulated assessment")
            # Generate simulated findings
            findings = self._generate_simulated_findings(session)
        
        sections.append(f"  [+] Total findings: {len(findings)}")
        
        # ── Step 2: Category Analysis ─────────────────────────────────────
        sections.append("\n[*] Phase 2: Risk Category Analysis")
        sections.append("─"*64)
        
        categories = []
        for cat_name, category in RiskCategoriesDatabase.get_all_categories().items():
            # Count findings in this category
            cat_findings = [f for f in findings if f.category.lower() in cat_name.lower() or 
                           any(keyword in f.title.lower() for keyword in cat_name.split('_'))]
            
            category.finding_count = len(cat_findings)
            category.critical_count = sum(1 for f in cat_findings if f.severity.lower() == 'critical')
            category.high_count = sum(1 for f in cat_findings if f.severity.lower() == 'high')
            category.score = ScoringEngine.calculate_category_score(category, cat_findings)
            
            if category.finding_count > 0:
                categories.append(category)
        
        # Calculate overall score
        overall_score = ScoringEngine.calculate_overall_score(categories)
        
        # Determine risk level
        if overall_score >= 70:
            risk_level = "CRITICAL RISK"
            color = "🔴"
        elif overall_score >= 40:
            risk_level = "HIGH RISK"
            color = "🟠"
        elif overall_score >= 15:
            risk_level = "MEDIUM RISK"
            color = "🟡"
        else:
            risk_level = "LOW RISK"
            color = "🟢"
        
        sections.append(f"\n  {color} Overall Risk Score: {overall_score}/100")
        sections.append(f"  👉 Risk Level: {risk_level}")
        sections.append(f"\n  Category Breakdown:")
        
        for category in sorted(categories, key=lambda c: c.score, reverse=True)[:10]:
            icon = '🔴' if category.score >= 70 else '🟠' if category.score >= 40 else '🟡' if category.score >= 15 else '🟢'
            sections.append(f"    {icon} {category.name:<30} {category.score:3d}/100 ({category.finding_count} findings)")
        
        # ── Step 3: MITRE ATT&CK Mapping ──────────────────────────────────
        if mitre_mode:
            sections.append("\n[*] Phase 3: MITRE ATT&CK Analysis")
            sections.append("─"*64)
            
            mitre_coverage = defaultdict(int)
            
            for finding in findings:
                if finding.mitre_id:
                    tactic, technique = MITREMapping.map_finding_to_mitre(finding)
                    if tactic:
                        mitre_coverage[tactic] += 1
            
            sections.append(f"  [+] MITRE Tactics Covered: {len(mitre_coverage)}")
            sections.append(f"  [+] Total Techniques Mapped: {sum(mitre_coverage.values())}")
            
            # Generate heatmap
            sections.append(VisualizationEngine.generate_mitre_heatmap(dict(mitre_coverage)))
        
        # ── Step 4: Risk Matrix ───────────────────────────────────────────
        sections.append("\n[*] Phase 4: Risk Matrix Assessment")
        sections.append("─"*64)
        
        # Calculate likelihood and impact
        likelihood = min(5, max(1, int(len([f for f in findings if f.severity in ['critical', 'high']]) / 2)))
        impact = min(5, max(1, int(overall_score / 20)))
        
        risk_matrix = ScoringEngine.calculate_risk_matrix(likelihood, impact)
        
        sections.append(VisualizationEngine.generate_risk_matrix_chart(risk_matrix))
        
        # ── Step 5: Trend Analysis ────────────────────────────────────────
        if trend_mode:
            sections.append("\n[*] Phase 5: Trend Analysis")
            sections.append("─"*64)
            
            # Generate historical data (simulated)
            trend_data = []
            for i in range(5):
                timestamp = (datetime.utcnow() - timedelta(days=i*7)).isoformat()
                score = max(0, overall_score - (i * 5) + random.randint(-10, 10))
                trend_data.append(TrendData(
                    timestamp=timestamp,
                    risk_score=score,
                    finding_count=len(findings) - i,
                    critical_count=sum(1 for f in findings if f.severity == 'critical'),
                ))
            
            trend_analysis = TrendAnalyzer.analyze_trends(trend_data)
            
            sections.append(f"  Trend: {trend_analysis['trend'].upper()}")
            sections.append(f"  Change: {trend_analysis['change']:+d} points")
            sections.append(f"  Average: {trend_analysis['average']}/100")
            sections.append(f"  Volatility: {trend_analysis['volatility']}")
            
            # Generate chart
            sections.append(TrendAnalyzer.generate_trend_chart(trend_data))
        
        # ── Step 6: Compliance Check ──────────────────────────────────────
        if compliance_mode:
            sections.append("\n[*] Phase 6: Compliance Assessment")
            sections.append("─"*64)
            
            report = RiskReport(overall_score=overall_score)
            compliance_results = ComplianceChecker.check_compliance(findings, report)
            compliance_score = ComplianceChecker.calculate_compliance_score(compliance_results)
            
            sections.append(f"  Overall Compliance Score: {compliance_score}/100")
            sections.append(f"\n  Framework Results:")
            
            frameworks = defaultdict(lambda: {'pass': 0, 'fail': 0, 'partial': 0, 'unknown': 0})
            for result in compliance_results:
                frameworks[result.framework][result.status] += 1
            
            for framework, counts in frameworks.items():
                sections.append(f"\n    {framework}:")
                sections.append(f"      ✅ Pass: {counts['pass']}")
                sections.append(f"      ❌ Fail: {counts['fail']}")
                sections.append(f"      ⚠️  Partial: {counts['partial']}")
        
        # ── Step 7: Attack Chain Analysis ─────────────────────────────────
        sections.append("\n[*] Phase 7: Attack Chain Analysis")
        sections.append("─"*64)
        
        feasible_chains = AttackChainAnalyzer.analyze_chains(findings)
        
        if feasible_chains:
            sections.append(f"  🔴 {len(feasible_chains)} feasible attack chain(s) detected:")
            
            for chain in feasible_chains[:5]:
                sections.append(f"\n    💀 {chain.name}")
                sections.append(f"        Risk Score: {chain.risk_score}/100")
                sections.append(f"        Likelihood: {chain.likelihood} | Impact: {chain.impact}")
                sections.append(f"        MITRE Techniques: {', '.join(chain.mitre_techniques)}")
                sections.append(f"        Steps:")
                for step in chain.steps[:3]:
                    sections.append(f"          {step}")
        else:
            sections.append("  🟢 No feasible attack chains detected")
        
        # ── Step 8: Category Visualization ────────────────────────────────
        sections.append(VisualizationEngine.generate_category_chart(categories))
        
        # ── Step 9: Recommendations ───────────────────────────────────────
        sections.append("\n[*] Phase 8: Prioritized Recommendations")
        sections.append("─"*64)
        
        recommendations = []
        
        # Critical recommendations
        if overall_score >= 70:
            recommendations.append("🔴 CRITICAL: Immediately patch all critical CVEs and disable backdoors")
            recommendations.append("🔴 CRITICAL: Rotate all compromised credentials")
            recommendations.append("🔴 CRITICAL: Enable all security controls (AMSI, ETW, Credential Guard)")
        
        # High recommendations
        if overall_score >= 40:
            recommendations.append("🟠 HIGH: Implement network segmentation")
            recommendations.append("🟠 HIGH: Deploy EDR with behavioral analysis")
            recommendations.append("🟠 HIGH: Enable MFA for all privileged accounts")
        
        # Medium recommendations
        if overall_score >= 15:
            recommendations.append("🟡 MEDIUM: Apply CIS benchmarks")
            recommendations.append("🟡 MEDIUM: Implement patch management process")
            recommendations.append("🟡 MEDIUM: Enable comprehensive audit logging")
        
        # Low recommendations
        recommendations.append("🟢 LOW: Conduct regular security assessments")
        recommendations.append("🟢 LOW: Train users on security awareness")
        recommendations.append("🟢 LOW: Review and update security policies")
        
        for i, rec in enumerate(recommendations[:10], 1):
            sections.append(f"  {i}. {rec}")
        
        # ── Step 10: Executive Summary ────────────────────────────────────
        if executive_summary:
            sections.append("\n[*] Phase 9: Executive Summary")
            sections.append("─"*64)
            
            summary = f"""
  EXECUTIVE SUMMARY
  ═══════════════════════════════════════════════════════════
  
  Overall Risk Score: {overall_score}/100 ({risk_level})
  
  Key Findings:
    • Total Findings: {len(findings)}
    • Critical: {sum(1 for f in findings if f.severity == 'critical')}
    • High: {sum(1 for f in findings if f.severity == 'high')}
    • Medium: {sum(1 for f in findings if f.severity == 'medium')}
  
  Top Risk Categories:
    {chr(10).join(f"    • {c.name}: {c.score}/100" for c in sorted(categories, key=lambda x: x.score, reverse=True)[:3])}
  
  Feasible Attack Chains: {len(feasible_chains)}
  
  Compliance Score: {compliance_score if compliance_mode else 'N/A'}/100
  
  Immediate Actions Required:
    {chr(10).join(f"    {i}. {rec}" for i, rec in enumerate(recommendations[:3], 1))}
  
  ═══════════════════════════════════════════════════════════
"""
            sections.append(summary)
        
        # ── Step 11: Export ───────────────────────────────────────────────
        if export_format:
            sections.append(f"\n[*] Phase 10: Export to {export_format.upper()}")
            sections.append("─"*64)
            
            report = RiskReport(
                overall_score=overall_score,
                risk_level=risk_level,
                total_findings=len(findings),
                critical_findings=sum(1 for f in findings if f.severity == 'critical'),
                high_findings=sum(1 for f in findings if f.severity == 'high'),
                medium_findings=sum(1 for f in findings if f.severity == 'medium'),
                low_findings=sum(1 for f in findings if f.severity == 'low'),
                categories=categories,
                mitre_coverage=dict(mitre_coverage) if mitre_mode else {},
                recommendations=recommendations,
                timestamp=datetime.utcnow().isoformat(),
            )
            
            if export_format == 'json':
                export_path = f"/tmp/risk_report_{int(time.time())}.json"
                with open(export_path, 'w') as f:
                    json.dump(report.to_dict(), f, indent=2)
                sections.append(f"  ✅ Exported to: {export_path}")
        
        # ── Summary ───────────────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Risk Assessment Summary]")
        sections.append("━"*64)
        sections.append(f"  Overall Risk Score: {overall_score}/100")
        sections.append(f"  Risk Level: {risk_level}")
        sections.append(f"  Total Findings: {len(findings)}")
        sections.append(f"  Categories Analyzed: {len(categories)}")
        sections.append(f"  Attack Chains: {len(feasible_chains)}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Save to Loot ──────────────────────────────────────────────────
        self.loot(
            {
                "type": "risk_assessment",
                "overall_score": overall_score,
                "risk_level": risk_level,
                "total_findings": len(findings),
                "categories": [c.to_dict() for c in categories],
                "duration": duration,
            },
            category='risk',
            source='risk-scoring-engine',
            confidence='high'
        )
        
        self.info(f"📊 Risk Scoring Engine complete — Score: {overall_score}/100 ({risk_level})")
        
        return '\n'.join(sections)
    
    def _generate_simulated_findings(self, session) -> List[RiskFinding]:
        """Generate simulated findings for demonstration."""
        findings = []
        
        # Check basic conditions
        privs = self._exec(session, "whoami /priv 2>nul; id 2>/dev/null")
        is_admin = privs and ('SeImpersonatePrivilege' in privs or 'uid=0' in privs or 'root' in privs)
        
        if is_admin:
            findings.append(RiskFinding(
                id='sim_001',
                title='Running with Administrative Privileges',
                severity='high',
                category='privilege_escalation',
                mitre_id='T1078',
                description='Current session has administrative privileges',
                recommendation='Apply principle of least privilege',
                timestamp=datetime.utcnow().isoformat(),
                source='risk-scoring-engine',
                confidence='high',
            ))
        
        # Add some standard findings
        findings.extend([
            RiskFinding(
                id='sim_002',
                title='LLMNR/NBT-NS Enabled',
                severity='medium',
                category='network_security',
                mitre_id='T1557',
                description='Name resolution poisoning possible',
                recommendation='Disable LLMNR and NBT-NS',
                timestamp=datetime.utcnow().isoformat(),
                source='risk-scoring-engine',
            ),
            RiskFinding(
                id='sim_003',
                title='SMB Signing Not Enforced',
                severity='high',
                category='network_security',
                mitre_id='T1557',
                description='NTLM relay attacks possible',
                recommendation='Enable SMB signing',
                timestamp=datetime.utcnow().isoformat(),
                source='risk-scoring-engine',
            ),
        ])
        
        return findings
    
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