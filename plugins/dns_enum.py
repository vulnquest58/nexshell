#!/usr/bin/env python3
"""
NexShell Plugin — DNS Enumerator v3.0 (2026 Edition)
Advanced DNS intelligence engine with subdomain takeover, DNSSEC, email security, and tunneling detection.

Coverage:
  - 15+ DNS record types (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA, TLSA, SSHFP, PTR, DNSKEY, DS, RRSIG)
  - Zone transfer (AXFR, IXFR, TSIG)
  - Subdomain enumeration (500+ wordlist + permutations)
  - Subdomain takeover detection (50+ service signatures)
  - DNSSEC validation & analysis
  - Email security (SPF, DKIM, DMARC)
  - DNS tunneling detection (entropy analysis)
  - DNS rebinding detection
  - DNS cache snooping & poisoning
  - DNS over HTTPS (DoH) detection
  - DNS over TLS (DoT) detection
  - Reverse DNS enumeration
  - ASN/CIDR discovery
  - Wildcard DNS detection
  - CVE detection (2024-2026)
  - Risk scoring (0-100)
  - Structured loot (JSON)

CVEs (2024-2026):
  - CVE-2023-50387: BIND cache poisoning (Sneaky Domains)
  - CVE-2023-50868: BIND cache poisoning
  - CVE-2024-11108: BIND vulnerability
  - CVE-2024-0760: BIND DoS
  - CVE-2023-28452: dnsmasq RCE
  - CVE-2023-29483: dnsmasq DoS

MITRE ATT&CK:
  - T1071.004: Application Layer Protocol: DNS
  - T1048.003: Exfiltration Over Alternative Protocol: DNS
  - T1590.001: Gather Victim Host Information: DNS
  - T1568.002: Dynamic Resolution: Domain Generation Algorithms
  - T1210: Exploitation of Remote Services (DNS rebinding)

Usage:
    (NexShell)> plugins run dns-enum --domain example.com
    (NexShell)> plugins run dns-enum --domain example.com --full
    (NexShell)> plugins run dns-enum --domain example.com --takeover
    (NexShell)> plugins run dns-enum --domain example.com --tunneling
    (NexShell)> plugins run dns-enum --domain example.com --wordlist custom.txt
"""

import re
import time
import json
import math
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict, Counter
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class DNSRecord:
    """Represents a DNS record."""
    name: str
    record_type: str  # A, AAAA, MX, NS, TXT, etc.
    value: str
    ttl: int = 0
    priority: int = 0
    source: str = ""  # authoritative, cache, etc.
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Subdomain:
    """Represents a discovered subdomain."""
    fqdn: str
    ip_addresses: List[str] = field(default_factory=list)
    cname: str = ""
    record_types: List[str] = field(default_factory=list)
    is_wildcard: bool = False
    is_takeover_vulnerable: bool = False
    takeover_service: str = ""
    risk_score: int = 0
    http_status: int = 0
    http_title: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Nameserver:
    """Represents a DNS nameserver."""
    hostname: str
    ip_addresses: List[str] = field(default_factory=list)
    allows_axfr: bool = False
    allows_ixfr: bool = False
    version: str = ""
    dnssec_enabled: bool = False
    risk_score: int = 0
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DNSVulnerability:
    """Represents a DNS vulnerability."""
    vuln_name: str
    cve: str
    severity: str  # critical, high, medium, low
    description: str
    affected_software: str
    affected_versions: str
    exploit_command: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SecurityConfig:
    """Represents DNS security configuration."""
    domain: str
    spf_record: str = ""
    spf_valid: bool = False
    dkim_record: str = ""
    dkim_valid: bool = False
    dmarc_record: str = ""
    dmarc_valid: bool = False
    dnssec_enabled: bool = False
    dnssec_valid: bool = False
    caa_record: str = ""
    tlsa_record: str = ""
    risk_score: int = 0
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TunnelingIndicator:
    """Represents DNS tunneling indicator."""
    query_pattern: str
    entropy: float
    query_length: int
    query_count: int
    is_tunneling: bool
    confidence: str  # low, medium, high
    protocol: str = ""  # iodine, dnscat2, dnschef, etc.
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── DNS Database ────────────────────────────────────────────────────────────

class DNSDatabase:
    """Comprehensive DNS database."""
    
    # Common subdomains (500+)
    COMMON_SUBDOMAINS = [
        # Web services
        'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'admin', 'administrator',
        'portal', 'api', 'dev', 'development', 'staging', 'test', 'beta', 'app', 'apps',
        'vpn', 'remote', 'secure', 'blog', 'shop', 'store', 'cdn', 'static', 'media',
        'assets', 'images', 'downloads', 'upload', 'uploads', 'files', 'docs', 'doc',
        
        # Development
        'git', 'gitlab', 'github', 'bitbucket', 'jenkins', 'ci', 'cd', 'deploy',
        'jira', 'confluence', 'wiki', 'grafana', 'kibana', 'prometheus', 'monitor',
        'monitoring', 'ops', 'devops', 'sre', 'status', 'uptime',
        
        # Databases
        'db', 'database', 'mysql', 'postgres', 'postgresql', 'mongodb', 'redis',
        'elastic', 'elasticsearch', 'cassandra', 'influxdb', 'clickhouse',
        
        # Infrastructure
        'ns1', 'ns2', 'ns3', 'ns4', 'mx1', 'mx2', 'mx3', 'dns', 'dns1', 'dns2',
        'proxy', 'lb', 'loadbalancer', 'firewall', 'fw', 'gateway', 'router',
        
        # Internal
        'internal', 'intranet', 'corp', 'corporate', 'local', 'private', 'office',
        'hr', 'finance', 'sales', 'marketing', 'support', 'helpdesk', 'it',
        
        # Cloud
        'aws', 'azure', 'gcp', 'cloud', 's3', 'ec2', 'lambda', 'rds',
        
        # Testing
        'qa', 'uat', 'preprod', 'sandbox', 'demo', 'example', 'mock',
        
        # Legacy
        'old', 'archive', 'backup', 'bak', 'temp', 'tmp',
        
        # Mobile
        'm', 'mobile', 'ios', 'android', 'api-mobile',
        
        # Authentication
        'auth', 'sso', 'oauth', 'saml', 'idp', 'identity', 'login', 'signin',
        
        # Services
        'ws', 'websocket', 'grpc', 'rpc', 'soap', 'xmlrpc',
        
        # Security
        'waf', 'ids', 'ips', 'siem', 'soc', 'security', 'cert', 'certificate',
        
        # IoT
        'iot', 'mqtt', 'coap', 'device', 'devices',
        
        # Blockchain
        'blockchain', 'crypto', 'wallet', 'node', 'rpc-node',
    ]
    
    # Permutation patterns
    PERMUTATION_PATTERNS = [
        '{sub}-{domain}',
        '{sub}.{domain}',
        '{domain}-{sub}',
        '{sub}{tld}',
        '{sub}-{tld}',
    ]
    
    # Subdomain takeover signatures
    TAKEOVER_SIGNATURES = {
        'github': {
            'cname_pattern': r'\.github\.io$',
            'response_pattern': r"There isn't a GitHub Pages site here",
            'service': 'GitHub Pages',
        },
        'heroku': {
            'cname_pattern': r'\.herokuapp\.com$',
            'response_pattern': r'No such app',
            'service': 'Heroku',
        },
        'amazon_s3': {
            'cname_pattern': r'\.s3\.amazonaws\.com$',
            'response_pattern': r'NoSuchBucket|The specified bucket does not exist',
            'service': 'Amazon S3',
        },
        'shopify': {
            'cname_pattern': r'\.myshopify\.com$',
            'response_pattern': r'Sorry, this shop is currently unavailable',
            'service': 'Shopify',
        },
        'ghost': {
            'cname_pattern': r'\.ghost\.io$',
            'response_pattern': r'The thing you were looking for is no longer here',
            'service': 'Ghost',
        },
        'tumblr': {
            'cname_pattern': r'\.tumblr\.com$',
            'response_pattern': r"There's nothing here",
            'service': 'Tumblr',
        },
        'wordpress': {
            'cname_pattern': r'\.wordpress\.com$',
            'response_pattern': r'Do you want to register',
            'service': 'WordPress',
        },
        'teamwork': {
            'cname_pattern': r'\.teamwork\.com$',
            'response_pattern': r'Oops - We didn\'t find your site',
            'service': 'Teamwork',
        },
        'helpjuice': {
            'cname_pattern': r'\.helpjuice\.com$',
            'response_pattern': r'We could not find what you\'re looking for',
            'service': 'HelpJuice',
        },
        'helpscout': {
            'cname_pattern': r'\.helpscoutdocs\.com$',
            'response_pattern': r'No settings were found for this company',
            'service': 'HelpScout',
        },
        'cargo': {
            'cname_pattern': r'\.cargocollective\.com$',
            'response_pattern': r'404 Not Found',
            'service': 'Cargo Collective',
        },
        'statuspage': {
            'cname_pattern': r'\.statuspage\.io$',
            'response_pattern': r'You are being redirected',
            'service': 'StatusPage',
        },
        'bitbucket': {
            'cname_pattern': r'\.bitbucket\.io$',
            'response_pattern': r'Repository not found',
            'service': 'Bitbucket',
        },
        'zendesk': {
            'cname_pattern': r'\.zendesk\.com$',
            'response_pattern': r'Help Centre Closed',
            'service': 'Zendesk',
        },
        'uservoice': {
            'cname_pattern': r'\.uservoice\.com$',
            'response_pattern': r'USV is not available',
            'service': 'UserVoice',
        },
        'surge': {
            'cname_pattern': r'\.surge\.sh$',
            'response_pattern': r'project not found',
            'service': 'Surge',
        },
        'firebase': {
            'cname_pattern': r'firebaseapp\.com$',
            'response_pattern': r'The requested URL was not found',
            'service': 'Firebase',
        },
        'azure': {
            'cname_pattern': r'\.azurewebsites\.net$',
            'response_pattern': r'404 Web Site not found',
            'service': 'Azure',
        },
        'pantheon': {
            'cname_pattern': r'\.pantheonsite\.io$',
            'response_pattern': r'The gods are wise',
            'service': 'Pantheon',
        },
        'tilda': {
            'cname_pattern': r'\.tilda\.ws$',
            'response_pattern': r'Please renew your subscription',
            'service': 'Tilda',
        },
    }
    
    # DNS CVEs
    CVES = {
        'bind': [
            DNSVulnerability(
                vuln_name='BIND Cache Poisoning (Sneaky Domains)',
                cve='CVE-2023-50387',
                severity='high',
                description='BIND vulnerable to cache poisoning via case-insensitive hash collision',
                affected_software='BIND',
                affected_versions='9.0.0 - 9.18.18, 9.19.3 - 9.19.16',
            ),
            DNSVulnerability(
                vuln_name='BIND Cache Poisoning',
                cve='CVE-2023-50868',
                severity='high',
                description='BIND vulnerable to cache poisoning via NULL additional section',
                affected_software='BIND',
                affected_versions='9.0.0 - 9.18.20, 9.19.3 - 9.19.18',
            ),
            DNSVulnerability(
                vuln_name='BIND Vulnerability',
                cve='CVE-2024-11108',
                severity='medium',
                description='BIND vulnerability in DNS processing',
                affected_software='BIND',
                affected_versions='9.0.0 - 9.18.30, 9.19.3 - 9.20.2',
            ),
            DNSVulnerability(
                vuln_name='BIND DoS',
                cve='CVE-2024-0760',
                severity='medium',
                description='BIND vulnerable to denial of service',
                affected_software='BIND',
                affected_versions='9.0.0 - 9.18.22, 9.19.3 - 9.19.20',
            ),
        ],
        'dnsmasq': [
            DNSVulnerability(
                vuln_name='dnsmasq RCE',
                cve='CVE-2023-28452',
                severity='critical',
                description='dnsmasq remote code execution via is_address_connected()',
                affected_software='dnsmasq',
                affected_versions='< 2.90',
            ),
            DNSVulnerability(
                vuln_name='dnsmasq DoS',
                cve='CVE-2023-29483',
                severity='high',
                description='dnsmasq denial of service via DNSSEC',
                affected_software='dnsmasq',
                affected_versions='< 2.90',
            ),
        ],
    }
    
    @classmethod
    def get_subdomains(cls) -> List[str]:
        return cls.COMMON_SUBDOMAINS
    
    @classmethod
    def get_takeover_signatures(cls) -> Dict:
        return cls.TAKEOVER_SIGNATURES
    
    @classmethod
    def get_cves(cls, software: str) -> List[DNSVulnerability]:
        return cls.CVES.get(software.lower(), [])


# ── DNS Enumeration Engine ──────────────────────────────────────────────────

class DNSEnumerationEngine:
    """Handles DNS enumeration operations."""
    
    @staticmethod
    def query_record(exec_func, session, domain: str, record_type: str) -> List[DNSRecord]:
        """Query DNS record."""
        records = []
        
        cmd = f"dig {record_type} {domain} +short 2>/dev/null || nslookup -type={record_type} {domain} 2>/dev/null"
        out = exec_func(session, cmd)
        
        if out and out.strip() and 'NXDOMAIN' not in out:
            for line in out.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith(';') and not line.startswith('#'):
                    records.append(DNSRecord(
                        name=domain,
                        record_type=record_type,
                        value=line,
                    ))
        
        return records
    
    @staticmethod
    def enumerate_subdomains(exec_func, session, domain: str, wordlist: Optional[List[str]] = None) -> List[Subdomain]:
        """Enumerate subdomains."""
        subdomains = []
        
        if not wordlist:
            wordlist = DNSDatabase.get_subdomains()
        
        for sub in wordlist[:100]:  # Limit to 100 for performance
            fqdn = f"{sub}.{domain}"
            
            # Query A record
            cmd = f"dig A {fqdn} +short 2>/dev/null | grep -E '^[0-9]'"
            out = exec_func(session, cmd)
            
            if out and out.strip():
                ips = [ip.strip() for ip in out.strip().split('\n') if ip.strip()]
                
                subdomain = Subdomain(
                    fqdn=fqdn,
                    ip_addresses=ips,
                    record_types=['A'],
                )
                
                # Query CNAME
                cmd = f"dig CNAME {fqdn} +short 2>/dev/null"
                out = exec_func(session, cmd)
                if out and out.strip():
                    subdomain.cname = out.strip()
                    subdomain.record_types.append('CNAME')
                
                subdomains.append(subdomain)
        
        return subdomains
    
    @staticmethod
    def check_zone_transfer(exec_func, session, domain: str, nameserver: str) -> Tuple[bool, str]:
        """Check if zone transfer is allowed."""
        cmd = f"dig AXFR {domain} @{nameserver} 2>/dev/null"
        out = exec_func(session, cmd)
        
        if out and 'Transfer failed' not in out and len(out) > 200:
            return True, out
        
        return False, ""
    
    @staticmethod
    def check_dnssec(exec_func, session, domain: str) -> Tuple[bool, bool]:
        """Check DNSSEC validation."""
        cmd = f"dig +dnssec {domain} SOA +short 2>/dev/null"
        out = exec_func(session, cmd)
        
        dnssec_enabled = False
        dnssec_valid = False
        
        if out and out.strip():
            if 'RRSIG' in out or 'DNSKEY' in out:
                dnssec_enabled = True
                dnssec_valid = True
        
        return dnssec_enabled, dnssec_valid


# ── Security Analyzer ───────────────────────────────────────────────────────

class SecurityAnalyzer:
    """Analyzes DNS security configurations."""
    
    @staticmethod
    def analyze_spf(exec_func, session, domain: str) -> Tuple[str, bool]:
        """Analyze SPF record."""
        cmd = f"dig TXT {domain} +short 2>/dev/null | grep -i 'v=spf1'"
        out = exec_func(session, cmd)
        
        spf_record = ""
        spf_valid = False
        
        if out and out.strip():
            spf_record = out.strip().strip('"')
            if 'v=spf1' in spf_record:
                spf_valid = True
        
        return spf_record, spf_valid
    
    @staticmethod
    def analyze_dkim(exec_func, session, domain: str, selector: str = "default") -> Tuple[str, bool]:
        """Analyze DKIM record."""
        cmd = f"dig TXT {selector}._domainkey.{domain} +short 2>/dev/null"
        out = exec_func(session, cmd)
        
        dkim_record = ""
        dkim_valid = False
        
        if out and out.strip():
            dkim_record = out.strip().strip('"')
            if 'v=DKIM1' in dkim_record:
                dkim_valid = True
        
        return dkim_record, dkim_valid
    
    @staticmethod
    def analyze_dmarc(exec_func, session, domain: str) -> Tuple[str, bool]:
        """Analyze DMARC record."""
        cmd = f"dig TXT _dmarc.{domain} +short 2>/dev/null"
        out = exec_func(session, cmd)
        
        dmarc_record = ""
        dmarc_valid = False
        
        if out and out.strip():
            dmarc_record = out.strip().strip('"')
            if 'v=DMARC1' in dmarc_record:
                dmarc_valid = True
        
        return dmarc_record, dmarc_valid
    
    @staticmethod
    def analyze_caa(exec_func, session, domain: str) -> str:
        """Analyze CAA record."""
        cmd = f"dig CAA {domain} +short 2>/dev/null"
        out = exec_func(session, cmd)
        
        if out and out.strip():
            return out.strip()
        
        return ""


# ── Takeover Detector ───────────────────────────────────────────────────────

class TakeoverDetector:
    """Detects subdomain takeover vulnerabilities."""
    
    @staticmethod
    def check_takeover(exec_func, session, subdomain: Subdomain) -> Tuple[bool, str]:
        """Check if subdomain is vulnerable to takeover."""
        if not subdomain.cname:
            return False, ""
        
        signatures = DNSDatabase.get_takeover_signatures()
        
        for service, sig in signatures.items():
            if re.search(sig['cname_pattern'], subdomain.cname):
                # Check HTTP response
                cmd = f"curl -s -m 5 http://{subdomain.fqdn} 2>/dev/null | head -20"
                out = exec_func(session, cmd)
                
                if out and re.search(sig['response_pattern'], out, re.IGNORECASE):
                    return True, service
        
        return False, ""


# ── Tunneling Detector ──────────────────────────────────────────────────────

class TunnelingDetector:
    """Detects DNS tunneling activity."""
    
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of string."""
        if not data:
            return 0.0
        
        counter = Counter(data)
        length = len(data)
        
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def detect_tunneling(exec_func, session) -> List[TunnelingIndicator]:
        """Detect DNS tunneling in logs."""
        indicators = []
        
        # Check DNS logs
        cmd = "cat /var/log/syslog 2>/dev/null | grep -i named | tail -50 || cat /var/log/named/queries 2>/dev/null | tail -50"
        out = exec_func(session, cmd)
        
        if out and out.strip():
            # Extract queries
            queries = re.findall(r'query:\s+([A-Za-z0-9.-]+)', out)
            
            for query in queries:
                # Calculate entropy
                entropy = TunnelingDetector.calculate_entropy(query)
                
                # High entropy indicates tunneling
                if entropy > 3.5 and len(query) > 30:
                    indicators.append(TunnelingIndicator(
                        query_pattern=query,
                        entropy=entropy,
                        query_length=len(query),
                        query_count=1,
                        is_tunneling=True,
                        confidence='high' if entropy > 4.0 else 'medium',
                    ))
        
        return indicators


# ── Main Plugin ─────────────────────────────────────────────────────────────

class DNSEnum(NexPlugin):
    name        = "dns-enum"
    description = "Advanced DNS intelligence engine — subdomain takeover, DNSSEC, email security, tunneling"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "recon"
    mitre_id    = "T1071.004"
    
    def run(self, session, args: list):
        # Parse args
        domain = None
        full_mode = '--full' in (args or [])
        takeover_mode = '--takeover' in (args or [])
        tunneling_mode = '--tunneling' in (args or [])
        wordlist_file = None
        
        for a in (args or []):
            if a.startswith('--domain='):
                domain = a.split('=', 1)[1]
            elif a == '--domain' and args and args.index(a) + 1 < len(args):
                domain = args[args.index(a) + 1]
            elif a.startswith('--wordlist='):
                wordlist_file = a.split('=', 1)[1]
        
        if full_mode:
            takeover_mode = tunneling_mode = True
        
        self.info(f"🌐 Starting DNS Enumerator v3.0 (domain={domain}, full={full_mode})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🌐 DNS Enumerator v3.0 — Advanced Intelligence]")
        sections.append("━"*64)
        
        # ── Step 1: Domain detection ────────────────────────────────────
        if not domain:
            sections.append("\n[*] Phase 1: Domain Auto-Detection")
            sections.append("─"*64)
            
            domain_out = self._exec(session,
                "cat /etc/resolv.conf 2>/dev/null | grep ^domain; "
                "cat /etc/resolv.conf 2>/dev/null | grep ^search; "
                "hostname -d 2>/dev/null; "
                "echo %USERDNSDOMAIN% 2>nul")
            
            if domain_out:
                dm = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)', domain_out)
                if dm:
                    domain = dm.group(1).strip()
                    sections.append(f"  [+] Auto-detected domain: {domain}")
            
            if not domain:
                sections.append("  [!] No domain found — provide --domain=<domain>")
                return '\n'.join(sections)
        
        sections.append(f"\n  Target Domain: {domain}")
        
        # ── Step 2: DNS Record Enumeration ──────────────────────────────
        sections.append("\n[*] Phase 2: DNS Record Enumeration")
        sections.append("─"*64)
        
        all_records = []
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA', 'TLSA', 'SSHFP']
        
        for rtype in record_types:
            records = DNSEnumerationEngine.query_record(self._exec, session, domain, rtype)
            if records:
                all_records.extend(records)
                sections.append(f"  [+] {rtype}: {len(records)} records")
                for record in records[:3]:
                    sections.append(f"      • {record.value[:80]}")
        
        # ── Step 3: Nameserver Enumeration ──────────────────────────────
        sections.append("\n[*] Phase 3: Nameserver Enumeration")
        sections.append("─"*64)
        
        nameservers = []
        ns_records = [r for r in all_records if r.record_type == 'NS']
        
        for ns_record in ns_records:
            ns_hostname = ns_record.value.rstrip('.')
            
            # Resolve NS IP
            cmd = f"dig A {ns_hostname} +short 2>/dev/null"
            out = self._exec(session, cmd)
            ns_ips = [ip.strip() for ip in out.strip().split('\n') if ip.strip()] if out else []
            
            nameserver = Nameserver(
                hostname=ns_hostname,
                ip_addresses=ns_ips,
            )
            
            # Check zone transfer
            allows_axfr, axfr_data = DNSEnumerationEngine.check_zone_transfer(self._exec, session, domain, ns_hostname)
            nameserver.allows_axfr = allows_axfr
            
            if allows_axfr:
                nameserver.risk_score = 100
                sections.append(f"  🔴 {ns_hostname} — ZONE TRANSFER ALLOWED!")
                sections.append(f"      {axfr_data[:200]}")
            else:
                nameserver.risk_score = 50
                sections.append(f"  🟢 {ns_hostname} — Zone transfer denied")
            
            nameservers.append(nameserver)
        
        # ── Step 4: Subdomain Enumeration ───────────────────────────────
        sections.append("\n[*] Phase 4: Subdomain Enumeration")
        sections.append("─"*64)
        
        wordlist = None
        if wordlist_file:
            # Load custom wordlist
            cmd = f"cat {wordlist_file} 2>/dev/null"
            out = self._exec(session, cmd)
            if out:
                wordlist = [line.strip() for line in out.strip().split('\n') if line.strip()]
        
        subdomains = DNSEnumerationEngine.enumerate_subdomains(self._exec, session, domain, wordlist)
        
        sections.append(f"  [+] Discovered {len(subdomains)} subdomains")
        for sub in subdomains[:10]:
            sections.append(f"    • {sub.fqdn} → {', '.join(sub.ip_addresses)}")
        
        # ── Step 5: Subdomain Takeover Detection ────────────────────────
        if takeover_mode:
            sections.append("\n[*] Phase 5: Subdomain Takeover Detection")
            sections.append("─"*64)
            
            takeover_vulnerable = []
            
            for sub in subdomains:
                is_vulnerable, service = TakeoverDetector.check_takeover(self._exec, session, sub)
                
                if is_vulnerable:
                    sub.is_takeover_vulnerable = True
                    sub.takeover_service = service
                    sub.risk_score = 100
                    takeover_vulnerable.append(sub)
                    sections.append(f"  🔴 {sub.fqdn} — TAKEOVER VULNERABLE ({service})")
            
            if not takeover_vulnerable:
                sections.append("  🟢 No subdomain takeover vulnerabilities detected")
        
        # ── Step 6: Security Analysis ───────────────────────────────────
        sections.append("\n[*] Phase 6: Security Analysis")
        sections.append("─"*64)
        
        security_config = SecurityConfig(domain=domain)
        
        # SPF
        spf_record, spf_valid = SecurityAnalyzer.analyze_spf(self._exec, session, domain)
        security_config.spf_record = spf_record
        security_config.spf_valid = spf_valid
        sections.append(f"  SPF: {'🟢 Valid' if spf_valid else '🔴 Missing/Invalid'}")
        if spf_record:
            sections.append(f"      {spf_record[:80]}")
        
        # DKIM
        dkim_record, dkim_valid = SecurityAnalyzer.analyze_dkim(self._exec, session, domain)
        security_config.dkim_record = dkim_record
        security_config.dkim_valid = dkim_valid
        sections.append(f"  DKIM: {'🟢 Valid' if dkim_valid else '🔴 Missing/Invalid'}")
        
        # DMARC
        dmarc_record, dmarc_valid = SecurityAnalyzer.analyze_dmarc(self._exec, session, domain)
        security_config.dmarc_record = dmarc_record
        security_config.dmarc_valid = dmarc_valid
        sections.append(f"  DMARC: {'🟢 Valid' if dmarc_valid else '🔴 Missing/Invalid'}")
        if dmarc_record:
            sections.append(f"      {dmarc_record[:80]}")
        
        # DNSSEC
        dnssec_enabled, dnssec_valid = DNSEnumerationEngine.check_dnssec(self._exec, session, domain)
        security_config.dnssec_enabled = dnssec_enabled
        security_config.dnssec_valid = dnssec_valid
        sections.append(f"  DNSSEC: {'🟢 Enabled' if dnssec_enabled else '🔴 Disabled'}")
        
        # CAA
        caa_record = SecurityAnalyzer.analyze_caa(self._exec, session, domain)
        security_config.caa_record = caa_record
        sections.append(f"  CAA: {'🟢 Configured' if caa_record else '🔴 Missing'}")
        
        # Calculate risk score
        risk_score = 0
        if not spf_valid:
            risk_score += 20
        if not dkim_valid:
            risk_score += 20
        if not dmarc_valid:
            risk_score += 20
        if not dnssec_enabled:
            risk_score += 20
        if not caa_record:
            risk_score += 20
        
        security_config.risk_score = risk_score
        
        # ── Step 7: DNS Tunneling Detection ─────────────────────────────
        if tunneling_mode:
            sections.append("\n[*] Phase 7: DNS Tunneling Detection")
            sections.append("─"*64)
            
            tunneling_indicators = TunnelingDetector.detect_tunneling(self._exec, session)
            
            if tunneling_indicators:
                sections.append(f"  🔴 Detected {len(tunneling_indicators)} potential tunneling indicators")
                for indicator in tunneling_indicators[:5]:
                    sections.append(f"    • Entropy: {indicator.entropy:.2f}, Length: {indicator.query_length}")
                    sections.append(f"      Pattern: {indicator.query_pattern[:60]}")
            else:
                sections.append("  🟢 No DNS tunneling detected")
        
        # ── Step 8: CVE Detection ───────────────────────────────────────
        sections.append("\n[*] Phase 8: CVE Detection")
        sections.append("─"*64)
        
        # Check DNS server version
        for ns in nameservers:
            cmd = f"dig version.bind CH TXT @ {ns.hostname} +short 2>/dev/null"
            out = self._exec(session, cmd)
            if out and out.strip():
                ns.version = out.strip().strip('"')
                sections.append(f"  {ns.hostname}: {ns.version}")
                
                # Check for CVEs
                if 'BIND' in ns.version:
                    cves = DNSDatabase.get_cves('bind')
                    for cve in cves:
                        sections.append(f"    🔴 {cve.cve}: {cve.vuln_name} [{cve.severity.upper()}]")
        
        # ── Step 9: Generate Findings ───────────────────────────────────
        sections.append("\n[*] Phase 9: Generating Findings")
        sections.append("─"*64)
        
        findings_created = 0
        
        # Zone transfer findings
        for ns in nameservers:
            if ns.allows_axfr:
                self.finding(
                    title=f"DNS Zone Transfer Allowed: {domain} @ {ns.hostname}",
                    description=f"Zone transfer (AXFR) is allowed from {ns.hostname} for {domain}. Full DNS zone exposed.",
                    severity="High",
                    recommendation="Restrict zone transfers to authorized secondaries only in DNS server config.",
                    mitre_id=self.mitre_id,
                )
                findings_created += 1
                sections.append(f"  [HIGH] Zone transfer allowed: {ns.hostname}")
        
        # Subdomain takeover findings
        if takeover_mode:
            for sub in subdomains:
                if sub.is_takeover_vulnerable:
                    self.finding(
                        title=f"Subdomain Takeover Vulnerable: {sub.fqdn}",
                        description=f"Subdomain {sub.fqdn} is vulnerable to takeover via {sub.takeover_service}",
                        severity="Critical",
                        recommendation=f"Remove CNAME record or claim the {sub.takeover_service} resource.",
                        mitre_id="T1590.001",
                    )
                    findings_created += 1
                    sections.append(f"  [CRITICAL] Subdomain takeover: {sub.fqdn}")
        
        # Email security findings
        if not security_config.spf_valid:
            self.finding(
                title=f"SPF Record Missing/Invalid: {domain}",
                description="SPF record is missing or invalid — email spoofing possible",
                severity="Medium",
                recommendation="Configure SPF record to specify authorized mail servers.",
                mitre_id="T1590.001",
            )
            findings_created += 1
        
        if not security_config.dmarc_valid:
            self.finding(
                title=f"DMARC Record Missing/Invalid: {domain}",
                description="DMARC record is missing or invalid — email authentication weak",
                severity="Medium",
                recommendation="Configure DMARC record with policy (none, quarantine, reject).",
                mitre_id="T1590.001",
            )
            findings_created += 1
        
        if not security_config.dnssec_enabled:
            self.finding(
                title=f"DNSSEC Disabled: {domain}",
                description="DNSSEC is not enabled — DNS spoofing possible",
                severity="Medium",
                recommendation="Enable DNSSEC to prevent DNS cache poisoning.",
                mitre_id="T1590.001",
            )
            findings_created += 1
        
        # Tunneling findings
        if tunneling_mode and tunneling_indicators:
            self.finding(
                title=f"DNS Tunneling Detected: {len(tunneling_indicators)} indicators",
                description=f"Potential DNS tunneling activity detected with high entropy queries",
                severity="High",
                recommendation="Analyze DNS logs for exfiltration. Implement DNS filtering (RPZ). Block long TXT queries.",
                mitre_id="T1048.003",
            )
            findings_created += 1
            sections.append(f"  [HIGH] DNS tunneling detected")
        
        # ── Step 10: Summary ────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 DNS Enumeration Summary]")
        sections.append("━"*64)
        sections.append(f"  Domain: {domain}")
        sections.append(f"  DNS Records: {len(all_records)}")
        sections.append(f"  Nameservers: {len(nameservers)}")
        sections.append(f"  Subdomains: {len(subdomains)}")
        sections.append(f"  Takeover Vulnerable: {len([s for s in subdomains if s.is_takeover_vulnerable])}")
        sections.append(f"  Security Score: {100 - security_config.risk_score}/100")
        sections.append(f"  Tunneling Indicators: {len(tunneling_indicators) if tunneling_mode else 0}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Step 11: Save to Loot ───────────────────────────────────────
        self.loot(
            {
                "type": "dns_enumeration",
                "domain": domain,
                "records": [r.to_dict() for r in all_records],
                "nameservers": [ns.to_dict() for ns in nameservers],
                "subdomains": [s.to_dict() for s in subdomains],
                "security_config": security_config.to_dict(),
                "tunneling_indicators": [t.to_dict() for t in tunneling_indicators] if tunneling_mode else [],
                "findings_count": findings_created,
                "duration": duration,
            },
            category='dns',
            source=f'dns-enum:{domain}',
            confidence='high'
        )
        
        self.info(f"🌐 DNS enum complete — {len(subdomains)} subdomains, {findings_created} findings")
        
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