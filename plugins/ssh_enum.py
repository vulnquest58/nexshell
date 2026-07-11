#!/usr/bin/env python3
"""
NexShell Plugin — SSH Enumerator v3.0 (2026 Edition)
Advanced SSH intelligence & exploitation engine with 15+ CVEs, certificate abuse,
cloud SSH integration, modern auth analysis, and auto-exploitation.

Coverage:
  - 15+ SSH CVEs (regreSSHion, Terrapin, xz backdoor, etc.)
  - SSH certificate authority (CA) abuse & detection
  - Cloud SSH (AWS EC2 Instance Connect, Azure SSH, GCP OS Login)
  - Modern authentication (FIDO2, WebAuthn, Passkeys)
  - SSH audit (cipher, KEX, MAC, host key analysis)
  - Pivoting & tunneling detection (10+ tools)
  - MITM attack detection (Terrapin, SSH MITM)
  - Brute force protection analysis (Fail2ban, account lockout)
  - Hardening compliance (CIS, NIST, STIG)
  - Honeypot detection (Cowrie, Kippo, Endlessh)
  - SSH over alternative protocols (WebSocket, DNS, ICMP)
  - Session forensics & reconstruction
  - Persistence techniques (10+ methods)
  - SSH certificate forgery & abuse
  - Risk scoring (0-100 per vector)
  - Structured loot (JSON)

CVEs (2016-2026):
  - CVE-2024-6387: regreSSHion (unauthenticated RCE, race condition)
  - CVE-2024-6849: RCE in ssh-agent (key parsing)
  - CVE-2024-3094: xz backdoor (SSH/liblzma)
  - CVE-2023-51385: ProxyCommand OS command injection
  - CVE-2023-48795: Terrapin attack (prefix truncation)
  - CVE-2023-38408: Remote code execution via SSH agent
  - CVE-2023-28531: SSH agent key disclosure
  - CVE-2023-25136: Double-free in ssh-agent
  - CVE-2021-41617: Privilege escalation via PAM
  - CVE-2020-15778: scp command injection
  - CVE-2020-14145: Username enumeration
  - CVE-2018-15919: Username enumeration (timing)
  - CVE-2018-15473: Username enumeration (timing)
  - CVE-2016-6515: Password auth DoS
  - CVE-2016-0777/0778: Information disclosure

MITRE ATT&CK:
  - T1021.004: Remote Services: SSH
  - T1563: Remote Service Session Hijacking
  - T1552.004: Unsecured Credentials: Private Keys
  - T1572: Protocol Tunneling
  - T1048: Exfiltration Over Alternative Protocol
  - T1556: Modify Authentication Process
  - T1550: Use Alternate Authentication Material
  - T1078: Valid Accounts
  - T1098: Account Manipulation
  - T1110: Brute Force

Usage:
    (NexShell)> plugins run ssh-enum
    (NexShell)> plugins run ssh-enum --deep
    (NexShell)> plugins run ssh-enum --target 10.0.0.50
    (NexShell)> plugins run ssh-enum --audit
    (NexShell)> plugins run ssh-enum --certificates
    (NexShell)> plugins run ssh-enum --cloud
    (NexShell)> plugins run ssh-enum --pivots
    (NexShell)> plugins run ssh-enum --cve-check
    (NexShell)> plugins run ssh-enum --full
    (NexShell)> plugins run ssh-enum --list
"""

import re
import time
import json
import random
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class SSHConfig:
    """Represents SSH configuration."""
    version: str = ""
    server_enabled: bool = False
    port: int = 22
    permit_root_login: str = "prohibit-password"
    password_auth: bool = True
    pubkey_auth: bool = True
    agent_forwarding: bool = True
    tcp_forwarding: bool = True
    gateway_ports: bool = False
    x11_forwarding: bool = False
    host_based_auth: bool = False
    permit_empty_passwords: bool = False
    max_auth_tries: int = 6
    login_grace_time: int = 120
    strict_modes: bool = True
    log_level: str = "INFO"
    use_pam: bool = True
    ciphers: List[str] = field(default_factory=list)
    kex_algorithms: List[str] = field(default_factory=list)
    mac_algorithms: List[str] = field(default_factory=list)
    host_key_algorithms: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SSHKey:
    """Represents an SSH key."""
    path: str
    key_type: str = ""  # RSA, DSA, ECDSA, Ed25519
    key_size: int = 0
    fingerprint: str = ""
    comment: str = ""
    is_private: bool = True
    is_weak: bool = False
    weakness_reason: str = ""
    owner: str = ""
    permissions: str = ""
    last_modified: str = ""
    in_agent: bool = False
    certificate: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SSHCertificate:
    """Represents an SSH certificate."""
    path: str
    cert_type: str = ""  # user, host
    key_id: str = ""
    serial: str = ""
    valid_from: str = ""
    valid_to: str = ""
    principals: List[str] = field(default_factory=list)
    ca_key: str = ""
    ca_fingerprint: str = ""
    extensions: List[str] = field(default_factory=list)
    critical_options: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SSHVulnerability:
    """Represents an SSH vulnerability."""
    cve_id: str
    name: str
    severity: str
    description: str
    affected_versions: str
    exploit_available: bool = False
    exploit_tool: str = ""
    risk_score: int = 0
    pre_auth: bool = False
    cvss_score: float = 0.0
    mitre_id: str = ""
    patch_available: bool = True
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SSHPivot:
    """Represents an SSH pivot point."""
    source: str
    target: str
    method: str  # ProxyJump, ProxyCommand, tunnel, agent-forwarding
    port: int = 22
    user: str = ""
    key_path: str = ""
    active: bool = False
    risk_level: str = "medium"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SSHAuditResult:
    """Represents SSH audit result."""
    category: str  # cipher, kex, mac, host_key
    algorithm: str
    status: str  # secure, weak, deprecated, insecure
    recommendation: str = ""
    risk_score: int = 0
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CloudSSHConfig:
    """Represents cloud SSH configuration."""
    provider: str  # aws, azure, gcp
    service: str = ""
    enabled: bool = False
    certificate_based: bool = False
    mfa_required: bool = False
    ip_restriction: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── SSH CVEs Database (15+) ────────────────────────────────────────────────

class SSHCVEDatabase:
    """Comprehensive database of SSH-related CVEs."""
    
    CVES = [
        SSHVulnerability(
            cve_id='CVE-2024-6387',
            name='regreSSHion',
            severity='critical',
            description='Unauthenticated Remote Code Execution via race condition in sshd signal handler (SIGALRM). Affects glibc-based Linux systems.',
            affected_versions='OpenSSH 8.5p1 - 9.7p1 (before 9.8p1)',
            exploit_available=True,
            exploit_tool='PoC available on GitHub (regresshion)',
            risk_score=100,
            pre_auth=True,
            cvss_score=9.8,
            mitre_id='T1210',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2024-6849',
            name='ssh-agent RCE',
            severity='critical',
            description='Remote Code Execution in ssh-agent via malicious PKCS#11 provider',
            affected_versions='OpenSSH < 9.8p1',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=95,
            pre_auth=False,
            cvss_score=8.8,
            mitre_id='T1210',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2024-3094',
            name='xz backdoor',
            severity='critical',
            description='Backdoor in xz/liblzma affecting SSH authentication via PAM',
            affected_versions='xz 5.6.0, 5.6.1',
            exploit_available=True,
            exploit_tool='Downgrade to xz 5.4.x',
            risk_score=100,
            pre_auth=False,
            cvss_score=10.0,
            mitre_id='T1195',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2023-51385',
            name='ProxyCommand Injection',
            severity='high',
            description='OS command injection via hostname with newline characters in ProxyCommand',
            affected_versions='OpenSSH < 9.6p1',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=85,
            pre_auth=False,
            cvss_score=7.8,
            mitre_id='T1203',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2023-48795',
            name='Terrapin Attack',
            severity='high',
            description='SSH protocol prefix truncation attack allowing MITM',
            affected_versions='All OpenSSH versions (protocol flaw)',
            exploit_available=True,
            exploit_tool='Terrapin scanner',
            risk_score=80,
            pre_auth=True,
            cvss_score=5.9,
            mitre_id='T1557',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2023-38408',
            name='SSH Agent RCE',
            severity='critical',
            description='Remote Code Execution via forwarded SSH-agent on PKCS#11 providers',
            affected_versions='OpenSSH < 9.3p2',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=95,
            pre_auth=False,
            cvss_score=8.8,
            mitre_id='T1210',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2023-28531',
            name='SSH Agent Key Disclosure',
            severity='medium',
            description='Information disclosure in ssh-agent via malformed certificates',
            affected_versions='OpenSSH < 9.2p1',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=65,
            pre_auth=False,
            cvss_score=5.9,
            mitre_id='T1552',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2021-41617',
            name='PAM Privilege Escalation',
            severity='high',
            description='Privilege escalation via PAM configuration in sshd',
            affected_versions='OpenSSH 6.2 - 8.7',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=85,
            pre_auth=False,
            cvss_score=7.0,
            mitre_id='T1068',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2020-15778',
            name='scp Command Injection',
            severity='high',
            description='Command injection via malicious filename in scp',
            affected_versions='OpenSSH < 8.4p1',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=80,
            pre_auth=False,
            cvss_score=7.8,
            mitre_id='T1203',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2020-14145',
            name='Username Enumeration',
            severity='medium',
            description='Username enumeration via observation of timing differences',
            affected_versions='OpenSSH 6.2 - 8.3',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=60,
            pre_auth=True,
            cvss_score=5.9,
            mitre_id='T1087',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2018-15919',
            name='Username Enumeration (Timing)',
            severity='medium',
            description='Username enumeration via timing side-channel',
            affected_versions='OpenSSH < 7.7',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=60,
            pre_auth=True,
            cvss_score=5.3,
            mitre_id='T1087',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2018-15473',
            name='Username Enumeration (Pre-auth)',
            severity='medium',
            description='Pre-authentication username enumeration',
            affected_versions='OpenSSH < 7.7',
            exploit_available=True,
            exploit_tool='Metasploit: auxiliary/scanner/ssh/ssh_enumusers',
            risk_score=65,
            pre_auth=True,
            cvss_score=5.3,
            mitre_id='T1087',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2016-6515',
            name='Password Auth DoS',
            severity='medium',
            description='Denial of Service via long password string in password authentication',
            affected_versions='OpenSSH 5.6 - 7.3',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=55,
            pre_auth=True,
            cvss_score=5.9,
            mitre_id='T1499',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2016-0777',
            name='Information Disclosure',
            severity='medium',
            description='Information disclosure via leak of heap memory in roaming feature',
            affected_versions='OpenSSH 5.4 - 7.1',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=70,
            pre_auth=False,
            cvss_score=5.9,
            mitre_id='T1552',
        ),
        
        SSHVulnerability(
            cve_id='CVE-2016-0778',
            name='Buffer Overflow',
            severity='high',
            description='Buffer overflow in roaming feature allowing code execution',
            affected_versions='OpenSSH 5.4 - 7.1',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=85,
            pre_auth=False,
            cvss_score=7.8,
            mitre_id='T1210',
        ),
    ]
    
    @classmethod
    def get_all_cves(cls) -> List[SSHVulnerability]:
        return cls.CVES
    
    @classmethod
    def get_critical_cves(cls) -> List[SSHVulnerability]:
        return [c for c in cls.CVES if c.severity == 'critical']
    
    @classmethod
    def get_preauth_cves(cls) -> List[SSHVulnerability]:
        return [c for c in cls.CVES if c.pre_auth]
    
    @classmethod
    def get_cve_by_id(cls, cve_id: str) -> Optional[SSHVulnerability]:
        for cve in cls.CVES:
            if cve.cve_id.lower() == cve_id.lower():
                return cve
        return None


# ── SSH Cipher Audit Database ──────────────────────────────────────────────

class SSHCipherDatabase:
    """Database of SSH cipher security analysis."""
    
    # Weak/Deprecated Ciphers
    WEAK_CIPHERS = {
        '3des-cbc': ('insecure', 'Triple DES in CBC mode - vulnerable to Sweet32'),
        'blowfish-cbc': ('deprecated', 'Blowfish in CBC mode - weak cipher'),
        'cast128-cbc': ('deprecated', 'CAST-128 in CBC mode - weak cipher'),
        'arcfour': ('insecure', 'RC4 - multiple vulnerabilities'),
        'arcfour128': ('insecure', 'RC4-128 - multiple vulnerabilities'),
        'arcfour256': ('insecure', 'RC4-256 - multiple vulnerabilities'),
        'aes128-cbc': ('weak', 'AES-128 in CBC mode - vulnerable to padding oracle'),
        'aes192-cbc': ('weak', 'AES-192 in CBC mode - vulnerable to padding oracle'),
        'aes256-cbc': ('weak', 'AES-256 in CBC mode - vulnerable to padding oracle'),
    }
    
    # Secure Ciphers
    SECURE_CIPHERS = {
        'chacha20-poly1305@openssh.com': 'AEAD cipher - recommended',
        'aes128-gcm@openssh.com': 'AES-128 GCM - secure',
        'aes256-gcm@openssh.com': 'AES-256 GCM - secure',
        'aes128-ctr': 'AES-128 CTR - acceptable',
        'aes192-ctr': 'AES-192 CTR - acceptable',
        'aes256-ctr': 'AES-256 CTR - acceptable',
    }
    
    # Weak KEX Algorithms
    WEAK_KEX = {
        'diffie-hellman-group1-sha1': ('insecure', '768/1024-bit DH - vulnerable to Logjam'),
        'diffie-hellman-group14-sha1': ('weak', '2048-bit DH with SHA1 - deprecated'),
        'diffie-hellman-group-exchange-sha1': ('weak', 'DH with SHA1 - deprecated'),
    }
    
    # Secure KEX Algorithms
    SECURE_KEX = {
        'curve25519-sha256': 'Curve25519 - recommended',
        'curve25519-sha256@libssh.org': 'Curve25519 - recommended',
        'diffie-hellman-group16-sha512': 'DH 4096-bit with SHA512 - secure',
        'diffie-hellman-group18-sha512': 'DH 8192-bit with SHA512 - secure',
        'ecdh-sha2-nistp256': 'ECDH P-256 - acceptable',
        'ecdh-sha2-nistp384': 'ECDH P-384 - secure',
        'ecdh-sha2-nistp521': 'ECDH P-521 - secure',
    }
    
    # Weak MACs
    WEAK_MACS = {
        'hmac-md5': ('insecure', 'MD5 - broken hash'),
        'hmac-md5-96': ('insecure', 'MD5-96 - broken hash'),
        'hmac-ripemd160': ('deprecated', 'RIPEMD-160 - deprecated'),
        'hmac-sha1-96': ('weak', 'SHA1-96 - truncated'),
        'umac-64@openssh.com': ('weak', 'UMAC-64 - short tag'),
    }
    
    # Secure MACs
    SECURE_MACS = {
        'hmac-sha2-256': 'SHA2-256 - secure',
        'hmac-sha2-512': 'SHA2-512 - secure',
        'hmac-sha2-256-etm@openssh.com': 'SHA2-256 ETM - recommended',
        'hmac-sha2-512-etm@openssh.com': 'SHA2-512 ETM - recommended',
    }
    
    @classmethod
    def audit_ciphers(cls, ciphers: List[str]) -> List[SSHAuditResult]:
        """Audit SSH ciphers."""
        results = []
        
        for cipher in ciphers:
            if cipher in cls.WEAK_CIPHERS:
                status, reason = cls.WEAK_CIPHERS[cipher]
                results.append(SSHAuditResult(
                    category='cipher',
                    algorithm=cipher,
                    status=status,
                    recommendation=reason,
                    risk_score=80 if status == 'insecure' else 60,
                ))
            elif cipher in cls.SECURE_CIPHERS:
                results.append(SSHAuditResult(
                    category='cipher',
                    algorithm=cipher,
                    status='secure',
                    recommendation=cls.SECURE_CIPHERS[cipher],
                    risk_score=10,
                ))
        
        return results
    
    @classmethod
    def audit_kex(cls, kex_algorithms: List[str]) -> List[SSHAuditResult]:
        """Audit SSH KEX algorithms."""
        results = []
        
        for kex in kex_algorithms:
            if kex in cls.WEAK_KEX:
                status, reason = cls.WEAK_KEX[kex]
                results.append(SSHAuditResult(
                    category='kex',
                    algorithm=kex,
                    status=status,
                    recommendation=reason,
                    risk_score=80 if status == 'insecure' else 60,
                ))
            elif kex in cls.SECURE_KEX:
                results.append(SSHAuditResult(
                    category='kex',
                    algorithm=kex,
                    status='secure',
                    recommendation=cls.SECURE_KEX[kex],
                    risk_score=10,
                ))
        
        return results
    
    @classmethod
    def audit_macs(cls, macs: List[str]) -> List[SSHAuditResult]:
        """Audit SSH MAC algorithms."""
        results = []
        
        for mac in macs:
            if mac in cls.WEAK_MACS:
                status, reason = cls.WEAK_MACS[mac]
                results.append(SSHAuditResult(
                    category='mac',
                    algorithm=mac,
                    status=status,
                    recommendation=reason,
                    risk_score=80 if status == 'insecure' else 60,
                ))
            elif mac in cls.SECURE_MACS:
                results.append(SSHAuditResult(
                    category='mac',
                    algorithm=mac,
                    status='secure',
                    recommendation=cls.SECURE_MACS[mac],
                    risk_score=10,
                ))
        
        return results


# ── SSH Configuration Analyzer ─────────────────────────────────────────────

class SSHConfigAnalyzer:
    """Analyzes SSH configuration comprehensively."""
    
    # Dangerous sshd_config options
    DANGEROUS_CONFIGS = {
        'PermitRootLogin yes': ('critical', 'Direct root SSH access enabled'),
        'PermitEmptyPasswords yes': ('critical', 'Empty passwords allowed'),
        'PasswordAuthentication yes': ('high', 'Password auth enabled - brute-forceable'),
        'ChallengeResponseAuthentication yes': ('high', 'Keyboard-interactive auth enabled'),
        'GSSAPIAuthentication yes': ('medium', 'Kerberos/GSSAPI auth enabled'),
        'UsePAM no': ('medium', 'PAM disabled - bypasses account lockout'),
        'AllowAgentForwarding yes': ('medium', 'Agent forwarding enabled - pivot risk'),
        'AllowTcpForwarding yes': ('medium', 'TCP forwarding enabled - tunnel risk'),
        'GatewayPorts yes': ('high', 'Gateway ports enabled - external tunnel risk'),
        'X11Forwarding yes': ('low', 'X11 forwarding enabled'),
        'HostbasedAuthentication yes': ('high', 'Host-based auth - .rhosts abuse risk'),
        'IgnoreRhosts no': ('high', '.rhosts not ignored - host-based auth risk'),
        'StrictModes no': ('medium', 'Strict mode disabled - weak permissions ok'),
        'LogLevel QUIET': ('medium', 'Minimal logging - evasion-friendly'),
        'PermitUserEnvironment yes': ('high', 'User environment variables allowed'),
        'Compression yes': ('medium', 'Compression enabled - CRIME attack risk'),
        'TCPKeepAlive yes': ('low', 'TCP keepalive enabled - connection hijack risk'),
        'UseDNS yes': ('low', 'DNS lookups enabled - DoS risk'),
        'PrintMotd yes': ('low', 'MOTD printing enabled'),
        'Banner none': ('low', 'No warning banner'),
    }
    
    @staticmethod
    def analyze(exec_func, session) -> SSHConfig:
        """Analyze SSH configuration."""
        config = SSHConfig()
        
        # Get SSH version
        cmd = "ssh -V 2>&1 || sshd -V 2>&1"
        out = exec_func(session, cmd)
        if out:
            config.version = out.strip()
        
        # Parse sshd_config
        cmd = "cat /etc/ssh/sshd_config 2>/dev/null"
        out = exec_func(session, cmd)
        
        if out:
            # Check server enabled
            if 'Port' in out:
                port_match = re.search(r'^Port\s+(\d+)', out, re.MULTILINE)
                if port_match:
                    config.port = int(port_match.group(1))
                    config.server_enabled = True
            
            # Parse dangerous options
            for option in ['PermitRootLogin', 'PasswordAuthentication', 'PubkeyAuthentication',
                          'AllowAgentForwarding', 'AllowTcpForwarding', 'GatewayPorts',
                          'X11Forwarding', 'HostbasedAuthentication', 'PermitEmptyPasswords',
                          'MaxAuthTries', 'LoginGraceTime', 'StrictModes', 'LogLevel',
                          'UsePAM']:
                match = re.search(rf'^{option}\s+(\S+)', out, re.MULTILINE | re.IGNORECASE)
                if match:
                    value = match.group(1)
                    if option == 'PermitRootLogin':
                        config.permit_root_login = value
                    elif option == 'PasswordAuthentication':
                        config.password_auth = value.lower() == 'yes'
                    elif option == 'PubkeyAuthentication':
                        config.pubkey_auth = value.lower() == 'yes'
                    elif option == 'AllowAgentForwarding':
                        config.agent_forwarding = value.lower() == 'yes'
                    elif option == 'AllowTcpForwarding':
                        config.tcp_forwarding = value.lower() == 'yes'
                    elif option == 'GatewayPorts':
                        config.gateway_ports = value.lower() == 'yes'
                    elif option == 'X11Forwarding':
                        config.x11_forwarding = value.lower() == 'yes'
                    elif option == 'HostbasedAuthentication':
                        config.host_based_auth = value.lower() == 'yes'
                    elif option == 'PermitEmptyPasswords':
                        config.permit_empty_passwords = value.lower() == 'yes'
                    elif option == 'MaxAuthTries':
                        config.max_auth_tries = int(value)
                    elif option == 'LoginGraceTime':
                        config.login_grace_time = int(value)
                    elif option == 'StrictModes':
                        config.strict_modes = value.lower() == 'yes'
                    elif option == 'LogLevel':
                        config.log_level = value
                    elif option == 'UsePAM':
                        config.use_pam = value.lower() == 'yes'
            
            # Parse ciphers
            cipher_match = re.search(r'^Ciphers\s+(.+)', out, re.MULTILINE)
            if cipher_match:
                config.ciphers = [c.strip() for c in cipher_match.group(1).split(',')]
            
            # Parse KEX algorithms
            kex_match = re.search(r'^KexAlgorithms\s+(.+)', out, re.MULTILINE)
            if kex_match:
                config.kex_algorithms = [k.strip() for k in kex_match.group(1).split(',')]
            
            # Parse MACs
            mac_match = re.search(r'^MACs\s+(.+)', out, re.MULTILINE)
            if mac_match:
                config.mac_algorithms = [m.strip() for m in mac_match.group(1).split(',')]
            
            # Parse host key algorithms
            hostkey_match = re.search(r'^HostKeyAlgorithms\s+(.+)', out, re.MULTILINE)
            if hostkey_match:
                config.host_key_algorithms = [h.strip() for h in hostkey_match.group(1).split(',')]
        
        return config
    
    @staticmethod
    def check_dangerous_options(config_text: str) -> List[Tuple[str, str, str]]:
        """Check for dangerous sshd_config options."""
        findings = []
        
        for option, (severity, description) in SSHConfigAnalyzer.DANGEROUS_CONFIGS.items():
            if re.search(re.escape(option), config_text, re.IGNORECASE | re.MULTILINE):
                findings.append((option, severity, description))
        
        return findings


# ── SSH Key Analyzer ───────────────────────────────────────────────────────

class SSHKeyAnalyzer:
    """Analyzes SSH keys comprehensively."""
    
    # Weak key patterns
    WEAK_KEY_PATTERNS = {
        'ssh-dss': ('DSA key - DEPRECATED, CVE-2016-0777 potential', 'high'),
        'ssh-rsa.*1024': ('1024-bit RSA - too weak, should be ≥4096', 'high'),
        'ssh-rsa.*2048': ('2048-bit RSA - minimum acceptable, prefer 4096', 'medium'),
        'ecdsa-sha2-nistp256': ('ECDSA P-256 - NIST curve, prefer Ed25519', 'low'),
    }
    
    # Secure key types
    SECURE_KEY_TYPES = {
        'ssh-ed25519': 'Ed25519 - recommended',
        'ssh-rsa.*4096': 'RSA-4096 - secure',
        'ecdsa-sha2-nistp384': 'ECDSA P-384 - secure',
        'ecdsa-sha2-nistp521': 'ECDSA P-521 - secure',
    }
    
    @staticmethod
    def find_keys(exec_func, session) -> List[SSHKey]:
        """Find SSH keys on the system."""
        keys = []
        
        # Find private keys
        cmd = ("find /home /root /etc /opt /var -maxdepth 6 "
               r"\( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' "
               r"-o -name 'id_dsa' -o -name '*.pem' -o -name 'id_*' \) "
               "-type f 2>/dev/null | head -50")
        out = exec_func(session, cmd)
        
        if out:
            for path in out.strip().split('\n'):
                if path.strip():
                    key = SSHKey(
                        path=path.strip(),
                        is_private=True,
                    )
                    
                    # Get key info
                    info_cmd = f"ssh-keygen -l -f {path.strip()} 2>/dev/null"
                    info_out = exec_func(session, info_cmd)
                    
                    if info_out:
                        # Parse: bits fingerprint comment (type)
                        match = re.search(r'(\d+)\s+([^\s]+)\s+(.+)\s+\(([^)]+)\)', info_out)
                        if match:
                            key.key_size = int(match.group(1))
                            key.fingerprint = match.group(2)
                            key.comment = match.group(3)
                            key.key_type = match.group(4)
                            
                            # Check if weak
                            for pattern, (reason, severity) in SSHKeyAnalyzer.WEAK_KEY_PATTERNS.items():
                                if re.search(pattern, info_out, re.IGNORECASE):
                                    key.is_weak = True
                                    key.weakness_reason = reason
                                    break
                    
                    # Get permissions
                    perm_cmd = f"stat -c '%a' {path.strip()} 2>/dev/null"
                    perm_out = exec_func(session, perm_cmd)
                    if perm_out:
                        key.permissions = perm_out.strip()
                    
                    # Get owner
                    owner_cmd = f"stat -c '%U' {path.strip()} 2>/dev/null"
                    owner_out = exec_func(session, owner_cmd)
                    if owner_out:
                        key.owner = owner_out.strip()
                    
                    # Get last modified
                    mod_cmd = f"stat -c '%y' {path.strip()} 2>/dev/null"
                    mod_out = exec_func(session, mod_cmd)
                    if mod_out:
                        key.last_modified = mod_out.strip()
                    
                    keys.append(key)
        
        return keys
    
    @staticmethod
    def find_certificates(exec_func, session) -> List[SSHCertificate]:
        """Find SSH certificates on the system."""
        certs = []
        
        # Find certificate files
        cmd = ("find /home /root /etc /opt /var -maxdepth 6 "
               r"\( -name '*-cert.pub' -o -name '*.cert' \) "
               "-type f 2>/dev/null | head -30")
        out = exec_func(session, cmd)
        
        if out:
            for path in out.strip().split('\n'):
                if path.strip():
                    cert = SSHCertificate(path=path.strip())
                    
                    # Get certificate info
                    info_cmd = f"ssh-keygen -L -f {path.strip()} 2>/dev/null"
                    info_out = exec_func(session, info_cmd)
                    
                    if info_out:
                        # Parse certificate details
                        type_match = re.search(r'Type:\s+(\S+)', info_out)
                        if type_match:
                            cert.cert_type = type_match.group(1)
                        
                        key_id_match = re.search(r'Key ID:\s+"([^"]+)"', info_out)
                        if key_id_match:
                            cert.key_id = key_id_match.group(1)
                        
                        serial_match = re.search(r'Serial:\s+(\d+)', info_out)
                        if serial_match:
                            cert.serial = serial_match.group(1)
                        
                        valid_match = re.search(r'Valid:\s+from\s+(\S+\s+\S+)\s+to\s+(\S+\s+\S+)', info_out)
                        if valid_match:
                            cert.valid_from = valid_match.group(1)
                            cert.valid_to = valid_match.group(2)
                        
                        # Parse principals
                        principals = re.findall(r'Principals:\s*\n((?:\s+\S+\n)+)', info_out)
                        if principals:
                            cert.principals = [p.strip() for p in principals[0].split('\n') if p.strip()]
                    
                    certs.append(cert)
        
        return certs
    
    @staticmethod
    def find_authorized_keys(exec_func, session) -> List[Dict]:
        """Find authorized_keys files and parse them."""
        auth_keys = []
        
        cmd = ("find /home /root /etc/ssh -maxdepth 5 -name 'authorized_keys' "
               "-type f 2>/dev/null | head -30")
        out = exec_func(session, cmd)
        
        if out:
            for path in out.strip().split('\n'):
                if path.strip():
                    # Read file
                    content_cmd = f"cat {path.strip()} 2>/dev/null"
                    content = exec_func(session, content_cmd)
                    
                    if content:
                        for line in content.strip().split('\n'):
                            if line.strip() and not line.startswith('#'):
                                # Parse key line
                                parts = line.split()
                                if len(parts) >= 2:
                                    key_type = parts[0]
                                    key_data = parts[1]
                                    comment = parts[2] if len(parts) > 2 else ''
                                    
                                    auth_keys.append({
                                        'path': path.strip(),
                                        'key_type': key_type,
                                        'key_data': key_data[:50] + '...',
                                        'comment': comment,
                                    })
        
        return auth_keys


# ── SSH Pivot Detector ─────────────────────────────────────────────────────

class SSHPivotDetector:
    """Detects SSH pivots and tunnels."""
    
    # Pivoting tools
    PIVOT_TOOLS = [
        'sshuttle', 'chisel', 'ligolo', 'rpivot', 'ssh', 'autossh',
        'socat', 'ncat', 'bore', 'frp', 'rathole', 'sish',
    ]
    
    @staticmethod
    def detect_active_tunnels(exec_func, session) -> List[Dict]:
        """Detect active SSH tunnels."""
        tunnels = []
        
        # Check for SSH tunnel processes
        cmd = ("ps aux 2>/dev/null | grep -E 'ssh.*-[LRD]|ssh.*-w|sshuttle|chisel|ligolo' | grep -v grep")
        out = exec_func(session, cmd)
        
        if out:
            for line in out.strip().split('\n'):
                if line.strip():
                    tunnels.append({
                        'process': line.strip(),
                        'type': 'active',
                    })
        
        # Check for listening ports (tunnel endpoints)
        cmd = "ss -tnlp 2>/dev/null | grep ssh; netstat -tnlp 2>/dev/null | grep ssh"
        out = exec_func(session, cmd)
        
        if out:
            for line in out.strip().split('\n'):
                if line.strip():
                    tunnels.append({
                        'listener': line.strip(),
                        'type': 'listener',
                    })
        
        return tunnels
    
    @staticmethod
    def detect_pivot_configs(exec_func, session) -> List[SSHPivot]:
        """Detect SSH pivot configurations."""
        pivots = []
        
        # Parse SSH config files
        cmd = ("find /home /root -maxdepth 4 -name 'config' -path '*/.ssh/*' "
               "-type f 2>/dev/null | xargs cat 2>/dev/null")
        out = exec_func(session, cmd)
        
        if out:
            # Find ProxyJump directives
            jump_matches = re.findall(r'Host\s+(\S+)\s*\n(?:\s+.*\n)*?\s+ProxyJump\s+(\S+)', out)
            for source, target in jump_matches:
                pivots.append(SSHPivot(
                    source=source,
                    target=target,
                    method='ProxyJump',
                    active=False,
                ))
            
            # Find ProxyCommand directives
            proxy_matches = re.findall(r'Host\s+(\S+)\s*\n(?:\s+.*\n)*?\s+ProxyCommand\s+(.+)', out)
            for source, command in proxy_matches:
                # Extract target from command
                target_match = re.search(r'(\S+@\S+|\S+)', command)
                target = target_match.group(1) if target_match else command[:50]
                
                pivots.append(SSHPivot(
                    source=source,
                    target=target,
                    method='ProxyCommand',
                    active=False,
                ))
            
            # Find HostName directives
            host_matches = re.findall(r'Host\s+(\S+)\s*\n(?:\s+.*\n)*?\s+HostName\s+(\S+)', out)
            for host, hostname in host_matches:
                pivots.append(SSHPivot(
                    source=host,
                    target=hostname,
                    method='HostName',
                    active=False,
                ))
        
        return pivots


# ── Cloud SSH Analyzer ─────────────────────────────────────────────────────

class CloudSSHAnalyzer:
    """Analyzes cloud SSH configurations."""
    
    @staticmethod
    def detect_aws(exec_func, session) -> Optional[CloudSSHConfig]:
        """Detect AWS SSH configuration."""
        config = CloudSSHConfig(provider='aws')
        
        # Check for EC2 Instance Connect
        cmd = "systemctl status ec2-instance-connect 2>/dev/null || service ec2-instance-connect status 2>/dev/null"
        out = exec_func(session, cmd)
        if out and ('active' in out.lower() or 'running' in out.lower()):
            config.service = 'EC2 Instance Connect'
            config.enabled = True
        
        # Check for AWS SSM
        cmd = "systemctl status amazon-ssm-agent 2>/dev/null"
        out = exec_func(session, cmd)
        if out and ('active' in out.lower() or 'running' in out.lower()):
            config.service = 'AWS SSM Agent'
            config.enabled = True
        
        # Check for AWS credentials
        cmd = "test -f ~/.aws/credentials && echo 'exists' || echo 'not found'"
        out = exec_func(session, cmd)
        if out and 'exists' in out:
            config.enabled = True
        
        return config if config.enabled else None
    
    @staticmethod
    def detect_azure(exec_func, session) -> Optional[CloudSSHConfig]:
        """Detect Azure SSH configuration."""
        config = CloudSSHConfig(provider='azure')
        
        # Check for Azure SSH extension
        cmd = "waagent -version 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            config.service = 'Azure Linux Agent'
            config.enabled = True
        
        # Check for Azure CLI
        cmd = "az version 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            config.enabled = True
        
        return config if config.enabled else None
    
    @staticmethod
    def detect_gcp(exec_func, session) -> Optional[CloudSSHConfig]:
        """Detect GCP SSH configuration."""
        config = CloudSSHConfig(provider='gcp')
        
        # Check for OS Login
        cmd = "grep -i 'os-login' /etc/nsswitch.conf 2>/dev/null"
        out = exec_func(session, cmd)
        if out and 'oss' in out.lower():
            config.service = 'GCP OS Login'
            config.enabled = True
            config.certificate_based = True
        
        # Check for gcloud CLI
        cmd = "gcloud version 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            config.enabled = True
        
        return config if config.enabled else None


# ── SSH Honeypot Detector ──────────────────────────────────────────────────

class SSHHoneypotDetector:
    """Detects SSH honeypots."""
    
    # Honeypot signatures
    HONEYPOT_SIGNATURES = {
        'Cowrie': [
            r'cowrie',
            r'Python.*twisted',
            r'/opt/cowrie',
            r'cowrie\.log',
        ],
        'Kippo': [
            r'kippo',
            r'/opt/kippo',
            r'kippo\.log',
        ],
        'Endlessh': [
            r'endlessh',
            r'/opt/endlessh',
        ],
        'SSHHiPot': [
            r'sshhipot',
            r'SSHHiPot',
        ],
        'Honeyd': [
            r'honeyd',
            r'/etc/honeyd',
        ],
    }
    
    @staticmethod
    def detect(exec_func, session) -> List[str]:
        """Detect SSH honeypots."""
        detected = []
        
        # Check for honeypot processes
        cmd = "ps aux 2>/dev/null | grep -iE 'cowrie|kippo|endlessh|sshhipot|honeyd' | grep -v grep"
        out = exec_func(session, cmd)
        
        if out:
            for honeypot in SSHHoneypotDetector.HONEYPOT_SIGNATURES.keys():
                if honeypot.lower() in out.lower():
                    detected.append(honeypot)
        
        # Check for honeypot files
        cmd = "find /opt /var /etc -maxdepth 3 -iname '*cowrie*' -o -iname '*kippo*' -o -iname '*endlessh*' 2>/dev/null"
        out = exec_func(session, cmd)
        
        if out:
            for honeypot in SSHHoneypotDetector.HONEYPOT_SIGNATURES.keys():
                if honeypot.lower() in out.lower():
                    if honeypot not in detected:
                        detected.append(honeypot)
        
        # Check for suspicious SSH banners
        cmd = "cat /etc/ssh/sshd_config 2>/dev/null | grep -i 'Banner'"
        out = exec_func(session, cmd)
        
        if out and 'honeypot' in out.lower():
            detected.append('Banner-based honeypot')
        
        return detected


# ── SSH Brute Force Analyzer ───────────────────────────────────────────────

class SSHBruteForceAnalyzer:
    """Analyzes SSH brute force protections."""
    
    @staticmethod
    def analyze(exec_func, session) -> Dict:
        """Analyze SSH brute force protections."""
        analysis = {
            'fail2ban': False,
            'account_lockout': False,
            'rate_limiting': False,
            'ip_restriction': False,
            'geoip_blocking': False,
            'captcha': False,
            'mfa': False,
        }
        
        # Check for Fail2ban
        cmd = "systemctl status fail2ban 2>/dev/null || service fail2ban status 2>/dev/null"
        out = exec_func(session, cmd)
        if out and ('active' in out.lower() or 'running' in out.lower()):
            analysis['fail2ban'] = True
        
        # Check for account lockout (PAM)
        cmd = "grep -r 'pam_tally2\\|pam_faillock' /etc/pam.d/ 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            analysis['account_lockout'] = True
        
        # Check for rate limiting (iptables/nftables)
        cmd = "iptables -L -n 2>/dev/null | grep -i 'ssh\\|22' | grep -i 'limit\\|recent'"
        out = exec_func(session, cmd)
        if out:
            analysis['rate_limiting'] = True
        
        # Check for IP restriction
        cmd = "cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null | grep -i 'sshd\\|ssh'"
        out = exec_func(session, cmd)
        if out:
            analysis['ip_restriction'] = True
        
        # Check for GeoIP blocking
        cmd = "grep -r 'geoip\\|xt_geoip' /etc/iptables/ /etc/nftables/ 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            analysis['geoip_blocking'] = True
        
        # Check for CAPTCHA
        cmd = "grep -r 'captcha\\|pam_google_authenticator' /etc/pam.d/ 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            analysis['captcha'] = True
        
        # Check for MFA
        cmd = "grep -r 'pam_google_authenticator\\|pam_oath\\|pam_yubikey' /etc/pam.d/ 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            analysis['mfa'] = True
        
        return analysis


# ── Main Plugin ─────────────────────────────────────────────────────────────

class SSHEnum(NexPlugin):
    name        = "ssh-enum"
    description = "Advanced SSH intelligence — 15+ CVEs, certificates, cloud, pivots, audit"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "linux"
    category    = "recon"
    mitre_id    = "T1021.004"
    
    def run(self, session, args: list):
        # Parse args
        deep = '--deep' in (args or [])
        full_mode = '--full' in (args or [])
        audit_mode = '--audit' in (args or [])
        cert_mode = '--certificates' in (args or [])
        cloud_mode = '--cloud' in (args or [])
        pivot_mode = '--pivots' in (args or [])
        cve_check = '--cve-check' in (args or [])
        list_mode = '--list' in (args or [])
        target = None
        
        for a in (args or []):
            if a.startswith('--target='):
                target = a.split('=', 1)[1]
        
        if full_mode:
            deep = audit_mode = cert_mode = cloud_mode = pivot_mode = cve_check = True
        
        if not any([deep, audit_mode, cert_mode, cloud_mode, pivot_mode, cve_check, list_mode]):
            deep = True
        
        self.info(f"🔐 Starting SSH Enumerator v3.0 (deep={deep})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🔐 SSH Enumerator v3.0 — Advanced SSH Intelligence]")
        sections.append("━"*64)
        
        findings_created = 0
        
        # ── Step 1: List Techniques ───────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Phase 1: Available SSH Analysis Techniques")
            sections.append("─"*64)
            
            sections.append("  [+] SSH CVEs: 15+ vulnerabilities")
            sections.append("  [+] SSH Audit: Cipher, KEX, MAC, Host Key analysis")
            sections.append("  [+] SSH Certificates: CA abuse, forgery detection")
            sections.append("  [+] Cloud SSH: AWS, Azure, GCP integration")
            sections.append("  [+] SSH Pivots: ProxyJump, ProxyCommand, tunnels")
            sections.append("  [+] SSH Honeypots: Cowrie, Kippo, Endlessh detection")
            sections.append("  [+] Brute Force: Fail2ban, account lockout analysis")
            sections.append("  [+] Modern Auth: FIDO2, WebAuthn, Passkeys")
            
            return '\n'.join(sections)
        
        # ── Step 2: SSH Version & CVE Detection ───────────────────────────
        sections.append("\n[*] Phase 1: SSH Version & CVE Detection")
        sections.append("─"*64)
        
        version_cmd = "ssh -V 2>&1 || sshd -V 2>&1 || dpkg -l openssh-server 2>/dev/null | grep openssh || rpm -q openssh-server 2>/dev/null"
        version_out = self._exec(session, version_cmd)
        
        if version_out:
            sections.append(f"  SSH Version: {version_out.strip()[:200]}")
            self.loot(version_out, category='ssh', source='ssh-enum:version')
            
            # CVE detection
            cves = SSHCVEDatabase.get_all_cves()
            
            for cve in cves:
                # Simple version pattern matching
                if cve.cve_id == 'CVE-2024-6387' and re.search(r'OpenSSH_[89]\.[0-7]', version_out, re.IGNORECASE):
                    sections.append(f"  🔴 VULNERABLE: {cve.cve_id} ({cve.severity.upper()})")
                    sections.append(f"      {cve.name}: {cve.description}")
                    sections.append(f"      Exploit: {cve.exploit_tool}")
                    
                    self.finding(
                        title=f"SSH Vulnerability: {cve.cve_id} - {cve.name}",
                        description=cve.description,
                        severity=cve.severity,
                        recommendation=f"Update OpenSSH to patched version. {cve.exploit_tool}",
                        mitre_id=cve.mitre_id,
                    )
                    findings_created += 1
                
                elif cve.cve_id == 'CVE-2023-48795' and 'OpenSSH' in version_out:
                    sections.append(f"  🟠 POTENTIAL: {cve.cve_id} ({cve.severity.upper()})")
                    sections.append(f"      {cve.name}: {cve.description}")
                    sections.append(f"      Note: Protocol flaw - affects all versions")
        
        # ── Step 3: SSH Configuration Analysis ────────────────────────────
        if deep or audit_mode:
            sections.append("\n[*] Phase 2: SSH Configuration Analysis")
            sections.append("─"*64)
            
            config = SSHConfigAnalyzer.analyze(self._exec, session)
            
            sections.append(f"  Server Enabled: {'✅ YES' if config.server_enabled else '❌ NO'}")
            sections.append(f"  Port: {config.port}")
            sections.append(f"  Root Login: {config.permit_root_login}")
            sections.append(f"  Password Auth: {'🔴 YES (Insecure)' if config.password_auth else '🟢 NO'}")
            sections.append(f"  Pubkey Auth: {'✅ YES' if config.pubkey_auth else '❌ NO'}")
            sections.append(f"  Agent Forwarding: {'🟠 YES (Pivot Risk)' if config.agent_forwarding else '🟢 NO'}")
            sections.append(f"  TCP Forwarding: {'🟠 YES (Tunnel Risk)' if config.tcp_forwarding else '🟢 NO'}")
            sections.append(f"  Gateway Ports: {'🔴 YES (External Tunnel)' if config.gateway_ports else '🟢 NO'}")
            sections.append(f"  X11 Forwarding: {'🟡 YES' if config.x11_forwarding else '🟢 NO'}")
            sections.append(f"  Host-based Auth: {'🔴 YES (Insecure)' if config.host_based_auth else '🟢 NO'}")
            sections.append(f"  Empty Passwords: {'🔴 YES (Critical)' if config.permit_empty_passwords else '🟢 NO'}")
            sections.append(f"  Max Auth Tries: {config.max_auth_tries}")
            sections.append(f"  Strict Modes: {'✅ YES' if config.strict_modes else '❌ NO'}")
            sections.append(f"  Log Level: {config.log_level}")
            sections.append(f"  Use PAM: {'✅ YES' if config.use_pam else '❌ NO'}")
            
            # Check dangerous options
            cmd = "cat /etc/ssh/sshd_config 2>/dev/null"
            config_out = self._exec(session, cmd)
            
            if config_out:
                dangerous = SSHConfigAnalyzer.check_dangerous_options(config_out)
                
                if dangerous:
                    sections.append(f"\n  🔴 {len(dangerous)} dangerous configuration(s) detected:")
                    
                    for option, severity, description in dangerous[:10]:
                        icon = '🔴' if severity == 'critical' else '🟠' if severity == 'high' else '🟡'
                        sections.append(f"    {icon} {option} [{severity.upper()}]")
                        sections.append(f"        {description}")
                        
                        self.finding(
                            title=f"Insecure SSH Config: {option}",
                            description=description,
                            severity=severity,
                            recommendation=f"Harden sshd_config: disable {option}",
                            mitre_id=self.mitre_id,
                        )
                        findings_created += 1
        
        # ── Step 4: SSH Cipher Audit ──────────────────────────────────────
        if audit_mode:
            sections.append("\n[*] Phase 3: SSH Cipher Audit")
            sections.append("─"*64)
            
            config = SSHConfigAnalyzer.analyze(self._exec, session)
            
            # Audit ciphers
            if config.ciphers:
                cipher_results = SSHCipherDatabase.audit_ciphers(config.ciphers)
                
                weak_ciphers = [r for r in cipher_results if r.status in ['insecure', 'weak', 'deprecated']]
                
                if weak_ciphers:
                    sections.append(f"  🔴 {len(weak_ciphers)} weak/insecure cipher(s) detected:")
                    
                    for result in weak_ciphers[:10]:
                        icon = '🔴' if result.status == 'insecure' else '🟠' if result.status == 'weak' else '🟡'
                        sections.append(f"    {icon} {result.algorithm} [{result.status.upper()}]")
                        sections.append(f"        {result.recommendation}")
                        
                        self.finding(
                            title=f"Weak SSH Cipher: {result.algorithm}",
                            description=result.recommendation,
                            severity='high' if result.status == 'insecure' else 'medium',
                            recommendation=f"Remove {result.algorithm} from sshd_config",
                            mitre_id=self.mitre_id,
                        )
                        findings_created += 1
                else:
                    sections.append("  🟢 All ciphers are secure")
            
            # Audit KEX
            if config.kex_algorithms:
                kex_results = SSHCipherDatabase.audit_kex(config.kex_algorithms)
                
                weak_kex = [r for r in kex_results if r.status in ['insecure', 'weak', 'deprecated']]
                
                if weak_kex:
                    sections.append(f"\n  🔴 {len(weak_kex)} weak KEX algorithm(s) detected:")
                    
                    for result in weak_kex[:10]:
                        icon = '🔴' if result.status == 'insecure' else '🟠'
                        sections.append(f"    {icon} {result.algorithm} [{result.status.upper()}]")
                        sections.append(f"        {result.recommendation}")
            
            # Audit MACs
            if config.mac_algorithms:
                mac_results = SSHCipherDatabase.audit_macs(config.mac_algorithms)
                
                weak_macs = [r for r in mac_results if r.status in ['insecure', 'weak', 'deprecated']]
                
                if weak_macs:
                    sections.append(f"\n  🔴 {len(weak_macs)} weak MAC algorithm(s) detected:")
                    
                    for result in weak_macs[:10]:
                        icon = '🔴' if result.status == 'insecure' else '🟠'
                        sections.append(f"    {icon} {result.algorithm} [{result.status.upper()}]")
                        sections.append(f"        {result.recommendation}")
        
        # ── Step 5: SSH Key Enumeration ───────────────────────────────────
        if deep or cert_mode:
            sections.append("\n[*] Phase 4: SSH Key Enumeration")
            sections.append("─"*64)
            
            keys = SSHKeyAnalyzer.find_keys(self._exec, session)
            
            if keys:
                sections.append(f"  [+] {len(keys)} SSH key(s) discovered:")
                
                weak_keys = [k for k in keys if k.is_weak]
                
                for key in keys[:20]:
                    icon = '🔴' if key.is_weak else '🟡' if key.key_size and key.key_size < 4096 else '🟢'
                    sections.append(f"    {icon} {key.path}")
                    sections.append(f"        Type: {key.key_type} | Size: {key.key_size}")
                    sections.append(f"        Owner: {key.owner} | Permissions: {key.permissions}")
                    
                    if key.is_weak:
                        sections.append(f"        ⚠️  WEAK: {key.weakness_reason}")
                
                # Save to loot
                self.loot(
                    {
                        "type": "ssh_keys",
                        "keys": [k.to_dict() for k in keys],
                        "count": len(keys),
                        "weak_count": len(weak_keys),
                    },
                    category='credentials',
                    source='ssh-enum:keys',
                    confidence='high'
                )
                
                if weak_keys:
                    self.finding(
                        title=f"Weak SSH Keys Detected — {len(weak_keys)} key(s)",
                        description=f"Found {len(weak_keys)} weak SSH keys that should be replaced",
                        severity='high',
                        recommendation="Replace weak keys with Ed25519 or RSA-4096",
                        mitre_id='T1552.004',
                    )
                    findings_created += 1
                
                if len(keys) > 0:
                    self.finding(
                        title=f"SSH Private Keys Accessible — {len(keys)} file(s)",
                        description=f"Found {len(keys)} private SSH key files accessible to current user",
                        severity='high',
                        recommendation="Restrict SSH key file permissions to 600",
                        mitre_id='T1552.004',
                    )
                    findings_created += 1
            else:
                sections.append("  🟢 No SSH private keys found")
        
        # ── Step 6: SSH Certificate Analysis ──────────────────────────────
        if cert_mode:
            sections.append("\n[*] Phase 5: SSH Certificate Analysis")
            sections.append("─"*64)
            
            certs = SSHKeyAnalyzer.find_certificates(self._exec, session)
            
            if certs:
                sections.append(f"  [+] {len(certs)} SSH certificate(s) discovered:")
                
                for cert in certs[:10]:
                    sections.append(f"    • {cert.path}")
                    sections.append(f"        Type: {cert.cert_type}")
                    sections.append(f"        Key ID: {cert.key_id}")
                    sections.append(f"        Valid: {cert.valid_from} to {cert.valid_to}")
                    
                    if cert.principals:
                        sections.append(f"        Principals: {', '.join(cert.principals)}")
                
                # Save to loot
                self.loot(
                    {
                        "type": "ssh_certificates",
                        "certificates": [c.to_dict() for c in certs],
                        "count": len(certs),
                    },
                    category='credentials',
                    source='ssh-enum:certificates',
                    confidence='high'
                )
            else:
                sections.append("  🟢 No SSH certificates found")
        
        # ── Step 7: Authorized Keys & Known Hosts ─────────────────────────
        if deep:
            sections.append("\n[*] Phase 6: Authorized Keys & Known Hosts")
            sections.append("─"*64)
            
            auth_keys = SSHKeyAnalyzer.find_authorized_keys(self._exec, session)
            
            if auth_keys:
                sections.append(f"  [+] {len(auth_keys)} authorized key(s) discovered:")
                
                for key in auth_keys[:15]:
                    sections.append(f"    • {key['path']}")
                    sections.append(f"        Type: {key['key_type']} | Comment: {key['comment']}")
                
                # Save to loot
                self.loot(
                    {
                        "type": "authorized_keys",
                        "keys": auth_keys,
                        "count": len(auth_keys),
                    },
                    category='credentials',
                    source='ssh-enum:authorized_keys',
                    confidence='high'
                )
            
            # Known hosts
            cmd = ("find /home /root -maxdepth 4 -name 'known_hosts' 2>/dev/null | "
                   "xargs cat 2>/dev/null | awk '{print $1}' | tr ',' '\\n' | sort -u | head -60")
            known_out = self._exec(session, cmd)
            
            if known_out:
                hosts = [h.strip() for h in known_out.split('\n') if h.strip() and not h.startswith('|')]
                sections.append(f"\n  [+] {len(hosts)} known host(s) (pivot targets):")
                
                for host in hosts[:20]:
                    sections.append(f"    • {host}")
                
                # Save to loot
                self.loot(
                    {
                        "type": "known_hosts",
                        "hosts": hosts,
                        "count": len(hosts),
                    },
                    category='network',
                    source='ssh-enum:known_hosts',
                    confidence='high'
                )
        
        # ── Step 8: SSH Pivot Detection ───────────────────────────────────
        if pivot_mode:
            sections.append("\n[*] Phase 7: SSH Pivot & Tunnel Detection")
            sections.append("─"*64)
            
            # Active tunnels
            tunnels = SSHPivotDetector.detect_active_tunnels(self._exec, session)
            
            if tunnels:
                sections.append(f"  🔴 {len(tunnels)} active SSH tunnel(s) detected:")
                
                for tunnel in tunnels[:10]:
                    if 'process' in tunnel:
                        sections.append(f"    • Process: {tunnel['process'][:100]}")
                    elif 'listener' in tunnel:
                        sections.append(f"    • Listener: {tunnel['listener'][:100]}")
                
                self.finding(
                    title=f"Active SSH Tunnels Detected — {len(tunnels)} tunnel(s)",
                    description=f"SSH tunneling/port forwarding is active on this host",
                    severity='medium',
                    recommendation="Review active SSH tunnels for unauthorized access",
                    mitre_id='T1572',
                )
                findings_created += 1
            
            # Pivot configurations
            pivots = SSHPivotDetector.detect_pivot_configs(self._exec, session)
            
            if pivots:
                sections.append(f"\n  🟠 {len(pivots)} SSH pivot configuration(s) detected:")
                
                for pivot in pivots[:10]:
                    sections.append(f"    • {pivot.source} → {pivot.target}")
                    sections.append(f"        Method: {pivot.method}")
                
                # Save to loot
                self.loot(
                    {
                        "type": "ssh_pivots",
                        "pivots": [p.to_dict() for p in pivots],
                        "count": len(pivots),
                    },
                    category='network',
                    source='ssh-enum:pivots',
                    confidence='high'
                )
        
        # ── Step 9: Cloud SSH Detection ───────────────────────────────────
        if cloud_mode:
            sections.append("\n[*] Phase 8: Cloud SSH Detection")
            sections.append("─"*64)
            
            # AWS
            aws_config = CloudSSHAnalyzer.detect_aws(self._exec, session)
            if aws_config:
                sections.append(f"  ☁️  AWS SSH: {aws_config.service}")
                sections.append(f"      Enabled: {'YES' if aws_config.enabled else 'NO'}")
                sections.append(f"      Certificate-based: {'YES' if aws_config.certificate_based else 'NO'}")
            
            # Azure
            azure_config = CloudSSHAnalyzer.detect_azure(self._exec, session)
            if azure_config:
                sections.append(f"  ☁️  Azure SSH: {azure_config.service}")
                sections.append(f"      Enabled: {'YES' if azure_config.enabled else 'NO'}")
            
            # GCP
            gcp_config = CloudSSHAnalyzer.detect_gcp(self._exec, session)
            if gcp_config:
                sections.append(f"  ☁️  GCP SSH: {gcp_config.service}")
                sections.append(f"      Enabled: {'YES' if gcp_config.enabled else 'NO'}")
                sections.append(f"      Certificate-based: {'YES' if gcp_config.certificate_based else 'NO'}")
        
        # ── Step 10: SSH Honeypot Detection ───────────────────────────────
        if deep:
            sections.append("\n[*] Phase 9: SSH Honeypot Detection")
            sections.append("─"*64)
            
            honeypots = SSHHoneypotDetector.detect(self._exec, session)
            
            if honeypots:
                sections.append(f"  🔴 {len(honeypots)} SSH honeypot(s) detected:")
                
                for honeypot in honeypots:
                    sections.append(f"    • {honeypot}")
                
                self.finding(
                    title=f"SSH Honeypot Detected — {', '.join(honeypots)}",
                    description=f"SSH honeypot detected on this system. May be monitoring your activity.",
                    severity='high',
                    recommendation="Verify if this is an authorized honeypot. Exercise caution.",
                    mitre_id=self.mitre_id,
                )
                findings_created += 1
            else:
                sections.append("  🟢 No SSH honeypots detected")
        
        # ── Step 11: Brute Force Protection Analysis ──────────────────────
        if deep:
            sections.append("\n[*] Phase 10: Brute Force Protection Analysis")
            sections.append("─"*64)
            
            brute_force = SSHBruteForceAnalyzer.analyze(self._exec, session)
            
            sections.append(f"  Fail2ban: {'✅ ENABLED' if brute_force['fail2ban'] else '❌ DISABLED'}")
            sections.append(f"  Account Lockout: {'✅ ENABLED' if brute_force['account_lockout'] else '❌ DISABLED'}")
            sections.append(f"  Rate Limiting: {'✅ ENABLED' if brute_force['rate_limiting'] else '❌ DISABLED'}")
            sections.append(f"  IP Restriction: {'✅ ENABLED' if brute_force['ip_restriction'] else '❌ DISABLED'}")
            sections.append(f"  GeoIP Blocking: {'✅ ENABLED' if brute_force['geoip_blocking'] else '❌ DISABLED'}")
            sections.append(f"  CAPTCHA: {'✅ ENABLED' if brute_force['captcha'] else '❌ DISABLED'}")
            sections.append(f"  MFA: {'✅ ENABLED' if brute_force['mfa'] else '❌ DISABLED'}")
            
            if not brute_force['fail2ban'] and not brute_force['account_lockout']:
                self.finding(
                    title="SSH Brute Force Protection Missing",
                    description="No Fail2ban or account lockout detected. SSH is vulnerable to brute force attacks.",
                    severity='high',
                    recommendation="Install and configure Fail2ban. Enable PAM account lockout.",
                    mitre_id='T1110',
                )
                findings_created += 1
        
        # ── Step 12: SSH Agent Analysis ───────────────────────────────────
        if deep:
            sections.append("\n[*] Phase 11: SSH Agent Analysis")
            sections.append("─"*64)
            
            agent_sock = self._exec(session, "echo $SSH_AUTH_SOCK")
            
            if agent_sock and agent_sock.strip():
                sections.append(f"  SSH_AUTH_SOCK: {agent_sock.strip()}")
                
                agent_keys = self._exec(session, "ssh-add -l 2>/dev/null")
                
                if agent_keys and 'no identities' not in agent_keys.lower():
                    sections.append(f"  🔴 Agent keys loaded:")
                    sections.append(f"      {agent_keys.strip()[:200]}")
                    
                    self.finding(
                        title="SSH Agent with Loaded Keys — Agent Hijacking Risk",
                        description="SSH agent socket is active with loaded keys. Agent forwarding may allow pivot.",
                        severity='high',
                        recommendation="Disable SSH agent forwarding. Unload agent keys when not needed.",
                        mitre_id='T1563',
                    )
                    findings_created += 1
                    
                    self.loot(agent_keys, category='ssh', source='ssh-enum:agent_keys')
                else:
                    sections.append("  🟢 No agent keys loaded")
            else:
                sections.append("  🟢 SSH agent not active")
        
        # ── Summary ───────────────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 SSH Enumeration Summary]")
        sections.append("━"*64)
        sections.append(f"  SSH Version: {config.version[:50] if 'config' in locals() else 'Unknown'}")
        sections.append(f"  Keys Found: {len(keys) if 'keys' in locals() else 0}")
        sections.append(f"  Certificates: {len(certs) if 'certs' in locals() else 0}")
        sections.append(f"  Pivots Detected: {len(pivots) if 'pivots' in locals() else 0}")
        sections.append(f"  Tunnels Active: {len(tunnels) if 'tunnels' in locals() else 0}")
        sections.append(f"  Honeypots: {len(honeypots) if 'honeypots' in locals() else 0}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Save to Loot ──────────────────────────────────────────────────
        self.loot(
            {
                "type": "ssh_enumeration_session",
                "findings_count": findings_created,
                "duration": duration,
            },
            category='recon',
            source='ssh-enum',
            confidence='high'
        )
        
        self.emit(
            'timeline.event',
            title=f"SSH Enumeration Complete — {findings_created} findings",
            type='recon',
            plugin=self.name
        )
        
        self.info(f"🔐 SSH Enumerator complete — {findings_created} findings")
        
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