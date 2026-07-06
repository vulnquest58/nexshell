#!/usr/bin/env python3
"""
NexShell — Professional UI Engine
Cross-platform auto-completion, contextual hints, dynamic prompt,
command aliases, history search, timing, and typo correction.
Works on Windows (pyreadline3 / msvcrt) and Linux (GNU readline).
"""

import os
import sys
import time
import difflib
import threading
from typing import List, Optional, Callable

IS_WINDOWS = os.name == 'nt'

# ── Readline / completion backend ─────────────────────────────────────────────
_RL = None

def _init_readline():
    global _RL
    if IS_WINDOWS:
        try:
            import pyreadline3 as readline
            _RL = readline
        except ImportError:
            try:
                import readline
                _RL = readline
            except ImportError:
                _RL = None
    else:
        try:
            import readline
            _RL = readline
        except ImportError:
            _RL = None
    return _RL

_init_readline()


# ══════════════════════════════════════════════════════════════════════════════
#  COMMAND DEFINITIONS  — for auto-complete + hints
# ══════════════════════════════════════════════════════════════════════════════

# All top-level commands
TOP_COMMANDS = [
    'run', 'upload', 'download', 'open', 'maintain', 'spawn', 'upgrade',
    'exec', 'script', 'portfwd', 'tag', 'note', 'quickenum', 'credharvest',
    'privesc', 'sessions', 'use', 'interact', 'kill', 'dir', 'listeners',
    'payloads', 'connect', 'Interfaces', 'help', 'history', 'cd', 'reset',
    'SET', 'exit', 'quit', 'clear', 'cls',
]

# Sub-completions per command
SUB_COMPLETIONS = {
    'run': [
        # Recon
        'quickenum', 'privesc', 'credharvest',
        'win-enum', 'win-privesc', 'win-creds',
        # AD
        'ad-recon', 'ad-kerberoast', 'ad-asreproast',
        # Persistence
        'persist', 'persist-linux', 'persist-win',
        # Lateral
        'lateral',
        # Container
        'container', 'container-auto', 'container-docker',
        'container-cgroup', 'container-k8s', 'container-ns',
        # Exfil
        'exfil',
        # Loot
        'loot', 'loot-scan', 'loot-report',
        # OPSEC
        'opsec', 'timestomp', 'logclean', 'obfuscate',
    ],
    'listeners': ['add', 'stop'],
    'payloads':  ['--linux', '--windows', '--all', '--obfuscate'],
    'use':       ['none'],
    'kill':      ['*'],
    'SET': [
        'jitter', 'maintain', 'stealth_mode', 'auto_enum',
        'shell_quality', 'opsec_profile', 'default_listener_port',
    ],
    'run opsec': ['ghost', 'normal', 'paranoid'],
    'loot-report': ['json', 'md', 'html'],
}

# Context hints shown after the prompt (dim text)
HINTS = {
    'run':       'run <module>  — Tab to see modules',
    'sessions':  'sessions [ID] — Tab for session IDs',
    'use':       'use <session_id>',
    'interact':  'interact <session_id>',
    'kill':      'kill <session_id|*>',
    'payloads':  'payloads [iface] [--linux|--windows] [--obfuscate]',
    'listeners': 'listeners [add -p <port>|stop <id>]',
    'exec':      'exec <remote_command>',
    'upload':    'upload <local_file_or_url>',
    'download':  'download <remote_path>',
    'portfwd':   'portfwd <host:port -> host:port>',
    'tag':       'tag [session_id] <label>',
    'note':      'note <text>',
    'script':    'script <file_or_url>',
    'cd':        'cd <path>',
    'SET':       'SET <option> <value>',
    'connect':   'connect <host> <port>',
}

# Command aliases: short → full command
ALIASES = {
    's':     'sessions',
    'ss':    'sessions',
    'ls':    'sessions',
    'i':     'interact',
    'u':     'use',
    'k':     'kill',
    'l':     'listeners',
    'p':     'payloads',
    'qe':    'quickenum',
    'pe':    'privesc',
    'ch':    'credharvest',
    'we':    'win-enum',  # used inside 'run'
    'ce':    'container',
    'ca':    'container-auto',
    'up':    'upgrade',
    'dl':    'download',
    'ul':    'upload',
    'x':     'exec',
    'q':     'exit',
    'quit':  'exit',
    'h':     'help',
    '?':     'help',
    '.':     'dir',
    'c':     'clear',
    'cls':   'clear',
}


# ══════════════════════════════════════════════════════════════════════════════
#  AUTO-COMPLETER
# ══════════════════════════════════════════════════════════════════════════════

class NexCompleter:
    """
    Readline completer.
    Context-aware: completes sub-commands, session IDs, file paths,
    module names, option values, etc.
    """

    def __init__(self, get_sessions_fn=None, get_listeners_fn=None):
        self._get_sessions  = get_sessions_fn  or (lambda: {})
        self._get_listeners = get_listeners_fn or (lambda: {})
        self._matches: List[str] = []

    # ── Install ───────────────────────────────────────────────────────────────
    def install(self, histfile: Optional[str] = None, histlen: int = 2000):
        if _RL is None:
            return False
        try:
            _RL.set_completer(self.complete)
            _RL.set_completer_delims(' \t')
            _RL.parse_and_bind('tab: complete')
            # History
            if histfile:
                try:
                    _RL.read_history_file(histfile)
                except FileNotFoundError:
                    pass
                import atexit
                atexit.register(_RL.write_history_file, histfile)
                _RL.set_history_length(histlen)
            # Key bindings
            _RL.parse_and_bind('Control-l: clear-screen')
            if not IS_WINDOWS:
                _RL.parse_and_bind(r'"\C-r": reverse-search-history')
                _RL.parse_and_bind(r'"\e[A": history-search-backward')
                _RL.parse_and_bind(r'"\e[B": history-search-forward')
            return True
        except Exception:
            return False

    # ── Core completer ────────────────────────────────────────────────────────
    def complete(self, text: str, state: int) -> Optional[str]:
        if state == 0:
            self._matches = self._build_matches(text)
        try:
            return self._matches[state]
        except IndexError:
            return None

    def _build_matches(self, text: str) -> List[str]:
        rl      = _RL
        line    = rl.get_line_buffer() if rl else text
        parts   = line.lstrip().split()
        n_parts = len(parts)

        # ── No input yet → complete top-level commands ───────────────────────
        if not parts or (n_parts == 1 and not line.endswith(' ')):
            candidates = TOP_COMMANDS + list(ALIASES.keys())
            return [c + ' ' for c in candidates if c.startswith(text)]

        cmd = parts[0].lower()

        # ── Second token: sub-command / arg ──────────────────────────────────
        if n_parts == 1 and line.endswith(' '):
            return self._sub_complete(cmd, '')

        if n_parts == 2 and not line.endswith(' '):
            return self._sub_complete(cmd, parts[1])

        # ── 'run opsec <profile>' ────────────────────────────────────────────
        if cmd == 'run' and n_parts >= 2:
            sub = parts[1].lower()
            if sub == 'opsec' and n_parts <= 3:
                pfx = parts[2] if n_parts == 3 else ''
                return [p for p in ('ghost', 'normal', 'paranoid') if p.startswith(pfx)]
            if sub == 'loot-report' and n_parts <= 3:
                pfx = parts[2] if n_parts == 3 else ''
                return [f for f in ('json', 'md', 'html') if f.startswith(pfx)]

        # ── File completion for upload/script/cd ─────────────────────────────
        if cmd in ('upload', 'script', 'cd', 'open') and n_parts >= 2:
            return self._file_complete(parts[-1] if not line.endswith(' ') else '')

        # ── SET option values ─────────────────────────────────────────────────
        if cmd == 'set' and n_parts == 3 and not line.endswith(' '):
            opt = parts[1].lower()
            if opt in ('stealth_mode', 'auto_enum', 'shell_quality'):
                return [v for v in ('true', 'false', 'True', 'False') if v.startswith(parts[2])]
            if opt == 'opsec_profile':
                return [v for v in ('ghost', 'normal', 'paranoid') if v.startswith(parts[2])]

        return []

    def _sub_complete(self, cmd: str, prefix: str) -> List[str]:
        """Return sub-completions for a given top-level command."""
        subs = []

        if cmd == 'run':
            subs = SUB_COMPLETIONS['run']
        elif cmd in ('use', 'interact', 'kill', 'tag', 'dir'):
            # Complete with session IDs
            subs = [str(sid) for sid in self._get_sessions().keys()]
            subs += SUB_COMPLETIONS.get(cmd, [])
        elif cmd == 'listeners':
            subs = ['add', 'stop'] + [str(lid) for lid in self._get_listeners().keys()]
        elif cmd == 'payloads':
            subs = SUB_COMPLETIONS['payloads']
        elif cmd == 'set':
            subs = SUB_COMPLETIONS['SET']
        elif cmd in SUB_COMPLETIONS:
            subs = SUB_COMPLETIONS[cmd]

        return [s + (' ' if cmd == 'run' else '') for s in subs if s.startswith(prefix)]

    @staticmethod
    def _file_complete(prefix: str) -> List[str]:
        from glob import glob
        matches = glob(prefix + '*') or []
        result  = []
        for m in matches:
            result.append(m + '/' if os.path.isdir(m) else m)
        return result


# ══════════════════════════════════════════════════════════════════════════════
#  TYPO CORRECTOR
# ══════════════════════════════════════════════════════════════════════════════

def suggest_command(unknown: str, all_cmds: List[str], cutoff: float = 0.6) -> Optional[str]:
    """Return closest matching command, or None."""
    matches = difflib.get_close_matches(unknown, all_cmds, n=1, cutoff=cutoff)
    return matches[0] if matches else None


# ══════════════════════════════════════════════════════════════════════════════
#  COMMAND TIMING
# ══════════════════════════════════════════════════════════════════════════════

class CommandTimer:
    """Non-intrusive command timing — show elapsed time for ops > threshold."""
    THRESHOLD_S = 1.5   # only show if > 1.5 seconds

    def __init__(self):
        self._start: Optional[float] = None
        self._cmd:   Optional[str]   = None

    def start(self, cmd: str):
        self._cmd   = cmd
        self._start = time.perf_counter()

    def stop(self) -> Optional[str]:
        if self._start is None:
            return None
        elapsed = time.perf_counter() - self._start
        self._start = None
        if elapsed >= self.THRESHOLD_S:
            return f"  [{elapsed:.2f}s]"
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  STATUS BAR  — live listener/session count in prompt
# ══════════════════════════════════════════════════════════════════════════════

def build_status_badge(n_sessions: int, n_listeners: int,
                       opsec_profile: str = 'normal') -> str:
    """Return a compact status badge for the prompt line."""
    parts = []
    if n_listeners:
        parts.append(f"L:{n_listeners}")
    if n_sessions:
        parts.append(f"S:{n_sessions}")
    opsec_colors = {'ghost': '\033[92m', 'paranoid': '\033[91m', 'normal': '\033[90m'}
    color = opsec_colors.get(opsec_profile, '\033[90m')
    reset = '\033[0m'
    badge_text = ' | '.join(parts) if parts else 'idle'
    return f"{color}[{badge_text}]{reset}"


# ══════════════════════════════════════════════════════════════════════════════
#  INLINE HINT ENGINE  — show dim suggestions below prompt
# ══════════════════════════════════════════════════════════════════════════════

_HINT_COLOR  = '\033[2;37m'   # dim white
_RESET       = '\033[0m'

def print_hint(cmd: str):
    """Print a dim hint line below the prompt for the given command."""
    hint = HINTS.get(cmd.lower())
    if hint and sys.stdout.isatty():
        print(f"  {_HINT_COLOR}{hint}{_RESET}", flush=True)


# ══════════════════════════════════════════════════════════════════════════════
#  ALIAS RESOLVER
# ══════════════════════════════════════════════════════════════════════════════

def resolve_alias(line: str) -> str:
    """Expand aliases in a command line, preserving args."""
    if not line.strip():
        return line
    parts  = line.strip().split(' ', 1)
    cmd    = parts[0].lower()
    rest   = (' ' + parts[1]) if len(parts) > 1 else ''
    # Check alias table
    if cmd in ALIASES:
        return ALIASES[cmd] + rest
    return line


# ══════════════════════════════════════════════════════════════════════════════
#  HISTORY MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class HistoryManager:
    """In-process history with search + export."""

    def __init__(self, maxlen: int = 500):
        self._history: List[dict] = []
        self._maxlen  = maxlen

    def add(self, cmd: str, elapsed: Optional[float] = None):
        if cmd.strip():
            self._history.append({
                'cmd': cmd,
                'ts':  time.strftime('%H:%M:%S'),
                'ms':  round((elapsed or 0) * 1000),
            })
            if len(self._history) > self._maxlen:
                self._history.pop(0)

    def search(self, pattern: str) -> List[str]:
        return [h['cmd'] for h in self._history if pattern in h['cmd']]

    def show(self, n: int = 50):
        for i, h in enumerate(self._history[-n:], 1):
            timing = f"  [{h['ms']}ms]" if h['ms'] > 100 else ''
            print(f"  \033[90m{i:4d}  {h['ts']}\033[0m  {h['cmd']}{timing}")

    def export(self, path: str):
        with open(path, 'w') as f:
            for h in self._history:
                f.write(f"[{h['ts']}] {h['cmd']}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  QUICK ACTION BAR  — show context actions on empty Enter
# ══════════════════════════════════════════════════════════════════════════════

def show_quick_actions(has_session: bool, n_listeners: int):
    """Display contextual quick actions when user presses Enter on empty line."""
    if not sys.stdout.isatty():
        return
    print()
    if not has_session and not n_listeners:
        print(f"  \033[2;37mNo sessions yet. Listeners: {n_listeners}  |  "
              f"Try: payloads · listeners add -p 4444\033[0m")
    elif not has_session:
        print(f"  \033[2;37mListening on {n_listeners} port(s). "
              f"Waiting for shell...  |  payloads [iface]\033[0m")
    else:
        print(f"  \033[2;37mQuick: sessions · run quickenum · run loot · "
              f"run opsec ghost\033[0m")
    print()


# ══════════════════════════════════════════════════════════════════════════════
#  SETUP ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def setup_ui(get_sessions_fn=None, get_listeners_fn=None,
             histfile: Optional[str] = None) -> 'NexCompleter':
    """
    Call once at startup. Installs readline completion, history,
    and returns the NexCompleter instance for future reference.
    """
    comp = NexCompleter(get_sessions_fn, get_listeners_fn)
    ok   = comp.install(histfile=histfile)
    return comp
