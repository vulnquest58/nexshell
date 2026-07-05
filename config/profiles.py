#!/usr/bin/env python3
"""
NexShell — Enterprise Configuration  (config/profiles.py)
OPSEC profiles, operator roles, and configuration templates.

CLI:
    SET opsec_profile ghost        ← paranoid/ghost/normal
    SET operator_name "redteam-1"
    config show
    config save
    config load <name>
"""

import os
import json
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

CONFIG_DIR = Path.home() / '.nexshell' / 'config'
CONFIG_DIR.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
#  OPSEC PROFILES
# ══════════════════════════════════════════════════════════════════════════════

OPSEC_PROFILES = {
    "normal": {
        "description": "Default mode — full logging, no evasion",
        "sleep_jitter":    0,       # ms
        "command_delay":   0,       # ms between commands
        "stdout_logging":  True,
        "log_commands":    True,
        "log_level":       "INFO",
        "shell_banner":    True,
        "heartbeat_interval": 30,   # seconds
        "auto_reconnect":  True,
    },
    "ghost": {
        "description": "Reduced footprint — minimal logging, random delays",
        "sleep_jitter":    500,     # ms random delay variation
        "command_delay":   200,     # ms between commands
        "stdout_logging":  False,   # suppress most output to stdout
        "log_commands":    False,   # don't log raw commands to DB
        "log_level":       "WARNING",
        "shell_banner":    False,
        "heartbeat_interval": 60,
        "auto_reconnect":  True,
    },
    "paranoid": {
        "description": "Maximum evasion — heavy delays, no logging, memory-only",
        "sleep_jitter":    2000,
        "command_delay":   500,
        "stdout_logging":  False,
        "log_commands":    False,
        "log_level":       "ERROR",
        "shell_banner":    False,
        "heartbeat_interval": 120,
        "auto_reconnect":  False,
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  OPERATOR ROLES
# ══════════════════════════════════════════════════════════════════════════════

ROLES = {
    "operator": {
        "description": "Standard operator — all shell operations",
        "permissions": ["sessions", "loot", "listeners", "plugins", "host",
                        "evidence", "finding", "mitre", "playbook", "workflow"],
    },
    "lead": {
        "description": "Team lead — all operator permissions + reporting + config",
        "permissions": ["*"],  # all
    },
    "readonly": {
        "description": "Read-only observer — view sessions/findings/loot only",
        "permissions": ["sessions.list", "loot.view", "finding.list",
                        "host.list", "evidence.list", "stats", "health"],
    },
    "junior": {
        "description": "Junior operator — limited to recon only",
        "permissions": ["sessions.list", "host", "mitre", "playbook",
                        "evidence.list", "finding.list", "stats"],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class ConfigManager:
    """
    Manages NexShell runtime configuration.
    Persists to ~/.nexshell/config/<name>.json.
    """

    DEFAULT_CONFIG = {
        'operator_name':   os.environ.get('USER', 'operator'),
        'opsec_profile':   'normal',
        'role':            'operator',
        'db_path':         str(Path.home() / '.nexshell' / 'nexshell.db'),
        'plugins_dir':     'plugins',
        'operations_dir':  str(Path.home() / '.nexshell' / 'operations'),
        'evidence_dir':    str(Path.home() / '.nexshell' / 'evidence'),
        'log_file':        str(Path.home() / '.nexshell' / 'nexshell.log'),
        'listener_default_port': 4444,
        'listener_default_ssl':  False,
        'auto_loot_scan':        True,   # auto-scan session output for credentials
        'auto_host_add':         True,   # auto-add host to inventory on session connect
        'auto_rule_eval':        True,   # auto-evaluate rules on session/loot events
        'plugins_auto_discover': True,   # auto-discover plugins on startup
        'scheduler_workers':     2,
        'version':         '2.0.0',
        'last_modified':   datetime.datetime.utcnow().isoformat(),
    }

    def __init__(self):
        self._config: Dict[str, Any] = dict(self.DEFAULT_CONFIG)
        self._active_profile: Optional[str] = 'default'
        self.load('default')

    # ── Persistence ───────────────────────────────────────────────────────────

    def _path(self, name: str) -> Path:
        safe = name.replace(' ', '_')
        return CONFIG_DIR / f"{safe}.json"

    def save(self, name: str = 'default') -> str:
        """Save current config to disk."""
        self._config['last_modified'] = datetime.datetime.utcnow().isoformat()
        path = self._path(name)
        path.write_text(json.dumps(self._config, indent=2), encoding='utf-8')
        return str(path)

    def load(self, name: str = 'default') -> bool:
        """Load config from disk. Returns True if found."""
        path = self._path(name)
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text())
            self._config.update(data)
            self._active_profile = name
            return True
        except Exception:
            return False

    def list_profiles(self) -> List[str]:
        return [p.stem for p in sorted(CONFIG_DIR.glob('*.json'))]

    # ── Config access ─────────────────────────────────────────────────────────

    def get(self, key: str, default=None):
        return self._config.get(key, default)

    def set(self, key: str, value: Any):
        """Set a config value and apply side effects."""
        old = self._config.get(key)
        self._config[key] = value
        # Side effects
        if key == 'opsec_profile' and value in OPSEC_PROFILES:
            self._apply_opsec_profile(value)
        return old

    def _apply_opsec_profile(self, profile_name: str):
        profile = OPSEC_PROFILES.get(profile_name, {})
        for k, v in profile.items():
            if k != 'description':
                self._config[f'opsec_{k}'] = v

    # ── OPSEC ─────────────────────────────────────────────────────────────────

    def current_opsec(self) -> dict:
        profile_name = self._config.get('opsec_profile', 'normal')
        return OPSEC_PROFILES.get(profile_name, OPSEC_PROFILES['normal'])

    # ── Display ───────────────────────────────────────────────────────────────

    def show(self) -> str:
        lines = [
            "\n  ╔══════════════════════════════════════════════╗",
            "  ║         NexShell Configuration               ║",
            "  ╚══════════════════════════════════════════════╝",
        ]
        skip = {'version', 'last_modified'}
        for k, v in sorted(self._config.items()):
            if k in skip:
                continue
            if k.startswith('opsec_') and k != 'opsec_profile':
                continue
            lines.append(f"  {k:<30} {v}")

        opsec = self.current_opsec()
        lines += [
            "",
            f"  OPSEC Profile: {self._config.get('opsec_profile', 'normal')}",
            f"    Description : {opsec.get('description','')}",
            f"    Jitter      : {opsec.get('sleep_jitter', 0)} ms",
            f"    Cmd Delay   : {opsec.get('command_delay', 0)} ms",
            f"    Log Commands: {opsec.get('log_commands', True)}",
            "",
            f"  Roles available : {', '.join(ROLES.keys())}",
            "",
        ]
        return '\n'.join(lines)

    def __getitem__(self, key: str):
        return self._config[key]

    def __setitem__(self, key: str, value: Any):
        self.set(key, value)


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

config = ConfigManager()
