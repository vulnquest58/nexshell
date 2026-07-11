"""
TTY Manager — Manages TTY upgrade sequence and state.
"""

from typing import Optional, Callable
from dataclasses import dataclass


@dataclass
class TTYUpgradeResult:
    success: bool
    method:  str
    shell:   str = "/bin/bash"
    error:   str = ""


_STAGES = [
    {
        "name":      "python3",
        "command":   "python3 -c \"import pty; pty.spawn('/bin/bash')\"",
        "indicator": "root@",
    },
    {
        "name":      "python",
        "command":   "python -c \"import pty; pty.spawn('/bin/sh')\"",
        "indicator": "$ ",
    },
    {
        "name":      "script",
        "command":   "script -qc /bin/bash /dev/null",
        "indicator": "bash",
    },
    {
        "name":      "perl",
        "command":   "perl -e \"exec '/bin/bash'\"",
        "indicator": "$ ",
    },
    {
        "name":      "socat",
        "command":   "socat file:`tty`,raw,echo=0 tcp-listen:4444",
        "indicator": "socat",
    },
]

_CONFIG_CMDS = [
    "export TERM=xterm-256color",
    "export SHELL=/bin/bash",
    "stty rows 40 columns 120",
    "stty sane",
]


class TTYManager:
    def __init__(self, terminal_callback: Callable):
        self.terminal_callback = terminal_callback
        self._upgraded        = False
        self._current_method: Optional[str] = None

    def upgrade_tty(self, method: str = "auto") -> TTYUpgradeResult:
        stages = _STAGES if method == "auto" else [
            s for s in _STAGES if s["name"] == method
        ]
        if not stages:
            return TTYUpgradeResult(False, method, error=f"Unknown method: {method}")

        for stage in stages:
            try:
                self.terminal_callback(stage["command"])
                for cmd in _CONFIG_CMDS:
                    self.terminal_callback(cmd)
                self._upgraded = True
                self._current_method = stage["name"]
                return TTYUpgradeResult(True, stage["name"])
            except Exception as e:
                if method != "auto":
                    return TTYUpgradeResult(False, method, error=str(e))
                continue

        return TTYUpgradeResult(False, "none", error="All TTY upgrade methods failed")

    def is_upgraded(self) -> bool:
        return self._upgraded

    def get_current_method(self) -> Optional[str]:
        return self._current_method

    def get_upgrade_command(self, method: str = "python3") -> str:
        s = next((s for s in _STAGES if s["name"] == method), None)
        return s["command"] if s else ""

    def reset(self):
        self._upgraded = False
        self._current_method = None
