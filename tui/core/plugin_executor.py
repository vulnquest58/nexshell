"""
Plugin Executor — Validates and dispatches plugin commands to the terminal.
"""

import threading
from typing import Optional, Callable, List
from dataclasses import dataclass
from enum import Enum


class ExecutionStatus(Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    BLOCKED   = "blocked"


@dataclass
class ExecutionRequest:
    plugin_name:        str
    command:            str
    session_id:         Optional[str] = None
    require_connection: bool = True
    require_tty:        bool = False
    priority:           int  = 0
    callback:           Optional[Callable] = None


@dataclass
class ExecutionResult:
    plugin_name: str
    status:      ExecutionStatus
    output:      str = ""
    error:       str = ""
    duration_ms: int = 0


# Plugins that don't need an active connection
_NO_CONNECTION_REQUIRED = {
    "smart_tty_upgrade",
    "reverse_shell_generator",
    "command_queue",
    "cloud_integration",
}

# Plugins that require a TTY upgrade first
_TTY_REQUIRED = {
    "file_transfer_engine",
    "local_file_sharer",
    "port_sniffer",
}

# Default commands for each plugin
_PLUGIN_COMMANDS = {
    "smart_tty_upgrade":      "plugins run smart-tty-upgrade --stage python",
    "file_transfer_engine":   "plugins run file-transfer-engine --detect",
    "persistence_engine":     "plugins run persistence-engine --list",
    "local_file_sharer":      "plugins run local-file-sharer --linux",
    "port_sniffer":           "plugins run port-sniffer --scan",
    "reverse_shell_generator":"plugins run reverse-shell-gen --list",
    "command_queue":          "plugins run command-queue --list",
    "cloud_integration":      "plugins run cloud-integration --test",
}

# Execution priority order
_PRIORITY = {
    "smart_tty_upgrade":      1,
    "persistence_engine":     2,
    "file_transfer_engine":   3,
    "local_file_sharer":      4,
    "port_sniffer":           5,
    "reverse_shell_generator":6,
    "command_queue":          7,
    "cloud_integration":      8,
}


class PluginExecutor:
    def __init__(self, session_manager, terminal_callback: Callable):
        self.session_manager   = session_manager
        self.terminal_callback = terminal_callback
        self._lock             = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def execute_plugin(self, request: ExecutionRequest) -> ExecutionResult:
        """Validate and execute a single plugin."""
        # Connection check
        if request.require_connection and \
           request.plugin_name not in _NO_CONNECTION_REQUIRED:
            if not self.session_manager.has_active_connection():
                return ExecutionResult(
                    plugin_name=request.plugin_name,
                    status=ExecutionStatus.BLOCKED,
                    error="No active connection. Connect to target first.",
                )

        # TTY check
        if request.require_tty or request.plugin_name in _TTY_REQUIRED:
            sess = self.session_manager.get_active_session()
            if not sess or not sess.tty_upgraded:
                return ExecutionResult(
                    plugin_name=request.plugin_name,
                    status=ExecutionStatus.BLOCKED,
                    error="TTY not upgraded. Run smart-tty-upgrade first.",
                )

        try:
            self.terminal_callback(request.command)
            return ExecutionResult(
                plugin_name=request.plugin_name,
                status=ExecutionStatus.RUNNING,
            )
        except Exception as e:
            return ExecutionResult(
                plugin_name=request.plugin_name,
                status=ExecutionStatus.FAILED,
                error=str(e),
            )

    def execute_chain(self, requests: List[ExecutionRequest]) -> List[ExecutionResult]:
        """Execute a list of plugins sorted by priority."""
        sorted_reqs = sorted(
            requests,
            key=lambda r: _PRIORITY.get(r.plugin_name, 99),
        )
        results = []
        for req in sorted_reqs:
            result = self.execute_plugin(req)
            results.append(result)
            if result.status in (ExecutionStatus.BLOCKED, ExecutionStatus.FAILED):
                break
        return results

    def get_plugin_command(self, plugin_name: str, **kwargs) -> str:
        return _PLUGIN_COMMANDS.get(plugin_name, f"plugins run {plugin_name}")

    def can_execute(self, plugin_name: str) -> tuple:
        """Returns (can_run: bool, reason: str)."""
        if plugin_name in _NO_CONNECTION_REQUIRED:
            return True, ""
        if not self.session_manager.has_active_connection():
            return False, "No active connection"
        if plugin_name in _TTY_REQUIRED:
            sess = self.session_manager.get_active_session()
            if not sess or not sess.tty_upgraded:
                return False, "TTY not upgraded"
        return True, ""
