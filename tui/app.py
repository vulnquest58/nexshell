#!/usr/bin/env python3
"""
NexShell TUI v2.0
─────────────────────────────────────────────────────
Professional Terminal Interface with:
  • Multi-tab terminal (Ctrl+T / Ctrl+W)
  • Auto-start file sharing server (tools/ → port 9001-9100)
  • Plugin playlist with connection/TTY validation
  • Reverse shell payload generator
  • Operation notes panel
  • Real-time top-bar status
─────────────────────────────────────────────────────
Run:  python tui/app.py
"""

import sys
import os

# Ensure project root is on sys.path
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical

from tui.core.session_manager import SessionManager, SessionStatus
from tui.core.port_allocator  import PortAllocator
from tui.core.plugin_executor import PluginExecutor, ExecutionRequest
from tui.core.tty_manager     import TTYManager

from tui.widgets.top_bar          import TopBar
from tui.widgets.terminal_tabs    import TerminalTabs
from tui.widgets.share_monitor    import ShareMonitor
from tui.widgets.notes_panel      import NotesPanel
from tui.widgets.plugin_playlist  import PluginPlaylist
from tui.widgets.revshell_generator import RevShellGenerator


class NexShellTUI(App):
    """NexShell Professional Terminal Interface v2.0."""

    TITLE    = "NexShell TUI v2.0"
    CSS_PATH = os.path.join(os.path.dirname(__file__), "styles", "nexshell.tcss")

    BINDINGS = [
        Binding("ctrl+q", "quit",          "Quit",      priority=True),
        Binding("ctrl+t", "new_tab",       "New Tab"),
        Binding("ctrl+w", "close_tab",     "Close Tab"),
        Binding("ctrl+p", "focus_plugins", "Plugins"),
        Binding("ctrl+n", "focus_notes",   "Notes"),
        Binding("ctrl+r", "focus_revshell","RevShell"),
        Binding("ctrl+s", "restart_share", "Restart Share"),
        Binding("f5",     "refresh_plugins","Refresh Plugins"),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.session_manager = SessionManager()
        self.port_allocator  = PortAllocator()
        self.tty_manager:    TTYManager    = None   # type: ignore
        self.plugin_executor: PluginExecutor = None  # type: ignore

        self.session_manager.add_listener(self._on_session_event)

    # ── Composition ───────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield TopBar(id="top-bar")

        with Horizontal(id="main-container"):
            # Left: 62% — Multi-Tab Terminal
            with Vertical(id="left-panel"):
                yield TerminalTabs(
                    port_allocator=self.port_allocator,
                    session_manager=self.session_manager,
                    id="terminal-tabs",
                )

            # Right: 38% — Four panels stacked
            with Vertical(id="right-panel"):
                yield ShareMonitor(
                    port_allocator=self.port_allocator,
                    tools_dir="tools",
                    auto_start=True,
                    id="share-monitor",
                )
                yield NotesPanel(id="notes-panel")
                yield PluginPlaylist(
                    plugins_dir="plugins",
                    id="plugin-playlist",
                )
                yield RevShellGenerator(id="revshell-gen")

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def on_mount(self):
        tabs = self.query_one("#terminal-tabs", TerminalTabs)

        self.tty_manager = TTYManager(
            terminal_callback=tabs.write_to_active,
        )
        self.plugin_executor = PluginExecutor(
            session_manager=self.session_manager,
            terminal_callback=tabs.execute_in_active,
        )

        playlist = self.query_one("#plugin-playlist", PluginPlaylist)
        playlist.plugin_executor = self.plugin_executor

    # ── Message handlers ──────────────────────────────────────────────────

    def on_terminal_tabs_tab_created(self, event: TerminalTabs.TabCreated):
        """Update top-bar when a new tab/session is created."""
        top = self.query_one("#top-bar", TopBar)
        top.set_connected(
            False,
            self.session_manager.get_session_count(),
        )

    def on_share_monitor_server_started(self, event: ShareMonitor.ServerStarted):
        """Update top-bar share port."""
        self.query_one("#top-bar", TopBar).set_share_port(event.port)

    def on_terminal_tabs_terminal_command(self, event: TerminalTabs.TerminalCommand):
        """Handle commands typed into the terminal tabs."""
        self._dispatch_command(event.command, event.session_id)

    def on_plugin_playlist_plugin_execute(self, event: PluginPlaylist.PluginExecute):
        """Single plugin execution from playlist."""
        tabs = self.query_one("#terminal-tabs", TerminalTabs)
        tabs.execute_in_active(event.command)
        self._post_plugin_hooks(event.plugin_name)

    def on_plugin_playlist_plugin_chain_execute(
        self, event: PluginPlaylist.PluginChainExecute
    ):
        """Chain execution from playlist."""
        requests = [
            ExecutionRequest(
                plugin_name=n,
                command=self.plugin_executor.get_plugin_command(n),
            )
            for n in event.plugin_names
        ]
        results = self.plugin_executor.execute_chain(requests)
        for r in results:
            self._post_plugin_hooks(r.plugin_name)

    def on_revshell_generator_payload_generated(
        self, event: RevShellGenerator.PayloadGenerated
    ):
        """Write generated payload into the active terminal."""
        tabs = self.query_one("#terminal-tabs", TerminalTabs)
        tabs.write_to_active(
            f"\n[RevShell · {event.language}]\n{event.payload}\n"
        )

    def _on_session_event(self, event: str, session):
        """React to session lifecycle events."""
        try:
            playlist = self.query_one("#plugin-playlist", PluginPlaylist)
            top      = self.query_one("#top-bar", TopBar)

            if event == "session_updated":
                connected = session.status == SessionStatus.CONNECTED
                playlist.set_connection_status(connected)
                top.set_connected(
                    connected,
                    self.session_manager.get_connected_count(),
                )
            elif event == "tty_upgraded":
                playlist.set_tty_status(True)
                top.set_tty_upgraded(True)
        except Exception:
            pass

    # ── Keybinding actions ────────────────────────────────────────────────

    def action_new_tab(self):
        self.query_one("#terminal-tabs", TerminalTabs).create_new_tab()

    def action_close_tab(self):
        tabs = self.query_one("#terminal-tabs", TerminalTabs)
        if tabs.active_tab:
            tabs.close_tab(tabs.active_tab)

    def action_focus_plugins(self):
        self.query_one("#plugin-playlist", PluginPlaylist).focus()

    def action_focus_notes(self):
        self.query_one("#notes-panel", NotesPanel).focus()

    def action_focus_revshell(self):
        self.query_one("#revshell-gen", RevShellGenerator).focus()

    def action_restart_share(self):
        self.query_one("#share-monitor", ShareMonitor).restart()

    def action_refresh_plugins(self):
        playlist = self.query_one("#plugin-playlist", PluginPlaylist)
        playlist._load_plugins()

    # ── Command dispatcher ────────────────────────────────────────────────

    def _dispatch_command(self, cmd: str, session_id: str):
        """Process special TUI commands; everything else shows in output."""
        tabs = self.query_one("#terminal-tabs", TerminalTabs)
        cmd_lower = cmd.strip().lower()

        if cmd_lower in ("clear", "cls"):
            t = tabs.get_active_terminal()
            if t:
                t.clear()
        elif cmd_lower == "tty upgrade":
            result = self.tty_manager.upgrade_tty()
            msg = "✓ TTY upgraded" if result.success else f"✗ {result.error}"
            tabs.write_to_active(msg)
        elif cmd_lower.startswith("plugins run "):
            plugin_cmd = cmd_lower.replace("plugins run ", "plugins run ", 1)
            tabs.write_to_active(f"[→] Executing: {cmd}")
        elif cmd_lower == "sessions":
            sessions = self.session_manager.get_all_sessions()
            tabs.write_to_active(f"Active sessions: {len(sessions)}")
            for s in sessions:
                tabs.write_to_active(
                    f"  {s.session_id}  port:{s.local_port}  "
                    f"status:{s.status.value}  "
                    f"tty:{'✓' if s.tty_upgraded else '✗'}"
                )
        # All other commands pass through to the shell (if connected)

    def _post_plugin_hooks(self, plugin_name: str):
        """Post-execution hooks for specific plugins."""
        if plugin_name == "smart_tty_upgrade":
            sess = self.session_manager.get_active_session()
            if sess:
                self.session_manager.mark_tty_upgraded(sess.session_id)
                self.query_one("#plugin-playlist", PluginPlaylist).set_tty_status(True)
                self.query_one("#top-bar", TopBar).set_tty_upgraded(True)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = NexShellTUI()
    app.run()
