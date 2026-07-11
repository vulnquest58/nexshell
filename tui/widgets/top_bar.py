"""
Top Bar Widget — Shows session status, TTY state, and connection info.
"""

from textual.widget import Widget
from textual.widgets import Static
from textual.containers import Horizontal
from textual.reactive import reactive
from datetime import datetime


class TopBar(Widget):
    """Top status bar showing session/connection/TTY state."""

    DEFAULT_CSS = """
    TopBar {
        height: 3;
        background: #161b22;
        border-bottom: solid #30363d;
        padding: 0 2;
        layout: horizontal;
    }
    """

    connected     = reactive(False)
    tty_upgraded  = reactive(False)
    session_count = reactive(0)
    share_port    = reactive(0)

    def compose(self):
        yield Static("🖥  NexShell TUI v2.0", id="top-title")
        yield Static("", id="top-session-info")
        yield Static("", id="top-status")

    def on_mount(self):
        self._refresh_display()
        self.set_interval(1.0, self._tick)

    def _tick(self):
        self._refresh_display()

    def _refresh_display(self):
        ts   = datetime.utcnow().strftime("%H:%M:%S UTC")
        conn = "● CONNECTED" if self.connected else "○ NO SESSION"
        tty  = "TTY✓" if self.tty_upgraded else "TTY✗"
        share = f"Share:{self.share_port}" if self.share_port else "Share:off"

        conn_style = "connected" if self.connected else "disconnected"
        tty_style  = "tty"       if self.tty_upgraded else "disconnected"

        info = self.query_one("#top-session-info", Static)
        info.update(
            f"Sessions: {self.session_count}  │  "
            f"{share}  │  {ts}"
        )

        status = self.query_one("#top-status", Static)
        status.update(f"{conn}  {tty}")

    def set_connected(self, value: bool, count: int = 0):
        self.connected     = value
        self.session_count = count
        self._refresh_display()

    def set_tty_upgraded(self, value: bool):
        self.tty_upgraded = value
        self._refresh_display()

    def set_share_port(self, port: int):
        self.share_port = port
        self._refresh_display()
