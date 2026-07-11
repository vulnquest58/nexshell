"""
Share Monitor Widget — Auto-starts HTTP server from tools/ on launch.
Shows incoming download requests in real-time.
"""

import http.server
import socketserver
import threading
import os
from datetime import datetime
from collections import deque
from typing import Optional

from textual.widget import Widget
from textual.widgets import ListView, ListItem, Label, Static
from textual.containers import Vertical
from textual.reactive import reactive
from textual.message import Message


class ShareMonitor(Widget):
    """Real-time monitor for the tools/ file sharing server."""

    DEFAULT_CSS = """
    ShareMonitor {
        height: 1fr;
        border: solid #d29922;
        padding: 1;
        background: #161b22;
    }
    """

    server_running = reactive(False)
    active_port    = reactive(0)

    class ServerStarted(Message):
        def __init__(self, port: int):
            self.port = port
            super().__init__()

    class RequestReceived(Message):
        def __init__(self, client_ip: str, method: str, path: str):
            self.client_ip = client_ip
            self.method    = method
            self.path      = path
            super().__init__()

    def __init__(self, port_allocator, tools_dir: str = "tools",
                 auto_start: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.port_allocator = port_allocator
        self.tools_dir      = tools_dir
        self.auto_start     = auto_start
        self._httpd         = None
        self._thread        = None
        self.request_log    = deque(maxlen=50)

    def compose(self):
        with Vertical():
            yield Static("📁 Share File Monitor", id="share-title")
            yield Static("Status: Initializing…", id="share-status")
            yield ListView(id="request-list")

    def on_mount(self):
        if self.auto_start:
            self._start_server()

    def on_unmount(self):
        self._stop_server()

    # ── Server ────────────────────────────────────────────────────────────

    def _start_server(self, port: int = None):
        if port is None:
            port = self.port_allocator.allocate_share_port()
        if not port:
            self._set_status("Error: No ports available (9001-9100)", active=False)
            return

        # Resolve tools_dir relative to project root
        base_dir = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        serve_dir = os.path.join(base_dir, self.tools_dir)
        os.makedirs(serve_dir, exist_ok=True)

        monitor = self

        class _Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **kw):
                super().__init__(*a, directory=serve_dir, **kw)

            def do_GET(self):
                monitor._log_request(self.client_address[0], "GET", self.path)
                return super().do_GET()

            def do_POST(self):
                monitor._log_request(self.client_address[0], "POST", self.path)
                return super().do_POST()

            def log_message(self, fmt, *args):
                pass  # Suppress default stderr output

        try:
            socketserver.TCPServer.allow_reuse_address = True
            self._httpd     = socketserver.TCPServer(("0.0.0.0", port), _Handler)
            self.active_port    = port
            self.server_running = True
            self._thread    = threading.Thread(
                target=self._httpd.serve_forever, daemon=True
            )
            self._thread.start()
            self._set_status(f"● Active on :{port}  →  {serve_dir}", active=True)
            self.post_message(self.ServerStarted(port))
        except Exception as e:
            self._set_status(f"Error: {e}", active=False)

    def _stop_server(self):
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
        if self.active_port:
            self.port_allocator.release_port(self.active_port)
            self.active_port = 0
        self.server_running = False

    def restart(self):
        self._stop_server()
        self._start_server()

    # ── Helpers ───────────────────────────────────────────────────────────

    def _set_status(self, msg: str, active: bool):
        try:
            bar = self.query_one("#share-status", Static)
            bar.update(f"Status: {msg}")
            if active:
                bar.remove_class("inactive")
            else:
                bar.add_class("inactive")
        except Exception:
            pass

    def _log_request(self, client_ip: str, method: str, path: str):
        ts   = datetime.utcnow().strftime("%H:%M:%S")
        text = f"[{ts}] {client_ip}  {method}  {path}"
        self.request_log.append(text)
        try:
            lv = self.query_one("#request-list", ListView)
            lv.append(ListItem(Label(text)))
            # Prune to 30 items
            while len(lv.children) > 30:
                lv.children[0].remove()
        except Exception:
            pass
        self.post_message(self.RequestReceived(client_ip, method, path))

    def is_running(self) -> bool:
        return self.server_running

    def get_port(self) -> int:
        return self.active_port
