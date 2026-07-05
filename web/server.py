#!/usr/bin/env python3
"""
NexShell — Web Dashboard Server  (web/server.py)
Real-time operator dashboard served over HTTP + WebSocket.
Zero external dependencies — pure Python stdlib only.

Features:
  - Real-time session feed (live updates via WebSocket)
  - Live findings, loot, hosts view
  - Engagement statistics
  - MITRE ATT&CK heatmap
  - Operation status
  - Evidence browser
  - Dark-mode UI (HTML/CSS/JS served from templates/)

Usage:
    from web.server import DashboardServer
    dash = DashboardServer(port=8888)
    dash.start()
    print("Dashboard:", dash.url)

    # Or from NexShell CLI:
    (NexShell)> web start 8888
    (NexShell)> web stop
"""

import base64
import hashlib
import json
import os
import queue
import select
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.parse


# ══════════════════════════════════════════════════════════════════════════════
#  Lightweight WebSocket server (RFC 6455) — reuses nexshell stdlib impl
# ══════════════════════════════════════════════════════════════════════════════

WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def _ws_accept_key(client_key: str) -> str:
    return base64.b64encode(
        hashlib.sha1((client_key + WS_GUID).encode()).digest()
    ).decode()


def _ws_send(sock, msg: str):
    """Send a text WebSocket frame."""
    try:
        payload = msg.encode()
        plen    = len(payload)
        if plen <= 125:
            header = bytes([0x81, plen])
        elif plen <= 65535:
            header = struct.pack('>BBH', 0x81, 126, plen)
        else:
            header = struct.pack('>BBQ', 0x81, 127, plen)
        sock.sendall(header + payload)
    except OSError:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  Dashboard Data Collector
# ══════════════════════════════════════════════════════════════════════════════

class DashboardData:
    """Aggregates real-time data from all NexShell v2 modules."""

    def sessions(self) -> List[dict]:
        try:
            from db import get_db
            rows = get_db().list_sessions()
            return [dict(r) for r in rows[:50]]
        except Exception:
            return []

    def hosts(self) -> List[dict]:
        try:
            from inventory import inventory
            return [h.__dict__ for h in inventory.all()[:50]]
        except Exception:
            return []

    def findings(self) -> List[dict]:
        try:
            from db import get_db
            rows = get_db().list_findings()
            return [dict(r) for r in rows[:50]]
        except Exception:
            return []

    def loot(self, limit: int = 30) -> List[dict]:
        try:
            from db import get_db
            rows = get_db().search_loot()
            return [dict(r) for r in rows[:limit]]
        except Exception:
            return []

    def stats(self) -> dict:
        try:
            from services.health import analytics
            return analytics.summary()
        except Exception:
            pass
        try:
            from db import get_db
            db = get_db()
            return {
                'sessions':  len(db.list_sessions()),
                'hosts':     len(db.list_hosts()),
                'findings':  len(db.list_findings()),
                'loot_items': len(db.search_loot()),
            }
        except Exception:
            return {}

    def operation(self) -> Optional[dict]:
        try:
            from operations import ops
            if ops.active:
                return {
                    'name':       ops.active.name,
                    'client':     ops.active.client,
                    'status':     ops.active.status,
                    'scope':      ops.active.scope,
                    'objectives': ops.active.objectives,
                    'start_date': ops.active.start_date,
                }
        except Exception:
            pass
        return None

    def mitre_tags(self) -> List[dict]:
        try:
            from db import get_db
            rows = get_db()._conn().execute(
                "SELECT DISTINCT mitre_id FROM sessions WHERE mitre_id != '' LIMIT 30"
            ).fetchall()
            from knowledge import mitre
            result = []
            for r in rows:
                t = mitre.get(r[0])
                if t:
                    result.append({'id': r[0], 'name': t['name'], 'tactic': t['tactic']})
            return result
        except Exception:
            return []

    def snapshot(self) -> dict:
        """Full dashboard snapshot."""
        return {
            'ts':        time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'sessions':  self.sessions(),
            'hosts':     self.hosts(),
            'findings':  self.findings(),
            'loot':      self.loot(20),
            'stats':     self.stats(),
            'operation': self.operation(),
            'mitre':     self.mitre_tags(),
        }


# ══════════════════════════════════════════════════════════════════════════════
#  Dashboard HTTP + WebSocket Server
# ══════════════════════════════════════════════════════════════════════════════

class DashboardServer:
    """
    Combined HTTP file server + WebSocket push server.
    HTTP: serves dashboard HTML/CSS/JS
    WS  : pushes real-time data to browser on /ws endpoint

    Usage:
        srv = DashboardServer(port=8888)
        srv.start()
        # Open http://localhost:8888 in browser
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 8888,
                 push_interval: int = 3):
        self.host           = host
        self.port           = port
        self.push_interval  = push_interval
        self._data          = DashboardData()
        self._ws_clients: List[socket.socket] = []
        self._ws_lock       = threading.Lock()
        self._http_server: Optional[HTTPServer] = None
        self._running       = False
        self._event_queue   = queue.Queue()

    # ── Event push (called by EventBus) ──────────────────────────────────────

    def push_event(self, event_type: str, data: dict):
        """Push a live event to all connected browser clients."""
        msg = json.dumps({'type': event_type, 'data': data})
        self._event_queue.put(msg)

    def _broadcast(self, msg: str):
        """Send message to all WebSocket clients."""
        with self._ws_lock:
            dead = []
            for sock in self._ws_clients:
                try:
                    _ws_send(sock, msg)
                except OSError:
                    dead.append(sock)
            for d in dead:
                self._ws_clients.remove(d)

    # ── Periodic push loop ────────────────────────────────────────────────────

    def _push_loop(self):
        """Every N seconds push a full snapshot to all WS clients."""
        while self._running:
            time.sleep(self.push_interval)
            if not self._ws_clients:
                continue
            try:
                snap = self._data.snapshot()
                self._broadcast(json.dumps({'type': 'snapshot', 'data': snap}))
            except Exception:
                pass

    # ── WebSocket upgrade handler ──────────────────────────────────────────────

    def _handle_ws(self, conn, client_key: str):
        """Accept a WebSocket upgrade and add to broadcast list."""
        accept = _ws_accept_key(client_key)
        resp   = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        )
        conn.sendall(resp.encode())
        with self._ws_lock:
            self._ws_clients.append(conn)
        # Send initial snapshot immediately
        try:
            snap = self._data.snapshot()
            _ws_send(conn, json.dumps({'type': 'snapshot', 'data': snap}))
        except Exception:
            pass
        # Keep connection alive until client disconnects
        while self._running:
            try:
                # Drain queued events
                while not self._event_queue.empty():
                    msg = self._event_queue.get_nowait()
                    _ws_send(conn, msg)
                # Check for close frame (non-blocking)
                ready, _, _ = select.select([conn], [], [], 1.0)
                if ready:
                    data = conn.recv(10)
                    if not data or (data[0] & 0x0F) == 0x8:  # CLOSE frame
                        break
            except OSError:
                break
        with self._ws_lock:
            if conn in self._ws_clients:
                self._ws_clients.remove(conn)
        try:
            conn.close()
        except OSError:
            pass

    # ── HTTP Request Handler ───────────────────────────────────────────────────

    def _make_handler(self):
        dash_ref = self
        tpl_dir  = Path(__file__).parent / 'templates'

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                path   = parsed.path

                # WebSocket upgrade
                if (path == '/ws' and
                    self.headers.get('Upgrade', '').lower() == 'websocket'):
                    key = self.headers.get('Sec-WebSocket-Key', '')
                    if key:
                        conn = self.request
                        dash_ref._handle_ws(conn, key)
                    return

                # REST endpoints
                if path == '/api/snapshot':
                    self._json(dash_ref._data.snapshot())
                    return
                if path == '/api/sessions':
                    self._json({'sessions': dash_ref._data.sessions()})
                    return
                if path == '/api/hosts':
                    self._json({'hosts': dash_ref._data.hosts()})
                    return
                if path == '/api/findings':
                    self._json({'findings': dash_ref._data.findings()})
                    return
                if path == '/api/loot':
                    self._json({'loot': dash_ref._data.loot()})
                    return
                if path == '/api/stats':
                    self._json(dash_ref._data.stats())
                    return
                if path == '/api/operation':
                    self._json(dash_ref._data.operation() or {})
                    return

                # Static files
                file_map = {
                    '/':            ('index.html', 'text/html; charset=utf-8'),
                    '/index.html':  ('index.html', 'text/html; charset=utf-8'),
                    '/style.css':   ('style.css',  'text/css'),
                    '/app.js':      ('app.js',     'application/javascript'),
                    '/favicon.ico': ('favicon.ico','image/x-icon'),
                }
                fname, ctype = file_map.get(path, (None, None))
                if fname:
                    fpath = tpl_dir / fname
                    if fpath.exists():
                        body = fpath.read_bytes()
                        self.send_response(200)
                        self.send_header('Content-Type', ctype)
                        self.send_header('Content-Length', str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                self.send_error(404)

            def _json(self, data):
                body = json.dumps(data, default=str).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(body)

        return _Handler

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self, daemon: bool = True) -> 'DashboardServer':
        handler = self._make_handler()
        srv     = HTTPServer((self.host, self.port), handler)
        self._http_server = srv
        self._running     = True

        # HTTP thread
        ht = threading.Thread(target=srv.serve_forever, daemon=daemon)
        ht.start()

        # Periodic push thread
        pt = threading.Thread(target=self._push_loop, daemon=daemon)
        pt.start()

        # Wire into EventBus for live events
        self._wire_events()
        return self

    def _wire_events(self):
        """Subscribe to NexShell EventBus events for live push."""
        try:
            from core.event_bus import bus
            bus.subscribe('session.connected',  lambda **kw: self.push_event('session', kw))
            bus.subscribe('loot.added',         lambda **kw: self.push_event('loot',    kw))
            bus.subscribe('finding.created',    lambda **kw: self.push_event('finding', kw))
            bus.subscribe('host.added',         lambda **kw: self.push_event('host',    kw))
            bus.subscribe('cred.discovered',    lambda **kw: self.push_event('cred',    kw))
        except Exception:
            pass

    def stop(self):
        self._running = False
        if self._http_server:
            self._http_server.shutdown()
            self._http_server.server_close()

    @property
    def url(self) -> str:
        host = 'localhost' if self.host in ('127.0.0.1', '0.0.0.0') else self.host
        return f"http://{host}:{self.port}"

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


# ══════════════════════════════════════════════════════════════════════════════
#  Module-level singleton (lazy-started)
# ══════════════════════════════════════════════════════════════════════════════

_dashboard: Optional[DashboardServer] = None


def get_dashboard() -> Optional[DashboardServer]:
    return _dashboard


def start_dashboard(host: str = '127.0.0.1', port: int = 8888,
                    push_interval: int = 3) -> DashboardServer:
    global _dashboard
    if _dashboard and _dashboard._running:
        return _dashboard
    _dashboard = DashboardServer(host=host, port=port, push_interval=push_interval)
    _dashboard.start()
    return _dashboard


def stop_dashboard():
    global _dashboard
    if _dashboard:
        _dashboard.stop()
        _dashboard = None
