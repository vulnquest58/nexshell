#!/usr/bin/env python3
"""
NexShell — Transport Package  (modules/transport/__init__.py)
Enhanced transport layer:
  - tcp        — Raw TCP (default)
  - tls/mtls   — TLS 1.3 (from modules/transport.py)
  - http        — HTTP POST tunnel (stdlib only)
  - https       — HTTPS tunnel
  - websocket   — WebSocket tunnel (RFC 6455, stdlib only)
  - doh         — DNS-over-HTTPS exfil channel

All transports implement the same interface:
    transport.start()
    transport.send(data: bytes) -> None
    transport.recv(n: int)      -> bytes
    transport.close()
"""

# Re-export v1 transports
from modules.transport_compat import TLSListener, HTTPTunnel, DoHExfil, TRANSPORT_INFO

# v2 enhanced transports
from modules.transport.http_tunnel import (
    HTTPTunnelServer,
    HTTPTunnelClient,
    HTTPSSession,
    generate_http_agent,
    generate_https_agent,
    generate_powershell_agent,
)
from modules.transport.websocket import (
    WebSocketServer,
    WebSocketClient,
    WebSocketFrame,
    generate_ws_agent_linux,
    generate_ws_agent_windows,
    generate_ws_agent_python,
)

# Updated transport registry
TRANSPORT_INFO.update({
    'websocket': {
        'desc': 'WebSocket tunnel (RFC 6455)',
        'stealth': '⭐⭐⭐⭐',
        'speed': '⚡⚡⚡',
        'encrypt': '❌ (use wss:// for TLS)',
        'agent_os': 'all',
    },
    'wss': {
        'desc': 'WebSocket over TLS (WSS)',
        'stealth': '⭐⭐⭐⭐⭐',
        'speed': '⚡⚡⚡',
        'encrypt': '✅',
        'agent_os': 'all',
    },
})

__all__ = [
    'TLSListener', 'HTTPTunnel', 'DoHExfil', 'TRANSPORT_INFO',
    'HTTPTunnelServer', 'HTTPTunnelClient', 'HTTPSSession',
    'generate_http_agent', 'generate_https_agent', 'generate_powershell_agent',
    'WebSocketServer', 'WebSocketClient', 'WebSocketFrame',
    'generate_ws_agent_linux', 'generate_ws_agent_windows', 'generate_ws_agent_python',
]
