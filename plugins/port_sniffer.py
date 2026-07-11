#!/usr/bin/env python3
"""
NexShell Plugin — Port Sniffer & Session Recorder v2.0 (2026 Edition)
Scans 4-digit ports (1000-9999), detects active sessions,
and records TCP traffic to timestamped log files.

Features:
  - Fast parallel port scanning (4-digit range: 1000-9999)
  - Protocol fingerprinting (SSH, HTTP, FTP, Telnet, Netcat raw, etc.)
  - Session recording — captures raw TCP traffic to .log files
  - Background recording threads (non-blocking)
  - Local scan (127.0.0.1) and remote target scan
  - Banner grabbing for service identification
  - Detection of reverse shell sessions by banner analysis

MITRE ATT&CK:
  - T1040 (Network Sniffing)
  - T1049 (System Network Connections Discovery)

Usage:
    (NexShell)> plugins run port-sniffer --scan
    (NexShell)> plugins run port-sniffer --scan --target 192.168.1.5
    (NexShell)> plugins run port-sniffer --record 4444
    (NexShell)> plugins run port-sniffer --record 4444,5555
    (NexShell)> plugins run port-sniffer --list
    (NexShell)> plugins run port-sniffer --stop 4444
"""

import re
import os
import time
import socket
import threading
import queue
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set
from datetime import datetime
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class PortInfo:
    """Information about a detected port."""
    port: int
    protocol: str = "unknown"
    banner: str = ""
    service: str = "unknown"
    is_shell: bool = False
    response_time_ms: int = 0
    timestamp: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionRecord:
    """A recorded session on a port."""
    port: int
    start_time: str
    end_time: str = ""
    bytes_rx: int = 0
    bytes_tx: int = 0
    log_path: str = ""
    protocol: str = "raw"
    active: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


# ── Protocol Fingerprinter ───────────────────────────────────────────────────

class ProtocolFingerprinter:
    """Identifies protocols from banner/response data."""

    SIGNATURES = {
        "ssh":     [b"SSH-", b"OpenSSH"],
        "http":    [b"HTTP/", b"<!DOCTYPE", b"<html"],
        "ftp":     [b"220 ", b"FTP", b"vsftpd", b"ProFTPD"],
        "telnet":  [b"\xff\xfd", b"\xff\xfb"],
        "smtp":    [b"220 ", b"ESMTP", b"Postfix"],
        "mysql":   [b"\x4a\x00\x00\x00", b"mysql_native"],
        "netcat":  [],   # raw, no banner
        "shell":   [b"$ ", b"# ", b"bash", b"sh-", b"root@", b"PS C:\\"],
    }

    SHELL_INDICATORS = [
        b"$ ", b"# ", b"bash-", b"sh-", b"root@",
        b"uid=", b"PS C:\\", b"C:\\>", b"% ",
        b"[root", b"[user",
    ]

    @classmethod
    def fingerprint(cls, data: bytes) -> tuple:
        """Returns (protocol, service, is_shell)."""
        if not data:
            return ("raw", "unknown", False)

        is_shell = any(sig in data for sig in cls.SHELL_INDICATORS)

        for proto, sigs in cls.SIGNATURES.items():
            if sigs and any(sig in data for sig in sigs):
                return (proto, proto, is_shell or proto == "shell")

        # Empty response → likely raw TCP (netcat/shell)
        return ("raw", "raw-tcp", is_shell)

    @classmethod
    def is_reverse_shell(cls, data: bytes, port: int) -> bool:
        """Heuristic: detect reverse shell by port and banner."""
        # Common shell ports
        if port in {4444, 4445, 5555, 6666, 7777, 8888, 9001, 9002}:
            return True
        # Shell indicators in banner
        if any(sig in data for sig in cls.SHELL_INDICATORS):
            return True
        return False


# ── Port Scanner ─────────────────────────────────────────────────────────────

class PortScanner:
    """Fast parallel port scanner."""

    @staticmethod
    def scan_range(target: str = "127.0.0.1",
                   port_start: int = 1000,
                   port_end: int = 9999,
                   timeout: float = 0.3,
                   max_threads: int = 200,
                   grab_banner: bool = True) -> List[PortInfo]:
        """Scan port range using thread pool."""
        results: List[PortInfo] = []
        results_lock = threading.Lock()
        port_queue: queue.Queue = queue.Queue()

        for port in range(port_start, port_end + 1):
            port_queue.put(port)

        def worker():
            while True:
                try:
                    port = port_queue.get_nowait()
                except queue.Empty:
                    break

                t0 = time.time()
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target, port))
                    ms = int((time.time() - t0) * 1000)

                    if result == 0:
                        banner = b""
                        if grab_banner:
                            try:
                                sock.settimeout(0.5)
                                banner = sock.recv(1024)
                            except Exception:
                                pass
                        sock.close()

                        proto, service, is_shell = ProtocolFingerprinter.fingerprint(banner)
                        is_shell = is_shell or ProtocolFingerprinter.is_reverse_shell(banner, port)

                        info = PortInfo(
                            port=port,
                            protocol=proto,
                            banner=banner.decode("utf-8", errors="replace")[:80].strip(),
                            service=service,
                            is_shell=is_shell,
                            response_time_ms=ms,
                            timestamp=datetime.utcnow().isoformat(),
                        )
                        with results_lock:
                            results.append(info)
                    else:
                        sock.close()
                except Exception:
                    pass
                finally:
                    port_queue.task_done()

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(min(max_threads, port_end - port_start + 1))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        return sorted(results, key=lambda p: p.port)

    @staticmethod
    def scan_remote_via_session(exec_fn, session,
                                 target: str = "127.0.0.1",
                                 port_start: int = 1000,
                                 port_end: int = 9999) -> str:
        """Use target session to scan ports (remote scan)."""
        cmd = (
            f"python3 -c \""
            f"import socket; "
            f"open_ports = []; "
            f"[open_ports.append(p) for p in range({port_start},{port_end}+1) "
            f"if socket.socket().connect_ex(('{target}',p))==0]; "
            f"print('OPEN:' + ','.join(map(str,open_ports)))"
            f"\" 2>/dev/null || "
            f"for p in $(seq {port_start} {port_end}); do "
            f"(echo >/dev/tcp/{target}/$p) 2>/dev/null && echo OPEN:$p; "
            f"done"
        )
        return exec_fn(session, cmd) or ""


# ── Session Recorder ─────────────────────────────────────────────────────────

# Global registry of active recording threads
_active_recordings: Dict[int, threading.Thread] = {}
_recording_data: Dict[int, SessionRecord] = {}
_recording_lock = threading.Lock()


class SessionRecorder:
    """Records TCP session traffic to log files."""

    LOG_DIR = os.path.expanduser("~/.nexshell/recordings")

    @classmethod
    def _ensure_dir(cls):
        os.makedirs(cls.LOG_DIR, exist_ok=True)

    @classmethod
    def start_recording(cls, port: int, timeout: int = 300) -> SessionRecord:
        """Start recording traffic on a port in background thread."""
        cls._ensure_dir()
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        log_path = os.path.join(cls.LOG_DIR, f"session_{port}_{ts}.log")

        record = SessionRecord(
            port=port,
            start_time=datetime.utcnow().isoformat(),
            log_path=log_path,
            active=True,
        )

        def _record_loop():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                srv.bind(("0.0.0.0", port))
                srv.listen(1)
                srv.settimeout(timeout)
                conn, addr = srv.accept()
                conn.settimeout(60)

                with open(log_path, "wb") as f:
                    header = (
                        f"# NexShell Session Recording\n"
                        f"# Port: {port}\n"
                        f"# Started: {record.start_time}\n"
                        f"# Remote: {addr}\n"
                        f"# {'─'*50}\n"
                    ).encode()
                    f.write(header)

                    while record.active:
                        try:
                            data = conn.recv(4096)
                            if not data:
                                break
                            f.write(data)
                            f.flush()
                            with _recording_lock:
                                record.bytes_rx += len(data)
                        except socket.timeout:
                            break
                        except Exception:
                            break

                conn.close()
            except Exception:
                pass
            finally:
                srv.close()
                record.active = False
                record.end_time = datetime.utcnow().isoformat()

        t = threading.Thread(target=_record_loop, daemon=True)
        with _recording_lock:
            _active_recordings[port] = t
            _recording_data[port] = record
        t.start()
        return record

    @classmethod
    def stop_recording(cls, port: int) -> Optional[SessionRecord]:
        """Stop recording on a specific port."""
        with _recording_lock:
            record = _recording_data.get(port)
            if record:
                record.active = False
            _active_recordings.pop(port, None)
        return record

    @classmethod
    def list_active(cls) -> List[SessionRecord]:
        """List all active recordings."""
        with _recording_lock:
            return list(_recording_data.values())

    @classmethod
    def get_all_recordings(cls) -> List[str]:
        """List all recording log files."""
        cls._ensure_dir()
        try:
            return [
                f for f in os.listdir(cls.LOG_DIR)
                if f.startswith("session_") and f.endswith(".log")
            ]
        except Exception:
            return []


# ── Main Plugin ──────────────────────────────────────────────────────────────

class PortSniffer(NexPlugin):
    name        = "port-sniffer"
    description = "Port sniffer & session recorder — scans 4-digit ports, records TCP traffic"
    author      = "vulnquest58"
    version     = "2.0"
    platform    = "all"
    category    = "recon"
    mitre_id    = "T1040"

    def run(self, session, args: list):
        # ── Parse args ───────────────────────────────────────────────────
        scan_mode     = False
        record_ports  = []
        stop_ports    = []
        list_mode     = False
        target        = "127.0.0.1"
        port_start    = 1000
        port_end      = 9999
        use_session   = False
        timeout_scan  = 0.3
        grab_banner   = True
        record_timeout = 300

        for a in (args or []):
            if a == "--scan":
                scan_mode = True
            elif a.startswith("--target="):
                target = a.split("=", 1)[1]
            elif a.startswith("--record="):
                raw = a.split("=", 1)[1]
                for p in raw.split(","):
                    try: record_ports.append(int(p.strip()))
                    except: pass
            elif a == "--record" and args:
                # handled by = format only
                pass
            elif a.startswith("--stop="):
                raw = a.split("=", 1)[1]
                for p in raw.split(","):
                    try: stop_ports.append(int(p.strip()))
                    except: pass
            elif a == "--list":
                list_mode = True
            elif a == "--remote":
                use_session = True
            elif a.startswith("--range="):
                parts = a.split("=", 1)[1].split("-")
                if len(parts) == 2:
                    try:
                        port_start = int(parts[0])
                        port_end = int(parts[1])
                    except: pass
            elif a == "--no-banner":
                grab_banner = False
            elif a.startswith("--timeout="):
                try: record_timeout = int(a.split("=", 1)[1])
                except: pass

        self.info("Port Sniffer v2.0 started")
        sections = []
        sections.append("\n" + "━" * 64)
        sections.append("  [🔌 Port Sniffer & Session Recorder v2.0]")
        sections.append("━" * 64)

        # ── List mode ─────────────────────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Active Recordings:")
            sections.append("─" * 64)
            active = SessionRecorder.list_active()
            if not active:
                sections.append("  No active recordings.")
            for r in active:
                status = "🟢 Active" if r.active else "⛔ Stopped"
                sections.append(f"  {status}  Port {r.port:5d} | {r.bytes_rx:8d} bytes | {r.log_path}")

            sections.append("\n[*] Recorded Sessions:")
            sections.append("─" * 64)
            recordings = SessionRecorder.get_all_recordings()
            if not recordings:
                sections.append("  No recorded sessions found.")
            for fname in sorted(recordings)[-10:]:
                path = os.path.join(SessionRecorder.LOG_DIR, fname)
                try:
                    size = os.path.getsize(path)
                    sections.append(f"  📄 {fname}  ({size:,} bytes)")
                except Exception:
                    sections.append(f"  📄 {fname}")

            return "\n".join(sections)

        # ── Stop recordings ────────────────────────────────────────────────
        if stop_ports:
            sections.append("\n[*] Stopping Recordings:")
            sections.append("─" * 64)
            for port in stop_ports:
                record = SessionRecorder.stop_recording(port)
                if record:
                    sections.append(f"  ⛔ Stopped recording on port {port}")
                    sections.append(f"     Bytes captured : {record.bytes_rx:,}")
                    sections.append(f"     Log file       : {record.log_path}")
                else:
                    sections.append(f"  ❌ No active recording on port {port}")
            return "\n".join(sections)

        # ── Port scan ──────────────────────────────────────────────────────
        if scan_mode:
            sections.append(f"\n[*] Phase 1: Port Scan")
            sections.append("─" * 64)
            sections.append(f"  Target     : {target}")
            sections.append(f"  Range      : {port_start} – {port_end}")
            sections.append(f"  Threads    : 200")
            sections.append(f"  Timeout    : {timeout_scan}s per port")
            sections.append(f"  Banner     : {'Yes' if grab_banner else 'No'}")
            sections.append(f"  Scanning...")

            if use_session:
                # Remote scan via session
                raw_out = PortScanner.scan_remote_via_session(
                    self._exec, session, target, port_start, port_end
                )
                open_ports_str = ""
                for line in raw_out.splitlines():
                    if "OPEN:" in line:
                        open_ports_str = line.split("OPEN:", 1)[1]
                open_ports = []
                for p_str in open_ports_str.split(","):
                    try: open_ports.append(int(p_str.strip()))
                    except: pass

                sections.append(f"\n  Found {len(open_ports)} open port(s) via remote scan:")
                for p in open_ports:
                    sections.append(f"    🔵 Port {p:5d}")
            else:
                # Local scan from attacker machine
                open_ports_info = PortScanner.scan_range(
                    target=target,
                    port_start=port_start,
                    port_end=port_end,
                    timeout=timeout_scan,
                    grab_banner=grab_banner,
                )

                if not open_ports_info:
                    sections.append(f"\n  No open 4-digit ports found on {target}.")
                else:
                    shell_ports = [p for p in open_ports_info if p.is_shell]
                    sections.append(f"\n  Found {len(open_ports_info)} open port(s):")
                    sections.append(f"  Possible shells: {len(shell_ports)}")
                    sections.append("")

                    for p in open_ports_info:
                        shell_flag = "  🐚 SHELL" if p.is_shell else ""
                        banner_str = f" | banner: {p.banner[:40]}" if p.banner else ""
                        sections.append(
                            f"  🔵 Port {p.port:5d} | {p.service:10s} | {p.response_time_ms:4d}ms"
                            f"{banner_str}{shell_flag}"
                        )

                    if shell_ports:
                        sections.append("\n  [!] Possible reverse shell ports detected:")
                        for p in shell_ports:
                            sections.append(f"    > plugins run port-sniffer --record {p.port}")

                    # Loot
                    self.loot(
                        f"Port scan {target} {port_start}-{port_end}: {len(open_ports_info)} open",
                        category="recon",
                        source=self.name,
                    )
                    self.emit(
                        "timeline.event",
                        title=f"Port scan: {len(open_ports_info)} ports found on {target}",
                        type="recon",
                        plugin=self.name,
                    )

        # ── Start recording ────────────────────────────────────────────────
        if record_ports:
            sections.append("\n[*] Phase 2: Session Recording")
            sections.append("─" * 64)
            sections.append(f"  Recording ports: {', '.join(map(str, record_ports))}")
            sections.append(f"  Timeout        : {record_timeout}s")
            sections.append(f"  Log directory  : {SessionRecorder.LOG_DIR}")

            for port in record_ports:
                try:
                    record = SessionRecorder.start_recording(port, timeout=record_timeout)
                    sections.append(f"\n  🟢 Started recording on port {port}")
                    sections.append(f"     Log : {record.log_path}")
                    sections.append(f"     Stop: plugins run port-sniffer --stop={port}")
                except Exception as e:
                    sections.append(f"\n  ❌ Failed to record port {port}: {e}")

        if not scan_mode and not record_ports and not list_mode and not stop_ports:
            sections.append("\n  Usage:")
            sections.append("    > plugins run port-sniffer --scan")
            sections.append("    > plugins run port-sniffer --scan --target 192.168.1.5")
            sections.append("    > plugins run port-sniffer --record=4444")
            sections.append("    > plugins run port-sniffer --record=4444,5555")
            sections.append("    > plugins run port-sniffer --stop=4444")
            sections.append("    > plugins run port-sniffer --list")
            sections.append("    > plugins run port-sniffer --scan --range=4000-5000")

        self.info("Port Sniffer complete")
        return "\n".join(sections)
