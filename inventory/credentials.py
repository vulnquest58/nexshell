#!/usr/bin/env python3
"""
NexShell — Credential Store  (inventory/credentials.py)
Tracks discovered credentials linked to hosts and sessions.
Deduplicates automatically. Supports crack status tracking.

Usage:
    from inventory.credentials import CredentialStore
    creds = CredentialStore()
    creds.add("10.0.0.1", username="admin", password="P@ssw0rd!", source="credharvest")
    creds.add("10.0.0.1", username="root",  hash_="$6$...", source="shadow")
    print(creds.summary())
    print(creds.by_host("10.0.0.1"))
"""

import datetime
import hashlib
import json
import uuid
from pathlib import Path
from typing import Dict, List, Optional


CRED_TYPES = {
    'plaintext':   '🔑',
    'hash':        '#️⃣ ',
    'key':         '🗝️ ',
    'token':       '🔐',
    'certificate': '📜',
    'kerberos':    '🎟️ ',
}

HASH_PATTERNS = {
    'ntlm':    (32,  r'^[a-fA-F0-9]{32}$'),
    'md5':     (32,  r'^[a-fA-F0-9]{32}$'),
    'sha1':    (40,  r'^[a-fA-F0-9]{40}$'),
    'sha256':  (64,  r'^[a-fA-F0-9]{64}$'),
    'bcrypt':  (60,  r'^\$2[aby]\$'),
    'sha512crypt': (106, r'^\$6\$'),
    'md5crypt':    (34,  r'^\$1\$'),
}


class Credential:
    def __init__(self, host_ip: str = "", username: str = "",
                 password: str = "", hash_: str = "",
                 key_data: str = "", token: str = "",
                 cred_type: str = "", source: str = "manual",
                 service: str = "", domain: str = "",
                 session_id: int = 0):
        self.id         = str(uuid.uuid4())[:10]
        self.host_ip    = host_ip
        self.username   = username
        self.password   = password
        self.hash_      = hash_
        self.key_data   = key_data[:100] if key_data else ''
        self.token      = token[:200] if token else ''
        self.service    = service
        self.domain     = domain
        self.source     = source
        self.session_id = session_id
        self.cracked    = False
        self.cracked_pw = ''
        self.ts         = datetime.datetime.utcnow().isoformat()
        # Auto-detect type
        if cred_type:
            self.type = cred_type
        elif password:
            self.type = 'plaintext'
        elif hash_:
            self.type = 'hash'
        elif key_data:
            self.type = 'key'
        elif token:
            self.type = 'token'
        else:
            self.type = 'plaintext'

    def fingerprint(self) -> str:
        """Unique fingerprint for deduplication."""
        key = f"{self.host_ip}|{self.username}|{self.password}|{self.hash_}|{self.token}"
        return hashlib.md5(key.encode()).hexdigest()[:12]

    @property
    def icon(self) -> str:
        return CRED_TYPES.get(self.type, '🔑')

    def mark_cracked(self, plaintext: str):
        self.cracked    = True
        self.cracked_pw = plaintext

    def to_dict(self) -> dict:
        return {
            'id': self.id, 'host_ip': self.host_ip,
            'username': self.username, 'password': self.password,
            'hash': self.hash_, 'key_data': self.key_data[:50],
            'token': self.token[:50], 'type': self.type,
            'service': self.service, 'domain': self.domain,
            'source': self.source, 'cracked': self.cracked,
            'cracked_pw': self.cracked_pw, 'ts': self.ts,
        }

    def display(self) -> str:
        parts = [f"{self.icon} [{self.type:<10}]"]
        if self.username: parts.append(f"user:{self.username}")
        if self.password: parts.append(f"pass:{self.password}")
        if self.hash_:    parts.append(f"hash:{self.hash_[:20]}…")
        if self.token:    parts.append(f"token:{self.token[:20]}…")
        if self.service:  parts.append(f"svc:{self.service}")
        if self.domain:   parts.append(f"dom:{self.domain}")
        if self.cracked:  parts.append(f"⚡CRACKED:{self.cracked_pw}")
        return ' | '.join(parts)


class CredentialStore:
    """
    Central credential registry.
    Deduplicates by fingerprint, links to hosts and sessions.
    Persists to DB loot table.
    """

    def __init__(self):
        self._creds: List[Credential]        = []
        self._fp_seen: Dict[str, Credential] = {}
        self._load_from_db()

    def _load_from_db(self):
        try:
            from db import get_db
            db    = get_db()
            rows  = db.search_loot(category='credentials')
            rows += db.search_loot(category='hashes')
            rows += db.search_loot(category='private_keys')
            rows += db.search_loot(category='api_tokens')
            for r in rows:
                data = r.get('data', '')
                # Try to parse JSON loot
                try:
                    d = json.loads(data)
                except Exception:
                    continue
                if not isinstance(d, dict):
                    continue
                cred = Credential(
                    host_ip    = r.get('host', ''),
                    username   = d.get('username', ''),
                    password   = d.get('password', ''),
                    hash_      = d.get('hash', ''),
                    token      = d.get('token', ''),
                    key_data   = d.get('key_data', ''),
                    service    = d.get('service', ''),
                    domain     = d.get('domain', ''),
                    source     = r.get('source', 'db'),
                    session_id = r.get('session_id') or 0,
                )
                fp = cred.fingerprint()
                if fp not in self._fp_seen:
                    self._fp_seen[fp] = cred
                    self._creds.append(cred)
        except Exception:
            pass

    def _save_to_db(self, cred: Credential):
        try:
            from db import get_db
            db       = get_db()
            cat_map  = {'plaintext': 'credentials', 'hash': 'hashes',
                        'key': 'private_keys', 'token': 'api_tokens'}
            category = cat_map.get(cred.type, 'credentials')
            db.add_loot(
                session_id = cred.session_id,
                host       = cred.host_ip,
                category   = category,
                source     = cred.source,
                data       = json.dumps(cred.to_dict()),
            )
        except Exception:
            pass

    def add(self, host_ip: str = "", username: str = "",
            password: str = "", hash_: str = "",
            key_data: str = "", token: str = "",
            cred_type: str = "", service: str = "",
            domain: str = "", source: str = "manual",
            session_id: int = 0) -> Optional[Credential]:
        """Add a credential. Returns None if duplicate."""
        cred = Credential(
            host_ip=host_ip, username=username, password=password,
            hash_=hash_, key_data=key_data, token=token,
            cred_type=cred_type, service=service, domain=domain,
            source=source, session_id=session_id,
        )
        fp = cred.fingerprint()
        if fp in self._fp_seen:
            return None  # deduplicated
        self._fp_seen[fp] = cred
        self._creds.append(cred)
        self._save_to_db(cred)
        # Emit event
        try:
            from core.event_bus import bus
            bus.emit('cred.discovered', host=host_ip, username=username,
                     cred_type=cred.type)
        except Exception:
            pass
        return cred

    def add_from_text(self, text: str, host_ip: str = "",
                      source: str = "auto") -> List[Credential]:
        """Parse text for username:password or username:hash patterns."""
        import re
        added = []
        # Match user:pass pairs
        for m in re.finditer(r'(\w[\w.\-@]{1,30}):([^\s:]{4,})', text):
            username = m.group(1)
            value    = m.group(2)
            # Detect hash vs plaintext
            is_hash = any(re.match(pat, value) for _, (_, pat) in HASH_PATTERNS.items())
            cred = self.add(
                host_ip=host_ip, username=username,
                hash_=value if is_hash else '',
                password=value if not is_hash else '',
                source=source,
            )
            if cred:
                added.append(cred)
        return added

    def mark_cracked(self, username: str, plaintext: str) -> bool:
        """Mark a hash as cracked."""
        for c in self._creds:
            if c.username == username and c.hash_:
                c.mark_cracked(plaintext)
                return True
        return False

    def by_host(self, host_ip: str) -> List[Credential]:
        return [c for c in self._creds if c.host_ip == host_ip]

    def by_type(self, cred_type: str) -> List[Credential]:
        return [c for c in self._creds if c.type == cred_type]

    def plaintexts(self) -> List[Credential]:
        return self.by_type('plaintext')

    def hashes(self) -> List[Credential]:
        return self.by_type('hash')

    def tokens(self) -> List[Credential]:
        return self.by_type('token') + self.by_type('certificate')

    def all(self) -> List[Credential]:
        return list(self._creds)

    def show(self, host_ip: Optional[str] = None) -> str:
        creds = self.by_host(host_ip) if host_ip else self._creds
        if not creds:
            return "\n  No credentials found.\n"
        lines = [f"\n  Credentials ({len(creds)} total):", ""]
        for c in creds:
            ts = c.ts[:16]
            lines.append(f"  [{ts}] {c.host_ip:<16} {c.display()}")
        lines.append("")
        return '\n'.join(lines)

    def summary(self) -> str:
        total      = len(self._creds)
        hosts      = len({c.host_ip for c in self._creds if c.host_ip})
        plaintext  = len(self.plaintexts())
        hashes_    = len(self.hashes())
        tokens_    = len(self.tokens())
        cracked    = len([c for c in self._creds if c.cracked])
        return (
            f"\n  Credentials: {total} total | "
            f"{plaintext} plaintext | {hashes_} hashes | "
            f"{tokens_} tokens | {cracked} cracked | "
            f"{hosts} hosts\n"
        )

    def export_list(self) -> str:
        """Export username:password list for use with tools."""
        lines = []
        for c in self._creds:
            if c.password:
                lines.append(f"{c.username}:{c.password}")
            elif c.cracked_pw:
                lines.append(f"{c.username}:{c.cracked_pw}")
        return '\n'.join(lines)


# Global singleton
cred_store = CredentialStore()
